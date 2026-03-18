#!/usr/bin/env python3
"""
Glyph decompressor for Jikkyou Powerful Pro Yakyuu 15.

Based on reverse-engineering of the function at main_prg.rel sec1+0x078800.

Format:
  byte 0: flag_count (number of bitstream bytes)
  bytes 1..flag_count: bitstream (control bits, read MSB first)
  bytes flag_count+1..: literal data stream

The decompressor produces an 11×28 symbol grid (each symbol = 1 byte),
padded to 16 bytes per row (5 bytes of 0xFF padding per row).
Total raw output = 28 * 16 = 448 bytes, then 64 bytes of 0xFF = 512.

Context: two 11-element arrays (counts[] and values[]) track run-length repeats
across rows. When counts[slot] > 0, the cached value is repeated without
reading new bits. NOTE: only counts[] is zeroed at function entry; values[]
persists from the previous decompressor call (BSS memory). For stand-alone
decompression, values[] starts as all zeros.

Variable-length integer encoding (used for both fill_count and repeat_count):
  Read 2 bits → value = bit_a*2 + bit_b
  If value != 0: result = value (1-3)
  If value == 0: read 4 more bits → result = 4 + (b*8 + c*4 + d*2 + e) (range 4-19)

Encoding (bit-by-bit from bitstream):
  bit1=0: LITERAL (read next byte from literal stream, output it)
  bit1=1: BACK-REFERENCE
    Read fill_count using variable-length encoding (1-19)
    Read repeat_count using variable-length encoding (1-19)
    Read literal_byte from literal stream
    For i in 0..fill_count-1: set counts[slot+i] = repeat_count, values[slot+i] = literal_byte
    Output literal_byte, decrement counts[slot]
"""
import struct
import sys
import os
from PIL import Image

FONTTEX2_PATH = "/sessions/kind-keen-brown/mnt/Jikkyou Powerful Pro Yakyuu 15 (Japan) (Rev 1)/DATA/files/fonttex2.rel"


class BitReader:
    """Read bits MSB-first from a byte array, matching the PPC assembly behavior."""
    def __init__(self, data):
        self.data = data
        self.byte_idx = 0
        self.bit_idx = 0
        # Bitmask table from sec4+0x1258: [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]
        self.masks = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

    def read_bit(self):
        if self.byte_idx >= len(self.data):
            return 0
        mask = self.masks[self.bit_idx]
        byte_val = self.data[self.byte_idx]
        # The assembly does: AND, NEG, OR, SRWI 31 → converts nonzero to 1
        bit = 1 if (byte_val & mask) else 0
        self.bit_idx += 1
        if self.bit_idx > 7:
            self.bit_idx = 0
            self.byte_idx += 1
        return bit

    def read_varlen(self):
        """Read a variable-length integer (1-19) using the 2+4 bit encoding.

        Read 2 bits → value. If nonzero, return value (1-3).
        If zero, read 4 more bits → return 4 + value (4-19).
        """
        a = self.read_bit()
        b = self.read_bit()
        value = a * 2 + b
        if value != 0:
            return value
        # Extended: read 4 more bits
        c = self.read_bit()
        d = self.read_bit()
        e = self.read_bit()
        f = self.read_bit()
        return 4 + (c * 8 + d * 4 + e * 2 + f)


def decompress_glyph(data, prev_values=None):
    """Decompress a single glyph from compressed data.

    Args:
        data: Raw compressed glyph bytes
        prev_values: Previous values[] context (11 bytes) for inter-glyph dependency.
                     If None, starts with all zeros (first-call behavior).

    Returns a tuple of (output_bytes, values_context):
        output_bytes: list of bytes (the decompressed glyph data, 512 bytes)
        values_context: the values[] array after decompression (for chaining)
    """
    if len(data) < 2:
        return [0xFF] * 512, [0] * 11

    flag_count = data[0]
    bitstream = data[1:1 + flag_count]
    literals = data[1 + flag_count:]

    bits = BitReader(bitstream)
    lit_idx = 0

    def read_literal():
        nonlocal lit_idx
        if lit_idx >= len(literals):
            return 0xFF
        val = literals[lit_idx]
        lit_idx += 1
        return val

    # Context arrays (11 slots each)
    counts = [0] * 11
    values = list(prev_values) if prev_values else [0] * 11

    output = []

    for row in range(28):
        for slot in range(11):
            if counts[slot] != 0:
                # ALTERNATE: repeat cached value, decrement count
                counts[slot] -= 1
                output.append(values[slot])
            else:
                # Decode new symbol from bitstream
                bit1 = bits.read_bit()

                if bit1 == 0:
                    # LITERAL: read byte from literal stream, output it directly
                    val = read_literal()
                    output.append(val)
                else:
                    # BACK-REFERENCE encoding
                    # Read fill_count (how many consecutive slots to fill)
                    fill_count = bits.read_varlen()  # 1-19

                    # Read repeat_count (how many rows the value persists)
                    repeat_count = bits.read_varlen()  # 1-19

                    # Read the literal byte value
                    literal_byte = read_literal()

                    # Fill context slots starting from current slot
                    for i in range(fill_count):
                        target_slot = slot + i
                        if target_slot >= 11:
                            break
                        counts[target_slot] = repeat_count
                        values[target_slot] = literal_byte

                    # Output current slot value and decrement
                    counts[slot] -= 1
                    output.append(values[slot])

        # Pad row to 16 bytes with 0xFF
        output.extend([0xFF] * 5)

    # Fill remaining 64 bytes with 0xFF (post-grid padding)
    output.extend([0xFF] * 64)

    return output, values


def load_glyph_data(glyph_index, font_offset=0):
    """Load compressed glyph data from fonttex2.rel.

    Args:
        glyph_index: Index into the glyph table
        font_offset: Offset within section 4 for the font dataset
                     (0 for FontTex2, 0x05DF64 for FontMain, 0x117400 for FontGaiji)
    """
    with open(FONTTEX2_PATH, "rb") as f:
        # Section 4 starts at offset 0x2A0
        sec4_offset = 0x2A0
        font_base = sec4_offset + font_offset

        # Read header: bytes 2-3 as LE u16 = glyph count
        f.seek(font_base + 2)
        glyph_count = struct.unpack("<H", f.read(2))[0]

        if glyph_index >= glyph_count:
            return None

        # Read offset table entry
        offset_table_start = font_base + 4
        f.seek(offset_table_start + glyph_index * 4)
        offset = struct.unpack("<I", f.read(4))[0]

        # Read next offset to determine size
        if glyph_index + 1 < glyph_count:
            next_offset = struct.unpack("<I", f.read(4))[0]
        else:
            next_offset = offset + 256  # fallback

        glyph_data_base = offset_table_start + glyph_count * 4
        f.seek(glyph_data_base + offset)
        size = next_offset - offset
        return f.read(size)


def render_glyph(output_bytes, filename, scale=4):
    """Render decompressed glyph data as a grayscale image.

    The decompressed data is 28 rows × 16 bytes, with the first 11 bytes
    being the actual glyph data and the last 5 being 0xFF padding.
    """
    width = 11
    height = 28
    img = Image.new('L', (width, height), 255)
    pixels = img.load()

    for row in range(height):
        for col in range(width):
            idx = row * 16 + col  # 16 bytes per row (11 data + 5 padding)
            if idx < len(output_bytes):
                pixels[col, row] = output_bytes[idx]

    # Scale up for visibility
    img_scaled = img.resize((width * scale, height * scale), Image.NEAREST)
    img_scaled.save(filename)
    return img


def render_glyph_grid(glyphs_data, filename, cols=16, scale=3):
    """Render multiple glyphs in a grid."""
    glyph_w, glyph_h = 11, 28
    rows = (len(glyphs_data) + cols - 1) // cols

    img = Image.new('L', (cols * glyph_w * scale, rows * glyph_h * scale), 255)

    for idx, (glyph_idx, output) in enumerate(glyphs_data):
        r, c = divmod(idx, cols)
        glyph_img = Image.new('L', (glyph_w, glyph_h), 255)
        pixels = glyph_img.load()
        for gy in range(glyph_h):
            for gx in range(glyph_w):
                bidx = gy * 16 + gx
                if bidx < len(output):
                    pixels[gx, gy] = output[bidx]
        glyph_scaled = glyph_img.resize((glyph_w * scale, glyph_h * scale), Image.NEAREST)
        img.paste(glyph_scaled, (c * glyph_w * scale, r * glyph_h * scale))

    img.save(filename)
    return img


def main():
    os.makedirs("/sessions/kind-keen-brown/glyph_test", exist_ok=True)

    # Test individual glyphs
    test_glyphs = {
        0: "glyph_000 (first)",
        1: "glyph_001",
        10: "glyph_010",
        210: "glyph_210 (あ hiragana_a)",
        219: "glyph_219 (か hiragana_ka)",
        254: "glyph_254 (の hiragana_no)",
        796: "glyph_796 (亜 kanji_a)",
        871: "glyph_871 (一 kanji_ichi)",
    }

    # Sequential decompression (respecting inter-glyph context)
    # Since values[] persists, we need to decompress all glyphs in order
    # For testing, first try with zero-initialized values (stand-alone)

    print("=" * 70)
    print("STAND-ALONE DECOMPRESSION (zero-initialized values[])")
    print("=" * 70)

    for idx in sorted(test_glyphs.keys()):
        name = test_glyphs[idx]
        data = load_glyph_data(idx)
        if data is None:
            print(f"Glyph {idx}: not found")
            continue

        print(f"\n--- Glyph {idx}: {name} ---")
        print(f"  Compressed: {len(data)} bytes, flag_count={data[0]}, "
              f"bitstream={data[0]}B, literals={len(data)-1-data[0]}B")

        try:
            output, values = decompress_glyph(data)

            # Count non-0xFF bytes per row
            non_ff_total = 0
            for row in range(28):
                row_data = output[row*16:row*16+11]
                non_ff = sum(1 for b in row_data if b != 0xFF)
                non_ff_total += non_ff

            print(f"  Output: {len(output)} bytes, non-0xFF pixels: {non_ff_total}/308")

            # Show first 5 rows (just the 11 data bytes)
            for row in range(min(5, 28)):
                row_data = output[row*16:row*16+11]
                hex_str = ' '.join(f'{b:02X}' for b in row_data)
                # Visual representation
                vis = ''.join('█' if b < 0x40 else '▓' if b < 0x80 else '░' if b < 0xC0 else '·' if b < 0xFF else ' ' for b in row_data)
                print(f"    Row {row:2d}: {hex_str}  |{vis}|")
            if non_ff_total > 0:
                print(f"    ...")

            # Render
            fname = f"/sessions/kind-keen-brown/glyph_test/glyph_{idx:04d}.png"
            render_glyph(output, fname)
            print(f"  Saved: {fname}")

        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()

    # Now try sequential decompression for a range
    print("\n" + "=" * 70)
    print("SEQUENTIAL DECOMPRESSION (glyphs 200-220, hiragana range)")
    print("=" * 70)

    values_ctx = [0] * 11  # Start fresh
    grid_data = []

    # First decompress glyphs 0-199 to build up context
    print("  Building context by decompressing glyphs 0-199...")
    for idx in range(200):
        data = load_glyph_data(idx)
        if data is None:
            continue
        _, values_ctx = decompress_glyph(data, values_ctx)

    # Now decompress and display 200-220
    for idx in range(200, 221):
        data = load_glyph_data(idx)
        if data is None:
            continue
        output, values_ctx = decompress_glyph(data, values_ctx)
        grid_data.append((idx, output))

        non_ff = sum(1 for i in range(28) for j in range(11)
                     if output[i*16+j] != 0xFF)
        print(f"  Glyph {idx}: non-0xFF={non_ff}")

    if grid_data:
        fname = "/sessions/kind-keen-brown/glyph_test/hiragana_grid.png"
        render_glyph_grid(grid_data, fname, cols=7, scale=4)
        print(f"  Grid saved: {fname}")

    # Also render a stand-alone grid of test glyphs
    standalone_data = []
    for idx in sorted(test_glyphs.keys()):
        data = load_glyph_data(idx)
        if data is None:
            continue
        output, _ = decompress_glyph(data)
        standalone_data.append((idx, output))

    if standalone_data:
        fname = "/sessions/kind-keen-brown/glyph_test/test_grid.png"
        render_glyph_grid(standalone_data, fname, cols=4, scale=4)
        print(f"  Test grid saved: {fname}")


if __name__ == "__main__":
    main()
