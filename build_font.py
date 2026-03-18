#!/usr/bin/env python3
"""
Half-width English font builder for Jikkyou Powerful Pro Yakyuu 15.

Renders 95 ASCII glyphs (0x20-0x7E) at 11x28 pixels using DejaVu Sans Mono Bold,
converts to I4 format, compresses using the game's RLE+entropy format, and outputs
font_patch.bin.

The inject_font() function in insert_text.py handles decompressing these glyphs,
re-compressing with optimal RLE, and writing them in-place into fonttex2.rel.
"""

import struct
import os
from pathlib import Path

try:
    from PIL import Image, ImageFont, ImageDraw
except ImportError:
    print("ERROR: Pillow is required. Install with: pip install Pillow --break-system-packages")
    raise


# ==============================================================================
# I4 PIXEL FORMAT & COMPRESSION
# ==============================================================================

class BitWriter:
    """Write bits MSB-first to a byte array."""
    def __init__(self):
        self.bytes = []
        self.current_byte = 0
        self.bit_idx = 0
        self.masks = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

    def write_bit(self, bit):
        if bit:
            self.current_byte |= self.masks[self.bit_idx]
        self.bit_idx += 1
        if self.bit_idx >= 8:
            self.bytes.append(self.current_byte)
            self.current_byte = 0
            self.bit_idx = 0

    def flush(self):
        if self.bit_idx > 0:
            self.bytes.append(self.current_byte)
            self.current_byte = 0
            self.bit_idx = 0

    def get_bytes(self):
        self.flush()
        return self.bytes


def write_varlen(writer, value):
    """Write a variable-length integer (1-19) using 2+4 bit encoding."""
    if not (1 <= value <= 19):
        raise ValueError(f"varlen out of range: {value}")

    if 1 <= value <= 3:
        writer.write_bit((value >> 1) & 1)
        writer.write_bit(value & 1)
    else:
        writer.write_bit(0)
        writer.write_bit(0)
        adjusted = value - 4
        writer.write_bit((adjusted >> 3) & 1)
        writer.write_bit((adjusted >> 2) & 1)
        writer.write_bit((adjusted >> 1) & 1)
        writer.write_bit(adjusted & 1)


def compress_glyph(decompressed_bytes):
    """Compress decompressed glyph data using all-LITERAL encoding.

    Each glyph is compressed independently (no inter-glyph context).
    Uses all LITERALs (bit=0) for simplicity and correctness.
    The insert_text.py inject_font() will re-compress with optimal RLE.
    """
    literals = []
    bit_writer = BitWriter()

    for row in range(28):
        for slot in range(11):
            idx = row * 16 + slot
            if idx < len(decompressed_bytes):
                current_byte = decompressed_bytes[idx]
            else:
                current_byte = 0
            bit_writer.write_bit(0)  # LITERAL
            literals.append(current_byte)

    bitstream = bit_writer.get_bytes()
    flag_count = len(bitstream)
    compressed = bytes([flag_count]) + bytes(bitstream) + bytes(literals)
    return compressed


class BitReader:
    """Read bits MSB-first from a byte array."""
    def __init__(self, data):
        self.data = data
        self.byte_idx = 0
        self.bit_idx = 0
        self.masks = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

    def read_bit(self):
        if self.byte_idx >= len(self.data):
            return 0
        mask = self.masks[self.bit_idx]
        byte_val = self.data[self.byte_idx]
        bit = 1 if (byte_val & mask) else 0
        self.bit_idx += 1
        if self.bit_idx > 7:
            self.bit_idx = 0
            self.byte_idx += 1
        return bit

    def read_varlen(self):
        a = self.read_bit()
        b = self.read_bit()
        value = a * 2 + b
        if value != 0:
            return value
        c = self.read_bit()
        d = self.read_bit()
        e = self.read_bit()
        f = self.read_bit()
        return 4 + (c * 8 + d * 4 + e * 2 + f)


def decompress_glyph(data):
    """Decompress a glyph from compressed data (for round-trip verification).

    Each glyph is decompressed independently (no inter-glyph context).
    """
    if len(data) < 2:
        return [0xFF] * 512

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

    counts = [0] * 11
    values = [0] * 11
    output = []

    for row in range(28):
        for slot in range(11):
            if counts[slot] != 0:
                counts[slot] -= 1
                output.append(values[slot])
            else:
                bit1 = bits.read_bit()
                if bit1 == 0:
                    val = read_literal()
                    output.append(val)
                else:
                    fill_count = bits.read_varlen()
                    repeat_count = bits.read_varlen()
                    literal_byte = read_literal()
                    for i in range(fill_count):
                        if slot + i < 11:
                            counts[slot + i] = repeat_count
                            values[slot + i] = literal_byte
                    counts[slot] -= 1
                    output.append(values[slot])
        output.extend([0xFF] * 5)

    output.extend([0xFF] * 64)
    return output


# ==============================================================================
# GLYPH RENDERING WITH PILLOW
# ==============================================================================

# Glyph dimensions: 22 pixels wide (11 I4 bytes), 28 pixels tall
# The game's glyph cell is 22×28 — each byte = 2 I4 pixels, 11 bytes per row.
# We render full-width to match the Japanese character spacing.
GLYPH_W = 22
GLYPH_H = 28
# Font size 22px fits within 22×28: max char width ~14px (centered in 22px cell)
FONT_SIZE = 19
# Font: DejaVu Sans Mono Bold for crisp, readable glyphs
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
# Luminance threshold for converting antialiased rendering to 1-bit
THRESHOLD = 64


def render_glyph(char, font):
    """Render a single ASCII character to a 22x28 pixel bitmap.

    Returns list of 28 strings, each 22 chars of '#' (opaque) or '.' (transparent).
    """
    img = Image.new('L', (GLYPH_W, GLYPH_H), 0)
    draw = ImageDraw.Draw(img)

    if char == ' ':
        # Space is all transparent
        return [('.' * GLYPH_W)] * GLYPH_H

    bbox = font.getbbox(char)
    char_w = bbox[2] - bbox[0]
    ascent, descent = font.getmetrics()

    # Center horizontally, offset by glyph's left bearing
    x = max(0, (GLYPH_W - char_w) // 2 - bbox[0])
    # Vertically center the font metrics in the glyph cell
    y = max(0, (GLYPH_H - ascent - descent) // 2)

    draw.text((x, y), char, fill=255, font=font)

    # Convert to '#'/'.'' pattern
    lines = []
    for row in range(GLYPH_H):
        line = ''
        for col in range(GLYPH_W):
            px = img.getpixel((col, row))
            line += '#' if px > THRESHOLD else '.'
        lines.append(line)

    return lines


def pattern_to_i4_rows(pattern_lines):
    """Convert 28 lines of 22-char patterns to I4 decompressed format.

    Each pixel becomes a 4-bit I4 nibble. Two pixels pack into one byte.
    22 pixels → 11 bytes per row (exact fit, no padding needed in data portion).
    Row layout: 11 data bytes + 5 0xFF padding = 16 bytes per row.
    Total: 28 rows × 16 bytes = 448 bytes + 64 trailing 0xFF = 512 bytes.
    """
    if len(pattern_lines) != GLYPH_H:
        raise ValueError(f"Expected {GLYPH_H} lines, got {len(pattern_lines)}")

    output = []

    for line in pattern_lines:
        if len(line) != GLYPH_W:
            raise ValueError(f"Expected {GLYPH_W} chars per line, got {len(line)}")

        # Convert to I4 nibbles: '#' = 0x1 (text foreground), '.' = 0xF (background)
        # IMPORTANT: nibble 0x0 is NEVER used by the game's original glyphs and
        # appears to be treated as transparent/skip by the GX renderer. FontMain
        # uses 0x1-0xF; FontTex2 uses 0x8-0xF. We use 0x1 (darkest valid value).
        pixels = [0x1 if c == '#' else 0xF for c in line]

        # Pack into bytes: 2 pixels per byte (high nibble, low nibble)
        # 22 pixels → 11 bytes exactly
        row_bytes = []
        for i in range(0, GLYPH_W, 2):
            byte_val = (pixels[i] << 4) | pixels[i + 1]
            row_bytes.append(byte_val)

        assert len(row_bytes) == 11, f"Expected 11 bytes per row, got {len(row_bytes)}"

        # Add 5 bytes of row padding (standard decompressed format)
        row_bytes.extend([0xFF] * 5)
        output.extend(row_bytes)

    # Trailing padding
    output.extend([0xFF] * 64)

    assert len(output) == 512, f"Expected 512 bytes, got {len(output)}"
    return output


# ==============================================================================
# MAIN BUILDER
# ==============================================================================

def main():
    base_dir = Path(__file__).parent
    output_path = base_dir / 'font_patch.bin'

    print("Building half-width English font...")
    print(f"  Glyph size: {GLYPH_W}x{GLYPH_H} pixels")
    print(f"  Font: DejaVu Sans Mono Bold @ {FONT_SIZE}px")
    print(f"  Characters: ASCII 0x20-0x7E (95 glyphs)")
    print()

    # Load font
    if not os.path.exists(FONT_PATH):
        print(f"ERROR: Font not found: {FONT_PATH}")
        print("Install with: apt-get install fonts-dejavu-core")
        return

    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)

    compressed_glyphs = []
    total_pixels = 0

    for char_code in range(0x20, 0x7F):
        char = chr(char_code)

        # Render glyph with Pillow
        pattern = render_glyph(char, font)

        # Count non-transparent pixels
        px_count = sum(line.count('#') for line in pattern)
        total_pixels += px_count

        # Convert to I4 decompressed format (512 bytes)
        decompressed = pattern_to_i4_rows(pattern)

        # Compress (all-literal for now; inject_font re-compresses with RLE)
        compressed = compress_glyph(decompressed)
        compressed_glyphs.append((char_code, compressed))

        # Round-trip verification
        test_decompressed = decompress_glyph(compressed)
        if test_decompressed == decompressed:
            status = "OK"
        else:
            status = "MISMATCH!"
        print(f"  0x{char_code:02X} '{char}': {len(compressed):4d} bytes, "
              f"{px_count:3d} pixels [{status}]")

    # Build font_patch.bin
    patch_data = b''
    glyph_count = len(compressed_glyphs)

    # Header: 4 bytes (u16 zero + u16 LE glyph_count)
    patch_data += struct.pack('<H', 0x0000)
    patch_data += struct.pack('<H', glyph_count)

    # Offset table: LE u32 offsets relative to glyph data start
    current_offset = 0
    for char_code, compressed in compressed_glyphs:
        patch_data += struct.pack('<I', current_offset)
        current_offset += len(compressed)

    # Glyph data
    for char_code, compressed in compressed_glyphs:
        patch_data += compressed

    # Write output
    with open(output_path, 'wb') as f:
        f.write(patch_data)

    print(f"\nFont patch saved: {output_path}")
    print(f"  Total size: {len(patch_data)} bytes")
    print(f"  Header + offset table: {4 + glyph_count * 4} bytes")
    print(f"  Glyph data: {current_offset} bytes")
    print(f"  Total visible pixels: {total_pixels}")
    print(f"  Glyphs: {glyph_count}")


if __name__ == "__main__":
    main()
