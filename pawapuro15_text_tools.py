#!/usr/bin/env python3
"""
Text extraction toolkit for Jikkyou Powerful Pro Yakyuu 15.

Provides:
  - Glyph index ↔ Unicode character mapping (JIS X 0208)
  - Font glyph decompression (from fonttex2.rel)
  - Text string extraction from REL module data sections
  - Script bytecode text extraction from scs_sce*.rel event scripts

Text encoding formats found in the game:
  1. Glyph-indexed text: 16-bit BE values where lower 13 bits = glyph index.
     Used for menu strings, labels, pitch names in scs_main.rel sec5.
     Terminated by 0x1FFF.
  2. Script bytecodes: Mixed opcode/operand format in scs_sce*.rel.
     Opcodes are low-range values (0x00-0xFF), glyph text is inline.
     Script VM format requires further reverse engineering.
  3. SJIS strings: Used for debug labels and error messages in code sections.

Font system:
  - FontTex2 (fonttex2.rel): 3,744 glyphs, main game font
  - FontMain (fonttex2.rel +0x05DF64): alternate font (untested)
  - FontGaiji (fonttex2.rel +0x117400): special characters (untested)
  - Glyph size: 11 bytes wide × 28 rows, I4 format (4-bit intensity)
  - Custom bit-level compression with inter-glyph context

Usage:
  python3 pawapuro15_text_tools.py --help
  python3 pawapuro15_text_tools.py extract-text      # Extract all text strings
  python3 pawapuro15_text_tools.py dump-font          # Render font atlas
  python3 pawapuro15_text_tools.py char-table         # Print glyph→character table
  python3 pawapuro15_text_tools.py decode-bytes XXXX  # Decode hex glyph indices
"""
import struct
import os
import sys
import glob
import argparse
from collections import defaultdict

# ── Configuration ──────────────────────────────────────────────────────────

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_FILES = os.path.join(BASE_PATH, "DATA", "files")
FONTTEX2_PATH = os.path.join(DATA_FILES, "fonttex2.rel")

MAX_GLYPH = 3743  # Total glyphs in FontTex2


# ── Glyph ↔ Character Mapping ─────────────────────────────────────────────

def jis_to_char(j1, j2):
    """Convert JIS X 0208 row/column to Unicode character via Shift-JIS."""
    if j1 % 2 == 1:
        s1 = (j1 + 1) // 2 + 0x70
        if s1 > 0x9F:
            s1 += 0x40
        s2 = j2 + 0x1F if j2 <= 0x5F else j2 + 0x20
    else:
        s1 = j1 // 2 + 0x70
        if s1 > 0x9F:
            s1 += 0x40
        s2 = j2 + 0x7E
    try:
        return bytes([s1, s2]).decode('shift_jis')
    except Exception:
        return '\uFFFD'


def char_to_jis(ch):
    """Convert Unicode character to JIS X 0208 row/column via Shift-JIS."""
    try:
        sjis = ch.encode('shift_jis')
        if len(sjis) != 2:
            return None, None
        s1, s2 = sjis
        if s1 >= 0xE0:
            s1 -= 0x40
        j1_base = (s1 - 0x70) * 2
        if s2 >= 0x9F:
            j1 = j1_base
            j2 = s2 - 0x7E
        else:
            j1 = j1_base - 1
            j2 = s2 - 0x1F if s2 <= 0x7E else s2 - 0x20
        return j1, j2
    except Exception:
        return None, None


def glyph_to_char(g):
    """Convert glyph index (0-3743) to Unicode character.

    Font layout (JIS X 0208 based):
      Glyphs 0-657:   JIS rows 0x21-0x27 (7 full rows × 94 = 658)
                       Row 1: Symbols/punctuation
                       Row 2: More symbols
                       Row 3: Numerals, uppercase Latin, some symbols
                       Row 4: Lowercase Latin, hiragana start
                       Row 5: Hiragana
                       Row 6: Katakana
                       Row 7: Greek, Cyrillic, line drawing
      Glyphs 658-705: JIS row 0x28 (48 slots, partial row 8)
      Glyphs 706-3743: Kanji (JIS rows 0x30+, 3038 characters)
    """
    if g < 0 or g > MAX_GLYPH:
        return None
    if g <= 657:
        jis_row = (g // 94) + 0x21
        jis_col = (g % 94) + 0x21
        return jis_to_char(jis_row, jis_col)
    elif g <= 705:
        return jis_to_char(0x28, (g - 658) + 0x21)
    else:
        k = g - 706
        return jis_to_char((k // 94) + 0x30, (k % 94) + 0x21)


def char_to_glyph(ch):
    """Convert Unicode character to glyph index. Returns None if not in font."""
    j1, j2 = char_to_jis(ch)
    if j1 is None:
        return None

    if 0x21 <= j1 <= 0x27:
        row = j1 - 0x21
        col = j2 - 0x21
        if 0 <= col < 94:
            return row * 94 + col
    elif j1 == 0x28:
        col = j2 - 0x21
        if 0 <= col < 48:
            return 658 + col
    elif j1 >= 0x30:
        row = j1 - 0x30
        col = j2 - 0x21
        if 0 <= col < 94:
            g = 706 + row * 94 + col
            if g <= MAX_GLYPH:
                return g
    return None


def decode_glyph_string(values):
    """Decode a list of 16-bit glyph values to a string.

    Values 0x0001-0x0E9F are glyph indices.
    0x1FFF is a string terminator.
    0x0000 is a null separator.
    Other values are control codes/flags.
    """
    chars = []
    for v in values:
        glyph = v & 0x1FFF
        flags = (v >> 13) & 0x7
        if v == 0x1FFF or v == 0x0000:
            break
        if 0 < glyph <= MAX_GLYPH:
            ch = glyph_to_char(glyph)
            if ch:
                if flags:
                    chars.append(f'{ch}')  # Character with flags (for now, ignore flags)
                else:
                    chars.append(ch)
            else:
                chars.append(f'[g{glyph}]')
        else:
            chars.append(f'[0x{v:04X}]')
    return ''.join(chars)


# ── REL File Parsing ──────────────────────────────────────────────────────

def parse_rel_header(filepath):
    """Parse REL file header and return section info."""
    with open(filepath, "rb") as f:
        header = f.read(0x40)
        if len(header) < 0x40:
            return None

        mod_id = struct.unpack_from(">I", header, 0)[0]
        num_sections = struct.unpack_from(">I", header, 0x0C)[0]
        sec_table_off = struct.unpack_from(">I", header, 0x10)[0]

        f.seek(sec_table_off)
        sections = []
        for s in range(min(num_sections, 30)):
            raw_off = struct.unpack_from(">I", f.read(4), 0)[0]
            sec_size = struct.unpack_from(">I", f.read(4), 0)[0]
            is_bss = (raw_off & 1) != 0
            actual_off = raw_off & ~3
            sections.append({
                'index': s,
                'offset': actual_off,
                'size': sec_size,
                'bss': is_bss,
            })

    return {'mod_id': mod_id, 'sections': sections, 'path': filepath}


def read_section_data(filepath, section_info):
    """Read raw bytes of a section."""
    if section_info['bss'] or section_info['size'] == 0:
        return b''
    with open(filepath, 'rb') as f:
        f.seek(section_info['offset'])
        return f.read(section_info['size'])


# ── Text Extraction ───────────────────────────────────────────────────────

def extract_glyph_strings(data, min_len=3, terminator=0x1FFF):
    """Extract 0x1FFF-terminated glyph-indexed text strings from binary data.

    Finds runs of valid glyph indices (1-3743) terminated by 0x1FFF or 0x0000.
    """
    strings = []
    i = 0
    while i < len(data) - 1:
        val = struct.unpack_from(">H", data, i)[0]
        if 0 < val <= MAX_GLYPH:
            start = i
            glyphs = []
            j = i
            while j < len(data) - 1:
                v = struct.unpack_from(">H", data, j)[0]
                if 0 < v <= MAX_GLYPH:
                    glyphs.append(v)
                    j += 2
                elif v == terminator:
                    j += 2
                    break
                elif v == 0x0000:
                    j += 2
                    break
                else:
                    break

            if len(glyphs) >= min_len:
                text = ''.join(glyph_to_char(g) or '?' for g in glyphs)
                strings.append({
                    'offset': start,
                    'text': text,
                    'glyphs': glyphs,
                    'length': len(glyphs),
                })
            i = j
        else:
            i += 2
    return strings


def extract_sjis_strings(data, min_len=6):
    """Extract Shift-JIS encoded strings from binary data."""
    strings = []
    i = 0
    while i < len(data):
        b = data[i]
        chars = []
        start = i
        j = i
        while j < len(data):
            b1 = data[j]
            if (0x81 <= b1 <= 0x9F or 0xE0 <= b1 <= 0xEF) and j + 1 < len(data):
                b2 = data[j + 1]
                if 0x40 <= b2 <= 0xFC and b2 != 0x7F:
                    try:
                        ch = bytes([b1, b2]).decode('shift_jis')
                        chars.append(ch)
                        j += 2
                        continue
                    except:
                        break
                else:
                    break
            elif 0x20 <= b1 <= 0x7E:
                chars.append(chr(b1))
                j += 1
                continue
            elif b1 == 0x0A:
                chars.append('\n')
                j += 1
                continue
            else:
                break

        text = ''.join(chars)
        jp_count = sum(1 for c in text if ord(c) > 0x7F)
        if len(text) >= min_len and jp_count >= 2:
            strings.append({
                'offset': start,
                'text': text,
                'length': len(text),
                'encoding': 'sjis',
            })
        i = max(j, i + 1)
    return strings


def is_clean_text(text, min_readable=0.5):
    """Check if a decoded string is clean readable Japanese (not bytecode artifacts)."""
    hiragana = sum(1 for c in text if '\u3040' <= c <= '\u309F')
    katakana = sum(1 for c in text if '\u30A0' <= c <= '\u30FF')
    kanji = sum(1 for c in text if '\u4E00' <= c <= '\u9FFF')
    fullwidth = sum(1 for c in text if '\uFF01' <= c <= '\uFF5E')
    punct = sum(1 for c in text if c in '。、！？「」『』（）・…ーゝゞ〜')

    total = len(text)
    if total == 0:
        return False
    readable = hiragana + katakana + kanji + fullwidth + punct
    return (readable / total >= min_readable and
            (hiragana + katakana + kanji) >= 2 and
            len(text) >= 3)


# ── Font Decompression ─────────────────────────────────────────────────────

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
        bit = 1 if (self.data[self.byte_idx] & self.masks[self.bit_idx]) else 0
        self.bit_idx += 1
        if self.bit_idx > 7:
            self.bit_idx = 0
            self.byte_idx += 1
        return bit

    def read_varlen(self):
        """Read variable-length integer (1-19): 2 bits, if zero then 4 more."""
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


def decompress_glyph(data, prev_values=None):
    """Decompress a single glyph from the custom compression format.

    Returns (output_bytes, values_context).
    Output is 512 bytes: 28 rows × 16 bytes (11 data + 5 padding) + 64 trailing 0xFF.
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

    counts = [0] * 11
    values = list(prev_values) if prev_values else [0] * 11
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
                        target_slot = slot + i
                        if target_slot >= 11:
                            break
                        counts[target_slot] = repeat_count
                        values[target_slot] = literal_byte
                    counts[slot] -= 1
                    output.append(values[slot])
        output.extend([0xFF] * 5)

    output.extend([0xFF] * 64)
    return output, values


def load_glyph_data(glyph_index, font_offset=0):
    """Load compressed glyph data from fonttex2.rel."""
    with open(FONTTEX2_PATH, "rb") as f:
        sec4_offset = 0x2A0
        font_base = sec4_offset + font_offset

        f.seek(font_base + 2)
        glyph_count = struct.unpack("<H", f.read(2))[0]

        if glyph_index >= glyph_count:
            return None

        offset_table_start = font_base + 4
        f.seek(offset_table_start + glyph_index * 4)
        offset = struct.unpack("<I", f.read(4))[0]

        if glyph_index + 1 < glyph_count:
            next_offset = struct.unpack("<I", f.read(4))[0]
        else:
            next_offset = offset + 256

        glyph_data_base = offset_table_start + glyph_count * 4
        f.seek(glyph_data_base + offset)
        size = next_offset - offset
        return f.read(size)


# ── CLI Commands ───────────────────────────────────────────────────────────

def cmd_extract_text(args):
    """Extract all readable text from game files."""
    print("=" * 80)
    print("JIKKYOU POWERFUL PRO YAKYUU 15 — TEXT EXTRACTION")
    print("=" * 80)
    print()

    all_strings = []

    # 1. Extract from scs_main.rel section 5 (main game data)
    main_path = os.path.join(DATA_FILES, "scs_main.rel")
    if os.path.exists(main_path):
        rel = parse_rel_header(main_path)
        if rel and len(rel['sections']) > 5:
            sec5 = rel['sections'][5]
            data = read_section_data(main_path, sec5)
            strings = extract_glyph_strings(data, min_len=3)
            clean = [s for s in strings if is_clean_text(s['text'])]
            print(f"scs_main.rel sec5: {len(strings)} raw strings, {len(clean)} clean")

            for s in clean:
                s['file'] = 'scs_main.rel'
                s['section'] = 5
                all_strings.append(s)

    # 2. Extract from all scs_*.rel files
    for relpath in sorted(glob.glob(os.path.join(DATA_FILES, "scs_*.rel"))):
        name = os.path.basename(relpath)
        if name == "scs_main.rel":
            continue  # Already done
        rel = parse_rel_header(relpath)
        if not rel:
            continue
        for sec in rel['sections']:
            if sec['bss'] or sec['size'] < 100 or sec['index'] < 4:
                continue
            data = read_section_data(relpath, sec)

            # Glyph strings
            strings = extract_glyph_strings(data, min_len=4)
            clean = [s for s in strings if is_clean_text(s['text'])]
            if clean:
                print(f"{name} sec{sec['index']}: {len(clean)} clean glyph strings")
                for s in clean:
                    s['file'] = name
                    s['section'] = sec['index']
                    all_strings.append(s)

            # SJIS strings
            sjis = extract_sjis_strings(data, min_len=10)
            sjis_clean = [s for s in sjis if is_clean_text(s['text'])]
            if sjis_clean:
                print(f"{name} sec{sec['index']}: {len(sjis_clean)} clean SJIS strings")
                for s in sjis_clean:
                    s['file'] = name
                    s['section'] = sec['index']
                    all_strings.append(s)

    print(f"\nTotal: {len(all_strings)} clean text strings")
    print()

    # Output
    output_path = args.output or os.path.join(BASE_PATH, "extracted_text.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("JIKKYOU POWERFUL PRO YAKYUU 15 — EXTRACTED TEXT\n")
        f.write(f"Total strings: {len(all_strings)}\n")
        f.write("=" * 80 + "\n\n")

        # Group by file
        by_file = defaultdict(list)
        for s in all_strings:
            by_file[s['file']].append(s)

        for filename in sorted(by_file.keys()):
            items = by_file[filename]
            f.write(f"\n{'─' * 60}\n")
            f.write(f"FILE: {filename} ({len(items)} strings)\n")
            f.write(f"{'─' * 60}\n\n")

            for s in sorted(items, key=lambda x: x['offset']):
                enc = s.get('encoding', 'glyph')
                f.write(f"[{enc}] sec{s['section']}+0x{s['offset']:06X} ({s['length']}ch)\n")
                f.write(f"  {s['text']}\n\n")

    print(f"Output saved to: {output_path}")


def cmd_char_table(args):
    """Print the full glyph index → Unicode character mapping table."""
    print("GLYPH INDEX → CHARACTER TABLE")
    print("=" * 60)

    sections = [
        ("Symbols (JIS row 1)", 0, 93),
        ("Symbols (JIS row 2)", 94, 187),
        ("Numbers/Latin upper (JIS row 3)", 188, 281),
        ("Latin lower/Hiragana (JIS row 4)", 282, 375),
        ("Hiragana (JIS row 5)", 376, 469),
        ("Katakana (JIS row 6)", 470, 563),
        ("Greek/Cyrillic/Line (JIS row 7)", 564, 657),
        ("Partial row 8", 658, 705),
        ("Kanji (JIS rows 0x30+)", 706, MAX_GLYPH),
    ]

    for name, start, end in sections:
        print(f"\n--- {name} (glyphs {start}-{end}) ---")
        line = []
        for g in range(start, end + 1):
            ch = glyph_to_char(g)
            if ch and ch != '\uFFFD':
                line.append(ch)
            else:
                line.append('·')
            if len(line) >= 47:
                print(f"  {g-len(line)+1:4d}: {''.join(line)}")
                line = []
        if line:
            print(f"  {end-len(line)+1:4d}: {''.join(line)}")


def cmd_decode_bytes(args):
    """Decode hex glyph index values to characters."""
    values = []
    for hexval in args.values:
        try:
            v = int(hexval, 16)
            values.append(v)
        except ValueError:
            print(f"Invalid hex value: {hexval}")
            return

    for v in values:
        glyph = v & 0x1FFF
        flags = (v >> 13) & 0x7
        ch = glyph_to_char(glyph) if 0 < glyph <= MAX_GLYPH else None
        flag_str = f" flags={flags}" if flags else ""
        char_str = f' = "{ch}"' if ch else " = [unmapped]"
        print(f"0x{v:04X}: glyph={glyph}{char_str}{flag_str}")


def cmd_dump_font(args):
    """Render font atlas as PNG."""
    try:
        from PIL import Image
    except ImportError:
        print("PIL/Pillow required: pip install Pillow")
        return

    cols = args.cols or 64
    scale = args.scale or 2
    glyph_w, glyph_h = 11, 28
    total = MAX_GLYPH + 1
    rows = (total + cols - 1) // cols

    print(f"Rendering {total} glyphs ({cols} per row, {rows} rows, scale {scale}x)...")

    img = Image.new('L', (cols * glyph_w * scale, rows * glyph_h * scale), 255)

    for glyph_idx in range(total):
        data = load_glyph_data(glyph_idx)
        if data is None:
            continue
        output, _ = decompress_glyph(data)

        r, c = divmod(glyph_idx, cols)
        glyph_img = Image.new('L', (glyph_w, glyph_h), 255)
        pixels = glyph_img.load()
        for gy in range(glyph_h):
            for gx in range(glyph_w):
                bidx = gy * 16 + gx
                if bidx < len(output):
                    pixels[gx, gy] = output[bidx]
        glyph_scaled = glyph_img.resize((glyph_w * scale, glyph_h * scale), Image.NEAREST)
        img.paste(glyph_scaled, (c * glyph_w * scale, r * glyph_h * scale))

        if glyph_idx % 500 == 0:
            print(f"  {glyph_idx}/{total}...")

    output_path = args.output or os.path.join(BASE_PATH, "font_atlas.png")
    img.save(output_path)
    print(f"Saved to: {output_path}")


def cmd_info(args):
    """Show information about the text system."""
    print("JIKKYOU POWERFUL PRO YAKYUU 15 — TEXT SYSTEM INFO")
    print("=" * 60)
    print()
    print("Font: fonttex2.rel")
    print(f"  Total glyphs: {MAX_GLYPH + 1}")
    print(f"  Glyph size: 11×28 pixels (I4 format, 4-bit intensity)")
    print(f"  Compression: Custom bit-level RLE with inter-glyph context")
    print()
    print("Character mapping (JIS X 0208):")
    print(f"  Glyphs    0- 93: Symbols/punctuation (JIS row 1)")
    print(f"  Glyphs   94-187: More symbols (JIS row 2)")
    print(f"  Glyphs  188-281: Digits, uppercase Latin (JIS row 3)")
    print(f"  Glyphs  282-375: Lowercase Latin, misc (JIS row 4)")
    print(f"  Glyphs  376-469: Hiragana (JIS row 5)")
    print(f"  Glyphs  470-563: Katakana (JIS row 6)")
    print(f"  Glyphs  564-657: Greek, Cyrillic, line drawing (JIS row 7)")
    print(f"  Glyphs  658-705: Miscellaneous (JIS row 8 partial)")
    print(f"  Glyphs  706-3743: Kanji (JIS level 1+2)")
    print()
    print("Text encoding:")
    print(f"  Format: 16-bit big-endian")
    print(f"  Lower 13 bits: glyph index (& 0x1FFF)")
    print(f"  Upper 3 bits: control flags (meaning TBD)")
    print(f"  Terminator: 0x1FFF")
    print(f"  Null separator: 0x0000")
    print()
    print("Key files:")
    print(f"  scs_main.rel sec5: Menu/UI strings, pitch names, kanji tables")
    print(f"  scs_sce1/2/3.rel: Event scripts (bytecode with inline text)")
    print(f"  scs_rens.rel: Character/rendering data")
    print(f"  main_prg.rel sec1+0x078800: Glyph decompressor function")
    print(f"  main_prg.rel sec1+0x0D4C20: Text rendering caller")


def main():
    parser = argparse.ArgumentParser(
        description="Text extraction toolkit for Jikkyou Powerful Pro Yakyuu 15")
    subparsers = parser.add_subparsers(dest='command')

    # extract-text
    p_extract = subparsers.add_parser('extract-text', help='Extract all text strings')
    p_extract.add_argument('-o', '--output', help='Output file path')

    # char-table
    subparsers.add_parser('char-table', help='Print glyph→character table')

    # decode-bytes
    p_decode = subparsers.add_parser('decode-bytes', help='Decode hex glyph values')
    p_decode.add_argument('values', nargs='+', help='Hex values (e.g. 01C0 017B)')

    # dump-font
    p_font = subparsers.add_parser('dump-font', help='Render font atlas PNG')
    p_font.add_argument('-o', '--output', help='Output file path')
    p_font.add_argument('-c', '--cols', type=int, help='Glyphs per row (default: 64)')
    p_font.add_argument('-s', '--scale', type=int, help='Scale factor (default: 2)')

    # info
    subparsers.add_parser('info', help='Show text system information')

    args = parser.parse_args()

    if args.command == 'extract-text':
        cmd_extract_text(args)
    elif args.command == 'char-table':
        cmd_char_table(args)
    elif args.command == 'decode-bytes':
        cmd_decode_bytes(args)
    elif args.command == 'dump-font':
        cmd_dump_font(args)
    elif args.command == 'info':
        cmd_info(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
