"""Command line tools for the character table and the font: `python3 -m pp15 glyphs COMMAND`.

These are inspection tools for people studying how the game stores text (the library code is pp15/glyphs.py):

  extract-text      list the readable Japanese text found in the scs_*.rel modules (a quick survey, not the
                    translation workflow; that is `pp15 script`, `pp15 strings`)
  dump-font         draw all 3,744 font pictures into one PNG atlas (needs Pillow)
  char-table        print the glyph number -> character table
  decode-bytes HEX  turn 16-bit hex values (such as 01C0 017B) into glyph numbers and characters
  info              a short description of the text system

Public functions: main(argv) and one cmd_* function per command (each takes the parsed argparse namespace).
"""
import argparse
import glob
import os
from collections import defaultdict
from typing import List, Optional

from pp15 import config
from pp15.glyphs import (GLYPH_BYTES_W, GLYPH_ROW_PITCH, GLYPH_ROWS, GLYPH_MASK, FLAGS_SHIFT,
                         MAX_GLYPH, decompress_glyph, extract_glyph_strings, extract_sjis_strings, glyph_to_char,
                         is_clean_text, load_glyph_data, parse_rel_header, read_section_data)

MAIN_MODULE = "scs_main.rel"
MAIN_TEXT_SECTION = 5               # the menu and label strings of scs_main.rel live in this section
FIRST_SCRIPT_SECTION = 4            # sections below this hold code and tables, not text, in the other scs_*.rel
MIN_SECTION_SIZE = 100              # smaller sections are skipped
CHAR_TABLE_LINE = 47                # characters per printed line of char-table

# (title, first glyph, last glyph) of the blocks char-table prints
CHAR_TABLE_BLOCKS = [
    ("Symbols (JIS row 1)", 0, 93),
    ("Symbols (JIS row 2)", 94, 187),
    ("Digits and Latin letters (JIS row 3)", 188, 281),
    ("Hiragana (JIS row 4)", 282, 375),
    ("Katakana (JIS row 5)", 376, 469),
    ("Greek (JIS row 6)", 470, 563),
    ("Cyrillic (JIS row 7)", 564, 657),
    ("Line drawing (JIS row 8, partial)", 658, 705),
    ("Kanji (JIS rows 0x30+)", 706, MAX_GLYPH),
]


def _tag(strings: List[dict], filename: str, section: int, into: List[dict]) -> None:
    """Add the file and section to each found string and append them to `into`."""
    for s in strings:
        s['file'] = filename
        s['section'] = section
        into.append(s)


def collect_clean_strings() -> List[dict]:
    """Clean Japanese strings of scs_main.rel section 5 and of every other scs_*.rel (glyph and Shift-JIS text)."""
    all_strings: List[dict] = []

    main_path = os.path.join(config.DATA_FILES, MAIN_MODULE)
    if os.path.exists(main_path):
        rel = parse_rel_header(main_path)
        if rel and len(rel['sections']) > MAIN_TEXT_SECTION:
            sec5 = rel['sections'][MAIN_TEXT_SECTION]
            data = read_section_data(main_path, sec5)
            strings = extract_glyph_strings(data, min_len=3)
            clean = [s for s in strings if is_clean_text(s['text'])]
            print(f"{MAIN_MODULE} sec{MAIN_TEXT_SECTION}: {len(strings)} raw strings, {len(clean)} clean")
            _tag(clean, MAIN_MODULE, MAIN_TEXT_SECTION, all_strings)

    for relpath in sorted(glob.glob(os.path.join(config.DATA_FILES, "scs_*.rel"))):
        name = os.path.basename(relpath)
        if name == MAIN_MODULE:
            continue  # already done above
        rel = parse_rel_header(relpath)
        if not rel:
            continue
        for sec in rel['sections']:
            if sec['bss'] or sec['size'] < MIN_SECTION_SIZE or sec['index'] < FIRST_SCRIPT_SECTION:
                continue
            data = read_section_data(relpath, sec)

            strings = extract_glyph_strings(data, min_len=4)
            clean = [s for s in strings if is_clean_text(s['text'])]
            if clean:
                print(f"{name} sec{sec['index']}: {len(clean)} clean glyph strings")
                _tag(clean, name, sec['index'], all_strings)

            sjis = extract_sjis_strings(data, min_len=10)
            sjis_clean = [s for s in sjis if is_clean_text(s['text'])]
            if sjis_clean:
                print(f"{name} sec{sec['index']}: {len(sjis_clean)} clean SJIS strings")
                _tag(sjis_clean, name, sec['index'], all_strings)
    return all_strings


def write_text_report(all_strings: List[dict], output_path: str) -> None:
    """Write the strings, grouped by file and sorted by offset, to a UTF-8 text file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("JIKKYOU POWERFUL PRO YAKYUU 15 — EXTRACTED TEXT\n")
        f.write(f"Total strings: {len(all_strings)}\n")
        f.write("=" * 80 + "\n\n")

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


def cmd_extract_text(args: argparse.Namespace) -> None:
    """Extract all readable text from the game's script modules and write it to a text file."""
    print("=" * 80)
    print("JIKKYOU POWERFUL PRO YAKYUU 15 — TEXT EXTRACTION")
    print("=" * 80)
    print()

    all_strings = collect_clean_strings()

    print(f"\nTotal: {len(all_strings)} clean text strings")
    print()

    output_path = args.output or os.path.join(config.ROOT, "extracted_text.txt")
    write_text_report(all_strings, output_path)
    print(f"Output saved to: {output_path}")


def cmd_char_table(args: argparse.Namespace) -> None:
    """Print the full glyph index → Unicode character mapping table."""
    print("GLYPH INDEX → CHARACTER TABLE")
    print("=" * 60)

    for name, start, end in CHAR_TABLE_BLOCKS:
        print(f"\n--- {name} (glyphs {start}-{end}) ---")
        line = []
        for g in range(start, end + 1):
            ch = glyph_to_char(g)
            if ch and ch != '�':
                line.append(ch)
            else:
                line.append('·')
            if len(line) >= CHAR_TABLE_LINE:
                print(f"  {g-len(line)+1:4d}: {''.join(line)}")
                line = []
        if line:
            print(f"  {end-len(line)+1:4d}: {''.join(line)}")


def cmd_decode_bytes(args: argparse.Namespace) -> None:
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
        glyph = v & GLYPH_MASK
        flags = (v >> FLAGS_SHIFT) & 0x7
        ch = glyph_to_char(glyph) if 0 < glyph <= MAX_GLYPH else None
        flag_str = f" flags={flags}" if flags else ""
        char_str = f' = "{ch}"' if ch else " = [unmapped]"
        print(f"0x{v:04X}: glyph={glyph}{char_str}{flag_str}")


def cmd_dump_font(args: argparse.Namespace) -> None:
    """Render the font atlas (every font picture, `cols` per row) as a PNG."""
    try:
        from PIL import Image
    except ImportError:
        print("PIL/Pillow required: pip install Pillow")
        return

    cols = args.cols or 64
    scale = args.scale or 2
    glyph_w, glyph_h = GLYPH_BYTES_W, GLYPH_ROWS
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
                bidx = gy * GLYPH_ROW_PITCH + gx
                if bidx < len(output):
                    pixels[gx, gy] = output[bidx]
        glyph_scaled = glyph_img.resize((glyph_w * scale, glyph_h * scale), Image.NEAREST)
        img.paste(glyph_scaled, (c * glyph_w * scale, r * glyph_h * scale))

        if glyph_idx % 500 == 0:
            print(f"  {glyph_idx}/{total}...")

    output_path = args.output or os.path.join(config.ROOT, "font_atlas.png")
    img.save(output_path)
    print(f"Saved to: {output_path}")


def cmd_info(args: argparse.Namespace) -> None:
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
    print(f"  Glyphs  188-281: Digits and Latin letters (JIS row 3)")
    print(f"  Glyphs  282-375: Hiragana (JIS row 4)")
    print(f"  Glyphs  376-469: Katakana (JIS row 5)")
    print(f"  Glyphs  470-563: Greek (JIS row 6)")
    print(f"  Glyphs  564-657: Cyrillic (JIS row 7)")
    print(f"  Glyphs  658-705: Line drawing (JIS row 8 partial)")
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


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser with one sub-command per tool."""
    parser = argparse.ArgumentParser(
        prog="pp15 glyphs",
        description="Text extraction toolkit for Jikkyou Powerful Pro Yakyuu 15 (character table and font)")
    subparsers = parser.add_subparsers(dest='command', metavar="COMMAND")

    p_extract = subparsers.add_parser('extract-text', help='Extract all text strings',
                                      description="List the readable Japanese text of the scs_*.rel modules "
                                                  "and write it to a text file.")
    p_extract.add_argument('-o', '--output', help='Output file path (default: extracted_text.txt in the repository)')

    subparsers.add_parser('char-table', help='Print glyph→character table',
                          description="Print the whole glyph number -> character table.")

    p_decode = subparsers.add_parser('decode-bytes', help='Decode hex glyph values',
                                     description="Decode 16-bit hex text values into glyph numbers and characters.")
    p_decode.add_argument('values', nargs='+', help='Hex values (e.g. 01C0 017B)')

    p_font = subparsers.add_parser('dump-font', help='Render font atlas PNG',
                                   description="Draw every font picture into one PNG (needs Pillow).")
    p_font.add_argument('-o', '--output', help='Output file path (default: font_atlas.png in the repository)')
    p_font.add_argument('-c', '--cols', type=int, help='Glyphs per row (default: 64)')
    p_font.add_argument('-s', '--scale', type=int, help='Scale factor (default: 2)')

    subparsers.add_parser('info', help='Show text system information',
                          description="Print a short description of the text system.")
    return parser


COMMANDS = {'extract-text': cmd_extract_text, 'char-table': cmd_char_table, 'decode-bytes': cmd_decode_bytes,
            'dump-font': cmd_dump_font, 'info': cmd_info}


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 glyphs COMMAND`; without a command print the help."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in COMMANDS:
        COMMANDS[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
