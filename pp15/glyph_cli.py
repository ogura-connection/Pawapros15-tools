"""Command-line tools for the glyph table and the font (the code is in glyphs.py).

  python3 -m pp15 glyphs extract-text      extract all text strings
  python3 -m pp15 glyphs dump-font         render the font atlas
  python3 -m pp15 glyphs char-table        print the glyph -> character table
  python3 -m pp15 glyphs decode-bytes XXXX decode hex glyph indices
  python3 -m pp15 glyphs info              the text system in short
"""
import argparse
import glob
import os
import sys

from pp15 import config
from pp15.glyphs import (DATA_FILES, MAX_GLYPH, decompress_glyph, extract_glyph_strings, extract_sjis_strings,
                         glyph_to_char, is_clean_text, load_glyph_data, parse_rel_header, read_section_data)


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
    output_path = args.output or os.path.join(config.ROOT, "extracted_text.txt")
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

    output_path = args.output or os.path.join(config.ROOT, "font_atlas.png")
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


def main(argv=None):
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

    args = parser.parse_args(argv)

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
