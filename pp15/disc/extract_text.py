"""Find readable Japanese text in the game's code modules (.rel files) and list it, by guessing from the bytes.

    pp15 extract-text [--data-dir DIR]        writes DATA/extracted_text_full.json and DATA/extraction_report.txt

What it is for: a first look at where text hides in a module, before a proper reader exists. The game stores text as
16-bit glyph numbers (see docs/GLOSSARY.md "Glyph"); this tool tries every position of a module's sections as the start
of such text, converts the glyph numbers to characters, and keeps the runs that look like real Japanese.
`is_quality_text` is also used by the story-script scanner (pp15/script/scan.py) to reject accidental runs.

Which modules are searched: see TEXT_MODULES. Sections: menu text in scs_main.rel (fixed 40-byte entries), then dialogue
and labels in section 5 of every module, scripts in section 4, data in section 6. Categories in the output: menu,
dialogue (10 characters or more), label (shorter), script, data.

Public functions: glyph_to_char, is_quality_text, decode_glyph_run, parse_rel_header, extract_region3_text,
extract_dialogue_text, extract_from_rel_file, deduplicate_entries, main.
"""
import argparse
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pp15 import config

# The story and Success Mode modules in which the text is searched, in this order
TEXT_MODULES = [
    "scs_main.rel",     # menus, system text and dialogue
    "scs_sce1.rel",     # the three scenario modules: dialogue in the script bytecode
    "scs_sce2.rel",
    "scs_sce3.rel",
    "scs_item.rel",     # item database
    "scs_data.rel",
    "scs_sys.rel",
    "scs_end.rel",
    "scs_comi.rel",
]

# Glyph numbers of the game's font, in three ranges (all index the JIS X 0208 character set, 94 characters per row)
GLYPH_JIS_ROWS_1_7_LAST = 657       # glyphs 0..657: JIS rows 0x21-0x27 (symbols, kana, Latin, Greek, Cyrillic)
GLYPH_JIS_ROW_8_LAST = 705          # glyphs 658..705: JIS row 0x28 (line-drawing characters)
GLYPH_KANJI_LAST = 3743             # glyphs 706..3743: kanji, JIS rows 0x30 and up
GLYPH_KANJI_FIRST = 706
GLYPH_MASK = 0x1FFF                 # the low 13 bits of a halfword are the glyph number
TEXT_END_MARKS = (0x1FFF, 0xFFFF, 0x0000)    # a halfword that ends a run of text

MENU_ENTRY_BYTES = 40               # scs_main.rel: menu text is stored in fixed entries of 20 glyphs
MENU_REGION_START, MENU_REGION_END = 0x3328, 0x01F274      # where those entries lie in section 5
DIALOGUE_MIN_CHARS = 4              # shorter runs are not reported
DIALOGUE_CATEGORY_MIN_CHARS = 10    # at this length a run counts as dialogue, below as a label
SKIP_HEADER_BYTES = 0x70            # a section starts with a debug header in ASCII
MAX_SECTIONS_READ = 20
SYMBOL_SHARE_LIMIT = 0.5            # a run with more symbols than this share is rejected
MARK_SHARE_LIMIT = 0.3              # ... or with more combining/voicing marks than this share
SECTION_LABELS = {4: "script", 6: "data"}       # category of the text found in other sections


def glyph_to_char(glyph: int) -> Optional[str]:
    """The character for a glyph number of the game's font, or None if the glyph is not a character.

    Glyphs 0-657 are JIS rows 0x21-0x27, 658-705 row 0x28, 706-3743 kanji (JIS rows 0x30 and up)."""
    def jis_to_char(row: int, cell: int) -> Optional[str]:
        try:
            # JIS X 0208 (row, cell) -> Shift-JIS bytes: two JIS rows share one Shift-JIS lead byte
            if row % 2 == 1:
                lead = (row + 1) // 2 + 0x70
                if lead > 0x9F:
                    lead += 0x40
                trail = cell + 0x1F if cell <= 0x5F else cell + 0x20
            else:
                lead = row // 2 + 0x70
                if lead > 0x9F:
                    lead += 0x40
                trail = cell + 0x7E
            return bytes([lead, trail]).decode("shift_jis")
        except ValueError:
            return None

    if glyph <= 0:
        return None
    if glyph <= GLYPH_JIS_ROWS_1_7_LAST:
        return jis_to_char((glyph // 94) + 0x21, (glyph % 94) + 0x21)
    elif glyph <= GLYPH_JIS_ROW_8_LAST:
        return jis_to_char(0x28, (glyph - 658) + 0x21)
    elif glyph <= GLYPH_KANJI_LAST:
        k = glyph - GLYPH_KANJI_FIRST
        return jis_to_char((k // 94) + 0x30, (k % 94) + 0x21)
    return None


def is_japanese_char(ch: str) -> bool:
    """True for hiragana, katakana or kanji (anything from U+4E00 up)."""
    code = ord(ch)
    return (0x3040 <= code <= 0x309F or     # hiragana
            0x30A0 <= code <= 0x30FF or     # katakana
            code >= 0x4E00)                 # kanji


def is_symbol_char(ch: str) -> bool:
    """True for a miscellaneous or mathematical symbol."""
    code = ord(ch)
    return 0x2100 <= code <= 0x2BFF or 0x2200 <= code <= 0x22FF


def is_quality_text(text: str) -> bool:
    """Reject bytecode that happens to decode, and runs of symbols.

    Keeps text that has at least 3 characters, at least one Japanese character, no more than half symbols, and
    no more than 30% combining or voicing marks."""
    if len(text) < 3:
        return False
    if not any(is_japanese_char(ch) for ch in text):
        return False
    symbols = sum(1 for ch in text if is_symbol_char(ch))
    if len(text) > 0 and symbols / len(text) > SYMBOL_SHARE_LIMIT:
        return False
    marks = 0
    for ch in text:
        if ord(ch) in (0x309B, 0x309C, 0x3099, 0x309A,      # combining marks
                       0xFF9E, 0xFF9F):                      # voiced-sound marks
            marks += 1
    if len(text) > 0 and marks / len(text) > MARK_SHARE_LIMIT:
        return False
    return True


def decode_glyph_run(data: bytes, offset: int, max_length: int = 1000) -> Optional[str]:
    """Decode the glyph halfwords from `offset` until an end mark, an unknown glyph or `max_length` bytes.
    Returns the text if it passes is_quality_text, else None."""
    chars = []
    pos = offset
    while pos < offset + max_length and pos + 1 < len(data):
        halfword = struct.unpack_from(">H", data, pos)[0]
        if halfword in TEXT_END_MARKS:
            break
        ch = glyph_to_char(halfword & GLYPH_MASK)
        if ch is None:
            break
        chars.append(ch)
        pos += 2
    text = "".join(chars)
    return text if is_quality_text(text) else None


def parse_rel_header(data: bytes) -> List[Tuple[int, int]]:
    """The sections of a .rel file as [(file offset, size)] (at most MAX_SECTIONS_READ; [] if the header is bad)."""
    if len(data) < 0x20:
        return []
    try:
        section_count = struct.unpack_from(">I", data, 0x0C)[0]
        table_offset = struct.unpack_from(">I", data, 0x10)[0]
    except struct.error:
        return []
    sections = []
    for i in range(min(section_count, MAX_SECTIONS_READ)):
        try:
            entry = table_offset + i * 8
            if entry + 4 > len(data) or entry + 8 > len(data):
                break
            raw_offset = struct.unpack_from(">I", data, entry)[0]
            size = struct.unpack_from(">I", data, entry + 4)[0]
            sections.append((raw_offset & ~1, size))        # bit 0 of the offset flags an executable section
        except struct.error:
            break
    return sections


def extract_region3_text(data: bytes, sec5_offset: int, sec5_size: int) -> List[Tuple[int, str]]:
    """The menu and UI text of scs_main.rel section 5: 40-byte fixed entries (20 glyph halfwords and padding) from
    section offset 0x3328. Returns [(offset in the section, text)]."""
    results = []
    offset = sec5_offset + MENU_REGION_START
    while offset < sec5_offset + MENU_REGION_END and offset + MENU_ENTRY_BYTES <= sec5_offset + sec5_size:
        text = decode_glyph_run(data, offset, MENU_ENTRY_BYTES)
        if text:
            results.append((offset - sec5_offset, text))
        offset += MENU_ENTRY_BYTES
    return results


def extract_dialogue_text(data: bytes, sec_offset: int, sec_size: int,
                          skip_start: int = SKIP_HEADER_BYTES) -> List[Tuple[int, str, str]]:
    """Scan a section for runs of valid glyphs that read as Japanese (skipping the first `skip_start` bytes, an
    ASCII debug header). Returns [(offset in the section, text, 'dialogue' or 'label')]."""
    results = []
    seen_offsets: Set[int] = set()
    offset = sec_offset + skip_start
    while offset < sec_offset + sec_size - 2:
        glyph = struct.unpack_from(">H", data, offset)[0] & GLYPH_MASK
        if 0 < glyph <= GLYPH_KANJI_LAST and glyph_to_char(glyph) is not None:
            text = decode_glyph_run(data, offset, 1000)
            if text and len(text) >= DIALOGUE_MIN_CHARS:
                text_offset = offset - sec_offset
                if text_offset not in seen_offsets:          # skip the starts inside a run already found
                    category = "dialogue" if len(text) >= DIALOGUE_CATEGORY_MIN_CHARS else "label"
                    results.append((text_offset, text, category))
                    seen_offsets.add(text_offset)
                    for i in range(1, min(10, len(text))):
                        seen_offsets.add(text_offset + i * 2)
        offset += 2
    return results


def _entry(file_label: str, category: str, offset: int, text: str) -> Dict:
    """One found text as the dictionary the output files use."""
    return {"file": file_label, "category": category, "offset": f"0x{offset:X}", "text": text, "length": len(text)}


def extract_from_rel_file(filepath: str, file_label: str) -> Dict[str, List[Dict]]:
    """All text found in one .rel file, as {category: [entry]} (entries: file, category, offset, text, length)."""
    results = defaultdict(list)
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read {filepath}: {e}")
        return results

    sections = parse_rel_header(data)

    def fits(index: int) -> bool:
        return len(sections) > index and sections[index][0] + sections[index][1] <= len(data)

    if fits(5):                                  # section 5 holds most text
        sec5_off, sec5_size = sections[5]
        if "scs_main" in file_label:             # scs_main.rel has the fixed menu entries first
            for offset, text in extract_region3_text(data, sec5_off, sec5_size):
                results["menu"].append(_entry(file_label, "menu", offset, text))
        for offset, text, category in extract_dialogue_text(data, sec5_off, sec5_size):
            results[category].append(_entry(file_label, category, offset, text))
    for index, category in SECTION_LABELS.items():       # section 4: script bytecode; section 6: extra data
        if fits(index):
            sec_off, sec_size = sections[index]
            for offset, text, _ in extract_dialogue_text(data, sec_off, sec_size):
                results[category].append(_entry(file_label, category, offset, text))
    return results


def deduplicate_entries(entries: List[Dict]) -> List[Dict]:
    """The entries with exact duplicate texts removed (the first of each kept)."""
    seen = set()
    deduped = []
    for entry in entries:
        if entry["text"] not in seen:
            seen.add(entry["text"])
            deduped.append(entry)
    return deduped


def build_report(final_entries: Dict[str, List[Dict]], file_stats: Dict[str, int], total: int) -> str:
    """The text of the human-readable report."""
    lines = ["=" * 70, "JIKKYOU POWERFUL PRO YAKYUU 15 — TEXT EXTRACTION REPORT", "=" * 70, "",
             "SUMMARY", "-" * 70,
             f"Total strings extracted: {total}", f"Files processed: {len(file_stats)}", "",
             "BREAKDOWN BY FILE", "-" * 70]
    for filename in sorted(file_stats):
        lines.append(f"  {filename:30s}: {file_stats[filename]:5d} strings")
    lines += ["", "BREAKDOWN BY CATEGORY", "-" * 70]
    for category in sorted(final_entries):
        lines.append(f"  {category:30s}: {len(final_entries[category]):5d} strings")
    lines += ["", "SAMPLE TEXT BY CATEGORY", "-" * 70]
    for category in sorted(final_entries):
        lines.append(f"\n{category.upper()}:")
        for i, entry in enumerate(final_entries[category][:3], 1):
            lines.append(f"  [{i}] {entry['text']}")
            lines.append(f"      File: {entry['file']}, Offset: {entry['offset']}")
    lines += ["", "=" * 70]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 extract-text [--data-dir DIR]`: search TEXT_MODULES, print counts, write the JSON and the report
    next to DIR (DIR's parent folder, normally DATA/). `argv` defaults to sys.argv[1:]."""
    parser = argparse.ArgumentParser(prog="pp15 extract-text", description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-dir", default=None,
                        help="the folder with the game's .rel files (default: DATA/files); the outputs go in its parent folder")
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir) if args.data_dir else Path(config.DATA_FILES)
    if not data_dir.exists():
        print(f"[ERROR] Data directory not found: {data_dir}")
        sys.exit(1)
    print(f"[INFO] Using data directory: {data_dir}")
    print()

    all_entries = defaultdict(list)
    file_stats = {}
    for filename in TEXT_MODULES:
        filepath = data_dir / filename
        if not filepath.exists():
            print(f"[SKIP] {filename} not found")
            continue
        print(f"[EXTRACT] {filename}...", end=" ", flush=True)
        file_total = 0
        for category, entries in extract_from_rel_file(str(filepath), filename).items():
            deduped = deduplicate_entries(entries)
            all_entries[category].extend(deduped)
            file_total += len(deduped)
        file_stats[filename] = file_total
        print(f"found {file_total} strings")

    print()
    print("[STATS] Extraction Complete")
    print("-" * 60)
    final_entries = {}                          # deduplicated across all files, per category
    total_all = 0
    for category in sorted(all_entries):
        deduped = deduplicate_entries(all_entries[category])
        final_entries[category] = deduped
        total_all += len(deduped)
        print(f"  {category:15s}: {len(deduped):5d} unique strings")
    print("-" * 60)
    print(f"  {'TOTAL':15s}: {total_all:5d} strings")
    print()

    json_output = [{"file": entry["file"], "category": entry["category"], "offset": entry["offset"], "index": idx,
                    "text": entry["text"], "length": entry["length"]}
                   for category in sorted(final_entries) for idx, entry in enumerate(final_entries[category])]
    json_path = data_dir.parent / "extracted_text_full.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_output, f, ensure_ascii=False, indent=2)
    print(f"[SAVE] JSON output: {json_path}")

    report_text = build_report(final_entries, file_stats, total_all)
    report_path = data_dir.parent / "extraction_report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"[SAVE] Report output: {report_path}")
    print()
    print(report_text)


if __name__ == "__main__":
    main()
