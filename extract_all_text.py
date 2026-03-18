#!/usr/bin/env python3
"""
Comprehensive Text Extraction Tool for Jikkyou Powerful Pro Yakyuu 15 (Wii)

Extracts all translatable text from game REL files:
- scs_main.rel: Menu/UI text (Region 3) and dialogue
- scs_sce1/2/3.rel: Inline bytecode text
- scs_item.rel: Item database
- Additional files: scs_data.rel, scs_sys.rel, scs_end.rel, etc.

Uses Shift-JIS three-range glyph mapping per RE_NOTES.md.
Outputs JSON and human-readable report with categorization.
"""

import json
import struct
import sys
from pathlib import Path
from collections import defaultdict
from typing import List, Tuple, Optional, Dict, Set


def glyph_to_char(g: int) -> Optional[str]:
    """Convert glyph index to Unicode character using three-range mapping.

    Glyphs 0-657: JIS rows 0x21-0x27
    Glyphs 658-705: JIS row 0x28
    Glyphs 706-3743: Kanji (JIS rows 0x30+)
    """
    def jis_to_char(j1: int, j2: int) -> Optional[str]:
        try:
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
            return bytes([s1, s2]).decode('shift_jis')
        except:
            return None

    if g <= 0:
        return None
    if g <= 657:
        return jis_to_char((g // 94) + 0x21, (g % 94) + 0x21)
    elif g <= 705:
        return jis_to_char(0x28, (g - 658) + 0x21)
    elif g <= 3743:
        k = g - 706
        return jis_to_char((k // 94) + 0x30, (k % 94) + 0x21)
    return None


def is_japanese_char(ch: str) -> bool:
    """Check if character is Japanese (hiragana, katakana, or kanji)."""
    code = ord(ch)
    return (0x3040 <= code <= 0x309F or   # Hiragana
            0x30A0 <= code <= 0x30FF or   # Katakana
            code >= 0x4E00)                # Kanji


def is_symbol_char(ch: str) -> bool:
    """Check if character is a miscellaneous or math symbol."""
    code = ord(ch)
    return 0x2100 <= code <= 0x2BFF or 0x2200 <= code <= 0x22FF


def is_quality_text(text: str) -> bool:
    """Filter out bytecode data and symbol spam.

    Keep text that:
    - Has minimum 3 characters
    - Contains at least 1 Japanese character
    - Is not mostly symbols (>50% in symbol ranges)
    - Has reasonable composition (not ALL symbols/decoration marks)
    """
    if len(text) < 3:
        return False

    has_jp = any(is_japanese_char(ch) for ch in text)
    if not has_jp:
        return False

    symbol_count = sum(1 for ch in text if is_symbol_char(ch))
    if len(text) > 0 and symbol_count / len(text) > 0.5:
        return False

    # Additional filter: reject strings that are mostly combining marks/diacritics
    # (U+3000-U+303F are CJK symbols and punctuation)
    combining_marks = 0
    for ch in text:
        code = ord(ch)
        if code in (0x309B, 0x309C, 0x3099, 0x309A,  # Combining marks
                    0xFF9E, 0xFF9F):  # Voiced sound marks
            combining_marks += 1

    if len(text) > 0 and combining_marks / len(text) > 0.3:
        return False

    return True


def decode_glyph_run(data: bytes, offset: int, max_length: int = 1000) -> Optional[str]:
    """Decode a run of glyphs starting at offset until terminator or invalid glyph."""
    chars = []
    pos = offset

    while pos < offset + max_length and pos + 1 < len(data):
        halfword = struct.unpack_from('>H', data, pos)[0]

        # Terminator or null
        if halfword == 0x1FFF or halfword == 0xFFFF or halfword == 0x0000:
            break

        # Extract glyph index (lower 13 bits)
        glyph = halfword & 0x1FFF

        # Try to decode
        ch = glyph_to_char(glyph)
        if ch is None:
            break

        chars.append(ch)
        pos += 2

    text = ''.join(chars)
    if is_quality_text(text):
        return text
    return None


def parse_rel_header(data: bytes) -> List[Tuple[int, int]]:
    """Parse REL header to extract section offsets and sizes."""
    if len(data) < 0x20:
        return []

    try:
        nsec = struct.unpack_from('>I', data, 0x0C)[0]
        sec_info_off = struct.unpack_from('>I', data, 0x10)[0]
    except struct.error:
        return []

    sections = []
    for i in range(min(nsec, 20)):
        try:
            off_idx = sec_info_off + i * 8
            size_idx = sec_info_off + i * 8 + 4

            if off_idx + 4 > len(data) or size_idx + 4 > len(data):
                break

            soff = struct.unpack_from('>I', data, off_idx)[0]
            ssize = struct.unpack_from('>I', data, size_idx)[0]

            # Exec flag is bit 0 of offset
            real_off = soff & ~1
            sections.append((real_off, ssize))
        except struct.error:
            break

    return sections


def extract_region3_text(data: bytes, sec5_offset: int, sec5_size: int) -> List[Tuple[int, str]]:
    """Extract Region 3 menu/UI text from scs_main.rel sec5.

    Format: 40-byte fixed entries starting at sec5+0x3328
    Each entry: 20 halfwords of glyph data + padding
    """
    results = []
    region3_start = 0x3328
    region3_end = 0x01F274

    offset = sec5_offset + region3_start
    entry_num = 0

    while offset < sec5_offset + region3_end and offset + 40 <= sec5_offset + sec5_size:
        # Try to decode glyphs from this entry
        text = decode_glyph_run(data, offset, 40)
        if text:
            results.append((offset - sec5_offset, text))

        offset += 40
        entry_num += 1

    return results


def extract_dialogue_text(data: bytes, sec_offset: int, sec_size: int,
                         skip_start: int = 0x70) -> List[Tuple[int, str, str]]:
    """Extract dialogue/inline text from a section.

    Scan for runs of valid glyphs with Japanese characters.
    Skip first skip_start bytes (ASCII debug header).
    Returns tuples of (offset, text, category).
    """
    results = []
    seen_offsets: Set[int] = set()

    offset = sec_offset + skip_start
    while offset < sec_offset + sec_size - 2:
        # Try to decode a glyph run starting at this offset
        halfword = struct.unpack_from('>H', data, offset)[0]

        # Valid glyph index?
        glyph = halfword & 0x1FFF
        if glyph > 0 and glyph <= 3743:
            ch = glyph_to_char(glyph)
            if ch is not None:
                # Found start of potential run
                text = decode_glyph_run(data, offset, 1000)
                if text and len(text) >= 4:  # At least 4 chars for a run
                    text_offset = offset - sec_offset

                    # Avoid duplicates within a small window
                    if text_offset not in seen_offsets:
                        # Categorize based on length and content
                        if len(text) >= 10:
                            category = 'dialogue'
                        else:
                            category = 'label'

                        results.append((text_offset, text, category))
                        # Mark nearby offsets as seen to avoid sub-strings
                        seen_offsets.add(text_offset)
                        for i in range(1, min(10, len(text))):
                            seen_offsets.add(text_offset + i * 2)

        offset += 2

    return results


def extract_from_rel_file(filepath: str, file_label: str) -> Dict[str, List[Dict]]:
    """Extract all text from a REL file."""
    results = defaultdict(list)

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read {filepath}: {e}")
        return results

    sections = parse_rel_header(data)

    # Extract from sec5 (most common text location)
    if len(sections) > 5:
        sec5_off, sec5_size = sections[5]
        if sec5_off + sec5_size <= len(data):
            # Special handling for scs_main.rel: extract Region 3 first
            if "scs_main" in file_label:
                region3_texts = extract_region3_text(data, sec5_off, sec5_size)
                for offset, text in region3_texts:
                    results['menu'].append({
                        'file': file_label,
                        'category': 'menu',
                        'offset': f'0x{offset:X}',
                        'text': text,
                        'length': len(text)
                    })

                # Also scan remainder for dialogue
                dialogue_texts = extract_dialogue_text(data, sec5_off, sec5_size)
                for offset, text, category in dialogue_texts:
                    results[category].append({
                        'file': file_label,
                        'category': category,
                        'offset': f'0x{offset:X}',
                        'text': text,
                        'length': len(text)
                    })
            else:
                # For other files, scan the whole sec5
                dialogue_texts = extract_dialogue_text(data, sec5_off, sec5_size)
                for offset, text, category in dialogue_texts:
                    results[category].append({
                        'file': file_label,
                        'category': category,
                        'offset': f'0x{offset:X}',
                        'text': text,
                        'length': len(text)
                    })

    # Extract from sec4 (script/bytecode)
    if len(sections) > 4:
        sec4_off, sec4_size = sections[4]
        if sec4_off + sec4_size <= len(data):
            script_texts = extract_dialogue_text(data, sec4_off, sec4_size)
            for offset, text, _ in script_texts:
                results['script'].append({
                    'file': file_label,
                    'category': 'script',
                    'offset': f'0x{offset:X}',
                    'text': text,
                    'length': len(text)
                })

    # Extract from sec6 (additional data in some files)
    if len(sections) > 6:
        sec6_off, sec6_size = sections[6]
        if sec6_off + sec6_size <= len(data):
            data_texts = extract_dialogue_text(data, sec6_off, sec6_size)
            for offset, text, _ in data_texts:
                results['data'].append({
                    'file': file_label,
                    'category': 'data',
                    'offset': f'0x{offset:X}',
                    'text': text,
                    'length': len(text)
                })

    return results


def deduplicate_entries(entries: List[Dict]) -> List[Dict]:
    """Remove exact duplicate texts from a list of entries."""
    seen = set()
    deduped = []

    for entry in entries:
        text = entry['text']
        if text not in seen:
            seen.add(text)
            deduped.append(entry)

    return deduped


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Extract all translatable text from Jikkyou Powerful Pro Yakyuu 15'
    )
    parser.add_argument('--data-dir', default=None,
                       help='Path to DATA/files directory')
    args = parser.parse_args()

    # Determine data directory
    if args.data_dir:
        data_dir = Path(args.data_dir)
    else:
        script_dir = Path(__file__).parent
        data_dir = script_dir / 'DATA' / 'files'

    if not data_dir.exists():
        print(f"[ERROR] Data directory not found: {data_dir}")
        sys.exit(1)

    print(f"[INFO] Using data directory: {data_dir}")
    print()

    # List of key files to extract from
    target_files = [
        'scs_main.rel',
        'scs_sce1.rel',
        'scs_sce2.rel',
        'scs_sce3.rel',
        'scs_item.rel',
        'scs_data.rel',
        'scs_sys.rel',
        'scs_end.rel',
        'scs_comi.rel',
    ]

    all_entries = defaultdict(list)
    file_stats = {}

    for filename in target_files:
        filepath = data_dir / filename
        if not filepath.exists():
            print(f"[SKIP] {filename} not found")
            continue

        print(f"[EXTRACT] {filename}...", end=' ', flush=True)

        results = extract_from_rel_file(str(filepath), filename)

        file_total = 0
        for category, entries in results.items():
            # Deduplicate
            deduped = deduplicate_entries(entries)
            all_entries[category].extend(deduped)
            file_total += len(deduped)

        file_stats[filename] = file_total
        print(f"found {file_total} strings")

    print()
    print("[STATS] Extraction Complete")
    print("-" * 60)

    # Deduplicate across all files per category
    final_entries = {}
    total_all = 0

    for category in sorted(all_entries.keys()):
        entries = all_entries[category]
        deduped = deduplicate_entries(entries)
        final_entries[category] = deduped
        total_all += len(deduped)
        print(f"  {category:15s}: {len(deduped):5d} unique strings")

    print("-" * 60)
    print(f"  {'TOTAL':15s}: {total_all:5d} strings")
    print()

    # Generate JSON output
    json_output = []
    for category in sorted(final_entries.keys()):
        for idx, entry in enumerate(final_entries[category]):
            json_output.append({
                'file': entry['file'],
                'category': entry['category'],
                'offset': entry['offset'],
                'index': idx,
                'text': entry['text'],
                'length': entry['length']
            })

    json_path = data_dir.parent / 'extracted_text_full.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_output, f, ensure_ascii=False, indent=2)
    print(f"[SAVE] JSON output: {json_path}")

    # Generate human-readable report
    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("JIKKYOU POWERFUL PRO YAKYUU 15 — TEXT EXTRACTION REPORT")
    report_lines.append("=" * 70)
    report_lines.append("")

    report_lines.append("SUMMARY")
    report_lines.append("-" * 70)
    report_lines.append(f"Total strings extracted: {total_all}")
    report_lines.append(f"Files processed: {len(file_stats)}")
    report_lines.append("")

    report_lines.append("BREAKDOWN BY FILE")
    report_lines.append("-" * 70)
    for filename in sorted(file_stats.keys()):
        count = file_stats[filename]
        report_lines.append(f"  {filename:30s}: {count:5d} strings")
    report_lines.append("")

    report_lines.append("BREAKDOWN BY CATEGORY")
    report_lines.append("-" * 70)
    for category in sorted(final_entries.keys()):
        count = len(final_entries[category])
        report_lines.append(f"  {category:30s}: {count:5d} strings")
    report_lines.append("")

    report_lines.append("SAMPLE TEXT BY CATEGORY")
    report_lines.append("-" * 70)
    for category in sorted(final_entries.keys()):
        entries = final_entries[category][:3]
        report_lines.append(f"\n{category.upper()}:")
        for i, entry in enumerate(entries, 1):
            report_lines.append(f"  [{i}] {entry['text']}")
            report_lines.append(f"      File: {entry['file']}, Offset: {entry['offset']}")

    report_lines.append("")
    report_lines.append("=" * 70)

    report_text = '\n'.join(report_lines)
    report_path = data_dir.parent / 'extraction_report.txt'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_text)
    print(f"[SAVE] Report output: {report_path}")

    print()
    print(report_text)


if __name__ == '__main__':
    main()
