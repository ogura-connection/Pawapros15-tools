#!/usr/bin/env python3
"""
VM-aware text extractor for Jikkyou Powerful Pro Yakyuu 15.
Parses bytecode instruction-by-instruction and extracts text regions
that appear between/after VM instructions, plus clean text from data sections.

Uses corrected glyph map (row 8 = 48 cols).
"""
import struct, os, json, sys
from collections import defaultdict

GAME_DIR = '/sessions/dreamy-confident-allen/mnt/Jikkyou Powerful Pro Yakyuu 15 (Japan) (Rev 1)/DATA/files'

# === Corrected Glyph Map ===
def build_glyph_map():
    """Corrected: rows 1-7 (94 cols) + row 8 (48 cols) + rows 16-84 (94 cols)."""
    glyph_map = {}
    idx = 0
    for row in range(1, 8):
        for col in range(1, 95):
            jis_hi, jis_lo = row + 0x20, col + 0x20
            sjis_lo = jis_lo + 0x1F + (1 if jis_lo >= 0x60 else 0) if jis_hi % 2 == 1 else jis_lo + 0x7E
            sjis_hi = (jis_hi + 1) // 2 + (0x70 if jis_hi < 0x5F else 0xB0)
            try: glyph_map[idx] = bytes([sjis_hi, sjis_lo]).decode('shift_jis')
            except: pass
            idx += 1
    for col in range(1, 49):  # Row 8: only 48 columns
        jis_hi, jis_lo = 8 + 0x20, col + 0x20
        sjis_lo = jis_lo + 0x1F + (1 if jis_lo >= 0x60 else 0) if jis_hi % 2 == 1 else jis_lo + 0x7E
        sjis_hi = (jis_hi + 1) // 2 + (0x70 if jis_hi < 0x5F else 0xB0)
        try: glyph_map[idx] = bytes([sjis_hi, sjis_lo]).decode('shift_jis')
        except: pass
        idx += 1
    for row in range(16, 85):
        for col in range(1, 95):
            jis_hi, jis_lo = row + 0x20, col + 0x20
            sjis_lo = jis_lo + 0x1F + (1 if jis_lo >= 0x60 else 0) if jis_hi % 2 == 1 else jis_lo + 0x7E
            sjis_hi = (jis_hi + 1) // 2 + (0x70 if jis_hi < 0x5F else 0xB0)
            try: glyph_map[idx] = bytes([sjis_hi, sjis_lo]).decode('shift_jis')
            except: pass
            idx += 1
    return glyph_map

GLYPH = build_glyph_map()

# Valid glyph index set for fast lookup
VALID_GLYPH_INDICES = set(GLYPH.keys())
MAX_GLYPH_IDX = max(VALID_GLYPH_INDICES)

# === Opcode Length Table ===
OPCODE_LENGTH = {}
for op in [0x00, 0x01]: OPCODE_LENGTH[op] = 1
for op in range(0x03, 0x16): OPCODE_LENGTH[op] = 1
for op in range(0x26, 0x36): OPCODE_LENGTH[op] = 1
for op in range(0x46, 0x59): OPCODE_LENGTH[op] = 1
for op in range(0x59, 0x6E): OPCODE_LENGTH[op] = 1
OPCODE_LENGTH[0x6F] = 1; OPCODE_LENGTH[0x70] = 1
for op in range(0x72, 0x7A): OPCODE_LENGTH[op] = 1
OPCODE_LENGTH[0x82] = 1; OPCODE_LENGTH[0x86] = 1; OPCODE_LENGTH[0x94] = 1
for op in range(0x96, 0x9D): OPCODE_LENGTH[op] = 1
for op in range(0xC7, 0xD5): OPCODE_LENGTH[op] = 1
for op in [0xD7, 0xD8, 0xD9, 0xDB, 0xDC, 0xDD, 0xDE]: OPCODE_LENGTH[op] = 1
for op in [0xDF, 0xE0, 0xE1, 0xE2]: OPCODE_LENGTH[op] = 1
for op in range(0xE3, 0xFE): OPCODE_LENGTH[op] = 1
for op in range(0x36, 0x46): OPCODE_LENGTH[op] = 2
OPCODE_LENGTH[0x71] = 2
for op in range(0x7A, 0x82): OPCODE_LENGTH[op] = 2
for op in [0x83, 0x84, 0x85, 0x87, 0x88]: OPCODE_LENGTH[op] = 2
for op in range(0x89, 0x94): OPCODE_LENGTH[op] = 2
OPCODE_LENGTH[0x95] = 2
for op in [0x9D, 0x9E]: OPCODE_LENGTH[op] = 2
for op in range(0x9F, 0xB3): OPCODE_LENGTH[op] = 2
for op in range(0xB3, 0xC7): OPCODE_LENGTH[op] = 2
for op in [0xD5, 0xD6, 0xDA]: OPCODE_LENGTH[op] = 2
for op in range(0x16, 0x26): OPCODE_LENGTH[op] = 3
OPCODE_LENGTH[0x6E] = 3
OPCODE_LENGTH[0x02] = 4

TEXT_OPCODES = {0xA5, 0xA6, 0xA7, 0xDF, 0xE0, 0xE1, 0xE2}

# === Quality Filters ===
def is_valid_glyph_hw(hw):
    """Check if a halfword is a valid displayable glyph."""
    if hw == 0 or hw == 0xFFFF or hw == 0x1FFF or hw == 0x1FFD:
        return False
    idx = hw & 0xFFF
    return idx in VALID_GLYPH_INDICES

def decode_run(data, offset, max_len=500):
    """Decode consecutive glyph halfwords starting at offset."""
    chars = []
    pos = offset
    while len(chars) < max_len and pos + 1 < len(data):
        hw = struct.unpack_from('>H', data, pos)[0]
        if not is_valid_glyph_hw(hw):
            break
        chars.append(GLYPH[hw & 0xFFF])
        pos += 2
    return ''.join(chars), (pos - offset) // 2

def sentence_quality(text):
    """Score sentence quality (0-100). Higher = more likely real Japanese."""
    if len(text) < 3:
        return 0

    hiragana = sum(1 for c in text if '\u3040' <= c <= '\u309f')
    katakana = sum(1 for c in text if '\u30a0' <= c <= '\u30ff')
    kanji = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    punct = sum(1 for c in text if c in '。、！？…ー〜「」『』（）・：；')
    fw_latin = sum(1 for c in text if '\uff01' <= c <= '\uff5e')  # Ａ-ｚ, ０-９

    # Core Japanese character ratio
    jp = hiragana + katakana + kanji + punct
    ratio = jp / len(text)

    # Hiragana is the strongest signal (grammar particles, verb endings)
    hira_ratio = hiragana / len(text)

    score = 0
    score += ratio * 40              # Up to 40 for overall JP ratio
    score += min(hira_ratio * 80, 30)  # Up to 30 for hiragana presence
    score += min(kanji / max(len(text), 1) * 30, 15)  # Up to 15 for kanji
    score += min(punct * 2, 10)      # Up to 10 for punctuation
    score += min(fw_latin * 0.5, 5)  # Up to 5 for fullwidth latin

    # Penalties
    # Very short strings with no hiragana are suspicious
    if len(text) < 6 and hiragana == 0:
        score -= 20
    # Repetitive patterns (likely data tables)
    if len(text) > 10 and len(set(text)) < len(text) * 0.25:
        score -= 30
    # No hiragana at all in a long string = likely not a sentence
    if len(text) > 8 and hiragana == 0 and katakana == 0:
        score -= 40

    return max(0, min(100, score))

# === REL Parser ===
def parse_rel(path):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 0x40:
        return data, [], 0
    module_id = struct.unpack_from('>I', data, 0)[0]
    num_sec = struct.unpack_from('>I', data, 0x0C)[0]
    sec_off = struct.unpack_from('>I', data, 0x10)[0]
    sections = []
    for i in range(min(num_sec, 30)):
        off = sec_off + i * 8
        if off + 8 > len(data): break
        raw = struct.unpack_from('>I', data, off)[0]
        size = struct.unpack_from('>I', data, off + 4)[0]
        sections.append({'idx': i, 'off': raw & ~1, 'size': size, 'exec': raw & 1})
    return data, sections, module_id

# === VM-Aware Text Extraction ===
def extract_text_vm_aware(data, sec_off, sec_size, min_quality=35, min_len=3):
    """
    Parse a bytecode section instruction-by-instruction.
    When we encounter halfwords that don't parse as valid opcodes but DO
    parse as valid glyph sequences, extract them as text.

    Also extract text that appears between 0xFFFF block boundaries.
    """
    text_regions = []
    pos = 0

    while pos < sec_size - 1:
        hw = struct.unpack_from('>H', data, sec_off + pos)[0]

        # Skip block terminators
        if hw == 0xFFFF:
            pos += 2
            continue

        # Try to parse as VM instruction
        opcode = hw & 0xFF

        if opcode in OPCODE_LENGTH:
            length = OPCODE_LENGTH[opcode]
            advance = length * 2

            # Check if this is actually a text opcode that triggers inline text
            # Text opcodes 0xDF-0xE2 are 1-HW, 0xA5-0xA7 are 2-HW
            # After text opcodes, there may be inline glyph data

            pos += advance

            # After certain instructions, check for inline text
            if pos < sec_size - 1:
                next_hw = struct.unpack_from('>H', data, sec_off + pos)[0]
                # If the next halfword looks like a glyph (not an opcode), try text extraction
                if is_valid_glyph_hw(next_hw) and (next_hw & 0xFFF) < MAX_GLYPH_IDX:
                    # Peek: is this a run of valid glyphs?
                    text, run_len = decode_run(data, sec_off + pos)
                    if run_len >= min_len:
                        quality = sentence_quality(text)
                        if quality >= min_quality:
                            text_regions.append({
                                'offset': pos,
                                'length': run_len,
                                'text': text,
                                'quality': quality,
                                'context': 'post_instruction'
                            })
                        pos += run_len * 2
                        continue
        else:
            # Unknown opcode — might be text data or padding
            if is_valid_glyph_hw(hw):
                text, run_len = decode_run(data, sec_off + pos)
                if run_len >= min_len:
                    quality = sentence_quality(text)
                    if quality >= min_quality:
                        text_regions.append({
                            'offset': pos,
                            'length': run_len,
                            'text': text,
                            'quality': quality,
                            'context': 'standalone'
                        })
                    pos += run_len * 2
                    continue
            pos += 2

    return text_regions

def extract_text_data_section(data, sec_off, sec_size, min_quality=35, min_len=3):
    """
    Extract text from a pure data section (no bytecode).
    Simpler: just scan for contiguous glyph runs.
    """
    text_regions = []
    pos = 0

    while pos < sec_size - 1:
        hw = struct.unpack_from('>H', data, sec_off + pos)[0]

        if is_valid_glyph_hw(hw):
            text, run_len = decode_run(data, sec_off + pos)
            if run_len >= min_len:
                quality = sentence_quality(text)
                if quality >= min_quality:
                    text_regions.append({
                        'offset': pos,
                        'length': run_len,
                        'text': text,
                        'quality': quality,
                        'context': 'data_section'
                    })
            pos += max(run_len, 1) * 2
        else:
            pos += 2

    return text_regions

# === Main Extraction ===
def process_file(fpath, bytecode_sections=None):
    """Process a REL file. bytecode_sections = set of section indices that contain VM bytecode."""
    data, sections, mod_id = parse_rel(fpath)
    fname = os.path.basename(fpath)

    if bytecode_sections is None:
        bytecode_sections = set()

    all_text = []

    for sec in sections:
        if sec['size'] == 0 or sec['off'] == 0:
            continue
        if sec['exec']:
            continue  # Skip code sections

        if sec['idx'] in bytecode_sections:
            regions = extract_text_vm_aware(data, sec['off'], sec['size'])
        else:
            regions = extract_text_data_section(data, sec['off'], sec['size'])

        for r in regions:
            r['file'] = fname
            r['section'] = sec['idx']
            r['section_type'] = 'bytecode' if sec['idx'] in bytecode_sections else 'data'
            all_text.append(r)

    return all_text

# === File Configuration ===
# Map files to their bytecode section indices
FILE_CONFIG = {
    # Success Mode
    'scs_main.rel': {'group': 'Success', 'bc_sections': {4}},  # sec4 has VM bytecode
    'scs_sce1.rel': {'group': 'Success', 'bc_sections': {4}},
    'scs_sce2.rel': {'group': 'Success', 'bc_sections': {4}},
    'scs_sce3.rel': {'group': 'Success', 'bc_sections': {5}},  # sce3 uses sec5
    'scs_data.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_item.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_rens.rel': {'group': 'Success', 'bc_sections': {4}},
    'scs_comi.rel': {'group': 'Success', 'bc_sections': {4}},
    'scs_end.rel':  {'group': 'Success', 'bc_sections': {4}},
    'scs_sys.rel':  {'group': 'Success', 'bc_sections': set()},
    'scs_make.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_grad.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_frnd.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_intr.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_open.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_titl.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_ren1.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_ren2.rel': {'group': 'Success', 'bc_sections': set()},
    'scs_ren3.rel': {'group': 'Success', 'bc_sections': set()},
    # Eikan Nine
    'sct_main.rel': {'group': 'Eikan Nine', 'bc_sections': {4, 5}},
    'sct_rens.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_card.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_sugo.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_titl.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_ar.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_ed.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_it.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_lb.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_mk.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_pd.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_pr.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_sc.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_sy.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_a_td.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_comd.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'sct_make.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    'school.rel':   {'group': 'Eikan Nine', 'bc_sections': set()},
    'school_g.rel': {'group': 'Eikan Nine', 'bc_sections': set()},
    # My Life
    'scc_main.rel': {'group': 'My Life', 'bc_sections': set()},
    'scc_tops.rel': {'group': 'My Life', 'bc_sections': set()},
    'scc_abi.rel':  {'group': 'My Life', 'bc_sections': set()},
    # Common
    'main_prg.rel': {'group': 'Common', 'bc_sections': set()},
}

def main():
    print("=" * 70)
    print("  Pawapuro 15 — VM-Aware Text Extraction (Corrected Glyph Map)")
    print("=" * 70)

    all_results = defaultdict(list)
    group_stats = defaultdict(lambda: {'strings': 0, 'chars': 0, 'files': 0})

    for fname, config in sorted(FILE_CONFIG.items()):
        fpath = os.path.join(GAME_DIR, fname)
        if not os.path.exists(fpath):
            continue

        text_regions = process_file(fpath, config.get('bc_sections', set()))

        if text_regions:
            group = config['group']
            all_results[fname] = text_regions
            total_chars = sum(r['length'] for r in text_regions)
            group_stats[group]['strings'] += len(text_regions)
            group_stats[group]['chars'] += total_chars
            group_stats[group]['files'] += 1

            # Show file summary
            avg_q = sum(r['quality'] for r in text_regions) / len(text_regions)
            print(f"  {fname:25s}: {len(text_regions):>5} strings, {total_chars:>7,} chars (avg quality: {avg_q:.0f})")

    # Group summaries
    print(f"\n{'='*70}")
    grand_strings = 0
    grand_chars = 0
    for group in ['Success', 'Eikan Nine', 'My Life', 'Common']:
        s = group_stats[group]
        print(f"  {group:15s}: {s['strings']:>6,} strings, {s['chars']:>8,} chars ({s['files']} files)")
        grand_strings += s['strings']
        grand_chars += s['chars']

    print(f"  {'TOTAL':15s}: {grand_strings:>6,} strings, {grand_chars:>8,} chars")

    # Quality distribution
    all_text = []
    for fname, regions in all_results.items():
        for r in regions:
            all_text.append(r)

    print(f"\n  Quality distribution:")
    for threshold in [80, 60, 40, 35]:
        count = sum(1 for r in all_text if r['quality'] >= threshold)
        chars = sum(r['length'] for r in all_text if r['quality'] >= threshold)
        print(f"    Quality >= {threshold}: {count:>6,} strings, {chars:>8,} chars")

    # Show sample high-quality strings from each group
    print(f"\n{'='*70}")
    print("  SAMPLE HIGH-QUALITY DIALOGUE")
    print("=" * 70)

    for group in ['Success', 'Eikan Nine', 'My Life', 'Common']:
        group_text = [(fname, r) for fname, regions in all_results.items()
                      for r in regions if FILE_CONFIG.get(fname, {}).get('group') == group]
        high_q = sorted(group_text, key=lambda x: (-x[1]['quality'], -x[1]['length']))

        seen = set()
        count = 0
        print(f"\n  [{group}]")
        for fname, r in high_q:
            if r['text'] not in seen and len(r['text']) > 8:
                seen.add(r['text'])
                count += 1
                if count <= 8:
                    q = r['quality']
                    print(f"    (Q{q:>2.0f}) [{fname:15s}] {r['text'][:75]}")
                if count >= 8:
                    break

    # Save complete extraction
    output = {
        'summary': {
            'total_strings': grand_strings,
            'total_chars': grand_chars,
            'groups': {g: dict(s) for g, s in group_stats.items()},
            'glyph_map_version': 'corrected_row8_48cols',
        },
        'files': {}
    }

    for fname, regions in all_results.items():
        output['files'][fname] = {
            'group': FILE_CONFIG[fname]['group'],
            'count': len(regions),
            'chars': sum(r['length'] for r in regions),
            'strings': [
                {
                    'text': r['text'],
                    'offset': r['offset'],
                    'section': r['section'],
                    'quality': r['quality'],
                    'length': r['length'],
                }
                for r in regions
            ]
        }

    out_path = '/sessions/dreamy-confident-allen/complete_text_extraction.json'
    with open(out_path, 'w') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n  Saved to: {out_path}")
    print(f"  File size: {os.path.getsize(out_path) / 1024:.0f} KB")

if __name__ == '__main__':
    main()
