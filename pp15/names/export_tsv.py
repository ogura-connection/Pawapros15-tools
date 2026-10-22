"""Write the first version of the English name files (translation/names/*.tsv) from the game's own data.

These are the commands behind `pp15 names export`, `export-given`, `export-draft`, `export-holders` and
`export-foreign`. Each one reads the untouched game module (_work/orig), takes the English from a hand-made helper
file in _work/names/ (or romanises the Japanese reading), and writes a tab-separated file that a person then edits.
Names already written by hand in an existing file are kept.

WARNING: `export-given`, `export-draft`, `export-holders` and `export-foreign` overwrite the files in
translation/names/in_place/, and when run on the current tree they write fewer rows than are checked in (656 lines
fewer; this is a known problem, see docs/refactor_notes_names_disc_kit.md). Look at `git diff` before keeping what they write.

Public functions: export_surnames (the surname list), export_given_names, export_draft_prospects,
export_record_holders, export_foreign_players; holder_fields, foreign_fields, scc_foreign_fields (find the name
fields in a module).
"""
import json
import os
import struct
from typing import Callable, List, Sequence, Tuple

from pp15 import config
from pp15.names import table
from pp15.script import scan

READINGS = os.path.join(config.WORK_DIR, "surnames.json")      # [kanji, call id, kana of the call] per surname
NAMES_SCRATCH = os.path.join(config.WORK_DIR, "names")         # hand-made English helper files (game text, not tracked)

# Where the name stores are
FOREIGN_TABLE = ("pennant.rel", 5, 0x7AE8, 82)         # module, section, pointer table offset, number of lists of eight
GIVEN = ("main_prg.rel", 5, 0x3B288, 200, 16)          # module, section, first record, records, bytes per record
DRAFT = ("draft.rel", 5, 0x2C08, 2000, 144, 0x3C)      # ... and the offset of the call id inside a record
GIVEN_FIXES = {18: "Koichi", 33: "Shoichi",           # romaji keeps "ou" before a vowel
               25: "Koutaro", 85: "Yuuki", 170: "Miyuu", 179: "Yuuka", 180: "Yuuna"}   # long vowel: kept apart

# The records of the record-holders store start with one of these marks
RECORD_START_MARKS = (0xFFFF, 0xFFFE)
RECORD_KIND_PLAIN = 0x0100                    # (0x0100, kind << 8 | team, year), then the name cells
RECORD_KIND_DATED = range(0x0120, 0x0141)     # a variant with a date: the name cells are one halfword later
# Success Mode's foreign players in scc_main.rel section 5: 360 records of six cells + 0x1FFF + call id lie in this span
SCC_FOREIGN_START, SCC_FOREIGN_END = 0x4AF0, 0x68D0 + 16
# Glyph numbers of the katakana (and the long-vowel bar) that the foreign names are made of
FOREIGN_GLYPH_MIN, FOREIGN_GLYPH_MAX, FOREIGN_GLYPH_BAR = 0x179, 0x1D0, 0x1B
FOREIGN_FIELDS_EXPECTED = 656
SCC_FOREIGN_EXPECTED = 360
# A cell with this flag set belongs to a name of four kana or more (the glyph number is the cell minus the flag)
LONG_NAME_FLAG = 0x1000


def _romaji() -> Callable[[str], str]:
    """The kana-to-romaji converter, a helper script that lives in the git-ignored _work/names folder."""
    config.use_scratch("names")
    from romaji import romaji
    return romaji


def _original_module(filename: str):
    """The untouched game module `filename` (a scan.Rel from _work/orig)."""
    return scan.Rel(os.path.join(config.ORIG_DIR, filename))


def _load_json(name: str):
    """A helper file of _work/names (hand-made English)."""
    with open(os.path.join(NAMES_SCRATCH, name), encoding="utf-8") as f:
        return json.load(f)


def _decode_cells(cells: Sequence[int]) -> str:
    """The Japanese text of name cells (the long-name flag is removed)."""
    return scan.decode_units([c if c < LONG_NAME_FLAG else c - LONG_NAME_FLAG for c in cells if c])


def _write_store(module: str, header: str, rows: List[Tuple[int, int, str]]) -> None:
    """Write translation/names/in_place/<module>.tsv, keeping the English already there for a field.
    `rows` = [(section, offset, English)]."""
    os.makedirs(table.IN_PLACE_DIR, exist_ok=True)
    path = os.path.join(table.IN_PLACE_DIR, module + ".tsv")
    have = {(s, o): english for s, o, english in table.inplace_stores().get(module, [])}
    with open(path, "w", encoding="utf-8") as f:
        f.write("# section\toffset\tEnglish (%s; up to 12 letters)\n" % header)
        for section, offset, english in rows:
            f.write("%d\t%X\t%s\n" % (section, offset, have.get((section, offset)) or english))
    print("%s: %d names" % (path, len(rows)))


# ── The surname list ───────────────────────────────────────────────────────

def export_surnames() -> None:
    """Write translation/names/surnames.tsv from _work/surnames.json; English already in the file is kept."""
    romaji = _romaji()
    with open(READINGS, encoding="utf-8") as f:
        rows = json.load(f)
    assert len(rows) == table.COUNT
    have = table.load_tsv() if os.path.exists(table.TSV) else {}
    os.makedirs(os.path.dirname(table.TSV), exist_ok=True)
    with open(table.TSV, "w", encoding="utf-8") as f:
        f.write("# index\tcall id\tEnglish (surname list: team-mates, name entry, generated players; up to 12 letters)\n")
        for i, (kanji, call, kana) in enumerate(rows):
            english = have[i][1] if i in have else table.KNOWN_FULL_NAMES.get(kanji) or romaji(kana)
            f.write("%d\t%d\t%s\n" % (i, call, english))
    print("%s: %d names" % (table.TSV, len(rows)))


# ── Given names, draft prospects ───────────────────────────────────────────

def export_given_names() -> None:
    """Write in_place/main_prg.rel.tsv: the 200 given names (100 boys, then 100 girls), romanised."""
    romaji = _romaji()
    module, section, start, count, stride = GIVEN
    data = _original_module(module).sec_data(section)
    rows = []
    for i in range(count):
        kana = scan.decode_units([c for c in struct.unpack_from(">6H", data, start + stride * i) if c])
        rows.append((section, start + stride * i, GIVEN_FIXES.get(i) or romaji(kana)))
    _write_store(module, "given names: the first 100 boys, the next 100 girls", rows)


def export_draft_prospects() -> None:
    """Write in_place/draft.rel.tsv: the 2,000 draft prospects, named like the surname list for the same call id,
    else romanised from the call's reading."""
    romaji = _romaji()
    with open(os.path.join(config.WORK_DIR, "call_readings.json"), encoding="utf-8") as f:
        readings = {int(k): v for k, v in json.load(f).items()}
    by_call = {call: english for call, english in table.load_tsv().values()}
    module, section, start, count, stride, call_at = DRAFT
    data = _original_module(module).sec_data(section)
    rows = []
    for i in range(count):
        o = start + stride * i
        call = struct.unpack_from(">H", data, o + call_at)[0]
        rows.append((section, o, by_call.get(call) or romaji(readings[call])))
    _write_store(module, "draft prospects, from the announcer's call ids", rows)


# ── Record holders ─────────────────────────────────────────────────────────

def holder_fields(data: bytes) -> List[Tuple[int, Sequence[int], int]]:
    """Every name field of the record holders store (pn_ore_i.rel section 4).

    Returns [(offset, six cells, team number)]. A record starts with 0xFFFF or 0xFFFE; the name follows after four
    halfwords (plain record) or five (dated record)."""
    halfwords = struct.unpack(">%dH" % (len(data) // 2), data)
    out = []
    for i, value in enumerate(halfwords[:-12]):
        if value not in RECORD_START_MARKS:
            continue
        at = i + 4 if halfwords[i + 1] == RECORD_KIND_PLAIN else i + 5 if halfwords[i + 1] in RECORD_KIND_DATED else None
        if at and table.name_field(data, 2 * at):
            out.append((2 * at, halfwords[at:at + table.CELLS], halfwords[i + 2] & 0xFF))
    return out


def export_record_holders() -> None:
    """Write in_place/pn_ore_i.rel.tsv from _work/names/holders_en.json (name as decoded -> English)."""
    english_by_name = _load_json("holders_en.json")
    module, section = "pn_ore_i.rel", 4
    data = _original_module(module).sec_data(section)
    rows, left = [], []
    for o, cells, team in holder_fields(data):
        key = _decode_cells(cells)
        english = english_by_name.get(key)
        if english == "Rhodes" and team == 4:       # two people share one kanji name: Bobby Rose played for team 4
            english = "Rose"
        if english:
            rows.append((section, o, english))
        else:
            left.append((hex(o), key))
    _write_store(module, "record holders, Pennant / My Life record books", rows)
    print("left as they are:", left)


# ── Foreign players ────────────────────────────────────────────────────────

def foreign_fields(rel) -> List[Tuple[int, Sequence[int]]]:
    """The 656 foreign-player name fields of pennant.rel in pool order: [(offset, six cells)].

    `rel` is the original pennant.rel (a scan.Rel). The fields are in 82 lists of eight, reached through a pointer
    table; an 0xFFFF 0 pair between lists is skipped."""
    _, section, table_at, lists = FOREIGN_TABLE
    data = rel.sec_data(section)
    pointers = {pos: addend for s, pos, typ, tm, ts, addend in rel.relocs()
                if s == section and tm == rel.mod_id and ts == section}
    out = []
    for k in range(lists):
        pos, n = pointers[table_at + 4 * k], 0
        while n < 8:
            if struct.unpack_from(">H", data, pos)[0] == 0xFFFF:
                pos += 4
                continue
            out.append((pos, struct.unpack_from(">6H", data, pos)))
            pos, n = pos + 12, n + 1
    return out


def scc_foreign_fields(data: bytes) -> List[Tuple[int, Sequence[int]]]:
    """The Success Mode foreign names in section 5 of scc_main.rel (six cells, 0x1FFF, call id): [(offset, cells)]."""
    out = []
    for o in range(SCC_FOREIGN_START, SCC_FOREIGN_END, 2):
        if struct.unpack_from(">H", data, o + 12)[0] == table.END and table.name_field(data, o):
            cells = struct.unpack_from(">6H", data, o)
            if all(x == 0 or FOREIGN_GLYPH_MIN <= x & 0xFFF <= FOREIGN_GLYPH_MAX or x & 0xFFF == FOREIGN_GLYPH_BAR for x in cells):
                out.append((o, cells))
    return out


def export_foreign_players() -> None:
    """Write in_place/pennant.rel.tsv and in_place/scc_main.rel.tsv from the hand-made pool files
    _work/names/foreign_pool_en.json (by pool index) and foreign_extra_en.json (decoded name -> English)."""
    pool_english, extra = _load_json("foreign_pool_en.json"), _load_json("foreign_extra_en.json")
    module = FOREIGN_TABLE[0]
    fields = foreign_fields(_original_module(module))
    assert len(fields) == len(pool_english) == FOREIGN_FIELDS_EXPECTED
    by_name = {}
    for (o, cells), english in zip(fields, pool_english):
        by_name.setdefault(_decode_cells(cells), english)
    _write_store(module, "foreign players: 45 surnames, then given names",
                 [(5, o, english) for (o, cells), english in zip(fields, pool_english)])
    data = _original_module(table.HOST).sec_data(table.HOST_SECTION)
    rows = [(table.HOST_SECTION, o, by_name.get(_decode_cells(cells)) or extra[_decode_cells(cells)])
            for o, cells in scc_foreign_fields(data)]
    assert len(rows) == SCC_FOREIGN_EXPECTED, len(rows)
    _write_store(table.HOST, "Success foreign players, written before the module moves", rows)
