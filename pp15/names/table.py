"""Player surnames in Latin letters: widen the game's surname lists and write English names into every copy of them.

What the player sees: the names of team-mates, of the name-entry screen, of the generated players and of the real 2008
professionals. The game stores a name as a few "cells" (one cell = one glyph slot; the pair font puts two letters in one
cell, see docs/GLOSSARY.md), and the original lists only reserve three cells (six letters), so "Takahashi" or
"Yamaguchi" would not fit. This module makes the lists wider and fills them from the English text files.

How the game stores them
- 1,856 surnames in two copies, as records of five 16-bit values: three name cells, 0x1FFF (the end mark), and the id of
  the announcer's recorded call of that name ("call id").
- scc_main.rel section 5 offset 0xC0 holds the list read by scc_main.rel, scs_main.rel, sct_main.rel and work_sct.rel
  (Success Mode, Eikan Nine). scc_main.rel's slot in the memory plan (0x807E8380) ends 28 bytes before scs_main.rel,
  so the build moves it to HOST_ADDR in the free area (as ore_work.rel for My Life) and appends a new table to its data
  section: records of 16 bytes, six cells padded with 0x1FFF, then 0x1FFF and the call id. The relocations that pointed
  at the old table are aimed at the new one (TableRemap), and the routines that read it are patched in place: the record
  size (`mulli 0xA -> 0x10`), the call id (`lhz 8(rX) -> 0xE(rX)`), and the copiers that took four cells become a loop of
  up to six cells in the same space. Every patched instruction is checked first.
- main_prg.rel section 5 offset 0x168F0 is read by one routine reached through a function pointer (where its names show
  is not known yet). main_prg.rel cannot grow (the next module follows 16 bytes behind it), so its table keeps its
  records and takes four cells (8 letters) in the slot that held 0x1FFF; its copier takes four cells already. Longer
  names use the short form (Kunrei spelling: Takahasi) when it fits, else stay kanji. (A main.dol section was tried
  first: the apploader refuses sections above 0x80900000.)

English text: translation/names/surnames.tsv (index, call id, English), first written by `pp15 names export` from the
game's own readings (_work/surnames.json: kanji, call id, kana of the call); edit the English column by hand where
needed. Real players: translation/names/players.tsv. Fields rewritten where they are (given names, draft prospects,
record holders, foreign players): translation/names/in_place/<module>.tsv; their formats are described above
`inplace_stores`.

Public functions (the build, pp15/build/rebuild.py, calls these)
- load_tsv, table, plates, letters_ok, plate, short_form, short_table, short_names: the surname lists.
- READERS, code_patches, patch_code: rewrite the routines that read the list.
- append_table, TableRemap, place_host: grow scc_main.rel and give it its new address.
- load_players, player_patches, player_plates: the real players of 2008.
- inplace_stores, inplace_patches, inplace_plates, name_field: names written where they are.
- CODE_NAMES, code_name_words, patch_code_name: the one name that the game's code builds by itself.
The `pp15 names` command is in pp15/names/commands.py; the TSV writers in pp15/names/export_tsv.py.
"""
import os
import struct
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from pp15 import config
from pp15.names.ppc_words import BEQLR, BLR, KEEP, NOP, add, addi, addis, beq, blt, branch, cmplwi, cmpwi, lhzx, li, loop_words, sthx

TSV = os.environ.get("NAMES_TSV") or os.path.join(config.TRANSLATION_DIR, "names", "surnames.tsv")   # NAMES_TSV: a test table

COUNT = 1856                    # surnames in the game's list
CELLS = 6                       # cells of the widened record (twelve letters)
STRIDE = 16                     # bytes of a widened record: six cells, 0x1FFF, 0x1FFF, call id
OLD_STRIDE = 10                 # bytes of an original record: three cells, 0x1FFF, call id
END = 0x1FFF                    # end mark of a name
HOST, HOST_SECTION, HOST_TABLE = "scc_main.rel", 5, 0xC0          # the module that gets the new table
HOST_ADDR = 0x81460000          # its new address: free area above ore_work.rel (0x81400000), below the arena (0x814E0000)
FREE_AREA_END = 0x814E0000      # the memory the build may not use (the game's general pool starts here)
SHORT_HOST, SHORT_SECTION, SHORT_TABLE, SHORT_CELLS = "main_prg.rel", 5, 0x168F0, 4   # the table that stays in place
KNOWN_FULL_NAMES = {"石井": "Ishii"}      # calls that read a full name, not just a surname: the romaniser would get them wrong

# Relocation types that point at an address (HA / LO halves of an address load, see docs/GLOSSARY.md "Relocation")
RELOC_HA, RELOC_LO = 4, 6
# Opcodes seen in the instructions we patch (top six bits of the word)
OPCODE_MULLI, OPCODE_LHZ = 7, 40
CALL_ID_OFFSET_OLD = 8          # the call id sits at +8 in an old record ...
CALL_ID_OFFSET_NEW = 2 * CELLS + 2      # ... and at +14 (0xE) in a widened one
PATCH_MASK_LOW16 = 0xFFFF


# ── The routines that read the scc_main.rel table (offsets are in section 1, the code) ──────────

def _copier_scc_main() -> Tuple[int, int, list]:
    """The name copier of scc_main.rel: (first address, address after it, words). r3 = table, r6 = record offset,
    r4 = cells copied (0 on entry), r22 = destination."""
    start, out = 0x4DCC, 0x4E1C
    loop = start + 8
    words = [add(3, 3, 6), li(5, 0), lhzx(0, 3, 5), cmplwi(0, END), lambda here: beq(here, out), sthx(0, 22, 5),
             addi(4, 4, 1), addi(5, 5, 2), cmpwi(4, CELLS), lambda here: blt(here, loop)]
    return start, out, words


def _copier_scs_leaf() -> Tuple[int, int, list]:
    """The name copier of scs_main.rel (a leaf routine, it calls nothing): r4 = table, r0 = record offset,
    r3 = destination, r5 = 0."""
    start, out = 0x60D18, 0x60D60
    loop = start + 4
    words = [add(4, 4, 0), lhzx(0, 4, 5), cmplwi(0, END), BEQLR, sthx(0, 3, 5), addi(5, 5, 2), cmplwi(5, 2 * CELLS),
             lambda here: blt(here, loop), BLR]
    return start, out, words


def _copier_sct(start: int, out: int, dest: int) -> Tuple[int, int, list]:
    """The name copier of sct_main.rel and work_sct.rel: r3 = table, r0 = record offset, r31 points at the pointer
    to the work area, destination = *r31 + 0x30000 + `dest`. Word 5 (`lwz r4, 0(r31)`) carries a relocation and stays
    (KEEP)."""
    loop = start + 8
    words = [add(5, 3, 0), li(6, 0), lhzx(7, 5, 6), cmplwi(7, END), lambda here: beq(here, out), KEEP,
             addis(3, 6, 3), addi(0, 3, dest), sthx(7, 4, 0), addi(6, 6, 2), cmplwi(6, 2 * CELLS),
             lambda here: blt(here, loop), lambda here: branch(here, out)]
    return start, out, words


# What to patch in each module that reads the surname list:
#   relocs   the HA / LO address-load pairs that point at the old table (aimed at the new one by TableRemap)
#   mulli    instructions `mulli rX, rY, 0xA` (record size) that become `mulli rX, rY, 0x10`
#   call     instructions `lhz rX, 8(rY)` (call id) that become `lhz rX, 0xE(rY)`
#   copier   (first address, end address, words) of the name copier routine, rewritten to copy six cells
#   keep     addresses inside the copier that hold a relocated word and must stay as they are
READERS = {
    "scc_main.rel": {"relocs": [0x4DC2, 0x4DCA, 0x4E82, 0x4E8A], "mulli": [0x4DB4],
                     "call": [0x4EB4, 0x4EC0], "copier": _copier_scc_main(), "keep": []},
    "scs_main.rel": {"relocs": [0x9D8A, 0x9D96, 0x3559A, 0x355CA, 0x60CFE, 0x60D06],    # the sites at 9D70 and 37054 already take six cells
                     "mulli": [0x9D8C, 0x37054, 0x60CF0], "call": [], "copier": _copier_scs_leaf(), "keep": []},
    "sct_main.rel": {"relocs": [0xC49A, 0xC4A6], "mulli": [0xC49C], "call": [],
                     "copier": _copier_sct(0xC4A8, 0xC528, 0x1B48), "keep": [0xC4BC, 0xC4DC, 0xC4FC, 0xC51C]},
    "work_sct.rel": {"relocs": [0x8486, 0x8492], "mulli": [0x8488], "call": [],
                     "copier": _copier_sct(0x8494, 0x8514, 0x1B36), "keep": [0x84A8, 0x84C8, 0x84E8, 0x8508]},
}


def code_patches(rel, host_id: int) -> Dict[int, Tuple[int, int]]:
    """The changed instruction words of one module that reads the surname list.

    Arguments: `rel` a pp15.script.scan.Rel (an original module), `host_id` the module id of scc_main.rel.
    Returns {section 1 offset: (original word, new word)}. Checks the original code and its relocations to the old
    table first and raises ValueError when a site is not what it should be. Reads only."""
    spec, code = READERS[rel.name], rel.sec_data(1)
    word = lambda at: struct.unpack_from(">I", code, at)[0]
    out = {}

    def put(at, new):
        out[at] = (word(at), new)
    relocs = {(s, pos): (typ, tm, ts, ad) for s, pos, typ, tm, ts, ad in rel.relocs()}
    for pos in spec["relocs"]:
        if relocs.get((1, pos)) not in ((RELOC_HA, host_id, HOST_SECTION, HOST_TABLE), (RELOC_LO, host_id, HOST_SECTION, HOST_TABLE)):
            raise ValueError("%s sec1+0x%X: not a relocation to the surname table" % (rel.name, pos))
    for at in spec["mulli"]:
        if word(at) >> 26 != OPCODE_MULLI or word(at) & PATCH_MASK_LOW16 != OLD_STRIDE:
            raise ValueError("%s sec1+0x%X: not mulli rX, rY, 0xA" % (rel.name, at))
        put(at, word(at) & ~PATCH_MASK_LOW16 | STRIDE)
    for at in spec["call"]:
        if word(at) >> 26 != OPCODE_LHZ or word(at) & PATCH_MASK_LOW16 != CALL_ID_OFFSET_OLD:
            raise ValueError("%s sec1+0x%X: not lhz rX, 8(rY)" % (rel.name, at))
        put(at, word(at) & ~PATCH_MASK_LOW16 | CALL_ID_OFFSET_NEW)
    start, end, words = spec["copier"]
    new = dict(loop_words(start, words))
    if len(new) > (end - start) // 4:
        raise ValueError("%s: the copier does not fit" % rel.name)
    for at in range(start, end, 4):
        new_word = new.get(at, NOP)           # words after the new, shorter copier become no-ops
        if at in spec["keep"]:
            if new_word is not KEEP and at in new:
                raise ValueError("%s sec1+0x%X: the copier would overwrite a relocated word" % (rel.name, at))
            if (1, at + 2) not in relocs:
                raise ValueError("%s sec1+0x%X: no relocation where one is kept" % (rel.name, at))
            continue
        if new_word is KEEP or any(s == 1 and at <= p < at + 4 for s, p in relocs):
            raise ValueError("%s sec1+0x%X: a relocation inside the copier" % (rel.name, at))
        put(at, new_word)
    return out


def patch_code(rel, image: bytes, host_id: int) -> Tuple[bytes, Dict[Tuple[int, int], bytes]]:
    """Write the patched instruction words (see `code_patches`) into the module image.

    Arguments: the original module `rel`, the image being built, the module id of scc_main.rel.
    Returns (new image, {(1, offset): the 4 bytes written}). Raises ValueError if the image differs from the original
    at a patch site."""
    out, base, written = bytearray(image), rel.sections[1]["offset"], {}
    for at, (old, new) in sorted(code_patches(rel, host_id).items()):
        if struct.unpack_from(">I", out, base + at)[0] != old:
            raise ValueError("%s sec1+0x%X: the built image differs from the original here" % (rel.name, at))
        struct.pack_into(">I", out, base + at, new)
        written[(1, at)] = struct.pack(">I", new)
    return bytes(out), written


class TableRemap:
    """scc_main.rel section 5 with the new table appended: everything stays where it was, only a pointer to the old
    table is aimed at the new one. Has the attributes `verify()` of the build reads from a Remap (lo, hi, growth)."""

    def __init__(self, size: int, growth: int, new_table: int):
        self.lo = self.hi = size
        self.growth, self.new_table = growth, new_table

    def __call__(self, off: int) -> int:
        """The new offset of what used to be at section offset `off`."""
        return self.new_table if off == HOST_TABLE else off


def append_table(host, data: bytes) -> Tuple[bytes, TableRemap]:
    """Append the new table to section 5 of scc_main.rel (8-byte aligned).

    Arguments: `host` the original scc_main.rel (a Rel), `data` the table bytes. Returns (new section 5 bytes,
    the TableRemap that aims pointers at the new table)."""
    old = host.sec_data(HOST_SECTION)
    pad = bytes(-len(old) % 8)
    return old + pad + data, TableRemap(len(old), len(pad) + len(data), len(old) + len(pad))


def place_host(plan: bytes, orig_plan: bytes, old: bytes, new: bytes,
               plan_tables: Callable, memory_size: Callable) -> Tuple[bytes, int]:
    """The memory plan (the file moduleID2addr.o: where each module is loaded) with scc_main.rel at HOST_ADDR.

    Arguments: `plan` the plan being built, `orig_plan` the original plan, `old` / `new` the original and new module
    images, `plan_tables(plan)` -> (address table, size table, file-size table, row count) and `memory_size(image)`
    from the build. The row of scc_main.rel is found by its file size (the size column holds the larger of the file
    and its memory, which the game reads the whole file into).
    Returns (new plan, end address of the module). Raises ValueError if the new place overlaps another module."""
    plan_out = bytearray(plan)
    t_addr, t_size, t_file, n = plan_tables(plan)
    rows = [i for i in range(n) if struct.unpack_from(">I", orig_plan, t_file + 4 * i)[0] == len(old)]
    if len(rows) != 1:
        raise ValueError("%s: %d rows of the memory plan have its file size" % (HOST, len(rows)))
    row, size = rows[0], max(len(new), memory_size(new))
    if struct.unpack_from(">I", orig_plan, t_size + 4 * row)[0] != max(len(old), memory_size(old)):
        raise ValueError("%s: its row does not hold the size expected" % HOST)
    end = HOST_ADDR + size
    for k in range(n):
        other_addr, other_size = (struct.unpack_from(">I", plan_out, t + 4 * k)[0] for t in (t_addr, t_size))
        if k != row and other_size and other_addr < end and other_addr + other_size > HOST_ADDR:
            raise ValueError("%s at 0x%08X would share memory with row %d (0x%08X..0x%08X)"
                             % (HOST, HOST_ADDR, k, other_addr, other_addr + other_size))
    if end > FREE_AREA_END:
        raise ValueError("%s ends at 0x%08X, past the free area" % (HOST, end))
    struct.pack_into(">I", plan_out, t_addr + 4 * row, HOST_ADDR)
    struct.pack_into(">I", plan_out, t_size + 4 * row, size)
    struct.pack_into(">I", plan_out, t_file + 4 * row, len(new))
    return bytes(plan_out), end


# ── The surname tables ─────────────────────────────────────────────────────

def load_tsv() -> Dict[int, Tuple[int, str]]:
    """Read translation/names/surnames.tsv. Returns {index: (call id, English)}; raises ValueError unless every
    index 0..COUNT-1 is present."""
    out = {}
    with open(TSV, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            index, call, english = line.rstrip("\n").split("\t")
            out[int(index)] = (int(call), english)
    if sorted(out) != list(range(COUNT)):
        raise ValueError("%s: needs every index 0..%d" % (TSV, COUNT - 1))
    return out


def letters_ok(english: str, cells: int = CELLS) -> bool:
    """True if the name is plain printable ASCII, not blank, and at most two letters per cell."""
    return 0 < len(english.strip()) and len(english) <= 2 * cells and all(0x20 <= ord(c) < 0x7F for c in english)


# Spellings that shorten a romanised name, tried one at a time (Kunrei style: shi -> si)
KUNREI_SHORTENINGS = (("shi", "si"), ("chi", "ti"), ("tsu", "tu"), ("sh", "sy"), ("ch", "ty"))


def short_form(english: str) -> Optional[str]:
    """The name in at most 8 letters (SHORT_CELLS cells), using Kunrei spellings one at a time, or None if it
    cannot be made short enough."""
    for long_spelling, short_spelling in KUNREI_SHORTENINGS:
        if len(english) <= 2 * SHORT_CELLS:
            break
        english = english.replace(long_spelling, short_spelling).replace(long_spelling.capitalize(), short_spelling.capitalize())
    return english if len(english) <= 2 * SHORT_CELLS else None


def plate(english: str) -> str:
    """The name as laid out in its cells (seen in game: the Eikan Nine squad list and result messages).

    - A name plate spreads the cells over its width, trailing blank cells dropped, a leading one kept, so a name of two
      cells shows as "Sa    to": names of four letters or fewer start with a blank cell.
    - Text drops blank cells but shows the space of a half-filled pair ("Goto 's", "Fujii 's"): an odd name starts with
      a space instead of ending with one.
    Ito -> "  " " I" "to", Goto -> "  " "Go" "to", Fujii -> " F" "uj" "ii", Takahashi -> " T" "ak" "ah" "as" "hi"."""
    padded = " " + english if len(english) % 2 else english
    return "  " + padded if len(padded) <= 4 else padded


def table(names: Dict[int, Tuple[int, str]], encode: Callable[[str], List[int]]) -> bytes:
    """The widened surname list: COUNT records of STRIDE bytes (six cells, 0x1FFF, 0x1FFF, call id).

    Arguments: `names` from load_tsv(); `encode` = pp15.build.rebuild.encode_text bound to the font slots (text ->
    list of cell numbers). Raises ValueError for a name that does not fit six cells."""
    out = bytearray()
    for i in range(COUNT):
        call, english = names[i]
        units = encode(plate(english))
        if not letters_ok(english) or len(units) > CELLS:
            raise ValueError("surname %d %r does not fit %d cells" % (i, english, CELLS))
        out += struct.pack(">8H", *(units + [END] * (CELLS - len(units))), END, call)
    return bytes(out)


def short_table(names: Dict[int, Tuple[int, str]], encode: Callable[[str], List[int]],
                old: bytes) -> Tuple[bytes, List[str]]:
    """main_prg.rel's list, rewritten in place with four cells per name.

    Arguments: `names` from load_tsv(); `encode` as in `table`; `old` the original table (COUNT records of
    OLD_STRIDE bytes). Returns (new table bytes, the names that did not fit even in short form and stay kanji)."""
    out, kanji = bytearray(old), []
    for i in range(COUNT):
        call, english = names[i]
        at = i * OLD_STRIDE
        if struct.unpack_from(">H", old, at + 8)[0] != call or struct.unpack_from(">H", old, at + 6)[0] != END:
            raise ValueError("main_prg.rel surname %d: not the record the TSV expects" % i)
        short = short_form(english)
        if short is None:
            kanji.append(english)
            continue
        units = encode(plate(short))
        assert len(units) <= SHORT_CELLS, short
        struct.pack_into(">4H", out, at, *(units + [END] * (SHORT_CELLS - len(units))))
    return bytes(out), kanji


def short_names(names: Dict[int, Tuple[int, str]]) -> List[str]:
    """The English that main_prg.rel's short list holds, as laid out (the font builder counts its letter pairs)."""
    return [plate(s) for s in (short_form(english) for _, english in names.values()) if s]


def plates(names: Dict[int, Tuple[int, str]]) -> List[str]:
    """The English of the widened list as laid out (the font builder counts its letter pairs)."""
    return [plate(english) for _, english in names.values()]


# ── Real players (main_prg.rel) ────────────────────────────────────────────
# The 2008 rosters: 480 records of six cells + (a, b, call id) at sec5+0x68826.., and the same six cells in a
# names-only list by team and in the 144-byte player records. Every copy is a six-cell field: written in place.
# Readings: the announcer's call (are_main.rel); English in translation/names/players.tsv (foreign players and a few
# registered names by hand). Copies in other modules (pn_ore_i, pennant, draft) are other people with the same
# surnames (draft prospects ...) and are not touched here.
PLAYERS_TSV = os.path.join(config.TRANSLATION_DIR, "names", "players.tsv")
# main_prg.rel section 5 spans that hold copies of the players' names: (start, end, copies expected)
PLAYER_REGIONS = [(0x3C738, 0x3E004, 477), (0x579F0, 0x6A9AA, 960)]    # the list by team; the records + roster
ROSTER_RECORD_BYTES = 144       # distance to look back for the call id of the record a copy belongs to
ROSTER_LOOKAHEAD_BYTES = 156


def load_players() -> List[Tuple[int, int, str]]:
    """Read translation/names/players.tsv. Returns [(section 5 offset of the roster record, call id, English)]."""
    out = []
    with open(PLAYERS_TSV, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            off, call, english = line.rstrip("\n").split("\t")
            out.append((int(off, 16), int(call), english))
    return out


def player_patches(rel, players: Sequence[Tuple[int, int, str]], encode: Callable[[str], List[int]]) -> Dict[int, bytes]:
    """The new bytes for every copy of a real player's name in main_prg.rel.

    Arguments: `rel` the original main_prg.rel (a Rel), `players` from load_players(), `encode` as in `table`.
    Returns {section 5 offset: 12 bytes}. Where two players share one kanji spelling but have different English, the
    copy is told apart by its roster record, a call id nearby, or the order of appearance."""
    data = rel.sec_data(5)
    cells_at = lambda o: data[o:o + 2 * CELLS]
    by_pattern = {}
    for off, call, english in players:
        if struct.unpack_from(">H", data, off + 2 * CELLS + 4)[0] != call:
            raise ValueError("main_prg.rel sec5+0x%X: not the roster record of call %d" % (off, call))
        if not letters_ok(english) or len(encode(plate(english))) > CELLS:
            raise ValueError("player %r does not fit %d cells" % (english, CELLS))
        by_pattern.setdefault(cells_at(off), []).append((off, call, english))
    out = {}
    for lo, hi, expected in PLAYER_REGIONS:
        seen, found = {}, 0
        for o in range(lo, hi, 2):
            candidates = by_pattern.get(cells_at(o))
            if not candidates:
                continue
            if len({english for _, _, english in candidates}) == 1:
                english = candidates[0][2]
            else:                       # same kanji, other English: the roster record, a call id near, or order
                calls = {struct.unpack_from(">H", data, p)[0]
                         for p in range(max(lo, o - ROSTER_RECORD_BYTES), min(hi, o + ROSTER_LOOKAHEAD_BYTES), 2)}
                own = [c for c in candidates if c[0] == o] or [c for c in candidates if c[1] in calls]
                k = seen[cells_at(o)] = seen.get(cells_at(o), -1) + 1
                english = (own[0] if own else candidates[k % len(candidates)])[2]
            units = encode(plate(english))
            out[o] = struct.pack(">6H", *(units + [0] * (CELLS - len(units))))
            found += 1
        if found != expected:
            raise ValueError("main_prg.rel sec5+0x%X..0x%X: %d player names, %d expected" % (lo, hi, found, expected))
    return out


def player_plates(players: Sequence[Tuple[int, int, str]]) -> List[str]:
    """The English of the real players as laid out (the font builder counts its letter pairs)."""
    return [plate(english) for _, _, english in players]


# ── Names written in place (given names, draft prospects, record holders, foreign players) ──
# Stores of fixed six-cell name fields that are rewritten where they are; nothing moves. One TSV per module,
# translation/names/in_place/<module>.tsv: section, offset of the field (hex), English (no Japanese). The build checks
# that each field holds a name in the original module (glyph cells, blank cells 0) and pads the English with blank cells
# after the plate layout. pp15/names/export_tsv.py writes the TSVs; what each store is:
#
# Given names: main_prg.rel sec5+0x3B288, 200 records of 16 bytes: six cells (hiragana, padded with 0), 0xFFFF, 0; a
#   pointer table follows (sec5+0x3BF08). Read by main_prg.rel sec1+0x8F690 (team set-up, called from camp.rel, the
#   Practice mode, and school_g.rel, Baseball School): it shuffles 100 names a side (0-99 boys, 100-199 girls) into
#   generated team-mates of teams 0x31..0x34. Not seen on screen yet.
# Draft prospects: draft.rel sec5+0x2C08, 2,000 records of 144 bytes: six cells (kanji, two-kanji names as k1, blank,
#   k2), the announcer's call id at +0x3C. English: the surname list's English for the same call id, else the call's
#   reading romanised.
# Record holders: pn_ore_i.rel sec4 (Pennant / My Life record books, NPB history): records start with 0xFFFF or
#   0xFFFE; (0x0100, kind << 8 | team, year) then six cells (two-kanji names as k1, blank, k2), or a variant with a
#   date (0x012A..0x0140, ...) and the cells one later. 810 fields, 303 people; English by hand in
#   _work/names/holders_en.json (name as decoded -> English, game text: not tracked). Two people share one name: Bobby
#   Rose (team 4, Yokohama) and Tuffy Rhodes (the rest).
# Foreign players: pennant.rel sec5, 656 six-cell fields in 82 lists of eight (pointer table sec5+0x7AE8, 0xFFFF, 0
#   between some): 45 single-kanji Korean / Taiwanese surnames, then katakana given names in kana order (names of four
#   kana or more with 0x1000 set in their cells). The game's own jersey spellings follow at sec5+0xC6F8 in the same
#   order (A = 1, 0xFFFF after each: ANDOREW, EDWARZ); they stay as they are. scc_main.rel sec5+0x4AF0..0x68D0
#   (Success): 360 records of six cells, 0x1FFF, call id: the same names plus 88 Korean / Taiwanese full names; this
#   module is moved by the build, so its fields are written into section 5 before the surname table is appended
#   (pp15/build/rebuild.py). English by hand in _work/names/foreign_pool_en.json (by pool index) and
#   foreign_extra_en.json (decoded name -> English).
IN_PLACE_DIR = os.path.join(config.TRANSLATION_DIR, "names", "in_place")
NAME_CELL_MIN_GLYPH = 0x100     # a cell below this is a control value, not a character
NAME_CELL_LIMIT = 0x2000        # a cell at or above this is an end mark or a flag, not part of a name (0x18 is the repeat mark)


def inplace_stores() -> Dict[str, List[Tuple[int, int, str]]]:
    """Read translation/names/in_place/*.tsv. Returns {module name: [(section, offset, English)]}."""
    out = {}
    if not os.path.isdir(IN_PLACE_DIR):
        return out
    for filename in sorted(os.listdir(IN_PLACE_DIR)):
        if not filename.endswith(".tsv"):
            continue
        rows = out.setdefault(filename[:-4], [])
        with open(os.path.join(IN_PLACE_DIR, filename), encoding="utf-8") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                section, offset, english = line.rstrip("\n").split("\t")
                rows.append((int(section), int(offset, 16), english))
    return out


def name_field(data: bytes, offset: int) -> Optional[Tuple[int, ...]]:
    """The six cells at `offset` if they hold a name (glyphs, blank cells 0, at least one glyph), else None."""
    cells = struct.unpack_from(">6H", data, offset)
    if not any(c >= NAME_CELL_MIN_GLYPH for c in cells) or any(c >= NAME_CELL_LIMIT for c in cells):
        return None
    return cells


def inplace_patches(rel, rows: Sequence[Tuple[int, int, str]],
                    encode: Callable[[str], List[int]]) -> Dict[Tuple[int, int], bytes]:
    """The new bytes for the in-place name fields of one module.

    Arguments: `rel` the original module, `rows` [(section, offset, English)] from inplace_stores(), `encode` as in
    `table`. Returns {(section, offset): 12 bytes}. Each original field is checked first (ValueError if it is not a
    name field, if the English does not fit six cells, or if two fields overlap)."""
    out = {}
    for section, offset, english in rows:
        if name_field(rel.sec_data(section), offset) is None:
            raise ValueError("%s sec%d+0x%X: not a name field" % (rel.name, section, offset))
        units = encode(plate(english))
        if not letters_ok(english) or len(units) > CELLS:
            raise ValueError("%s sec%d+0x%X: name %r does not fit %d cells" % (rel.name, section, offset, english, CELLS))
        if (section, offset) in out or any(s == section and abs(p - offset) < 2 * CELLS for s, p in out):
            raise ValueError("%s sec%d+0x%X: fields overlap" % (rel.name, section, offset))
        out[(section, offset)] = struct.pack(">6H", *(units + [0] * (CELLS - len(units))))
    return out


def inplace_plates(stores: Dict[str, List[Tuple[int, int, str]]]) -> List[str]:
    """The English of all in-place names (and the code-built name) as laid out, for the font builder's letter pairs."""
    return ([plate(english) for rows in stores.values() for _, _, english in rows]
            + [plate(english) for _, _, english in CODE_NAMES.values()])


# A name built by code: orepena.rel sec1+0x3F76C creates the rival 奥居 (the speaker plate and every {name} of My Life)
# by storing six halfwords of glyph numbers: li r3, 0x37B; li r0, 0x4E6; sth r3, 0(r29); sth 0, 2(r29); sth r0,
# 4(r29); 0 for cells 3-5. Ten words from 0x3F7A0; the English is stored in cells 0..2 (the plate layout of `plate`)
# by the same ten words, with the middle cell loaded into r5 (free there) and the last two blank cells cleared by one
# stw. {module: (section, offset, English)}
CODE_NAMES = {"orepena.rel": (1, 0x3F7A0, "Okui")}
CODE_NAME_ORIGINAL = (0x3860037B, 0x380004E6, 0xB07D0000, 0x7FA3EB78, 0x38800000,
                      0xB39D0002, 0xB01D0004, 0xB39D0006, 0xB39D0008, 0xB39D000A)


def code_name_words(english: str, encode: Callable[[str], List[int]]) -> Tuple[int, ...]:
    """The ten instruction words that build the name `english` (at most three cells) in place of the original ten."""
    units = encode(plate(english))
    if not letters_ok(english) or len(units) > 3:
        raise ValueError("code name %r does not fit three cells" % english)
    first, middle, last = (units + [0, 0, 0])[:3]
    return (0x38600000 | first, 0x38000000 | last, 0xB07D0000, 0x7FA3EB78, 0x38800000,
            0x38A00000 | middle, 0xB0BD0002, 0xB01D0004, 0xB39D0006, 0x939D0008)


def patch_code_name(rel, image: bytes, encode: Callable[[str], List[int]]) -> Tuple[bytes, Dict[Tuple[int, int], bytes]]:
    """Write the ten words of the name builder into the module image.

    Arguments: the original module `rel` (its name picks the entry of CODE_NAMES), the image being built, `encode`
    as in `table`. Returns (new image, {(section, offset): 4 bytes written}). Each word is checked against the
    original first (ValueError otherwise)."""
    section, offset, english = CODE_NAMES[rel.name]
    if not rel.sections[section]["exec"]:
        raise ValueError("%s sec%d: not a code section" % (rel.name, section))
    out, written = bytearray(image), {}
    new_words = code_name_words(english, encode)
    for k, (old, new) in enumerate(zip(CODE_NAME_ORIGINAL, new_words)):
        o = offset + 4 * k
        if any(s == section and o <= p < o + 4 for s, p, *_ in rel.relocs()):
            raise ValueError("%s sec%d+0x%X: a relocation points into this word" % (rel.name, section, o))
        pos = rel.sections[section]["offset"] + o
        if struct.unpack_from(">I", rel.data, pos)[0] != old or struct.unpack_from(">I", out, pos)[0] != old:
            raise ValueError("%s sec%d+0x%X: not the expected original word 0x%08X" % (rel.name, section, o, old))
        struct.pack_into(">I", out, pos, new)
        written[(section, o)] = struct.pack(">I", new)
    return bytes(out), written
