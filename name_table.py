"""Surnames in Latin letters: the team-mate / name-entry surname list, widened from 3 to 6 cells.

The game keeps 1,856 surnames in two copies, records of five 16-bit values: three name cells, 0x1FFF, the
announcer's call id. Three cells hold six letters in the pair font, and most copiers stop after four cells,
so a romanised name (Takahashi, Yamaguchi) does not fit.

- scc_main.rel sec5+0xC0 (read by scc_main.rel, scs_main.rel, sct_main.rel, work_sct.rel: Success, Eikan Nine):
  scc_main.rel's slot in the memory plan (0x807E8380) ends 28 bytes before scs_main.rel, so the build moves it
  to HOST_ADDR in the free area (as ore_work.rel for My Life) and appends a new table to its data section: records of 16 bytes, six cells padded with 0x1FFF, 0x1FFF, the call id. The relocations
  that pointed at the old table are aimed at the new one (TableRemap), and the readers are patched in place:
  the record size (mulli 0xA -> 0x10), the call id (lhz 8(rX) -> 0xE(rX)), and the copiers that took four
  cells become a loop of up to six cells in the same space. Every patched instruction is checked first.
- main_prg.rel sec5+0x168F0 (read by one routine of main_prg.rel, reached through a function pointer; where
  its names show is not known yet): main_prg.rel cannot grow (the next module follows 16 bytes behind it), so
  its table keeps its records and takes four cells (8 letters) in the slot that held 0x1FFF; its copier takes
  four cells already. Longer names use the short form (Kunrei spelling: Takahasi) when it fits, else stay kanji.
  (A main.dol section was tried first: the apploader refuses sections above 0x80900000.)

English: translation/names/surnames.tsv (index, call id, English), written by `python3 name_table.py export`
from the game's own readings (_work/surnames.json: kanji, call id, kana of the call); edit the English column
by hand where needed.
    python3 name_table.py export      write the TSV (keeps English already there)
    python3 name_table.py check       lengths, short forms, the patch sites of the original modules
    python3 name_table.py export-given / -draft / -holders   translation/names/in_place/<module>.tsv (see below)
"""
import os, struct, sys

import scan_story as S

HERE = os.path.dirname(os.path.abspath(__file__))
TSV = os.environ.get("NAMES_TSV") or os.path.join(HERE, "translation", "names", "surnames.tsv")   # NAMES_TSV: a test table
READINGS = os.path.join(S.WORK_DIR, "surnames.json")
COUNT, CELLS, STRIDE, OLD_STRIDE = 1856, 6, 16, 10
END = 0x1FFF
OVERRIDES = {"石井": "Ishii"}           # calls that read a full name
HOST, HOST_SECTION, HOST_TABLE = "scc_main.rel", 5, 0xC0
HOST_ADDR = 0x81460000                  # free area: above ore_work.rel (0x81400000), below the arena (0x814E0000)
SHORT_HOST, SHORT_SECTION, SHORT_TABLE, SHORT_CELLS = "main_prg.rel", 5, 0x168F0, 4

# ── PowerPC words ──────────────────────────────────────────────────────────

def _d(op, d, a, imm): return op << 26 | d << 21 | a << 16 | imm & 0xFFFF
def _x(d, a, b, xo): return 31 << 26 | d << 21 | a << 16 | b << 11 | xo << 1
def addi(d, a, imm): return _d(14, d, a, imm)       # rA = 0 means the value 0, not r0
def li(d, imm): return addi(d, 0, imm)
def addis(d, a, imm): return _d(15, d, a, imm)
def cmplwi(a, imm): return _d(10, 0, a, imm)
def cmpwi(a, imm): return _d(11, 0, a, imm)
def lhzx(d, a, b): return _x(d, a, b, 279)
def sthx(s, a, b): return _x(s, a, b, 407)
def add(d, a, b): return _x(d, a, b, 266)
def _bc(bo, bi, here, to): return 16 << 26 | bo << 21 | bi << 16 | (to - here) & 0xFFFC
def beq(here, to): return _bc(12, 2, here, to)
def blt(here, to): return _bc(12, 0, here, to)
def b(here, to): return 18 << 26 | (to - here) & 0x3FFFFFC
BEQLR, BLR, NOP = 0x4D820020, 0x4E800020, 0x60000000
KEEP = None                             # leave the original word (it carries a relocation)


def loop_words(at, words):
    """[(address, word)] for a list of words that may reference their own addresses (callables)."""
    return [(at + 4 * i, w(at + 4 * i) if callable(w) else w) for i, w in enumerate(words)]


# ── The readers of the scc_main.rel table (section 1 offsets) ───────────────

def _copier_scc_main():
    a, out = 0x4DCC, 0x4E1C              # r3 = table, r6 = record offset, r4 = cells copied (0), r22 = dest
    loop = a + 8
    w = [add(3, 3, 6), li(5, 0), lhzx(0, 3, 5), cmplwi(0, END), lambda h: beq(h, out), sthx(0, 22, 5),
         addi(4, 4, 1), addi(5, 5, 2), cmpwi(4, 6), lambda h: blt(h, loop)]
    return a, out, w


def _copier_scs_leaf():
    a, out = 0x60D18, 0x60D60            # leaf: r4 = table, r0 = record offset, r3 = dest, r5 = 0
    loop = a + 4
    w = [add(4, 4, 0), lhzx(0, 4, 5), cmplwi(0, END), BEQLR, sthx(0, 3, 5), addi(5, 5, 2), cmplwi(5, 12),
         lambda h: blt(h, loop), BLR]
    return a, out, w


def _copier_sct(a, out, dest):
    """sct_main.rel / work_sct.rel: r3 = table, r0 = record offset, r31 -> the pointer to the work area,
    destination = *r31 + 0x30000 + dest. Word 5 (lwz r4, 0(r31)) carries a relocation and stays."""
    loop = a + 8
    w = [add(5, 3, 0), li(6, 0), lhzx(7, 5, 6), cmplwi(7, END), lambda h: beq(h, out), KEEP,
         addis(3, 6, 3), addi(0, 3, dest), sthx(7, 4, 0), addi(6, 6, 2), cmplwi(6, 12),
         lambda h: blt(h, loop), lambda h: b(h, out)]
    return a, out, w


READERS = {         # relocs: the HA / LO pairs that point at the old table (aimed at the new one by TableRemap)
    "scc_main.rel": {"relocs": [0x4DC2, 0x4DCA, 0x4E82, 0x4E8A], "mulli": [0x4DB4],
                     "call": [0x4EB4, 0x4EC0], "copier": _copier_scc_main(), "keep": []},
    "scs_main.rel": {"relocs": [0x9D8A, 0x9D96, 0x3559A, 0x355CA, 0x60CFE, 0x60D06],    # 9D70, 37054: six cells
                     "mulli": [0x9D8C, 0x37054, 0x60CF0], "call": [], "copier": _copier_scs_leaf(), "keep": []},
    "sct_main.rel": {"relocs": [0xC49A, 0xC4A6], "mulli": [0xC49C], "call": [],
                     "copier": _copier_sct(0xC4A8, 0xC528, 0x1B48), "keep": [0xC4BC, 0xC4DC, 0xC4FC, 0xC51C]},
    "work_sct.rel": {"relocs": [0x8486, 0x8492], "mulli": [0x8488], "call": [],
                     "copier": _copier_sct(0x8494, 0x8514, 0x1B36), "keep": [0x84A8, 0x84C8, 0x84E8, 0x8508]},
}


def code_patches(rel, host_id):
    """{section 1 offset: (original word, new word)} for one module. Checks the original code and its
    relocations to the old table: raises ValueError when a site is not what it should be."""
    spec, code = READERS[rel.name], rel.sec_data(1)
    word = lambda a: struct.unpack_from(">I", code, a)[0]
    out = {}

    def put(a, new):
        out[a] = (word(a), new)
    relocs = {(s, pos): (typ, tm, ts, ad) for s, pos, typ, tm, ts, ad in rel.relocs()}
    for pos in spec["relocs"]:
        if relocs.get((1, pos)) not in ((4, host_id, HOST_SECTION, HOST_TABLE), (6, host_id, HOST_SECTION, HOST_TABLE)):
            raise ValueError("%s sec1+0x%X: not a relocation to the surname table" % (rel.name, pos))
    for a in spec["mulli"]:
        if word(a) >> 26 != 7 or word(a) & 0xFFFF != OLD_STRIDE:
            raise ValueError("%s sec1+0x%X: not mulli rX, rY, 0xA" % (rel.name, a))
        put(a, word(a) & ~0xFFFF | STRIDE)
    for a in spec["call"]:
        if word(a) >> 26 != 40 or word(a) & 0xFFFF != 8:
            raise ValueError("%s sec1+0x%X: not lhz rX, 8(rY)" % (rel.name, a))
        put(a, word(a) & ~0xFFFF | 2 * CELLS + 2)
    start, end, words = spec["copier"]
    new = dict(loop_words(start, words))
    if len(new) > (end - start) // 4:
        raise ValueError("%s: the copier does not fit" % rel.name)
    for a in range(start, end, 4):
        w = new.get(a, NOP)
        if a in spec["keep"]:
            if w is not KEEP and a in new:
                raise ValueError("%s sec1+0x%X: the copier would overwrite a relocated word" % (rel.name, a))
            if (1, a + 2) not in relocs:
                raise ValueError("%s sec1+0x%X: no relocation where one is kept" % (rel.name, a))
            continue
        if w is KEEP or any(s == 1 and a <= p < a + 4 for s, p in relocs):
            raise ValueError("%s sec1+0x%X: a relocation inside the copier" % (rel.name, a))
        put(a, w)
    return out


def patch_code(rel, image, host_id):
    """The module image with its readers patched. Returns (image, {(1, offset): 4 bytes})."""
    d, base, written = bytearray(image), rel.sections[1]["offset"], {}
    for a, (old, new) in sorted(code_patches(rel, host_id).items()):
        if struct.unpack_from(">I", d, base + a)[0] != old:
            raise ValueError("%s sec1+0x%X: the built image differs from the original here" % (rel.name, a))
        struct.pack_into(">I", d, base + a, new)
        written[(1, a)] = struct.pack(">I", new)
    return bytes(d), written


class TableRemap:
    """scc_main.rel section 5 with the new table appended: everything stays, a pointer to the old table
    goes to the new one. Has the attributes verify() reads of a Remap (lo, hi, growth)."""

    def __init__(self, size, growth, new_table):
        self.lo = self.hi = size
        self.growth, self.new_table = growth, new_table

    def __call__(self, off):
        return self.new_table if off == HOST_TABLE else off


def append_table(host, data):
    """(new section 5 of scc_main.rel, TableRemap) with `data` appended, 8-aligned."""
    old = host.sec_data(HOST_SECTION)
    pad = bytes(-len(old) % 8)
    return old + pad + data, TableRemap(len(old), len(pad) + len(data), len(old) + len(pad))


def place_host(plan, orig_plan, old, new, plan_tables, memory_size):
    """The memory plan with scc_main.rel at HOST_ADDR. Its row is found by its file size (the size column
    holds the larger of the file and its memory, which the game reads the whole file into)."""
    d = bytearray(plan)
    t_addr, t_size, t_file, n = plan_tables(plan)
    rows = [i for i in range(n) if struct.unpack_from(">I", orig_plan, t_file + 4 * i)[0] == len(old)]
    if len(rows) != 1:
        raise ValueError("%s: %d rows of the memory plan have its file size" % (HOST, len(rows)))
    i, size = rows[0], max(len(new), memory_size(new))
    if struct.unpack_from(">I", orig_plan, t_size + 4 * i)[0] != max(len(old), memory_size(old)):
        raise ValueError("%s: its row does not hold the size expected" % HOST)
    end = HOST_ADDR + size
    for k in range(n):
        a2, s2 = (struct.unpack_from(">I", d, t + 4 * k)[0] for t in (t_addr, t_size))
        if k != i and s2 and a2 < end and a2 + s2 > HOST_ADDR:
            raise ValueError("%s at 0x%08X would share memory with row %d (0x%08X..0x%08X)" % (HOST, HOST_ADDR, k, a2, a2 + s2))
    if end > 0x814E0000:
        raise ValueError("%s ends at 0x%08X, past the free area" % (HOST, end))
    struct.pack_into(">I", d, t_addr + 4 * i, HOST_ADDR)
    struct.pack_into(">I", d, t_size + 4 * i, size)
    struct.pack_into(">I", d, t_file + 4 * i, len(new))
    return bytes(d), end


# ── The tables ─────────────────────────────────────────────────────────────

def load_tsv():
    out = {}
    with open(TSV, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            i, call, en = line.rstrip("\n").split("\t")
            out[int(i)] = (int(call), en)
    if sorted(out) != list(range(COUNT)):
        raise ValueError("%s: needs every index 0..%d" % (TSV, COUNT - 1))
    return out


def letters_ok(en, cells=CELLS):
    return 0 < len(en.strip()) and len(en) <= 2 * cells and all(0x20 <= ord(c) < 0x7F for c in en)


def short_form(en):
    """The name in at most 8 letters (Kunrei spellings one at a time), or None."""
    for a, b_ in (("shi", "si"), ("chi", "ti"), ("tsu", "tu"), ("sh", "sy"), ("ch", "ty")):
        if len(en) <= 2 * SHORT_CELLS:
            break
        en = en.replace(a, b_).replace(a.capitalize(), b_.capitalize())
    return en if len(en) <= 2 * SHORT_CELLS else None


def plate(en):
    """The name as laid out in its cells (seen in game, Eikan Nine squad list and result messages):
    - a name plate spreads the cells over its width, trailing blank cells dropped, a leading one kept, so a
      name of two cells shows as "Sa    to": names of four letters or fewer start with a blank cell;
    - text drops blank cells but shows the space of a half-filled pair ("Goto 's", "Fujii 's"): an odd name
      starts with a space instead of ending with one.
    Ito -> "  " " I" "to", Goto -> "  " "Go" "to", Fujii -> " F" "uj" "ii", Takahashi -> " T" "ak" "ah" "as" "hi"."""
    s = " " + en if len(en) % 2 else en
    return "  " + s if len(s) <= 4 else s


def table(names, encode):
    """The 16-byte records. names = load_tsv(), encode = rebuild_scripts.encode_text bound to the font slots."""
    out = bytearray()
    for i in range(COUNT):
        call, en = names[i]
        units = encode(plate(en))
        if not letters_ok(en) or len(units) > CELLS:
            raise ValueError("surname %d %r does not fit %d cells" % (i, en, CELLS))
        out += struct.pack(">8H", *(units + [END] * (CELLS - len(units))), END, call)
    return bytes(out)


def short_table(names, encode, old):
    """main_prg.rel's table in place: (bytes, names that stay kanji). old = its original 1,856 x 10 bytes."""
    out, kanji = bytearray(old), []
    for i in range(COUNT):
        call, en = names[i]
        at = i * OLD_STRIDE
        if struct.unpack_from(">H", old, at + 8)[0] != call or struct.unpack_from(">H", old, at + 6)[0] != END:
            raise ValueError("main_prg.rel surname %d: not the record the TSV expects" % i)
        s = short_form(en)
        if s is None:
            kanji.append(en)
            continue
        units = encode(plate(s))
        assert len(units) <= SHORT_CELLS, s
        struct.pack_into(">4H", out, at, *(units + [END] * (SHORT_CELLS - len(units))))
    return bytes(out), kanji


def short_names(names):
    """The English that main_prg.rel's table holds (for the font's letter pairs)."""
    return [plate(s) for s in (short_form(en) for _, en in names.values()) if s]


def plates(names):
    """The English of the wide table as laid out (for the font's letter pairs)."""
    return [plate(en) for _, en in names.values()]


# ── Real players (main_prg.rel) ────────────────────────────────────────────
# The 2008 rosters: 480 records of six cells + (a, b, call id) at sec5+0x68826.., and the same six cells in a
# names-only list by team and in the 144-byte player records. Every copy is a six-cell field: written in place.
# Readings: the announcer's call (are_main.rel); English in translation/names/players.tsv (foreign players and
# a few registered names by hand). Copies in other modules (pn_ore_i, pennant, draft) are other people with
# the same surnames (draft prospects ...) and are not touched here.
PLAYERS_TSV = os.path.join(HERE, "translation", "names", "players.tsv")
PLAYER_REGIONS = [(0x3C738, 0x3E004, 477), (0x579F0, 0x6A9AA, 960)]    # sec5 spans: list by team; records + roster


def load_players():
    out = []
    with open(PLAYERS_TSV, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            off, call, en = line.rstrip("\n").split("\t")
            out.append((int(off, 16), int(call), en))
    return out


def player_patches(rel, players, encode):
    """{sec5 offset: 12 bytes} for every copy of a real player's name in main_prg.rel."""
    d = rel.sec_data(5)
    cells = lambda o: d[o:o + 2 * CELLS]
    by_pat = {}
    for off, call, en in players:
        if struct.unpack_from(">H", d, off + 2 * CELLS + 4)[0] != call:
            raise ValueError("main_prg.rel sec5+0x%X: not the roster record of call %d" % (off, call))
        if not letters_ok(en) or len(encode(plate(en))) > CELLS:
            raise ValueError("player %r does not fit %d cells" % (en, CELLS))
        by_pat.setdefault(cells(off), []).append((off, call, en))
    out = {}
    for lo, hi, want in PLAYER_REGIONS:
        seen, n = {}, 0
        for o in range(lo, hi, 2):
            cands = by_pat.get(cells(o))
            if not cands:
                continue
            if len({en for _, _, en in cands}) == 1:
                en = cands[0][2]
            else:                       # same kanji, other English: the roster record, a call id near, or order
                calls = {struct.unpack_from(">H", d, p)[0] for p in range(max(lo, o - 144), min(hi, o + 156), 2)}
                own = [c for c in cands if c[0] == o] or [c for c in cands if c[1] in calls]
                k = seen[cells(o)] = seen.get(cells(o), -1) + 1
                en = (own[0] if own else cands[k % len(cands)])[2]
            units = encode(plate(en))
            out[o] = struct.pack(">6H", *(units + [0] * (CELLS - len(units))))
            n += 1
        if n != want:
            raise ValueError("main_prg.rel sec5+0x%X..0x%X: %d player names, %d expected" % (lo, hi, n, want))
    return out


def player_plates(players):
    return [plate(en) for _, _, en in players]


# ── Names written in place (given names, draft prospects, record holders ...) ──
# Stores of fixed six-cell name fields that are rewritten where they are; nothing moves. One TSV per module,
# translation/names/in_place/<module>.tsv: section, offset of the field (hex), English (no Japanese). The
# build checks that each field holds a name in the original module (glyph cells, blank cells 0) and pads
# the English with blank cells after the plate layout. Written by the export commands below.
#
# Given names: main_prg.rel sec5+0x3B288, 200 records of 16 bytes: six cells (hiragana, padded with 0),
#   0xFFFF, 0; a pointer table follows (sec5+0x3BF08). Read by main_prg.rel sec1+0x8F690 (team set-up,
#   called from camp.rel, the Practice mode, and school_g.rel, Baseball School): it shuffles 100 names a side
#   (0-99 boys, 100-199 girls) into generated team-mates of teams 0x31..0x34. Not seen on screen yet.
# Draft prospects: draft.rel sec5+0x2C08, 2,000 records of 144 bytes: six cells (kanji, two-kanji names
#   as k1, blank, k2), the announcer's call id at +0x3C. English: the surname list's English for the same
#   call id, else the call's reading romanised.
# Record holders: pn_ore_i.rel sec4 (Pennant / My Life record books, NPB history): records start with 0xFFFF
#   or 0xFFFE; (0x0100, kind << 8 | team, year) then six cells (two-kanji names as k1, blank, k2), or a
#   variant with a date (0x012A..0x0140, ...) and the cells one later. 810 fields, 303 people; English by hand
#   in _work/names/holders_en.json (name as decoded -> English, game text: not tracked). Two people share
#   one name: Bobby Rose (team 4, Yokohama) and Tuffy Rhodes (the rest).
IN_PLACE_DIR = os.path.join(HERE, "translation", "names", "in_place")
GIVEN = ("main_prg.rel", 5, 0x3B288, 200, 16)
GIVEN_FIXES = {18: "Koichi", 33: "Shoichi",           # romaji keeps "ou" before a vowel
               25: "Koutaro", 85: "Yuuki", 170: "Miyuu", 179: "Yuuka", 180: "Yuuna"}   # long vowel: kept apart
DRAFT = ("draft.rel", 5, 0x2C08, 2000, 144, 0x3C)


def inplace_stores():
    """{module: [(section, offset, English)]} from translation/names/in_place/*.tsv."""
    out = {}
    if not os.path.isdir(IN_PLACE_DIR):
        return out
    for fn in sorted(os.listdir(IN_PLACE_DIR)):
        if not fn.endswith(".tsv"):
            continue
        rows = out.setdefault(fn[:-4], [])
        with open(os.path.join(IN_PLACE_DIR, fn), encoding="utf-8") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                sec, off, en = line.rstrip("\n").split("\t")
                rows.append((int(sec), int(off, 16), en))
    return out


def name_field(d, o):
    """The six cells at o if they hold a name (glyphs, blank cells 0, at least one glyph), else None."""
    cells = struct.unpack_from(">6H", d, o)
    if not any(c >= 0x100 for c in cells) or any(c >= 0x2000 for c in cells):   # 0x18 is the repeat mark
        return None
    return cells


def inplace_patches(rel, rows, encode):
    """{(section, offset): 12 bytes} for one module; each original field is checked first."""
    out = {}
    for sec, o, en in rows:
        if name_field(rel.sec_data(sec), o) is None:
            raise ValueError("%s sec%d+0x%X: not a name field" % (rel.name, sec, o))
        units = encode(plate(en))
        if not letters_ok(en) or len(units) > CELLS:
            raise ValueError("%s sec%d+0x%X: name %r does not fit %d cells" % (rel.name, sec, o, en, CELLS))
        if (sec, o) in out or any(s == sec and abs(p - o) < 2 * CELLS for s, p in out):
            raise ValueError("%s sec%d+0x%X: fields overlap" % (rel.name, sec, o))
        out[(sec, o)] = struct.pack(">6H", *(units + [0] * (CELLS - len(units))))
    return out


def inplace_plates(stores):
    return [plate(en) for rows in stores.values() for _, _, en in rows]


def holder_fields(d):
    """[(offset, cells, team)] of every name field of the record holders (pn_ore_i.rel sec4)."""
    hw = struct.unpack(">%dH" % (len(d) // 2), d)
    out = []
    for i, x in enumerate(hw[:-12]):
        if x not in (0xFFFF, 0xFFFE):
            continue
        at = i + 4 if hw[i + 1] == 0x0100 else i + 5 if 0x0120 <= hw[i + 1] <= 0x0140 else None
        if at and name_field(d, 2 * at):
            out.append((2 * at, hw[at:at + CELLS], hw[i + 2] & 0xFF))
    return out


def cmd_export_holders():
    import json
    with open(os.path.join(S.WORK_DIR, "names", "holders_en.json"), encoding="utf-8") as f:
        english = json.load(f)
    fn, sec = "pn_ore_i.rel", 4
    d = S.Rel(os.path.join(S.WORK_DIR, "orig", fn)).sec_data(sec)
    rows, left = [], []
    for o, cells, team in holder_fields(d):
        key = S.decode_units([c if c < 0x1000 else c - 0x1000 for c in cells if c])
        en = english.get(key)
        if en == "Rhodes" and team == 4:
            en = "Rose"
        if en:
            rows.append((sec, o, en))
        else:
            left.append((hex(o), key))
    _write_store(fn, "record holders, Pennant / My Life record books", rows)
    print("left as they are:", left)


def _write_store(module, header, rows):
    os.makedirs(IN_PLACE_DIR, exist_ok=True)
    path = os.path.join(IN_PLACE_DIR, module + ".tsv")
    have = {(s, o): en for s, o, en in inplace_stores().get(module, [])}
    with open(path, "w", encoding="utf-8") as f:
        f.write("# section\toffset\tEnglish (%s; up to 12 letters)\n" % header)
        for sec, o, en in rows:
            f.write("%d\t%X\t%s\n" % (sec, o, have.get((sec, o)) or en))
    print("%s: %d names" % (path, len(rows)))


def _romaji():
    sys.path.insert(0, os.path.join(S.WORK_DIR, "names"))
    from romaji import romaji
    return romaji


def cmd_export_given():
    romaji = _romaji()
    fn, sec, at, n, stride = GIVEN
    d = S.Rel(os.path.join(S.WORK_DIR, "orig", fn)).sec_data(sec)
    rows = []
    for i in range(n):
        kana = S.decode_units([c for c in struct.unpack_from(">6H", d, at + stride * i) if c])
        rows.append((sec, at + stride * i, GIVEN_FIXES.get(i) or romaji(kana)))
    _write_store(fn, "given names: the first 100 boys, the next 100 girls", rows)


def cmd_export_draft():
    import json
    romaji = _romaji()
    with open(os.path.join(S.WORK_DIR, "call_readings.json"), encoding="utf-8") as f:
        readings = {int(k): v for k, v in json.load(f).items()}
    by_call = {call: en for call, en in load_tsv().values()}
    fn, sec, at, n, stride, call_at = DRAFT
    d = S.Rel(os.path.join(S.WORK_DIR, "orig", fn)).sec_data(sec)
    rows = []
    for i in range(n):
        o = at + stride * i
        call = struct.unpack_from(">H", d, o + call_at)[0]
        rows.append((sec, o, by_call.get(call) or romaji(readings[call])))
    _write_store(fn, "draft prospects, from the announcer's call ids", rows)


# ── Commands ───────────────────────────────────────────────────────────────

def cmd_export():
    import json
    sys.path.insert(0, os.path.join(S.WORK_DIR, "names"))
    from romaji import romaji
    with open(READINGS, encoding="utf-8") as f:
        rows = json.load(f)
    assert len(rows) == COUNT
    have = load_tsv() if os.path.exists(TSV) else {}
    os.makedirs(os.path.dirname(TSV), exist_ok=True)
    with open(TSV, "w", encoding="utf-8") as f:
        f.write("# index\tcall id\tEnglish (surname list: team-mates, name entry, generated players; up to 12 letters)\n")
        for i, (kanji, call, kana) in enumerate(rows):
            en = have[i][1] if i in have else OVERRIDES.get(kanji) or romaji(kana)
            f.write("%d\t%d\t%s\n" % (i, call, en))
    print("%s: %d names" % (TSV, len(rows)))


def cmd_check():
    names = load_tsv()
    bad = [(i, en) for i, (_, en) in names.items() if not letters_ok(en)]
    short = [en for _, en in names.values() if len(en) > 2 * SHORT_CELLS]
    kanji = [en for en in short if short_form(en) is None]
    print("%d names, %d too long or not plain ASCII: %s" % (len(names), len(bad), bad[:20]))
    print("main_prg.rel (8 letters): %d use a short form, %d stay kanji: %s" % (len(short) - len(kanji), len(kanji), kanji))
    host = S.Rel(os.path.join(S.WORK_DIR, "orig", HOST))
    for fn in READERS:
        rel = S.Rel(os.path.join(S.WORK_DIR, "orig", fn))
        print("  %-13s %d words patched" % (fn, len(code_patches(rel, host.mod_id))))


if __name__ == "__main__":
    {"export": cmd_export, "export-given": cmd_export_given, "export-draft": cmd_export_draft,
     "export-holders": cmd_export_holders,
     "check": cmd_check}.get((sys.argv + [""])[1], lambda: sys.exit(__doc__))()
