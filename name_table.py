"""Surnames in Latin letters: the team-mate / name-entry surname list, widened from 3 to 6 cells.

The game keeps 1,856 surnames in two copies (main_prg.rel sec5+0x168F0, scc_main.rel sec5+0xC0), records of
five 16-bit values: three name cells, 0x1FFF, the announcer's call id. Three cells hold six letters in the pair
font, and the copiers stop after four cells, so a romanised name (Takahashi, Yamaguchi) does not fit.

The build puts a new table into an extra data section of main.dol, loaded at TABLE_ADDR (the top of the area
the game keeps free for modules, so it is in memory in every mode): records of 16 bytes, six cells padded with
0x1FFF, 0x1FFF, the call id. The nine readers of the old tables are patched in place:
  - the table address: the immediate written in, its relocation turned into R_NOP (same file layout)
  - the record size: mulli 0xA -> 0x10
  - the call id: lhz 8(rX) -> 0xE(rX)
  - the copiers that took four cells: a loop of up to six cells in the same space
Every patched instruction is checked against the original first.

English: translation/names/surnames.tsv (index, call id, English), written by `python3 name_table.py export`
from the game's own readings (_work/surnames.json: kanji, call id, kana of the call); edit the English column
by hand where needed.
    python3 name_table.py export      write the TSV (keeps English already there)
    python3 name_table.py check       lengths, letters, the patch sites of the original modules
"""
import os, struct, sys

import scan_story as S

HERE = os.path.dirname(os.path.abspath(__file__))
TSV = os.path.join(HERE, "translation", "names", "surnames.tsv")
READINGS = os.path.join(S.WORK_DIR, "surnames.json")
COUNT, CELLS, STRIDE = 1856, 6, 16
TABLE_ADDR = 0x814D8000                 # .. 0x814DF400; modules stay below (rebuild_scripts.NAME_AREA)
TABLE_SIZE = COUNT * STRIDE
DOL_SECTION = 15                        # a free data slot of main.dol
END = 0x1FFF
OVERRIDES = {"石井": "Ishii"}           # calls that read a full name

# ── PowerPC words ──────────────────────────────────────────────────────────

def _d(op, d, a, imm): return op << 26 | d << 21 | a << 16 | imm & 0xFFFF
def _x(d, a, b, xo): return 31 << 26 | d << 21 | a << 16 | b << 11 | xo << 1
def addi(d, a, imm): return _d(14, d, a, imm)
def li(d, imm): return addi(d, 0, imm)
def addis(d, a, imm): return _d(15, d, a, imm)
def addic(d, a, imm): return _d(12, d, a, imm)     # unlike addi, rA = r0 is the register
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


# ── The nine readers (section 1 offsets) ─────────────────────────────────────

def _copier_main_prg():
    a, out = 0x2D0BC, 0x2D0F4            # r18 = record, r30 = destination; r0 and r15 are free here
    loop = a + 4
    w = [li(0, 0), lhzx(15, 18, 0), cmplwi(15, END), lambda h: beq(h, out), sthx(15, 30, 0), addic(0, 0, 2),
         cmplwi(0, 12), lambda h: blt(h, loop)]
    return a, out, w


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


def _copier_sct(a, out, dest, keep):
    """sct_main.rel / work_sct.rel: r3 = table, r0 = record offset, r31 -> the pointer to the work area,
    destination = *r31 + 0x30000 + dest. `keep` = the lwz r4,0(r31) words that carry a relocation."""
    loop = a + 8
    w = [add(5, 3, 0), li(6, 0), lhzx(7, 5, 6), cmplwi(7, END), lambda h: beq(h, out), KEEP,
         addis(3, 6, 3), addi(0, 3, dest), sthx(7, 4, 0), addi(6, 6, 2), cmplwi(6, 12),
         lambda h: blt(h, loop), lambda h: b(h, out)]
    assert a + 20 == keep[0]
    return a, out, w


READERS = {
    "main_prg.rel": {"relocs": [0x2CF96, 0x2CFA2, 0x2D0FE, 0x2D10A], "mulli": [0x2CF8C],
                     "call": [0x2D128, 0x2D134], "copier": _copier_main_prg()},
    "scc_main.rel": {"relocs": [0x4DC2, 0x4DCA, 0x4E82, 0x4E8A], "mulli": [0x4DB4],
                     "call": [0x4EB4, 0x4EC0], "copier": _copier_scc_main()},
    "scs_main.rel": {"relocs": [0x9D8A, 0x9D96, 0x3559A, 0x355CA, 0x60CFE, 0x60D06],
                     "mulli": [0x9D8C, 0x37054, 0x60CF0], "call": [], "copier": _copier_scs_leaf()},
    "sct_main.rel": {"relocs": [0xC49A, 0xC4A6], "mulli": [0xC49C], "call": [],
                     "copier": _copier_sct(0xC4A8, 0xC528, 0x1B48, [0xC4BC, 0xC4DC, 0xC4FC, 0xC51C]),
                     "keep": [0xC4BC, 0xC4DC, 0xC4FC, 0xC51C]},
    "work_sct.rel": {"relocs": [0x8486, 0x8492], "mulli": [0x8488], "call": [],
                     "copier": _copier_sct(0x8494, 0x8514, 0x1B36, [0x84A8, 0x84C8, 0x84E8, 0x8508]),
                     "keep": [0x84A8, 0x84C8, 0x84E8, 0x8508]},
}
# the old tables the relocations point at: (module, section, addend)
OLD_TABLES = {"main_prg.rel": 0x168F0, "scc_main.rel": 0xC0}


def code_patches(rel):
    """{section 1 offset: (original word, new word)} and the relocations to turn off [(sec, pos)] for one
    module. Checks the original code: raises ValueError when a site is not what it should be."""
    spec, code = READERS[rel.name], rel.sec_data(1)
    word = lambda a: struct.unpack_from(">I", code, a)[0]
    out = {}

    def put(a, new):
        out[a] = (word(a), new)
    want_tables = {OLD_TABLES["main_prg.rel"], OLD_TABLES["scc_main.rel"]}
    relocs = {(s, pos): (typ, tm, ts, ad) for s, pos, typ, tm, ts, ad in rel.relocs()}
    ha, lo = (TABLE_ADDR + 0x8000) >> 16, TABLE_ADDR & 0xFFFF
    for pos in spec["relocs"]:
        typ, tm, ts, ad = relocs.get((1, pos), (None,) * 4)
        if typ not in (4, 6) or ts != 5 or ad not in want_tables:
            raise ValueError("%s sec1+0x%X: not a relocation to the surname table" % (rel.name, pos))
        a = pos & ~3
        if word(a) & 0xFFFF:
            raise ValueError("%s sec1+0x%X: the immediate is not 0" % (rel.name, a))
        put(a, word(a) | (ha if typ == 6 else lo))
    for a in spec["mulli"]:
        if word(a) >> 26 != 7 or word(a) & 0xFFFF != 0xA:
            raise ValueError("%s sec1+0x%X: not mulli rX, rY, 0xA" % (rel.name, a))
        put(a, word(a) & ~0xFFFF | 0x10)
    for a in spec["call"]:
        if word(a) >> 26 != 40 or word(a) & 0xFFFF != 8:
            raise ValueError("%s sec1+0x%X: not lhz rX, 8(rY)" % (rel.name, a))
        put(a, word(a) & ~0xFFFF | 0xE)
    start, end, words = spec["copier"]
    new = loop_words(start, words)
    if len(new) > (end - start) // 4:
        raise ValueError("%s: the copier does not fit" % rel.name)
    keep = set(spec.get("keep", ()))
    for a in range(start, end, 4):
        w = dict(new).get(a, NOP)
        if a in keep:
            if (a, w) in new and w is not KEEP:
                raise ValueError("%s sec1+0x%X: the copier would overwrite a relocated word" % (rel.name, a))
            if (1, a + 2) not in relocs:
                raise ValueError("%s sec1+0x%X: no relocation where one is kept" % (rel.name, a))
            continue
        if any(s == 1 and a <= p < a + 4 for s, p in relocs):
            raise ValueError("%s sec1+0x%X: a relocation inside the copier" % (rel.name, a))
        put(a, w)
    return out, [(1, pos) for pos in spec["relocs"]]


def patch_module(rel, image, parse_imports, r_nop):
    """The module image with the readers patched. Returns (image, {(1, offset): 4 bytes}, {(sec, pos)})."""
    patches, nops = code_patches(rel)
    d = bytearray(image)
    base = rel.sections[1]["offset"]
    written = {}
    for a, (old, new) in sorted(patches.items()):
        if struct.unpack_from(">I", d, base + a)[0] != old:
            raise ValueError("%s sec1+0x%X: the built image differs from the original here" % (rel.name, a))
        struct.pack_into(">I", d, base + a, new)
        written[(1, a)] = struct.pack(">I", new)
    hit = set()
    imp_off, imp_size = struct.unpack_from(">II", d, 0x28)      # a rebuilt module has moved its tables
    for mod, _, entries, _ in parse_imports(bytes(d), imp_off, imp_size):
        for sec, pos, typ, tsec, addend, off in entries:
            if (sec, pos) in nops and typ in (4, 6) and tsec == 5:
                d[off + 2] = r_nop
                hit.add((sec, pos))
    if hit != set(nops):
        raise ValueError("%s: relocations not found: %s" % (rel.name, sorted(set(nops) - hit)))
    return bytes(d), written, set(nops)


# ── The table ──────────────────────────────────────────────────────────────

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


def letters_ok(en):
    return 0 < len(en) <= 2 * CELLS and all(0x20 < ord(c) < 0x7F for c in en)


def table(names, encode):
    """names = load_tsv(), encode = rebuild_scripts.encode_text bound to the font slots."""
    out = bytearray()
    for i in range(COUNT):
        call, en = names[i]
        units = encode(en)
        if not letters_ok(en) or len(units) > CELLS:
            raise ValueError("surname %d %r does not fit %d cells" % (i, en, CELLS))
        out += struct.pack(">8H", *(units + [END] * (CELLS - len(units))), END, call)
    assert len(out) == TABLE_SIZE
    return bytes(out)


def add_dol_section(dol, data):
    """main.dol with `data` as data section DOL_SECTION at TABLE_ADDR, appended to the file."""
    offs = struct.unpack_from(">18I", dol, 0)
    if offs[DOL_SECTION] or struct.unpack_from(">I", dol, 0x90 + 4 * DOL_SECTION)[0]:
        raise ValueError("main.dol: data section %d is in use" % DOL_SECTION)
    d = bytearray(dol)
    d += bytes(-len(d) % 32)
    at = len(d)
    d += data + bytes(-len(data) % 32)
    struct.pack_into(">I", d, 4 * DOL_SECTION, at)
    struct.pack_into(">I", d, 0x48 + 4 * DOL_SECTION, TABLE_ADDR)
    struct.pack_into(">I", d, 0x90 + 4 * DOL_SECTION, len(data))
    return bytes(d)


def dol_section(dol):
    """(address, bytes) of the name section of a built main.dol, or None."""
    off = struct.unpack_from(">I", dol, 4 * DOL_SECTION)[0]
    if not off:
        return None
    addr = struct.unpack_from(">I", dol, 0x48 + 4 * DOL_SECTION)[0]
    size = struct.unpack_from(">I", dol, 0x90 + 4 * DOL_SECTION)[0]
    return addr, dol[off:off + size]


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
    long = [(i, en) for i, (_, en) in names.items() if not letters_ok(en)]
    print("%d names, %d too long or not plain ASCII: %s" % (len(names), len(long), long[:20]))
    for fn in READERS:
        rel = S.Rel(os.path.join(S.WORK_DIR, "orig", fn))
        patches, nops = code_patches(rel)
        print("  %-13s %d words patched, %d relocations turned off" % (fn, len(patches), len(nops)))


if __name__ == "__main__":
    {"export": cmd_export, "check": cmd_check}.get((sys.argv + [""])[1], lambda: sys.exit(__doc__))()
