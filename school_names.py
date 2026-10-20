"""Eikan Nine school names in Latin letters (sct_main.rel).

sct_main.rel section 5 holds about 12,700 school names (and the pro team names) as glyph strings closed by
0xFFFF, each reached through exactly one pointer: an R_PPC_ADDR32 relocation of sct_main.rel's own data
(section 5) into section 5. The Japanese slots are as long as their kanji (3.9 cells on average, 8 letters in
the pair font), too short for "Kitami East", and sct_main.rel cannot grow (24 bytes of its memory slot free).

So the English goes into a new table appended to scc_main.rel's section 5, behind the surname table
(name_table.py): scc_main.rel sits at a fixed address (name_table.HOST_ADDR) in the free area and is loaded
in Success and Eikan Nine. Each pointer becomes that absolute address, written into the data word, and its
relocation entry becomes R_NOP (same position delta), so sct_main.rel keeps its size and its stream layout.
The Japanese strings stay where they were, unread.

English: translation/names/schools.tsv (section 5 offset of the Japanese string, English), written by
_work/schools/make_schools.py from the place list _work/schools/places_en.py.
"""
import os, struct

import scan_story as S

HERE = os.path.dirname(os.path.abspath(__file__))
TSV = os.path.join(HERE, "translation", "names", "schools.tsv")
MODULE, SECTION = "sct_main.rel", 5
R_ADDR32 = 1


def load_tsv():
    """{section 5 offset: English}"""
    out = {}
    if not os.path.exists(TSV):
        return out
    with open(TSV, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            off, en = line.rstrip("\n").split("\t")
            out[int(off)] = en
    return out


def pointers(rel, names):
    """{position in section 5 of the pointer: offset of the string it points at} for the strings in `names`;
    every string must have exactly one pointer."""
    found = {}
    for sec, pos, typ, tm, ts, addend in rel.relocs():
        if tm == rel.mod_id and sec == SECTION and ts == SECTION and typ == R_ADDR32 and addend in names:
            found.setdefault(addend, []).append(pos)
    bad = [o for o in names if len(found.get(o, ())) != 1]
    if bad:
        raise ValueError("%s: %d school names do not have exactly one pointer (first at sec5+0x%X)"
                         % (MODULE, len(bad), bad[0]))
    return {found[o][0]: o for o in names}


def table(names, encode):
    """(bytes, {string offset: offset in the table}): each name as units + 0xFFFF, 4-byte aligned."""
    data, where = bytearray(), {}
    for off in sorted(names):
        units = encode(names[off])
        if not units or any(u >= 0xF000 for u in units):
            raise ValueError("school name %r does not encode" % names[off])
        where[off] = len(data)
        data += struct.pack(">%dH" % (len(units) + 1), *units, 0xFFFF)
        data += bytes(-len(data) % 4)
    return bytes(data), where


def patch_pointers(rel, image, ptrs, address):
    """sct_main.rel image with each pointer's relocation turned into R_NOP and the absolute address of its
    English string written into the data word. address(string offset) -> absolute address.
    Returns (image, {(section, position): 4 bytes written})."""
    import rebuild_scripts as R
    d = bytearray(image)
    sec_off = rel.sections[SECTION]["offset"]
    written, n = {}, 0
    for mod, _, entries, _ in R.parse_imports(bytes(d), rel.imp_off, rel.imp_size):
        if mod != rel.mod_id:
            continue
        for sec, pos, typ, tsec, addend, off in entries:
            if sec == SECTION and typ == R_ADDR32 and tsec == SECTION and pos in ptrs:
                assert ptrs[pos] == addend, (pos, addend)
                d[off + 2] = S.R_NOP                         # delta (2 bytes) stays, type -> NOP
                struct.pack_into(">BI", d, off + 3, 0, 0)
                word = struct.pack(">I", address(addend))
                d[sec_off + pos:sec_off + pos + 4] = word
                written[(SECTION, pos)] = word
                n += 1
    if n != len(ptrs):
        raise ValueError("%s: %d of %d school-name pointers found in its relocations" % (MODULE, n, len(ptrs)))
    return bytes(d), written
