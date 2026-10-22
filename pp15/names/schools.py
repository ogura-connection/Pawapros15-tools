"""School names in Latin letters for Eikan Nine (sct_main.rel) and the names of My Life (orepena.rel).

What the player sees: the names of about 12,700 high schools and the pro teams in Eikan Nine (Success Mode scenario in
which you lead a high-school team), and about 1,460 names in My Life (career mode).

How the game stores them: sct_main.rel section 5 holds the names as glyph strings closed by 0xFFFF, each reached
through exactly one pointer (an address-load relocation of sct_main.rel's own data, section 5 into section 5; see
docs/GLOSSARY.md "Relocation"). The Japanese slots are as long as their kanji (3.9 cells on average, 8 letters in the
pair font), too short for "Kitami East", and sct_main.rel cannot grow (24 bytes of its memory slot free).

So the English goes into a new table appended to scc_main.rel's section 5, behind the surname table
(pp15/names/table.py): scc_main.rel sits at a fixed address (pp15.names.table.HOST_ADDR) in the free area and is loaded
in Success and Eikan Nine. Each pointer becomes that absolute address, written into the data word, and its relocation
entry becomes a no-op relocation (R_NOP, same position delta), so sct_main.rel keeps its size and its stream layout.
The Japanese strings stay where they were, unread. My Life (orepena.rel) has the same kind of names; their table goes
behind the annexes in ore_work.rel (pp15.build.rebuild.ORE_WORK_ADDR).

English: translation/names/schools.tsv (section 5 offset of the Japanese string, English), written by
_work/schools/make_schools.py from the place list _work/schools/places_en.py. My Life: translation/names/ore_names.tsv.

Public functions: load_tsv, pointers, table, patch_pointers, relocation_entries.
"""
import os
import struct
from typing import Callable, Dict, List, Sequence, Tuple

from pp15 import config
from pp15.script import scan

TSV = os.path.join(config.TRANSLATION_DIR, "names", "schools.tsv")
MODULE, SECTION = "sct_main.rel", 5
ORE_TSV = os.path.join(config.TRANSLATION_DIR, "names", "ore_names.tsv")
ORE_MODULE = "orepena.rel"
R_ADDR32 = 1                    # relocation type "write the 32-bit address of the target"
NAME_END = 0xFFFF               # closes a name in the table
INVALID_UNIT_MIN = 0xF000       # glyph values from here are control codes, not letters
IMPORT_TABLE_HEADER_AT = 0x28   # in a REL header: offset and size of the import (relocation) table


def load_tsv(path: str = TSV) -> Dict[int, str]:
    """Read a names file (section 5 offset, tab, English). Returns {offset: English}; empty if the file is missing."""
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            off, english = line.rstrip("\n").split("\t")
            out[int(off)] = english
    return out


def pointers(rel, names: Sequence[int]) -> Dict[int, int]:
    """Find the pointer to each Japanese name.

    Arguments: `rel` the original module (a scan.Rel), `names` the section 5 offsets of the strings. Returns
    {position in section 5 of the pointer: offset of the string it points at}. A few strings (the team names) have two
    pointers. A string reached by code and not by a pointer is left alone and reported on the screen."""
    found = {}
    for sec, pos, typ, target_module, target_section, addend in rel.relocs():
        if target_module == rel.mod_id and sec == SECTION and target_section == SECTION and typ == R_ADDR32 and addend in names:
            found.setdefault(addend, []).append(pos)
    missing = sorted(o for o in names if not found.get(o))
    if missing:
        print("%s: %d names have no data pointer, left Japanese (sec5+%s)"
              % (rel.name, len(missing), ", ".join("0x%X" % o for o in missing)))
    return {pos: o for o in names if found.get(o) for pos in found[o]}


def table(names: Dict[int, str], encode: Callable[[str], List[int]]) -> Tuple[bytes, Dict[int, int]]:
    """The new table: each English name as glyph units + 0xFFFF, 4-byte aligned.

    Arguments: `names` {offset of the Japanese string: English}, `encode` text -> list of glyph units. Returns
    (table bytes, {string offset: offset of its English in the table}). Raises ValueError for a name that does not
    encode."""
    data, where = bytearray(), {}
    for off in sorted(names):
        units = encode(names[off])
        if not units or any(u >= INVALID_UNIT_MIN for u in units):
            raise ValueError("name %r does not encode" % names[off])
        where[off] = len(data)
        data += struct.pack(">%dH" % (len(units) + 1), *units, NAME_END)
        data += bytes(-len(data) % 4)
    return bytes(data), where


def relocation_entries(image: bytes, import_offset: int, import_size: int) -> List[Tuple[int, int, list, int]]:
    """Read the relocation streams of a module image.

    A module lists, for each module it points into, a stream of 8-byte entries: (distance from the previous
    position, type, target section, addend). Returns [(target module id, stream offset, entries, stream end)] with
    entries = [section, position, type, target section, addend, file offset of the entry]. No-op entries are skipped.
    (The build has the same reader, pp15.build.rebuild.parse_imports; it is kept here so that this package does not
    import the build, which imports this package.)"""
    out = []
    for k in range(import_size // 8):
        module, off = struct.unpack_from(">II", image, import_offset + k * 8)
        start, sec, pos, entries = off, 0, 0, []
        while True:
            delta, typ, target_section, addend = struct.unpack_from(">HBBI", image, off)
            off += 8
            pos += delta
            if typ == scan.R_END:
                break
            if typ == scan.R_SECTION:
                sec, pos = target_section, 0
            elif typ != scan.R_NOP:
                entries.append([sec, pos, typ, target_section, addend, off - 8])
        out.append((module, start, entries, off))
    return out


def patch_pointers(rel, image: bytes, ptrs: Dict[int, int], address: Callable[[int], int]) -> Tuple[bytes, Dict[Tuple[int, int], bytes]]:
    """Aim the name pointers at the English table.

    Each pointer's relocation is turned into a no-op and the absolute address of its English string is written into
    the data word. Arguments: the original module `rel`, the image being built, `ptrs` from pointers(),
    `address(string offset)` -> absolute address of the English string. Returns (new image, {(section, position): the
    4 bytes written}). Raises ValueError unless every pointer was found in the image's relocations."""
    out = bytearray(image)
    section_start = rel.sections[SECTION]["offset"]
    written, n = {}, 0
    import_offset, import_size = struct.unpack_from(">2I", out, IMPORT_TABLE_HEADER_AT)    # the image's own (My Life: streams rebuilt)
    for module, _, entries, _ in relocation_entries(bytes(out), import_offset, import_size):
        if module != rel.mod_id:
            continue
        for sec, pos, typ, target_section, addend, entry_at in entries:
            if sec == SECTION and typ == R_ADDR32 and target_section == SECTION and pos in ptrs:
                assert ptrs[pos] == addend, (pos, addend)
                out[entry_at + 2] = scan.R_NOP                         # delta (2 bytes) stays, type -> no-op
                struct.pack_into(">BI", out, entry_at + 3, 0, 0)
                word = struct.pack(">I", address(addend))
                out[section_start + pos:section_start + pos + 4] = word
                written[(SECTION, pos)] = word
                n += 1
    if n != len(ptrs):
        raise ValueError("%s: %d of %d name pointers found in its relocations" % (rel.name, n, len(ptrs)))
    return bytes(out), written
