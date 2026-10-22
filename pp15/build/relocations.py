"""Read and rewrite the relocation tables of the game's REL modules.

What it is for: a REL file is a code-and-data module the game loads while it runs. Wherever one piece of data
holds the address of another piece (a pointer), the file does not store the address: it stores a *relocation*, a
small record saying "when the module is loaded, write the address of that thing at this position" (see
"Relocation" in docs/GLOSSARY.md). When translated text changes length, everything behind it moves, so every such
record has to be rewritten. This module reads the records, writes them back, and re-assembles a module whose
script section changed size.

A relocation stream is a list of 8-byte entries: u16 distance from the previous entry, u8 type, u8 target section,
u32 addend (the offset inside the target). Special types switch the current section (R_SECTION), pad a distance
longer than 16 bits (R_NOP) and close the stream (R_END). A module has one stream per module it points into.

Public functions:
    parse_imports(data, imp_off, imp_size)   all streams of a module as lists of entries
    encode_stream(entries)                   entries -> the bytes of one stream
    rebuild_module(rel, sec, new_sec, remaps)  the module's file with section `sec` replaced and every pointer fixed
    patch_addends(rel, remaps, image)        other modules: pointers into a rebuilt section aimed at the new places
"""
import struct

from pp15.script.scan import R_END, R_NOP, R_SECTION


# Offsets in the REL header (all big-endian u32), see docs/GLOSSARY.md "REL".
HEADER_SECTION_TABLE = 0x10      # file offset of the section table (8 bytes per section: offset, size)
HEADER_REL_OFFSET = 0x24         # file offset of the relocation streams; the u32 after it is the offset of the stream table
HEADER_FIX_SIZE = 0x48           # size of the part of the module kept in memory after linking (fixSize)
ENTRY_SIZE = 8                   # bytes of one relocation entry, and of one row of the stream table
MAX_DELTA = 0xFFFF               # the largest distance one entry can span; longer ones use R_NOP entries
MAX_STREAM_GAP = 32              # the stream table follows its section within this many bytes (alignment)


def parse_imports(data: bytes, imp_off: int, imp_size: int) -> list[tuple]:
    """All relocation streams of a module.

    `imp_off`, `imp_size` = position and size of the stream table in the file. Returns
    [(target module id, offset of the stream, entries, offset just behind the stream)] where each entry is
    [section, position in that section, type, target section, addend, file offset of the entry].
    """
    out = []
    for k in range(imp_size // ENTRY_SIZE):
        mod, off = struct.unpack_from(">II", data, imp_off + k * ENTRY_SIZE)
        start, sec, pos, entries = off, 0, 0, []
        while True:
            delta, typ, tsec, addend = struct.unpack_from(">HBBI", data, off)
            off += ENTRY_SIZE
            pos += delta
            if typ == R_END:
                break
            if typ == R_SECTION:
                sec, pos = tsec, 0
            elif typ != R_NOP:
                entries.append([sec, pos, typ, tsec, addend, off - ENTRY_SIZE])
        out.append((mod, start, entries, off))
    return out


def encode_stream(entries: list) -> bytes:
    """The bytes of one relocation stream; the inverse of one stream of `parse_imports`.

    Entries must be sorted by section and position. A gap longer than 16 bits is bridged with R_NOP entries.
    """
    out, cur_sec, cur = [], None, 0
    for sec, pos, typ, tsec, addend, _ in entries:
        if sec != cur_sec:
            out.append(struct.pack(">HBBI", 0, R_SECTION, sec, 0))
            cur_sec, cur = sec, 0
        delta = pos - cur
        assert delta >= 0, "relocations out of order"
        while delta > MAX_DELTA:
            out.append(struct.pack(">HBBI", MAX_DELTA, R_NOP, 0, 0))
            delta -= MAX_DELTA
        out.append(struct.pack(">HBBI", delta, typ, tsec, addend))
        cur = pos
    out.append(struct.pack(">HBBI", 0, R_END, 0, 0))
    return b"".join(out)


def rebuild_module(rel, sec: int, new_sec: bytes, remaps: dict) -> bytes:
    """The file image of a module whose section `sec` was written again as `new_sec`.

    Every relocation is moved and re-aimed: entries applied inside `sec` get their position mapped through
    remaps[(module id, sec)], and entries that point into any rebuilt section get their addend mapped through
    remaps[(target module, target section)]. The header (section size, stream offsets, fixSize) follows.
    The section must be the last one in the file, directly followed by the relocation tables.
    Raises ValueError when the file is laid out differently from what the build expects.
    """
    d = rel.data
    s = rel.sections[sec]
    sec_end = s["offset"] + s["size"]
    later = [t for t in rel.sections if t["offset"] > s["offset"]]
    if later or not sec_end <= rel.imp_off < sec_end + MAX_STREAM_GAP or rel.imp_off + rel.imp_size != rel.rel_off:
        raise ValueError("%s: unexpected file layout" % rel.name)
    imports = parse_imports(d, rel.imp_off, rel.imp_size)
    spans = sorted((start, end) for _, start, _, end in imports)
    if spans[0][0] != rel.rel_off or any(a[1] != b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError("%s: relocation streams are not contiguous" % rel.name)
    tail = d[spans[-1][1]:]
    sec_table = struct.unpack_from(">I", d, HEADER_SECTION_TABLE)[0]
    fix_size = struct.unpack_from(">I", d, HEADER_FIX_SIZE)[0]

    head = bytearray(d[:s["offset"]]) + new_sec + d[sec_end:rel.imp_off]
    struct.pack_into(">I", head, sec_table + sec * 8 + 4, len(new_sec))
    imp_off = len(head)
    rel_off = imp_off + rel.imp_size
    table, streams, off, new_fix = [], [], rel_off, None
    for mod, start, entries, _ in imports:
        for e in entries:
            if e[0] == sec:
                e[1] = remaps[(rel.mod_id, sec)](e[1])
            if (mod, e[3]) in remaps:
                e[4] = remaps[(mod, e[3])](e[4])
        blob = encode_stream(entries)
        if start == fix_size:
            new_fix = off
        table.append(struct.pack(">II", mod, off))
        streams.append(blob)
        off += len(blob)
    if new_fix is None:
        raise ValueError("%s: fixSize does not match a relocation stream" % rel.name)
    struct.pack_into(">II", head, HEADER_REL_OFFSET, rel_off, imp_off)
    struct.pack_into(">I", head, HEADER_FIX_SIZE, new_fix)
    return bytes(head) + b"".join(table) + b"".join(streams) + tail


def patch_addends(rel, remaps: dict, image: bytes | None = None) -> tuple[bytes, int]:
    """Re-aim the pointers of a module that was not rebuilt itself.

    Every relocation whose target (module, section) is in `remaps` gets its addend mapped through that remap, in
    place (the tables do not move). `image` = the module as built so far, when other changes were made to it first.
    Returns (new image, number of addends changed).
    """
    d, n = bytearray(image if image is not None else rel.data), 0
    for mod, _, entries, _ in parse_imports(bytes(d), rel.imp_off, rel.imp_size):
        for sec, pos, typ, tsec, addend, off in entries:
            if (mod, tsec) in remaps:
                new = remaps[(mod, tsec)](addend)
                if new != addend:
                    struct.pack_into(">I", d, off + 4, new)
                    n += 1
    return bytes(d), n
