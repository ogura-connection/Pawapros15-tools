"""Write the My Life script out again, with an annex for the pieces that no longer fit.

What it is for: My Life (the career mode) keeps its story in `orepena.rel`, whose memory is full to the last byte,
and the English is longer than the Japanese. The script is cut into pieces that can stand anywhere (each ends with
a return or a jump that nothing runs past). The build puts the pieces back in place wherever they fit between the
fixed "islands" of other data, and moves the rest to an *annex* appended to the data of `ore_work.rel`, which is
always loaded. A label pointing at a moved piece is turned into an absolute address (see "Annex" in
docs/GLOSSARY.md). The annex starts with a four-letter marker and its own address, so a built file can be read back
without the memory plan.

Public names:
    OreRemap                      old offset -> new offset (or annex address)
    ore_chunks(script, a, b, replacements)   the pieces between two offsets
    emit_ore(script, replacements, base, magic)   lay it out: stretches, annex bytes, remap
    ore_relocations(module, image, script, remap) the label table of orepena.rel aimed at the new places
"""
import struct

from pp15.build.relocations import HEADER_FIX_SIZE, encode_stream, parse_imports
from pp15.build.script_emit import SECTION_ALIGN
from pp15.script import scan


class OreRemap:
    """Old section offset -> new one for the My Life script.

    An offset at or past `annex_lo` is in the annex; `annex_lo` stands for the address `base` (see `address`).
    Offsets in the islands (data between script stretches) and outside the script stay where they are.
    """
    growth = 0

    def __init__(self, lo: int, hi: int, newidx: dict, annex_lo: int, base: int, islands=()):
        """lo, hi = byte range of the script; newidx = {old halfword index: new halfword index};
        annex_lo = byte offset where the annex begins; base = its absolute address; islands = [(from, to)]."""
        self.lo, self.hi, self.newidx, self.annex_lo, self.base = lo, hi, newidx, annex_lo, base
        self.islands = islands

    def __call__(self, off: int) -> int:
        if not self.lo <= off < self.hi or any(a <= off < b for a, b in self.islands):
            return off                          # other data, and the islands, stay where they are
        if off % 2 or off // 2 not in self.newidx:
            raise ValueError("reference into the middle of a text run or instruction: 0x%X" % off)
        return self.newidx[off // 2] * 2

    def address(self, new_off: int) -> int | None:
        """Absolute address of a new offset that lies in the annex, else None."""
        return self.base + new_off - self.annex_lo if new_off >= self.annex_lo else None


def ore_chunks(script, a: int, b: int, replacements: dict) -> list:
    """The instructions between section offsets a and b as pieces that can stand anywhere.

    A piece ends with the return or jump that nothing runs past (found by following the nesting of blocks).
    A piece is [(old halfword index or None, [halfwords])].
    """
    hw, chunks, cur, depth, i = script.hw, [], [], 0, a // 2
    while i < b // 2:
        k = script.kind.get(i)
        if k is None:                           # zero padding in front of a label
            i += 1
            continue
        if k == "dead":                         # a return nothing reaches: kept, it closes a piece
            cur.append((None, [hw[i]]))
            chunks.append(cur)
            cur, depth, i = [], 0, i + 1
            continue
        assert k == "op", (script.rel.name, i, k)
        op = hw[i]
        if i in script.texts:
            j = script.texts[i][2]
            cur.append((i, [op] + list(scan.pack_text(replacements[i]) if i in replacements else hw[i + 1:j])))
            i = j
            continue
        n = script._length(i)
        cur.append((i, list(hw[i:i + n])))
        if op == scan.ORE_BLOCK or (op in scan.ORE_IF + (scan.ORE_ELSE,) and hw[i + n - 1] == scan.ORE_BLOCK):
            depth += 1
        elif op == scan.ORE_BLOCK_END:
            depth -= 1
        if op in script.ends and depth == 0:
            chunks.append(cur)
            cur = []
        i += n
    assert not cur, "%s: the script runs into an island at +%d" % (script.rel.name, b)
    return chunks


def emit_ore(script, replacements: dict, base: int, magic=scan.ORE_ANNEX_MAGIC) -> tuple:
    """Lay the My Life script out again.

    Every stretch between two islands keeps the pieces that fit in it, in their order; the others go to the annex.
    `base` = the address of the first halfword of the annex. Returns
    ([(section offset, bytes of the stretch)], annex bytes with its header or b"", OreRemap,
    (pieces kept in place, bytes left in the stretches)).
    """
    newidx, annex, segs, kept, room = {}, [], [], 0, 0
    for a, b in script.segments():
        out, size = [], (b - a) // 2
        for chunk in ore_chunks(script, a, b, replacements):
            n = sum(len(h) for _, h in chunk)
            if len(out) + n <= size:
                at, dest, kept = a // 2 + len(out), out, kept + 1
            else:
                at, dest = script.annex_at + len(annex), annex
            for i, h in chunk:
                if i is not None:
                    newidx[i] = at
                at += len(h)
                dest += h
        room += size - len(out)
        out += [0] * (size - len(out))
        segs.append((a, struct.pack(">%dH" % size, *out)))
    blob = b""
    if annex:
        annex += [0] * (-(len(annex) + 4) % (SECTION_ALIGN // 2))
        blob = struct.pack(">2HI", *magic, base - 8) + struct.pack(">%dH" % len(annex), *annex)
    remap = OreRemap(script.region[0], script.region[1], newidx, script.annex_at * 2, base, script.spec["islands"])
    return segs, blob, remap, (kept, room * 2)


def ore_relocations(module, image: bytes, script, remap: OreRemap) -> tuple[bytes, int]:
    """orepena.rel with its label table aimed at the new places.

    A label in the annex leaves the module's own relocations for those against main.dol (an absolute address);
    both streams lie behind fixSize, so the memory the module needs does not change.
    Returns (image, number of labels in the annex). Raises ValueError if the module is not laid out as expected.
    """
    imports = parse_imports(image, module.imp_off, module.imp_size)
    fix_size = struct.unpack_from(">I", image, HEADER_FIX_SIZE)[0]
    (own_k, own), (dol_k, dol) = [next((k, x) for k, x in enumerate(imports) if x[0] == mod)
                                  for mod in (module.mod_id, 0)]
    if (own_k, dol_k) != (len(imports) - 2, len(imports) - 1) or own[1] != fix_size or own[3] != dol[1] \
            or dol[3] != len(image):
        raise ValueError("%s: unexpected order of the relocation streams" % module.name)
    a, b = script.spec["labels"]
    stay, go = [], []
    for e in own[2]:
        sec, pos, typ, tsec, addend = e[:5]
        if tsec == script.sec and script.region[0] <= addend < script.region[1] and not script.in_island(addend):
            if not (sec == script.sec and typ == 1 and a <= pos < b):
                raise ValueError("%s: sec%d+%d points into the script and is not a label" % (module.name, sec, pos))
            new = remap(addend)
            if remap.address(new) is not None:
                go.append([sec, pos, 1, 4, remap.address(new), 0])      # as the module's other main.dol entries
                continue
            e = [sec, pos, typ, tsec, new, 0]
        stay.append(e)
    order = [e[:2] for e in dol[2]]
    assert order == sorted(order), module.name + ": main.dol relocations are not in order"
    blobs = encode_stream(stay), encode_stream(sorted(dol[2] + go, key=lambda e: e[:2]))
    d = bytearray(image[:own[1]] + blobs[0] + blobs[1])
    struct.pack_into(">II", d, module.imp_off + dol_k * 8, 0, own[1] + len(blobs[0]))
    return bytes(d), len(go)
