"""Rewrite the system dialogs (the blue save and memory notices) that live in the game's main program, main.dol.

What it is for: the DOL is the program the Wii starts (see docs/GLOSSARY.md). A block of about 264 short strings
in it holds the system dialogs, back to back, each closed by 0xFFFF, and relocations of main_prg.rel point at them.
The build lays the block out again inside its original space (a string that no relocation points at keeps its
place, the "fixed" strings), writes the new addresses into the relocations, and re-reads both files to check them.
The original main.dol is kept in _work/orig_sys/ and the built one is installed to DATA/sys.

Public functions:
    load_dol(entries)                          the strings of main.dol with their English (or None)
    build_dol(dol, slots, orig, remaps)        the main.dol image with the block laid out again
    verify_dol(orig, new, dol, slots, ...)     re-read the built file and check it against the original
    encode_dol / decode_dol                    English <-> the units of a dialog string
    layout_dol(strs, units)                    the block bytes and where each string starts
    parse_dol(data)                            the strings of a main.dol image
"""
import bisect
import os
import struct
import sys

from pp15 import config
from pp15.build.relocations import parse_imports
from pp15.build.text_encode import encode_text
from pp15.glyphs import glyph_to_char
from pp15.script import scan
from pp15.script.scan import R_NOP
from pp15.text import strings

DOL = strings.DOL
DOL_BUILT = os.path.join(config.BUILD_DIR, DOL)     # where the build leaves the new main.dol before installing it
DOL_END = 0xFFFF       # closes a dialog string of main.dol, and fills the space the block has left
GLYPH_MASK = 0xFFF     # the low 12 bits of a dialog unit are the glyph number (0x1000 marks it as a glyph)


def encode_dol(en: str, slots: dict) -> list[int]:
    """English of one dialog line -> units: 0x1000 | glyph number, each {} is the control unit
    0x1FFD. Letter pairs start again behind a {}."""
    units = []
    for k, part in enumerate(en.split("{}")):
        if k:
            units.append(strings.DOL_CTRL)
        cells = encode_text(part, slots)
        if scan.TEXT_NEWLINE in cells:
            raise ValueError("a dialog string of %s is one line: %r" % (DOL, en))
        units += [strings.DOL_GLYPH | u for u in cells]
    return units


def decode_dol(units: list[int], slots: dict) -> str:
    """Units of a dialog string -> text, letter pairs spelled out (for checks and listings)."""
    back = {g: pair for pair, g in slots.items()}
    return "".join("{}" if u == strings.DOL_CTRL else
                   back.get(u & GLYPH_MASK) or ("  " if u & GLYPH_MASK == 0 else glyph_to_char(u & GLYPH_MASK) or "?")
                   for u in units)


def parse_dol(data: bytes) -> list[tuple[int, list[int]]]:
    """[(file offset, units)] of the dialog strings in a main.dol image: every run of units that
    0xFFFF closes. Reads nothing but the block, so it also serves to check a built file."""
    a, b = strings.DOL_BLOCK
    hw = struct.unpack_from(">%dH" % ((b - a) // 2), data, a)
    out, start = [], None
    for i, u in enumerate(hw):
        if u != DOL_END:
            start = i if start is None else start
        elif start is not None:
            out.append((a + start * 2, list(hw[start:i])))
            start = None
    if start is not None:
        raise ValueError("the dialog block of %s does not end with 0xFFFF" % DOL)
    return out


def layout_dol(strs: list[dict], units: list[list[int]]) -> tuple[bytes, list[int]]:
    """Re-emit the dialog block. strs = pp15.text.strings.dol_strings(), units = the units of each string.
    The strings follow each other in their original order. A fixed string keeps its file offset;
    the space left in front of it, and at the end of the block, is filled with 0xFFFF.
    Returns (block bytes, [file offset of each string])."""
    a, b = strings.DOL_BLOCK
    out, starts, run = [], [], []

    def fill(limit: int, what: str) -> None:          # the strings since the last fixed one must end at `limit`
        over = (a + len(out) * 2 - limit) // 2
        if over > 0:
            new = ["0:%d" % s["offset"] for s, u in run if u != s["units"]]
            raise ValueError("%s: the dialog strings 0:%d..0:%d (%d in a row) do not fit in front of %s: %d units "
                             "too many. Shorten the translated ones among them by %d cells (%d letters) in all: %s"
                             % (DOL, run[0][0]["offset"], run[-1][0]["offset"], len(run), what, over, over,
                                over * 2, " ".join(new) or "none is translated"))
        out.extend([DOL_END] * -over)

    for s, u in zip(strs, units):
        if s["fixed"]:
            fill(s["offset"], "the fixed string 0:%d" % s["offset"])
            run = []
        run.append((s, u))
        starts.append(a + len(out) * 2)
        out += list(u) + [DOL_END]
    fill(b, "the end of the block")
    return struct.pack(">%dH" % len(out), *out), starts


class DolRemap:
    """Old address -> new address for the dialog strings of main.dol (relocation addends)."""

    def __init__(self, strs, starts):
        self.old = [s["offset"] for s in strs]
        self.new = dict(zip(self.old, starts))

    def __call__(self, addr):
        off = addr - strings.DOL_ADDRESS
        if not strings.DOL_BLOCK[0] <= off < strings.DOL_BLOCK[1]:
            return addr
        start = self.old[bisect.bisect_right(self.old, off) - 1]
        if off != start and self.new[start] != start:
            raise ValueError("reference into the middle of the dialog string 0:%d of %s, which moved" % (start, DOL))
        return addr - start + self.new[start]


def load_dol(entries: list[dict] | None) -> list[tuple[dict, str | None]]:
    """[(string of pp15.text.strings.dol_strings(), English or None)] for all dialog strings of main.dol.
    entries = pp15.text.strings.load_dol_for_build(). Empty when there is no main.dol to work on."""
    if not (os.path.exists(strings.DOL_ORIG) or os.path.exists(strings.DOL_SOURCE)):
        if any(e["en"] is not None for e in entries or []):
            sys.exit("%s has translations but %s is missing" % (DOL, strings.DOL_SOURCE))
        return []
    strs = strings.dol_strings()
    if not entries:
        return [(s, None) for s in strs]
    if [(e["offset"], e["cells"], e["fixed"]) for e in entries] != [(s["offset"], s["cells"], s["fixed"]) for s in strs]:
        sys.exit("%s does not match %s: run `python3 -m pp15 merge-strings`" % (strings.OUT_JSON, DOL))
    # the same rules as `pp15 strings check`, whatever wrote the entries: one line, drawable, the {}
    # of the Japanese, a fixed string within its cells, no line over the longest Japanese one
    longest = max(s["cells"] for s in strs)
    bad = ["%s 0:%d: %s" % (DOL, s["offset"], "; ".join(strings.judge(s, e["en"], longest)[0]))
           for s, e in zip(strs, entries) if e["en"] is not None and strings.judge(s, e["en"], longest)[0]]
    if bad:
        sys.exit("\n".join(bad))
    return [(s, e["en"]) for s, e in zip(strs, entries)]


def build_dol(dol: list, slots: dict, orig: dict, remaps: dict) -> bytes:
    """The main.dol image with the dialog block laid out again. dol = load_dol(). When strings
    moved, their remap is added to `remaps` so that the relocations pointing at them follow."""
    data, (a, b) = strings.dol_data(), strings.DOL_BLOCK
    strs, units = [s for s, _ in dol], []
    for s, en in dol:
        try:
            u = s["units"] if en is None else encode_dol(en, slots)
        except ValueError as e:
            sys.exit("%s 0:%d: %s" % (DOL, s["offset"], e))
        if not u or u.count(strings.DOL_CTRL) != s["ctrl"]:
            sys.exit("%s 0:%d: %r must not be empty and needs %d {} like the Japanese" % (DOL, s["offset"], en, s["ctrl"]))
        if en is not None and (len(u) != strings.dol_cells(en) or (s["fixed"] and len(u) > s["cells"])):
            sys.exit("%s 0:%d: %r takes %d units, `pp15 strings` counts %d and the string holds %d%s"
                     % (DOL, s["offset"], en, len(u), strings.dol_cells(en), s["cells"], " (fixed)" * s["fixed"]))
        units.append(u)
    try:
        block, starts = layout_dol(strs, units)
    except ValueError as e:
        sys.exit(str(e))
    assert len(block) == b - a
    remap = DolRemap(strs, starts)
    moved = sum(s["offset"] != n for s, n in zip(strs, starts))
    targets = set()                 # target "sections" the relocations into the block are filed under
    for m in orig.values():
        for sec, pos, typ, tm, ts, addend in m.relocs():
            if tm == 0 and a <= addend - strings.DOL_ADDRESS < b:
                targets.add(ts)
                try:
                    remap(addend)
                except ValueError as e:
                    sys.exit("%s sec%d+0x%X: %s" % (m.name, sec, pos, e))
    if moved:
        for ts in targets:
            remaps[(0, ts)] = remap
    print("%-13s %5d of %d dialog strings in English, %d moved, %d units of the block left"
          % (DOL, sum(en is not None for _, en in dol), len(dol), moved,
             (b - a) // 2 - sum(len(u) + 1 for u in units)))
    return data[:a] + block + data[b:]


def verify_dol(orig: dict, new: dict, dol: list, slots: dict, relinked=(), dropped=()) -> None:
    """Re-read main.dol as built (or the original when nothing was built) and check it against the
    original file and the relocations of all modules, without the layout: orig, new = the modules
    before and after, as verify() read them from disk."""
    a, b = strings.DOL_BLOCK
    with open(strings.DOL_ORIG, "rb") as f:
        old_d = f.read()
    with open(DOL_BUILT if os.path.exists(DOL_BUILT) else strings.DOL_ORIG, "rb") as f:
        new_d = f.read()
    assert len(old_d) == len(new_d) and old_d[:a] == new_d[:a] and old_d[b:] == new_d[b:], \
        DOL + ": bytes outside the dialog block changed"
    olds, news = parse_dol(old_d), parse_dol(new_d)
    assert len(olds) == len(news) == strings.DOL_STRINGS == len(dol), \
        "%s: the block holds %d strings, not %d" % (DOL, len(news), len(olds))
    for (off, old_u), (pos, new_u), (s, en) in zip(olds, news, dol):
        assert off == s["offset"], (off, s["offset"])
        assert new_u == (old_u if en is None else encode_dol(en, slots)), "%s 0:%d: wrong units at 0x%X" % (DOL, off, pos)
        if en is not None:          # and they read as the English when decoded through the font slots
            assert decode_dol(new_u, slots).replace(" ", "") == en.replace(" ", ""), \
                "%s 0:%d decodes to %r, not %r (a character of it lost its glyph to a letter pair?)" \
                % (DOL, off, decode_dol(new_u, slots), en)
    old_at, new_at = [off for off, _ in olds], [pos for pos, _ in news]
    at_start, inside, count = set(), set(), 0
    for mid, m in orig.items():
        theirs = new[mid].relocs()
        if m.name in relinked:      # relocations changed stream or place: pair them by where they stand
            at = {r[:2]: r for r in theirs}
            theirs = [at[(s, pos)] for (s, pos, typ, tm, ts, ad) in m.relocs() if tm == 0]
            mine = [r for r in m.relocs() if r[3] == 0]
        else:
            mine = [r for r in m.relocs() if (mid, r[0], r[1]) not in dropped]     # dropped: now R_NOP
        for (s, pos, typ, tm, ts, ad), (_, _, typ2, tm2, ts2, ad2) in zip(mine, theirs):
            if tm != 0:
                continue            # relocations against modules: verify()
            where = "%s: relocation sec%d+0x%X" % (m.name, s, pos)
            assert (typ, tm, ts) == (typ2, tm2, ts2), where
            if not a <= ad - strings.DOL_ADDRESS < b:
                assert ad2 == ad, where + " changed, it does not point into the dialog block"
                continue
            i = bisect.bisect_right(old_at, ad - strings.DOL_ADDRESS) - 1
            dist = ad - strings.DOL_ADDRESS - old_at[i]
            assert ad2 - strings.DOL_ADDRESS == new_at[i] + dist, where + " does not point at dialog string %d" % i
            (inside if dist else at_start).add(i)
            count += 1
        # outside its sections (header, relocation tables) a module that was not rebuilt differs
        # from the original in relocation addends only
        if m.name not in scan.SCRIPT_FILES and m.name not in relinked and m.data != new[mid].data:
            assert len(m.data) == len(new[mid].data), m.name + ": size changed"
            image = bytearray(m.data)
            for mod, _, entries, _ in parse_imports(m.data, m.imp_off, m.imp_size):
                for e in entries:
                    if mod == mid and (mid, e[0], e[1]) in dropped:
                        struct.pack_into(">BBI", image, e[5] + 2, R_NOP, 0, 0)
            for _, _, entries, _ in parse_imports(new[mid].data, m.imp_off, m.imp_size):
                for e in entries:
                    struct.pack_into(">I", image, e[5] + 4, e[4])
            other = bytearray(new[mid].data)
            for t in m.sections:
                if t["offset"] and not t["bss"]:
                    image[t["offset"]:t["offset"] + t["size"]] = other[t["offset"]:t["offset"] + t["size"]]
            assert image == other, m.name + ": changes outside sections and relocation addends"
    fixed = [i for i in range(len(olds)) if i not in at_start or i in inside]
    assert all(new_at[i] == old_at[i] for i in fixed), DOL + ": a string without a relocation moved"
    assert fixed == [i for i, (s, _) in enumerate(dol) if s["fixed"]], DOL + ": fixed strings differ from strings.dol_strings()"
    print("Verified: %s is the original outside the dialog block, %d strings, %d relocations point at "
          "their strings, %d fixed strings in place." % (DOL, len(news), count, len(fixed)))
