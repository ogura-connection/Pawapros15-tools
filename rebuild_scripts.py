#!/usr/bin/env python3
"""
rebuild_scripts.py - rebuild the Success Mode scripts with new (longer or shorter) text

Jikkyou Powerful Pro Yakyuu 15 (Wii, RP5JA4, Rev 1). See FINDINGS.md for the format.

Text is stored inline in the scripts, so changing its length moves everything behind it.
This tool re-emits each script region and then fixes every reference to the moved data:

  - relocation addends in ALL modules that point into a rebuilt section (the label tables
    in scs_main.rel, the ADDR16_HA/LO pairs in code, pointers to the tables behind the script)
  - the positions of relocations that are applied inside a rebuilt section
  - the section size, relocation/import table offsets and fixSize in the REL header
  - the module's file size and memory size in moduleID2addr.o (see "Memory plan" below)

Memory plan: the game loads every module at a fixed address. /moduleID2addr.o on the disc holds
three tables (address, memory size, file size) and the game reads exactly "file size" bytes, so
a grown module that is not entered there loads truncated. In the original plan scs_main.rel ends
8 bytes before the scenario modules (scs_sce1/2/3.rel, one slot of 0x5D980 bytes). When that is
not enough the build moves the scenario slot to memory the plan leaves unused
(0x812CB800..0x814E0000, 2.1 MB) and scs_main.rel grows into the old slot (up to +383 KB).
The build stops if a module does not fit even then.

Translation file: a JSON list of entries in the format of _work/story_text.json
(scan_story.py extract --dump) with an added "en" field:
  {"file": "scs_sce1.rel", "section_offset": 25148, "text": "<original>", "en": "New text"}
"file" + "section_offset" identify the run, "text" (optional) is checked against the original,
"en" is the replacement. Use \\n for a line break inside the run. Entries without "en" are ignored.

UI strings (menu and system text in fixed 16-bit slots, see ui_strings.py) come from
_work/strings.json and are written into their slots in place: no size changes, nothing moves.

English is stored two letters per glyph cell (see pair_font.py): every letter pair that occurs
gets a glyph slot of a kanji the remaining Japanese text does not use, and the build draws the
pairs into fonttex2.rel. A dialogue line is 17 cells, so 34 letters. Japanese characters in an
"en" text keep their own cell.

System dialogs (the blue save and memory notices) are in main.dol: one block of strings back to
back, pointed at by relocations of main_prg.rel. The build lays the block out again inside its
original space (a string no relocation points at keeps its place), writes the new addresses into
the relocations and re-reads both files to check them. The original main.dol is kept in
_work/orig_sys/ and the built one is installed to DATA/sys.

Original .rel files and moduleID2addr.o are kept in _work/orig/ (copied from DATA/files on first use, so the first
run must be on unpatched files). Built files are checked in _work/build/ before they are
installed to DATA/files. Both folders are game data: git-ignored, never commit them.
"""

import argparse
import bisect
import collections
import filecmp
import json
import os
import shutil
import struct
import sys

import kyu_names
import pair_font
import scan_story as S
import ui_messages
import ui_strings
from pawapuro15_text_tools import char_to_glyph, glyph_to_char

ORIG_DIR = os.path.join(S.WORK_DIR, "orig")
BUILD_DIR = os.path.join(S.WORK_DIR, "build")
R_NOP, R_SECTION, R_END = S.R_NOP, S.R_SECTION, S.R_END
SECTION_ALIGN = 8      # data behind a script keeps its alignment (REL header align = 8)
LINE_CELLS = 17        # width of the dialogue box (window type 29) in glyph cells
POPUP_WINDOW, POPUP_CELLS = 31, 30   # glossary pop-ups: the original lines run to about 31 cells
PLAN_FILE = "moduleID2addr.o"
# Memory plan. scs_main.rel is followed by the scenario slot, then by scs_load.rel / scs_face.rel.
# The game reserves everything below 0x814E0000 for modules (main.dol 0x8003A938 raises the OS
# arena to it) and its plan ends at 0x812CB794: the area in between is free.
MAIN, SCENARIOS = "scs_main.rel", ("scs_sce1.rel", "scs_sce2.rel", "scs_sce3.rel")
SCENARIO_SLOT = (0x80B5F880, 0x80BBD200)
FREE_AREA = (0x812CB800, 0x814E0000)
# My Life: the scenes that do not fit in orepena.rel go behind the data of ore_work.rel (S.ORE_ANNEX_MODULE),
# which is then loaded here, in the upper part of the free area (the scenario modules use the lower part).
ORE_WORK_ADDR = 0x81400000
DOL = ui_strings.DOL
DOL_BUILT = os.path.join(BUILD_DIR, DOL)
DOL_END = 0xFFFF       # closes a dialog string of main.dol, and fills the space the block has left

# ── English -> glyph units ────────────────────────────────────────────────

def encode_text(text, slots):
    """String -> list of 12-bit units. slots = {letter pair: glyph index}"""
    units = []
    for kind, value in pair_font.text_segments(text):
        if kind == "newline":
            units.append(S.TEXT_NEWLINE)
        elif kind == "pair":
            units.append(0 if value == "  " else slots[value])
        else:
            g = char_to_glyph(value)
            if g is None:
                raise ValueError("no glyph for %r in %r" % (value, text))
            units.append(g)
    return units


# ── REL relocation streams ────────────────────────────────────────────────

def parse_imports(data, imp_off, imp_size):
    """[(target module, stream offset, entries, stream end)], entries =
    [section, position, type, target section, addend, file offset of the entry]"""
    out = []
    for k in range(imp_size // 8):
        mod, off = struct.unpack_from(">II", data, imp_off + k * 8)
        start, sec, pos, entries = off, 0, 0, []
        while True:
            delta, typ, tsec, addend = struct.unpack_from(">HBBI", data, off)
            off += 8
            pos += delta
            if typ == R_END:
                break
            if typ == R_SECTION:
                sec, pos = tsec, 0
            elif typ != R_NOP:
                entries.append([sec, pos, typ, tsec, addend, off - 8])
        out.append((mod, start, entries, off))
    return out


def encode_stream(entries):
    out, cur_sec, cur = [], None, 0
    for sec, pos, typ, tsec, addend, _ in entries:
        if sec != cur_sec:
            out.append(struct.pack(">HBBI", 0, R_SECTION, sec, 0))
            cur_sec, cur = sec, 0
        delta = pos - cur
        assert delta >= 0, "relocations out of order"
        while delta > 0xFFFF:
            out.append(struct.pack(">HBBI", 0xFFFF, R_NOP, 0, 0))
            delta -= 0xFFFF
        out.append(struct.pack(">HBBI", delta, typ, tsec, addend))
        cur = pos
    out.append(struct.pack(">HBBI", 0, R_END, 0, 0))
    return b"".join(out)


# ── Script re-emission ────────────────────────────────────────────────────

class Remap:
    """Old section offset -> new section offset for one rebuilt script section."""

    def __init__(self, lo, hi, newidx, growth):
        self.lo, self.hi, self.newidx, self.growth = lo * 2, hi * 2, newidx, growth

    def __call__(self, off):
        if off < self.lo:
            return off
        if off >= self.hi:
            return off + self.growth
        if off % 2 or off // 2 not in self.newidx:
            raise ValueError("reference into the middle of a text run or instruction: 0x%X" % off)
        return self.newidx[off // 2] * 2


def emit_script(sc, repl, pad=0):
    """Re-emit one script section. repl = {halfword index of the text instruction: units}.
    Returns (section bytes, Remap). pad = extra zero bytes at the end (memory headroom tests)."""
    hw = sc.hw
    lo, hi = min(sc.kind), max(sc.kind) + 1
    out, newidx, i = list(hw[:lo]), {}, lo
    while i < hi:
        newidx[i] = len(out)
        out.append(hw[i])
        if i in sc.texts:
            _, _, j = sc.texts[i]
            out += S.pack_text(repl[i]) if i in repl else hw[i + 1:j]
            i = j
        else:
            i += 1
    while (len(out) - hi) * 2 % SECTION_ALIGN:
        out.append(0)
    growth = (len(out) - hi) * 2
    out += hw[hi:]
    data = struct.pack(">%dH" % len(out), *out) + b"\0" * pad
    return data, Remap(lo, hi, newidx, growth)


class BlockRemap:
    """Old section offset -> new one for a script laid out again inside its own space (S.BlockScript)."""
    growth = 0

    def __init__(self, lo, hi, newidx):
        self.lo, self.hi, self.newidx = lo, hi, newidx

    def __call__(self, off):
        if not self.lo <= off < self.hi:
            return off
        if off % 2 or off // 2 not in self.newidx:
            raise ValueError("reference into the middle of a text run or instruction: 0x%X" % off)
        return self.newidx[off // 2] * 2


def emit_block(sc, repl):
    """Lay a block script out again in the bytes it has: the zero padding in front of the labels is given
    up (the Success scripts run without that alignment since their first rebuild) and collected at the end.
    Returns (bytes of the region, BlockRemap); stops if the English needs more than the padding gives."""
    hw = sc.hw
    lo, hi = sc.region[0] // 2, sc.region[1] // 2
    out, newidx, i = [], {}, lo
    while i < hi:
        k = sc.kind.get(i)
        if k is None:
            i += 1
            continue
        if k == "op":
            newidx[i] = lo + len(out)
        out.append(hw[i])
        if i in sc.texts:
            _, _, j = sc.texts[i]
            out += S.pack_text(repl[i]) if i in repl else hw[i + 1:j]
            i = j
        else:
            i += 1
    room = hi - lo - len(out)
    if room < 0:
        sys.exit("%s: the script is %d bytes too long for its place (%d bytes); shorten some lines."
                 % (sc.rel.name, -room * 2, (hi - lo) * 2))
    out += [0] * room
    return struct.pack(">%dH" % len(out), *out), BlockRemap(lo * 2, hi * 2, newidx), room * 2


class OreRemap:
    """Old section offset -> new one for the My Life script. An offset at or past annex_lo is in the annex:
    annex_lo stands for the address `base`."""
    growth = 0

    def __init__(self, lo, hi, newidx, annex_lo, base, islands=()):
        self.lo, self.hi, self.newidx, self.annex_lo, self.base = lo, hi, newidx, annex_lo, base
        self.islands = islands

    def __call__(self, off):
        if not self.lo <= off < self.hi or any(a <= off < b for a, b in self.islands):
            return off                          # other data, and the islands, stay where they are
        if off % 2 or off // 2 not in self.newidx:
            raise ValueError("reference into the middle of a text run or instruction: 0x%X" % off)
        return self.newidx[off // 2] * 2

    def address(self, new_off):
        """Absolute address of a new offset that lies in the annex, else None."""
        return self.base + new_off - self.annex_lo if new_off >= self.annex_lo else None


def ore_chunks(sc, a, b, repl):
    """The instructions between section offsets a and b as pieces that can stand anywhere: a piece ends with
    the return or jump that nothing runs past. A piece is [(old halfword index or None, [halfwords])]."""
    hw, chunks, cur, depth, i = sc.hw, [], [], 0, a // 2
    while i < b // 2:
        k = sc.kind.get(i)
        if k is None:                           # zero padding in front of a label
            i += 1
            continue
        if k == "dead":                         # a return nothing reaches: kept, it closes a piece
            cur.append((None, [hw[i]]))
            chunks.append(cur)
            cur, depth, i = [], 0, i + 1
            continue
        assert k == "op", (sc.rel.name, i, k)
        op = hw[i]
        if i in sc.texts:
            j = sc.texts[i][2]
            cur.append((i, [op] + list(S.pack_text(repl[i]) if i in repl else hw[i + 1:j])))
            i = j
            continue
        n = sc._length(i)
        cur.append((i, list(hw[i:i + n])))
        if op == S.ORE_BLOCK or (op in S.ORE_IF + (S.ORE_ELSE,) and hw[i + n - 1] == S.ORE_BLOCK):
            depth += 1
        elif op == S.ORE_BLOCK_END:
            depth -= 1
        if op in sc.ends and depth == 0:
            chunks.append(cur)
            cur = []
        i += n
    assert not cur, "%s: the script runs into an island at +%d" % (sc.rel.name, b)
    return chunks


def emit_ore(sc, repl, base):
    """Lay the My Life script out again: every stretch between two islands keeps the pieces that fit in it,
    in their order, and the others go to the annex. base = address of the first halfword of the annex.
    Returns ([(section offset, bytes of the stretch)], annex bytes with its header or b"", OreRemap, notes)."""
    newidx, annex, segs, kept, room = {}, [], [], 0, 0
    for a, b in sc.segments():
        out, size = [], (b - a) // 2
        for chunk in ore_chunks(sc, a, b, repl):
            n = sum(len(h) for _, h in chunk)
            if len(out) + n <= size:
                at, dest, kept = a // 2 + len(out), out, kept + 1
            else:
                at, dest = sc.annex_at + len(annex), annex
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
        blob = struct.pack(">2HI", *S.ORE_ANNEX_MAGIC, base - 8) + struct.pack(">%dH" % len(annex), *annex)
    remap = OreRemap(sc.region[0], sc.region[1], newidx, sc.annex_at * 2, base, sc.spec["islands"])
    return segs, blob, remap, (kept, room * 2)


def ore_relocations(m, image, sc, remap):
    """orepena.rel with its label table aimed at the new places. A label in the annex leaves the module's own
    relocations for those against main.dol (an absolute address); both streams lie behind fixSize, so the
    memory the module needs does not change. Returns (image, labels in the annex)."""
    imports = parse_imports(image, m.imp_off, m.imp_size)
    fix_size = struct.unpack_from(">I", image, 0x48)[0]
    (own_k, own), (dol_k, dol) = [next((k, x) for k, x in enumerate(imports) if x[0] == mod) for mod in (m.mod_id, 0)]
    if (own_k, dol_k) != (len(imports) - 2, len(imports) - 1) or own[1] != fix_size or own[3] != dol[1] \
            or dol[3] != len(image):
        raise ValueError("%s: unexpected order of the relocation streams" % m.name)
    a, b = sc.spec["labels"]
    stay, go = [], []
    for e in own[2]:
        sec, pos, typ, tsec, addend = e[:5]
        if tsec == sc.sec and sc.region[0] <= addend < sc.region[1] and not sc.in_island(addend):
            if not (sec == sc.sec and typ == 1 and a <= pos < b):
                raise ValueError("%s: sec%d+%d points into the script and is not a label" % (m.name, sec, pos))
            new = remap(addend)
            if remap.address(new) is not None:
                go.append([sec, pos, 1, 4, remap.address(new), 0])      # as the module's other main.dol entries
                continue
            e = [sec, pos, typ, tsec, new, 0]
        stay.append(e)
    order = [e[:2] for e in dol[2]]
    assert order == sorted(order), m.name + ": main.dol relocations are not in order"
    blobs = encode_stream(stay), encode_stream(sorted(dol[2] + go, key=lambda e: e[:2]))
    d = bytearray(image[:own[1]] + blobs[0] + blobs[1])
    struct.pack_into(">II", d, m.imp_off + dol_k * 8, 0, own[1] + len(blobs[0]))
    return bytes(d), len(go)


def plan_index(plan, image):
    """The row of a module in the memory plan (found by its file size and the memory it needs)."""
    t_addr, t_size, t_file, n = plan_tables(plan)
    hits = [i for i in range(n) if struct.unpack_from(">I", plan, t_file + i * 4)[0] == len(image)
            and struct.unpack_from(">I", plan, t_size + i * 4)[0] == memory_size(image)]
    if len(hits) != 1:
        raise ValueError("a module is not in the memory plan, or twice (%d rows)" % len(hits))
    return hits[0]


def update_plan_ore(plan, orig_plan, changes):
    """changes = {name: (original image, new image, new address or None)}: the My Life modules. Returns the plan."""
    d = bytearray(plan)
    t_addr, t_size, t_file, n = plan_tables(plan)
    for name, (old, new, addr) in changes.items():
        i = plan_index(orig_plan, old)
        struct.pack_into(">I", d, t_file + i * 4, len(new))
        if addr is None:
            if memory_size(new) != memory_size(old):
                sys.exit("%s would need another amount of memory; it cannot grow." % name)
            continue
        end = addr + memory_size(new)
        for k in range(n):                  # nothing else may reach into the place (the scenario modules do not)
            a2, s2 = (struct.unpack_from(">I", d, t + k * 4)[0] for t in (t_addr, t_size))
            if k != i and s2 and a2 < end and a2 + s2 > addr:
                sys.exit("%s at 0x%08X would share memory with module row %d of the plan (0x%08X..0x%08X)."
                         % (name, addr, k, a2, a2 + s2))
        if end > FREE_AREA[1]:
            sys.exit("%s does not fit in the free memory: it ends at 0x%08X, the limit is 0x%08X (%d bytes "
                     "too many)." % (name, end, FREE_AREA[1], end - FREE_AREA[1]))
        struct.pack_into(">I", d, t_addr + i * 4, addr)
        struct.pack_into(">I", d, t_size + i * 4, memory_size(new))
        print("  %-13s 0x%08X..0x%08X, %d KB of room left" % (name, addr, end, (FREE_AREA[1] - end) // 1024))
    return bytes(d)


# ── Memory plan (moduleID2addr.o) ─────────────────────────────────────────

def plan_tables(d):
    """File offsets of the three tables in the ELF object and their entry count."""
    shoff = struct.unpack_from(">I", d, 0x20)[0]
    shentsize, shnum = struct.unpack_from(">HH", d, 0x2E)
    secs = [struct.unpack_from(">10I", d, shoff + i * shentsize) for i in range(shnum)]
    symtab = next(s for s in secs if s[1] == 2)
    strtab = secs[symtab[6]][4]
    out = {}
    for k in range(symtab[5] // 16):
        name, value, size, _, _, shndx = struct.unpack_from(">IIIBBH", d, symtab[4] + k * 16)
        name = d[strtab + name:d.index(b"\0", strtab + name)].decode()
        if name.startswith("moduleID2") and shndx < shnum:
            out[name] = (secs[shndx][4] + value, size // 4)
    return out["moduleID2addr"][0], out["moduleID2size"][0], out["moduleID2relFileSize"][0], out["moduleID2addr"][1]


def memory_size(image):
    """Memory a module needs once linked: the part kept after linking, then its BSS."""
    bss_size, bss_align, fix_size = (struct.unpack_from(">I", image, o)[0] for o in (0x20, 0x44, 0x48))
    return (fix_size + bss_align - 1) // bss_align * bss_align + bss_size


def update_plan(plan, images):
    """images = {name: (original image, new image)} for the four script modules.
    Returns the new moduleID2addr.o."""
    d = bytearray(plan)
    t_addr, t_size, t_file, n = plan_tables(plan)
    index = {}
    for name, (old, _) in images.items():
        hits = [i for i in range(n) if struct.unpack_from(">I", plan, t_file + i * 4)[0] == len(old)
                and struct.unpack_from(">I", plan, t_size + i * 4)[0] == memory_size(old)]
        if len(hits) != 1:
            raise ValueError("%s: not found in the memory plan" % name)
        index[name] = hits[0]
    addr = {name: struct.unpack_from(">I", plan, t_addr + i * 4)[0] for name, i in index.items()}
    need = {name: memory_size(new) for name, (_, new) in images.items()}
    if addr[MAIN] + need[MAIN] > SCENARIO_SLOT[0] or \
            max(need[fn] for fn in SCENARIOS) > SCENARIO_SLOT[1] - SCENARIO_SLOT[0]:
        for fn in SCENARIOS:
            addr[fn] = FREE_AREA[0]
        print("  memory plan: scenario modules moved to 0x%08X, scs_main.rel may use their old slot" % FREE_AREA[0])
        limit = {MAIN: SCENARIO_SLOT[1], **{fn: FREE_AREA[1] for fn in SCENARIOS}}
    else:
        limit = {MAIN: SCENARIO_SLOT[0], **{fn: SCENARIO_SLOT[1] for fn in SCENARIOS}}
    for name, (old, new) in images.items():
        i, end = index[name], addr[name] + need[name]
        struct.pack_into(">I", d, t_addr + i * 4, addr[name])
        struct.pack_into(">I", d, t_size + i * 4, need[name])
        struct.pack_into(">I", d, t_file + i * 4, len(new))
        if end > limit[name]:
            sys.exit("%s does not fit in memory: it needs 0x%X bytes at 0x%08X, the limit is 0x%08X "
                     "(%d bytes too many)." % (name, need[name], addr[name], limit[name], end - limit[name]))
        if old != new:
            print("  %-13s 0x%08X..0x%08X, %d KB of room left" % (name, addr[name], end, (limit[name] - end) // 1024))
    return bytes(d)


# ── System dialogs of main.dol ────────────────────────────────────────────

def encode_dol(en, slots):
    """English of one dialog line -> units: 0x1000 | glyph number, each {} is the control unit
    0x1FFD. Letter pairs start again behind a {}."""
    units = []
    for k, part in enumerate(en.split("{}")):
        if k:
            units.append(ui_strings.DOL_CTRL)
        cells = encode_text(part, slots)
        if S.TEXT_NEWLINE in cells:
            raise ValueError("a dialog string of %s is one line: %r" % (DOL, en))
        units += [ui_strings.DOL_GLYPH | u for u in cells]
    return units


def decode_dol(units, slots):
    """Units of a dialog string -> text, letter pairs spelled out (for checks and listings)."""
    back = {g: pair for pair, g in slots.items()}
    return "".join("{}" if u == ui_strings.DOL_CTRL else
                   back.get(u & 0xFFF) or ("  " if u & 0xFFF == 0 else glyph_to_char(u & 0xFFF) or "?")
                   for u in units)


def parse_dol(data):
    """[(file offset, units)] of the dialog strings in a main.dol image: every run of units that
    0xFFFF closes. Reads nothing but the block, so it also serves to check a built file."""
    a, b = ui_strings.DOL_BLOCK
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


def layout_dol(strs, units):
    """Re-emit the dialog block. strs = ui_strings.dol_strings(), units = the units of each string.
    The strings follow each other in their original order. A fixed string keeps its file offset;
    the space left in front of it, and at the end of the block, is filled with 0xFFFF.
    Returns (block bytes, [file offset of each string])."""
    a, b = ui_strings.DOL_BLOCK
    out, starts, run = [], [], []

    def fill(limit, what):          # the strings since the last fixed one must end at `limit`
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
        off = addr - ui_strings.DOL_ADDRESS
        if not ui_strings.DOL_BLOCK[0] <= off < ui_strings.DOL_BLOCK[1]:
            return addr
        start = self.old[bisect.bisect_right(self.old, off) - 1]
        if off != start and self.new[start] != start:
            raise ValueError("reference into the middle of the dialog string 0:%d of %s, which moved" % (start, DOL))
        return addr - start + self.new[start]


def load_dol(entries):
    """[(string of ui_strings.dol_strings(), English or None)] for all dialog strings of main.dol.
    entries = ui_strings.load_dol_for_build(). Empty when there is no main.dol to work on."""
    if not (os.path.exists(ui_strings.DOL_ORIG) or os.path.exists(ui_strings.DOL_SOURCE)):
        if any(e["en"] is not None for e in entries or []):
            sys.exit("%s has translations but %s is missing" % (DOL, ui_strings.DOL_SOURCE))
        return []
    strs = ui_strings.dol_strings()
    if not entries:
        return [(s, None) for s in strs]
    if [(e["offset"], e["cells"], e["fixed"]) for e in entries] != [(s["offset"], s["cells"], s["fixed"]) for s in strs]:
        sys.exit("%s does not match %s: run ui_strings.py merge" % (ui_strings.OUT_JSON, DOL))
    # the same rules as ui_strings.py check, whatever wrote the entries: one line, drawable, the {}
    # of the Japanese, a fixed string within its cells, no line over the longest Japanese one
    longest = max(s["cells"] for s in strs)
    bad = ["%s 0:%d: %s" % (DOL, s["offset"], "; ".join(ui_strings.judge(s, e["en"], longest)[0]))
           for s, e in zip(strs, entries) if e["en"] is not None and ui_strings.judge(s, e["en"], longest)[0]]
    if bad:
        sys.exit("\n".join(bad))
    return [(s, e["en"]) for s, e in zip(strs, entries)]


def build_dol(dol, slots, orig, remaps):
    """The main.dol image with the dialog block laid out again. dol = load_dol(). When strings
    moved, their remap is added to `remaps` so that the relocations pointing at them follow."""
    data, (a, b) = ui_strings.dol_data(), ui_strings.DOL_BLOCK
    strs, units = [s for s, _ in dol], []
    for s, en in dol:
        try:
            u = s["units"] if en is None else encode_dol(en, slots)
        except ValueError as e:
            sys.exit("%s 0:%d: %s" % (DOL, s["offset"], e))
        if not u or u.count(ui_strings.DOL_CTRL) != s["ctrl"]:
            sys.exit("%s 0:%d: %r must not be empty and needs %d {} like the Japanese" % (DOL, s["offset"], en, s["ctrl"]))
        if en is not None and (len(u) != ui_strings.dol_cells(en) or (s["fixed"] and len(u) > s["cells"])):
            sys.exit("%s 0:%d: %r takes %d units, ui_strings.py counts %d and the string holds %d%s"
                     % (DOL, s["offset"], en, len(u), ui_strings.dol_cells(en), s["cells"], " (fixed)" * s["fixed"]))
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
            if tm == 0 and a <= addend - ui_strings.DOL_ADDRESS < b:
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


def verify_dol(orig, new, dol, slots, relinked=()):
    """Re-read main.dol as built (or the original when nothing was built) and check it against the
    original file and the relocations of all modules, without the layout: orig, new = the modules
    before and after, as verify() read them from disk."""
    a, b = ui_strings.DOL_BLOCK
    with open(ui_strings.DOL_ORIG, "rb") as f:
        old_d = f.read()
    with open(DOL_BUILT if os.path.exists(DOL_BUILT) else ui_strings.DOL_ORIG, "rb") as f:
        new_d = f.read()
    assert len(old_d) == len(new_d) and old_d[:a] == new_d[:a] and old_d[b:] == new_d[b:], \
        DOL + ": bytes outside the dialog block changed"
    olds, news = parse_dol(old_d), parse_dol(new_d)
    assert len(olds) == len(news) == ui_strings.DOL_STRINGS == len(dol), \
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
            at = {(s2, remap_pos): r for r in theirs for s2, remap_pos in [r[:2]]}
            theirs = [at[(s, pos)] for (s, pos, typ, tm, ts, ad) in m.relocs() if tm == 0]
            mine = [r for r in m.relocs() if r[3] == 0]
        else:
            mine = m.relocs()
        for (s, pos, typ, tm, ts, ad), (_, _, typ2, tm2, ts2, ad2) in zip(mine, theirs):
            if tm != 0:
                continue            # relocations against modules: verify()
            where = "%s: relocation sec%d+0x%X" % (m.name, s, pos)
            assert (typ, tm, ts) == (typ2, tm2, ts2), where
            if not a <= ad - ui_strings.DOL_ADDRESS < b:
                assert ad2 == ad, where + " changed, it does not point into the dialog block"
                continue
            i = bisect.bisect_right(old_at, ad - ui_strings.DOL_ADDRESS) - 1
            dist = ad - ui_strings.DOL_ADDRESS - old_at[i]
            assert ad2 - ui_strings.DOL_ADDRESS == new_at[i] + dist, where + " does not point at dialog string %d" % i
            (inside if dist else at_start).add(i)
            count += 1
        # outside its sections (header, relocation tables) a module that was not rebuilt differs
        # from the original in relocation addends only
        if m.name not in S.SCRIPT_FILES and m.name not in relinked and m.data != new[mid].data:
            assert len(m.data) == len(new[mid].data), m.name + ": size changed"
            image = bytearray(m.data)
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
    assert fixed == [i for i, (s, _) in enumerate(dol) if s["fixed"]], DOL + ": fixed strings differ from ui_strings"
    print("Verified: %s is the original outside the dialog block, %d strings, %d relocations point at "
          "their strings, %d fixed strings in place." % (DOL, len(news), count, len(fixed)))


# ── Build ─────────────────────────────────────────────────────────────────

def ensure_orig():
    if not os.path.isdir(ORIG_DIR):
        os.makedirs(ORIG_DIR)
        print("Saving the original files to %s" % ORIG_DIR)
    for fn in sorted(os.listdir(S.DATA_FILES)):
        if (fn.endswith(".rel") or fn == PLAN_FILE) and not os.path.exists(os.path.join(ORIG_DIR, fn)):
            shutil.copy2(os.path.join(S.DATA_FILES, fn), os.path.join(ORIG_DIR, fn))


def load_dir(*dirs):
    """Load every module, later directories overriding earlier ones. {module id: Rel}"""
    paths = {}
    for d in dirs:
        for fn in os.listdir(d):
            if fn.endswith(".rel"):
                paths[fn] = os.path.join(d, fn)
    mods = {}
    for fn in sorted(paths):
        r = S.Rel(paths[fn])
        mods[r.mod_id] = r
    return mods


def load_scripts(mods, remaps=None):
    """Parse the four script modules. remaps: the label tables have moved (rebuilt files)."""
    by_name = {m.name: m for m in mods.values()}
    main = by_name["scs_main.rel"]
    move = (remaps or {}).get((main.mod_id, main.script_section()), lambda off: off)
    tables = tuple(move(off) for off in S.LABEL_TABLES)
    return [S.Script(by_name[fn], mods, tables) for fn in S.SCRIPT_FILES]


def rebuild_module(rel, sec, new_sec, remaps):
    """New file image for a module whose section `sec` was re-emitted."""
    d = rel.data
    s = rel.sections[sec]
    sec_end = s["offset"] + s["size"]
    later = [t for t in rel.sections if t["offset"] > s["offset"]]
    if later or not sec_end <= rel.imp_off < sec_end + 32 or rel.imp_off + rel.imp_size != rel.rel_off:
        raise ValueError("%s: unexpected file layout" % rel.name)
    imports = parse_imports(d, rel.imp_off, rel.imp_size)
    spans = sorted((start, end) for _, start, _, end in imports)
    if spans[0][0] != rel.rel_off or any(a[1] != b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError("%s: relocation streams are not contiguous" % rel.name)
    tail = d[spans[-1][1]:]
    sec_table, fix_size = struct.unpack_from(">I", d, 0x10)[0], struct.unpack_from(">I", d, 0x48)[0]

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
    struct.pack_into(">II", head, 0x24, rel_off, imp_off)
    struct.pack_into(">I", head, 0x48, new_fix)
    return bytes(head) + b"".join(table) + b"".join(streams) + tail


def patch_addends(rel, remaps, image=None):
    """Other modules: addends that point into a rebuilt section, patched in place.
    image = the module as built so far, when its relocation tables have not moved."""
    d, n = bytearray(image if image is not None else rel.data), 0
    for mod, _, entries, _ in parse_imports(bytes(d), rel.imp_off, rel.imp_size):
        for sec, pos, typ, tsec, addend, off in entries:
            if (mod, tsec) in remaps:
                new = remaps[(mod, tsec)](addend)
                if new != addend:
                    struct.pack_into(">I", d, off + 4, new)
                    n += 1
    return bytes(d), n


def load_translation(path, scripts):
    """{module name: {halfword index: new text}}"""
    by_name = {sc.rel.name: sc for sc in scripts}
    texts = collections.defaultdict(dict)
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)
    for e in entries:
        if e.get("en") is None:
            continue
        sc = by_name.get(e["file"])
        i = e["section_offset"] // 2
        if sc is None or e["section_offset"] % 2 or i not in sc.texts:
            sys.exit("%s +0x%X: not a text run" % (e["file"], e["section_offset"]))
        old = S.decode_units(sc.texts[i][1])
        if "text" in e and e["text"] != old:
            sys.exit("%s +0x%X: original text is %r, the translation file says %r"
                     % (e["file"], e["section_offset"], old, e["text"]))
        texts[e["file"]][i] = e["en"]
        cells, line = 0, 0
        for kind, _ in pair_font.text_segments(e["en"]):
            line = 0 if kind == "newline" else line + 1
            cells = max(cells, line)
        limit = sc.spec["line"] if hasattr(sc, "spec") else POPUP_CELLS if sc.texts[i][0] == POPUP_WINDOW else LINE_CELLS
        if cells > limit:
            print("warning: %s +0x%X is %d cells wide, the line holds %d (%d letters): %r"
                  % (e["file"], e["section_offset"], cells, limit, limit * 2, e["en"]))
    return texts


def assign_pairs(scripts, texts, orig, strings=None, dol=None, messages=None):
    """Choose a glyph slot for every letter pair in the translation. Returns {pair: glyph index}.
    dol = load_dol(): the dialog strings of main.dol with their English."""
    pairs, usage = set(), collections.Counter()
    for msgs in (messages or {}).values():      # message scripts: the pairs start again in every piece
        for _, pieces in msgs.values():
            for en in pieces:
                for kind, value in pair_font.text_segments(en):
                    if kind == "pair" and value != "  ":
                        pairs.add(value)
                    elif kind == "char":
                        usage[char_to_glyph(value)] += 1
    for s, en in dol or []:
        if en is None:              # stays Japanese: its glyphs are in use (units are 0x1000 | glyph)
            usage.update(u & 0xFFF for u in s["units"] if u != ui_strings.DOL_CTRL and u & 0xFFF)
            continue
        for part in en.split("{}"):
            for kind, value in pair_font.text_segments(part):
                if kind == "pair" and value != "  ":
                    pairs.add(value)
                elif kind == "char":
                    usage[char_to_glyph(value)] += 1
    for name, slots_ in (strings or {}).items():
        for _, en in slots_.values():
            for kind, value in (seg for _, part in ui_strings.colour_runs(en) for seg in pair_font.text_segments(part)):
                if kind == "pair" and value != "  ":
                    pairs.add(value)
                elif kind == "char":
                    usage[char_to_glyph(value)] += 1
    for sc in scripts:              # the string tables of the script modules that stay Japanese
        if hasattr(sc, "spec"):     # a block script's module is counted with the other modules, below
            continue
        idx = sorted(sc.kind)
        done = (strings or {}).get(sc.rel.name, {})
        for st in ui_strings.find(sc.rel, (sc.sec, idx[0] * 2, (idx[-1] + 1) * 2)):
            if (st["section"], st["offset"]) not in done:
                usage.update(u & 0xFFF if u > S.MAX_GLYPH else u for u in st["units"] if u & 0xFFF)
    for sc in scripts:
        new = texts.get(sc.rel.name, {})
        for i, (_, units, _) in sc.texts.items():
            if i not in new:
                if not hasattr(sc, "spec"):
                    usage.update(units)
                continue
            for kind, value in pair_font.text_segments(new[i]):
                if kind == "pair" and value != "  ":
                    pairs.add(value)
                elif kind == "char":
                    usage[char_to_glyph(value)] += 1
    if not pairs:
        return {}
    # namein.rel is the name-entry kanji picker: it lists every kanji once and is not text
    usage.update(pair_font.other_text_usage(orig, set(S.SCRIPT_FILES) | {"fonttex2.rel", "namein.rel"}))
    names = pair_font.name_usage(orig, {"fonttex2.rel", "namein.rel"})      # team-mates, real players
    slots, taken, lost = pair_font.allocate(pairs, usage, names)
    print("Font: %d letter pairs in %d kanji slots (%d slots left)%s%s"
          % (len(slots), len(slots), len(pair_font.KANJI_SLOTS) - len(slots),
             "" if not taken else "; %d of them are kanji that Japanese text elsewhere still uses" % taken,
             "; all %d kanji of the name tables are kept" % len(names) if not lost else
             "; %d of the %d kanji of the name tables are LOST" % (lost, len(names))))
    return slots


def build_font_file(orig, slots):
    """fonttex2.rel with the pair glyphs. The file keeps its size."""
    rel = next(m for m in orig.values() if m.name == "fonttex2.rel")
    cache_path, cache = os.path.join(S.WORK_DIR, "pair_glyphs.json"), {}
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            cache = json.load(f)
    known = len(cache)
    image = pair_font.build_font(rel.data, rel.sections[4]["offset"], {g: p for p, g in slots.items()}, cache)
    if len(cache) != known:
        with open(cache_path, "w") as f:
            json.dump(cache, f)
    sec4 = image[rel.sections[4]["offset"]:]
    for name, pos, _ in pair_font.FONTS:                       # read it back
        old = pair_font.font_glyphs(rel.sec_data(4), pos)
        new = pair_font.font_glyphs(sec4, pos)
        for pair, g in slots.items():
            assert new[g] == pair_font.pair_glyph(pair, name == "large", cache), pair
        assert all(a == b for g, (a, b) in enumerate(zip(old, new)) if g not in set(slots.values())), name
    assert len(image) == len(rel.data)
    return image


def encode_string(en, cells, slots):
    """An English UI string as the bytes of its slot: glyph numbers, padded with glyph 0. A run written
    {c:...} (ui_strings.colour_runs) gets colour c in the top four bits of each of its units."""
    units = []
    for colour, part in ui_strings.colour_runs(en):
        units += [u | colour << 12 for u in encode_text(part, slots)] if colour else encode_text(part, slots)
    if S.TEXT_NEWLINE in units or len(units) > cells:
        raise ValueError("%r does not fit a slot of %d cells (no line breaks)" % (en, cells))
    return struct.pack(">%dH" % cells, *(units + [0] * (cells - len(units))))


def layout_block(m, blk, english, slots):
    """A block of movable strings (ui_strings.BLOCKS) laid out again: (the bytes of the block,
    {position of a pointer in its section: new addend}, {new addend: the units it must read}).
    english = {(section, offset): (cells, text)}; a string without English keeps its Japanese."""
    sec, start, end = blk["section"], blk["start"], blk["end"]
    table = {pos: addend for s, pos, typ, mod, tsec, addend in m.relocs()
             if s == sec and blk["table"] <= pos < blk["table"] + 4 * blk["count"]
             and (typ, mod, tsec) == (1, m.mod_id, sec)}                      # R_PPC_ADDR32 into the block
    if len(table) != blk["count"] or len(set(table.values())) != len(table) \
            or not all(start <= a < end for a in table.values()):
        sys.exit("%s: the pointer table at sec%d+%d is not as expected" % (m.name, sec, blk["table"]))
    hw = struct.unpack(">%dH" % ((end - start) // 2), m.sec_data(sec)[start:end])
    seqs = []
    for pos in sorted(table):
        old = table[pos]
        if (sec, old) in english:
            units = encode_text(english[(sec, old)][1], slots)
            if S.TEXT_NEWLINE in units or len(units) > blk["max"]:
                sys.exit("%s %d:%d: %r is not one line of %d cells" % (m.name, sec, old, english[(sec, old)][1], blk["max"]))
        else:
            i = (old - start) // 2
            units = list(hw[i:hw.index(0xFFFF, i)])
        seqs.append(tuple(units))
    starts, used = ui_strings.block_layout(seqs)
    if used > len(hw):
        sys.exit("%s: the strings at sec%d+%d need %d cells, the block has %d" % (m.name, sec, start, used, len(hw)))
    out = [0] * len(hw)
    for a, units in zip(starts, seqs):
        out[a:a + len(units) + 1] = list(units) + [0xFFFF]
    addends = {pos: start + 2 * a for pos, a in zip(sorted(table), starts)}
    return struct.pack(">%dH" % len(out), *out), addends, {start + 2 * a: u for a, u in zip(starts, seqs)}


def build(texts, pad=None, strings=None, dol=None, messages=None):
    """Build every changed module, and main.dol, into _work/build/. Returns the list of file names.
    dol = ui_strings.load_dol_for_build(), messages = ui_messages.load_for_build()."""
    orig = load_dir(ORIG_DIR)
    scripts = load_scripts(orig)
    strings = strings or {}
    messages = messages or {}
    kyu_english = kyu_names.load_tsv()
    dol = load_dol(dol)
    for sc in scripts:
        if sc.errors or len(sc.hw) * 2 != sc.rel.sections[sc.sec]["size"]:
            sys.exit("%s: script does not parse cleanly, not rebuilding" % sc.rel.name)
    blocks = S.load_block_scripts(orig)         # scripts of the other modes: laid out again in place
    for sc in blocks:
        if sc.errors:
            sys.exit("%s: script does not parse cleanly, not rebuilding" % sc.rel.name)
    slots = assign_pairs(scripts + blocks, texts, orig, strings, dol, messages)
    patched = {}                    # module id -> {(section, old offset): new bytes}
    moved = {}                      # (module id, section, position of a relocation) -> new addend
    repl = {name: {i: encode_text(t, slots) for i, t in runs.items()} for name, runs in texts.items()}
    remaps, new_secs = {}, {}
    inplace, block_data, ore, extra_images = {}, {}, None, {}
    for sc in blocks:
        r = repl.get(sc.rel.name, {})
        if not r:
            continue
        if sc.spec.get("engine") == "ore":      # My Life: laid out again in place, the overflow in an annex
            host = next(m for m in orig.values() if m.name == S.ORE_ANNEX_MODULE)
            hsec, hfrom = sc.spec["annex_section"], sc.spec["annex_from"]
            if host.sections[hsec]["size"] != hfrom or hfrom % SECTION_ALIGN:
                sys.exit("%s: its data section is not the %d bytes the annex expects" % (host.name, hfrom))
            base = ORE_WORK_ADDR + host.sections[hsec]["offset"] + hfrom + 8
            segs, annex, remap, (kept, room) = emit_ore(sc, r, base)
            ore = {"sc": sc, "segs": segs, "remap": remap, "annex": annex, "host": host}
            if annex:
                remaps[(host.mod_id, hsec)] = Remap(hfrom // 2, hfrom // 2, {}, len(annex))
                new_secs[host.mod_id] = (hsec, host.sec_data(hsec) + annex)
            print("%-13s %5d runs replaced, %d pieces stay in place (%d bytes left there), %d bytes go to the "
                  "annex in %s" % (sc.rel.name, len(r), kept, room, len(annex), host.name))
            continue
        data, remap, room = emit_block(sc, r)
        inplace[(sc.rel.mod_id, sc.sec)] = remap
        block_data[sc.rel.mod_id] = (sc.sec, sc.region[0], data)
        print("%-13s %5d runs replaced, script laid out again in its 0x%X bytes (%d bytes left)"
              % (sc.rel.name, len(r), len(data), room))
    for sc in scripts:
        r = repl.get(sc.rel.name, {})
        p = (pad or {}).get(sc.rel.name, 0)
        if not r and not p:
            continue
        data, remap = emit_script(sc, r, p)
        remaps[(sc.rel.mod_id, sc.sec)] = remap
        new_secs[sc.rel.mod_id] = (sc.sec, data)
        print("%-13s %5d runs replaced, script section 0x%X -> 0x%X bytes (data behind it moves %+d)"
              % (sc.rel.name, len(r), sc.rel.sections[sc.sec]["size"], len(data), remap.growth))
    dol_image = build_dol(dol, slots, orig, remaps) if dol else None
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    os.makedirs(BUILD_DIR)
    changed, images = [], {sc.rel.name: (sc.rel.data, sc.rel.data) for sc in scripts}
    if dol and dol_image != ui_strings.dol_data():
        with open(DOL_BUILT, "wb") as f:
            f.write(dol_image)
        changed.append(DOL)
    for m in orig.values():
        if m.name == "fonttex2.rel" and slots:
            image, note = build_font_file(orig, slots), "%d glyphs replaced in both fonts" % len(slots)
        elif m.mod_id in new_secs:
            sec, data = new_secs[m.mod_id]
            image, note = rebuild_module(m, sec, data, remaps), "rebuilt"
            if ore and m is ore["host"]:
                extra_images[m.name] = (m.data, image, ORE_WORK_ADDR)
            else:
                images[m.name] = (m.data, image)
        else:
            image, n = patch_addends(m, remaps)
            note = "%d addends" % n
        if m.name in strings:                                    # UI strings, in place
            image = bytearray(image)
            patched[m.mod_id] = {}
            for (sec, off), (cells, en) in strings[m.name].items():
                if ui_strings.block_of(m.name, sec, off):
                    continue                                     # laid out with its block, below
                data = encode_string(en, cells, slots)
                remap = remaps.get((m.mod_id, sec), lambda o: o)
                pos = m.sections[sec]["offset"] + remap(off)     # sections in front of a rebuilt one stay
                if any(mid == m.mod_id and s < sec for mid, s in remaps):
                    sys.exit("%s: a string table behind the rebuilt section is not supported" % m.name)
                assert image[pos + len(data):pos + len(data) + 2] == b"\xff\xff", (m.name, sec, off)
                image[pos:pos + len(data)] = data
                patched[m.mod_id][(sec, off)] = data
            for blk in ui_strings.BLOCKS.get(m.name, ()):        # strings that move: new layout, new pointers
                if not any(ui_strings.block_of(m.name, sec, off) is blk for sec, off in strings[m.name]):
                    continue
                if m.mod_id in new_secs or any(mid == m.mod_id for mid, _ in remaps):
                    sys.exit("%s: a block of movable strings in a rebuilt module is not supported" % m.name)
                data, addends, reads = layout_block(m, blk, strings[m.name], slots)
                pos = m.sections[blk["section"]]["offset"] + blk["start"]
                image[pos:pos + len(data)] = data
                patched[m.mod_id][(blk["section"], blk["start"])] = data
                done = 0
                for mod, _, entries, _ in parse_imports(bytes(image), m.imp_off, m.imp_size):
                    for sec, rpos, typ, tsec, addend, off in entries:
                        if mod == m.mod_id and sec == blk["section"] and rpos in addends:
                            struct.pack_into(">I", image, off + 4, addends[rpos])
                            moved[(m.mod_id, sec, rpos)] = addends[rpos]
                            done += 1
                assert done == blk["count"], (m.name, done)
                for a, units in reads.items():                   # every pointer reads its string, closed by 0xFFFF
                    at = m.sections[blk["section"]]["offset"] + a
                    got = struct.unpack_from(">%dH" % (len(units) + 1), image, at)
                    assert got == units + (0xFFFF,) and blk["start"] <= a < blk["end"], (m.name, a)
                note += ", %d strings laid out again at sec%d+%d" % (blk["count"], blk["section"], blk["start"])
            image = bytes(image)
            note += ", %d UI strings" % len(strings[m.name])
        if m.name in messages:                                   # message scripts: each laid out again in its span
            if m.mod_id in new_secs or any(mid == m.mod_id for mid, _ in remaps):
                sys.exit("%s: message scripts in a rebuilt module are not supported" % m.name)
            image = bytearray(image)
            patched.setdefault(m.mod_id, {})
            for (sec, off), (msg, pieces) in messages[m.name].items():
                units = ui_messages.encode(msg, pieces, lambda text: encode_text(text, slots))
                data = struct.pack(">%dH" % len(units), *units)
                if any(s == sec and off <= o < off + len(data) for s, o in strings.get(m.name, ())):
                    sys.exit("%s %d:%d: a UI string is translated inside this message" % (m.name, sec, off))
                pos = m.sections[sec]["offset"] + off
                image[pos:pos + len(data)] = data
                patched[m.mod_id][(sec, off)] = data
            image = bytes(image)
            note += ", %d messages" % len(messages[m.name])
        if m.name in kyu_names.BLOCKS and kyu_english:           # pitch names (kyu font): new layout, new pointers
            if m.mod_id in new_secs or any(mid == m.mod_id for mid, _ in remaps):
                sys.exit("%s: pitch names in a rebuilt module are not supported" % m.name)
            blk = kyu_names.BLOCKS[m.name]
            if any(s == blk["section"] and blk["start"] <= o < blk["end"] for s, o in strings.get(m.name, ())):
                sys.exit("%s: a UI string is translated inside the pitch names" % m.name)
            try:
                data, addends, reads = kyu_names.layout(m, blk, kyu_english)
            except ValueError as e:
                sys.exit(str(e))
            image = bytearray(image)
            pos = m.sections[blk["section"]]["offset"] + blk["start"]
            image[pos:pos + len(data)] = data
            patched.setdefault(m.mod_id, {})[(blk["section"], blk["start"])] = data
            done = 0
            for mod, _, entries, _ in parse_imports(bytes(image), m.imp_off, m.imp_size):
                for sec, rpos, typ, tsec, addend, off in entries:
                    if mod == m.mod_id and sec == blk["section"] and rpos in addends:
                        struct.pack_into(">I", image, off + 4, addends[rpos])
                        moved[(m.mod_id, sec, rpos)] = addends[rpos]
                        done += 1
            assert done == blk["count"], (m.name, done)
            for a, s in reads.items():                           # every pointer reads its name, closed by the end mark
                at = m.sections[blk["section"]]["offset"] + a
                assert image[at:at + len(s) + 1] == s + bytes([kyu_names.END]) and blk["start"] <= a < blk["end"]
            image = bytes(image)
            note += ", %d pitch names" % len(kyu_english)
        if inplace and m.name != "fonttex2.rel":                 # a block script laid out again: bytes and pointers
            if m.mod_id in new_secs:
                image, n = bytes(image), sum((mod, e[3]) in inplace for mod, _, entries, _ in
                                             parse_imports(m.data, m.imp_off, m.imp_size) for e in entries)
                if n or m.mod_id in block_data:
                    sys.exit("%s: a rebuilt module that also points at a block script is not supported" % m.name)
            else:
                if m.mod_id in block_data:
                    sec, off, data = block_data[m.mod_id]
                    pos = m.sections[sec]["offset"] + off
                    if any(s == sec and off <= o < off + len(data) for s, o in strings.get(m.name, ())):
                        sys.exit("%s: a UI string is translated inside the script" % m.name)
                    image = image[:pos] + data + image[pos + len(data):]
                    patched.setdefault(m.mod_id, {})[(sec, off)] = data
                image, n = patch_addends(m, inplace, bytes(image))
                if n:
                    note += ", %d pointers into a script laid out again" % n
        if ore and m is ore["sc"].rel:                             # My Life: the script and its label table
            sc = ore["sc"]
            if m.mod_id in new_secs or any(mid == m.mod_id for mid, _ in remaps):
                sys.exit("%s: a rebuilt module cannot hold the My Life script" % m.name)
            image = bytearray(image)
            for off, data in ore["segs"]:
                if any(t == sc.sec and off <= o < off + len(data) for t, o in strings.get(m.name, ())):
                    sys.exit("%s: a UI string is translated inside the script" % m.name)
                pos = m.sections[sc.sec]["offset"] + off
                image[pos:pos + len(data)] = data
                patched.setdefault(m.mod_id, {})[(sc.sec, off)] = data
            image, n = ore_relocations(m, bytes(image), sc, ore["remap"])
            extra_images[m.name] = (m.data, image, None)
            note += ", script laid out again, %d labels in the annex" % n
        elif ore and any(mod == ore["sc"].rel.mod_id and e[3] == ore["sc"].sec
                         and ore["sc"].region[0] <= e[4] < ore["sc"].region[1] and not ore["sc"].in_island(e[4])
                         for mod, _, entries, _ in parse_imports(m.data, m.imp_off, m.imp_size) for e in entries):
            sys.exit("%s points into the My Life script: not supported" % m.name)
        if image != m.data:
            with open(os.path.join(BUILD_DIR, m.name), "wb") as f:
                f.write(image)
            changed.append(m.name)
            print("  %-13s %s, 0x%X -> 0x%X bytes" % (m.name, note, len(m.data), len(image)))
    with open(os.path.join(ORIG_DIR, PLAN_FILE), "rb") as f:
        plan = f.read()
    new_plan = update_plan(plan, images)
    if extra_images:
        new_plan = update_plan_ore(new_plan, plan, extra_images)
    if new_plan != plan:
        with open(os.path.join(BUILD_DIR, PLAN_FILE), "wb") as f:
            f.write(new_plan)
        changed.append(PLAN_FILE)
    new = verify(orig, scripts, repl, remaps, patched, moved, inplace, blocks, ore)
    if dol:                             # the My Life modules: relocations and sections are checked in verify()
        verify_dol(orig, new, dol, slots, tuple(extra_images))
    return changed


def verify(orig, old_scripts, repl, remaps, patched=None, moved=None, inplace=None, blocks=(), ore=None):
    """Re-read the built files and compare them with the originals, structure by structure.
    Returns the modules as re-read (for verify_dol). moved = the relocations whose addend the build
    changed on purpose (pointers to strings that were laid out again): {(module, section, position): addend}."""
    new = load_dir(ORIG_DIR, BUILD_DIR)

    def expected(m, idx):           # the original section with the UI strings written in
        d = bytearray(m.sec_data(idx))
        for (sec, off), data in (patched or {}).get(m.mod_id, {}).items():
            if sec == idx:
                d[off:off + len(data)] = data
        return bytes(d)
    inplace = inplace or {}
    new_scripts = load_scripts(new, remaps) + S.load_block_scripts(new)
    for old, sc in zip(list(old_scripts) + list(blocks), new_scripts):
        name = old.rel.name
        remap = remaps.get((old.rel.mod_id, old.sec)) or inplace.get((old.rel.mod_id, old.sec), lambda off: off)
        if ore and old is ore["sc"]:
            remap = ore["remap"]
        assert not sc.errors, (name, sc.errors)
        # same instructions at the mapped positions, same labels, same text except replacements
        assert {remap(i * 2) // 2 for i, k in old.kind.items() if k == "op"} == \
               {i for i, k in sc.kind.items() if k == "op"}, name + ": instructions moved"
        assert collections.Counter({remap(i * 2) // 2: n for i, n in old.labels.items()}) == sc.labels, \
            name + ": labels differ"
        assert old.op_count == sc.op_count and len(old.texts) == len(sc.texts), name
        for i, (window, units, _) in old.texts.items():
            w2, u2, _ = sc.texts[remap(i * 2) // 2]
            assert w2 == window and u2 == repl.get(name, {}).get(i, units), "%s: text at 0x%X" % (name, i * 2)
    # every relocation: same kind and target, positions and addends moved exactly as mapped
    for mid, m in orig.items():
        a, b = m.relocs(), new[mid].relocs()
        assert len(a) == len(b), m.name
        want = []
        for (s, pos, typ, tm, ts, ad) in a:
            pos = remaps[(mid, s)](pos) if (mid, s) in remaps else pos
            ad = remaps[(tm, ts)](ad) if (tm, ts) in remaps else ad
            ad = inplace[(tm, ts)](ad) if (tm, ts) in inplace else ad
            ad = (moved or {}).get((mid, s, pos), ad)
            if ore and (tm, ts) == (ore["sc"].rel.mod_id, ore["sc"].sec):
                ad = ore["remap"](ad)                   # a label of the My Life script
                if ore["remap"].address(ad) is not None:
                    tm, ts, ad = 0, 4, ore["remap"].address(ad)     # in the annex: an absolute address
            want.append((s, pos, typ, tm, ts, ad))
        if ore and m is ore["sc"].rel:                  # labels changed stream: the same set, another order
            assert sorted(want) == sorted(b), m.name + ": relocations"
            want = b
        for (s, pos, typ, tm, ts, ad), got in zip(want, b):
            assert (s, pos, typ, tm, ts, ad) == got, "%s: relocation sec%d+0x%X" % (m.name, s, pos)
        # everything in front of a rebuilt section, and the data behind the script, is untouched
        for t, t2 in zip(m.sections, new[mid].sections):
            if (mid, t["index"]) in remaps:
                r = remaps[(mid, t["index"])]
                assert expected(m, t["index"])[r.hi:] == \
                    new[mid].sec_data(t["index"])[r.hi + r.growth:r.growth + t["size"]], m.name + ": tail"
                assert expected(m, t["index"])[:r.lo] == new[mid].sec_data(t["index"])[:r.lo], m.name + ": head"
            elif m.name != "fonttex2.rel":          # the font is checked in build_font_file()
                assert expected(m, t["index"]) == new[mid].sec_data(t["index"]), m.name + ": section data"
    print("Verified: scripts re-parse, labels, text and all relocations match the originals.")
    return new


def install(changed):
    """DATA/files = originals + built files."""
    n = 0
    for fn in sorted(os.listdir(ORIG_DIR)):
        src = os.path.join(BUILD_DIR if fn in changed else ORIG_DIR, fn)
        dst = os.path.join(S.DATA_FILES, fn)
        if not filecmp.cmp(src, dst, shallow=False):
            shutil.copy2(src, dst)
            n += 1
    print("Installed: %d file(s) written to DATA/files (%d differ from the originals)."
          % (n, len([fn for fn in changed if fn != DOL])))
    if os.path.exists(ui_strings.DOL_ORIG):         # main.dol: DATA/sys = the built one or the original
        src = DOL_BUILT if DOL in changed else ui_strings.DOL_ORIG
        if not os.path.exists(ui_strings.DOL_SOURCE) or not filecmp.cmp(src, ui_strings.DOL_SOURCE, shallow=False):
            shutil.copy2(src, ui_strings.DOL_SOURCE)
            print("Installed: %s written to DATA/sys (%s)." % (DOL, "translated dialogs" if DOL in changed else "the original"))


def cmd_check(args):
    orig = load_dir(ORIG_DIR)
    scripts = load_scripts(orig)
    bad = 0
    for sc in scripts:
        data, remap = emit_script(sc, {})
        remaps = {(sc.rel.mod_id, sc.sec): remap}
        image = rebuild_module(sc.rel, sc.sec, data, remaps)
        ok = image == sc.rel.data and remap.growth == 0
        bad += not ok
        print("%-13s rebuilt with no changes: %s" % (sc.rel.name, "identical" if ok else "DIFFERENT"))
    n = 0
    for m in orig.values():
        for mod, start, entries, end in parse_imports(m.data, m.imp_off, m.imp_size):
            n += 1
            if encode_stream(entries) != m.data[start:end]:
                bad += 1
                print("%-13s relocation stream for module %d does not re-encode identically" % (m.name, mod))
    print("%d relocation streams in %d modules re-encoded" % (n, len(orig)))
    with open(os.path.join(ORIG_DIR, PLAN_FILE), "rb") as f:
        plan = f.read()
    same = update_plan(plan, {sc.rel.name: (sc.rel.data, sc.rel.data) for sc in scripts}) == plan
    bad += not same
    print("memory plan (%s): %s" % (PLAN_FILE, "entries found and unchanged" if same else "DIFFERENT"))
    font = next(m for m in orig.values() if m.name == "fonttex2.rel")
    for name, pos, _ in pair_font.FONTS:
        glyphs = pair_font.font_glyphs(font.sec_data(4), pos)
        size = pair_font.FONT_END[pos] - pos
        used = 4 + 4 * len(glyphs) + sum(map(len, glyphs))
        ok = pair_font.pack_font(glyphs, size)[:used] == font.sec_data(4)[pos:pos + used] and all(
            pair_font.decompress(pair_font.compress(pair_font.decompress(g)[0]))[0] == pair_font.decompress(g)[0]
            for g in glyphs)
        bad += not ok
        print("%s font: %d glyphs repacked and recompressed: %s" % (name, len(glyphs), "identical" if ok else "DIFFERENT"))
    dol = load_dol(None)
    if dol:
        strs = [s for s, _ in dol]
        block, starts = layout_dol(strs, [s["units"] for s in strs])
        data, (a, b) = ui_strings.dol_data(), ui_strings.DOL_BLOCK
        remaps = {}
        ok = block == data[a:b] and starts == [s["offset"] for s in strs] and \
            parse_dol(data) == [(s["offset"], s["units"]) for s in strs] and \
            build_dol(dol, {}, orig, remaps) == data and not remaps
        bad += not ok
        print("%-13s dialog block re-emitted with no translations: %s" % (DOL, "identical" if ok else "DIFFERENT"))
    sys.exit("FAILED" if bad else None)


def cmd_build(args):
    orig = load_dir(ORIG_DIR)
    scripts = load_scripts(orig) + S.load_block_scripts(orig)
    texts = load_translation(args.json, scripts)
    pad = {}
    for item in args.pad or []:
        name, size = item.split("=")
        pad[name] = int(size, 0)
    install(build(texts, pad, ui_strings.load_for_build(), ui_strings.load_dol_for_build(),
                  ui_messages.load_for_build()))


def cmd_restore(args):
    install([])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("check", help="round-trip test, no files are changed").set_defaults(func=cmd_check)
    p = sub.add_parser("build", help="apply a translation file and install the result")
    p.add_argument("json", nargs="?", default=os.path.join(S.WORK_DIR, "translation.json"))
    p.add_argument("--pad", action="append", metavar="FILE=BYTES",
                   help="test only: add empty space to a script module, e.g. scs_main.rel=0x80000")
    p.set_defaults(func=cmd_build)
    sub.add_parser("restore", help="put the original files back").set_defaults(func=cmd_restore)
    args = ap.parse_args()
    if not args.cmd:
        return ap.print_help()
    if not os.path.isdir(S.DATA_FILES):
        sys.exit("Game files not found at %s" % S.DATA_FILES)
    ensure_orig()
    args.func(args)


if __name__ == "__main__":
    main()
