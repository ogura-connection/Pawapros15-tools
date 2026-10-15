#!/usr/bin/env python3
"""
scan_story.py - locate and decode Success Mode story dialogue (static analysis only)

Jikkyou Powerful Pro Yakyuu 15 (Wii, RP5JA4, Rev 1).

The story dialogue is stored inline in the script sections of scs_sce1/2/3.rel.
A script halfword whose low byte is 0x00 switches the interpreter into text mode;
the text that follows is a stream of 12-bit glyph indices (3 nibbles each),
terminated by 0xFFF and padded with 0xF nibbles to the next halfword.
See FINDINGS.md for the full write-up.

Commands:
  extract   parse the scripts, count lines, verify byte-exact re-encoding
  xref      show the code evidence (needs: pip install capstone)
  entropy   entropy map of the script modules and other game files
  scan      look for other packed-text stores and for compressed data

Full text dumps are written only to _work/ (git-ignored). Never commit them.
"""

import argparse
import collections
import json
import math
import os
import re
import struct
import sys

from pawapuro15_text_tools import glyph_to_char
from extract_all_text import is_quality_text

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_FILES = os.path.join(BASE_PATH, "DATA", "files")
WORK_DIR = os.path.join(BASE_PATH, "_work")

# Script modules: common events live in scs_main.rel itself, scenario scripts in scs_sce1/2/3.
SCRIPT_FILES = ["scs_main.rel", "scs_sce1.rel", "scs_sce2.rel", "scs_sce3.rel"]
# Label tables in scs_main.rel sec5 (zero in the file, filled by ADDR32 relocations at load).
# sec5+0xD0870 holds three table pointers; each table is 14,101 labels into scs_main sec5
# followed by the labels of one scenario module.
LABEL_TABLES = (0xD0880, 0xFED88)
MAX_GLYPH = 3743
TEXT_END = 0xFFF      # end of text run
TEXT_NEWLINE = 0xFFE  # line break inside a run (becomes 0x1FFE in the display buffer)

RELOC_NAMES = {1: "ADDR32", 2: "ADDR24", 3: "ADDR16", 4: "ADDR16_LO", 5: "ADDR16_HI",
               6: "ADDR16_HA", 10: "REL24", 11: "REL14"}
R_NOP, R_SECTION, R_END = 201, 202, 203


# ── REL parsing ───────────────────────────────────────────────────────────

class Rel:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        (self.mod_id, _, _, nsec, sec_off, _, _, self.version, self.bss_size,
         self.rel_off, self.imp_off, self.imp_size) = struct.unpack_from(">12I", d, 0)
        self.sections = []
        for i in range(nsec):
            raw, size = struct.unpack_from(">II", d, sec_off + i * 8)
            off = raw & ~3
            self.sections.append({"index": i, "offset": off, "size": size,
                                  "exec": bool(raw & 1), "bss": off == 0 and size != 0})
        self._relocs = None

    def sec_data(self, i):
        s = self.sections[i]
        if s["bss"] or not s["size"]:
            return b""
        return self.data[s["offset"]:s["offset"] + s["size"]]

    def relocs(self):
        """[(src_section, src_offset, type, target_module, target_section, addend)]"""
        if self._relocs is None:
            d, out = self.data, []
            for k in range(self.imp_size // 8):
                mod, off = struct.unpack_from(">II", d, self.imp_off + k * 8)
                sec = pos = 0
                while True:
                    delta, typ, tsec, addend = struct.unpack_from(">HBBI", d, off)
                    off += 8
                    pos += delta
                    if typ == R_END:
                        break
                    if typ == R_SECTION:
                        sec, pos = tsec, 0
                    elif typ != R_NOP:
                        out.append((sec, pos, typ, mod, tsec, addend))
            self._relocs = out
        return self._relocs

    def script_section(self):
        """The script lives in the largest non-executable section stored in the file."""
        cands = [s for s in self.sections if s["size"] and not s["bss"] and not s["exec"]]
        return max(cands, key=lambda s: s["size"])["index"]


def load_all_rels():
    # Offsets in this tool refer to the original files. Once rebuild_scripts.py has patched
    # DATA/files, the originals are in _work/orig.
    orig = os.path.join(WORK_DIR, "orig")
    src = orig if os.path.isdir(orig) else DATA_FILES
    mods = {}
    for fn in sorted(os.listdir(src)):
        if fn.endswith(".rel"):
            r = Rel(os.path.join(src, fn))
            mods[r.mod_id] = r
    return mods


# ── 12-bit packed text ────────────────────────────────────────────────────

def unpack_text(hw, i, max_units=None, strict=False):
    """Read a packed text run starting at halfword index i.

    Mirrors the reader in scs_main.rel sec1+0x034F08: a nibble phase 0..3 selects
    which 12 bits of the current/next halfword form the next unit.
    Returns (units, next_halfword_index), or None if the data ends first
    (or, for scanning unknown data, no terminator within max_units / strict: an
    impossible unit is met).
    """
    units, phase, n = [], 0, len(hw)
    while i < n:
        if max_units is not None and len(units) > max_units:
            return None
        if phase == 0:
            u = hw[i] >> 4
        elif phase == 3:
            u = hw[i] & 0xFFF
        else:
            if i + 1 >= n:
                return None
            if phase == 1:
                u = ((hw[i] & 0xF) << 8) | (hw[i + 1] >> 8)
            else:
                u = ((hw[i] & 0xFF) << 4) | (hw[i + 1] >> 12)
        if u == TEXT_END:
            return units, i + (2 if phase in (1, 2) else 1)
        if strict and MAX_GLYPH < u < 0xF00:
            return None
        units.append(u)
        if phase:
            i += 1
        phase = (phase + 1) & 3
    return None


def pack_text(units):
    """Inverse of unpack_text: units -> halfwords (terminator and padding included)."""
    nib = []
    for u in list(units) + [TEXT_END]:
        nib += [u >> 8, (u >> 4) & 15, u & 15]
    while len(nib) % 4:
        nib.append(0xF)
    return [(nib[k] << 12) | (nib[k + 1] << 8) | (nib[k + 2] << 4) | nib[k + 3]
            for k in range(0, len(nib), 4)]


def decode_units(units):
    out = []
    for u in units:
        if u == TEXT_NEWLINE:
            out.append("\\n")
            continue
        ch = glyph_to_char(u) if u <= MAX_GLYPH else None
        out.append(ch if ch else "<%03X>" % u)
    return "".join(out)


def units_valid(units):
    return all(u <= MAX_GLYPH or u >= 0xF00 for u in units)


# ── Script parsing ────────────────────────────────────────────────────────

# Instruction length in halfwords, opcode = low byte. Derived from the handlers in
# scs_main.rel (jump table at sec5+0x0FF63C); `xref` re-derives and checks this table.
OP_LEN = {op: 1 for op in range(0x100)}
for _op in ([0x71, 0x72] + list(range(0x75, 0x82)) + list(range(0x83, 0x9A)) + [0x9B, 0x9C, 0x9E]
            + list(range(0x9F, 0xC7)) + [0xD5, 0xD6, 0xDA] + list(range(0xE5, 0xE9))
            + list(range(0xEE, 0xF2))):
    OP_LEN[_op] = 2
for _op in list(range(0x26, 0x46)) + [0x9D]:
    OP_LEN[_op] = 3
for _op in range(0x16, 0x26):
    OP_LEN[_op] = 4
OP_TEXT, OP_RETURN, OP_IF, OP_SKIPLIST, OP_GOTO = 0x00, 0x01, 0x02, 0x6E, 0x9B
OP_NEWLINE, OP_NEWLINE_WAIT, OP_WAIT = 0x46, 0x49, 0x4A   # meaning inferred from handlers


def instruction_length(hw, i):
    op = hw[i] & 0xFF
    if op == OP_IF:
        # [expr, comparison, operand] repeated, joined by 0x14 (and) / 0x15 (or),
        # optionally closed by 0x03, then a label index.
        j = i + 1
        while True:
            j += 3
            if j >= len(hw):
                break
            if hw[j] == 3:
                j += 1
                break
            if hw[j] in (0x14, 0x15):
                j += 1
                continue
            break
        return j + 1 - i
    if op == OP_SKIPLIST:
        j = i + 1
        while j < len(hw) and hw[j] != 0:
            j += 1
        return j + 1 - i
    return OP_LEN[op]


class Script:
    """One script module, parsed by following control flow from every label."""

    def __init__(self, rel, all_mods, label_tables=LABEL_TABLES):
        self.rel = rel
        self.sec = rel.script_section()
        d = rel.sec_data(self.sec)
        self.sec_file_offset = rel.sections[self.sec]["offset"]
        self.hw = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
        # Labels: entries of the label tables in scs_main.rel sec5 that point into this
        # section. Jumps/calls/ifs take a label index, never a raw offset.
        self.labels = collections.Counter()
        main = next(m for m in all_mods.values() if m.name == "scs_main.rel")
        for (s, pos, typ, tm, ts, addend) in main.relocs():
            if (s == 5 and typ == 1 and label_tables[0] <= pos < label_tables[1]
                    and tm == rel.mod_id and ts == self.sec and addend % 2 == 0):
                self.labels[addend // 2] += 1
        self.kind = {}       # halfword index -> 'op' | 'arg' | 'text'
        self.texts = {}      # index of the text-mode halfword -> (window, units, end index)
        self.op_count = collections.Counter()
        self.errors = collections.Counter()
        self._parse()

    def _parse(self):
        hw, kind = self.hw, self.kind
        work = sorted(self.labels)
        while work:
            i = work.pop()
            while 0 <= i < len(hw):
                if i in kind:
                    if kind[i] != "op":
                        self.errors["label lands mid-instruction"] += 1
                    break
                op = hw[i] & 0xFF
                self.op_count[op] += 1
                kind[i] = "op"
                if op == OP_TEXT:
                    r = unpack_text(hw, i + 1)
                    if r is None:
                        self.errors["text runs off the end"] += 1
                        del kind[i]
                        break
                    units, j = r
                    for k in range(i + 1, j):
                        kind[k] = "text"
                    self.texts[i] = (hw[i] >> 8, units, j)
                    i = j
                    continue
                n = instruction_length(hw, i)
                for k in range(i + 1, min(i + n, len(hw))):
                    kind[k] = "arg"
                if op in (OP_GOTO, OP_RETURN):
                    break
                i += n

    def offset_of(self, idx):
        """File offset of halfword idx."""
        return self.sec_file_offset + idx * 2


def load_scripts():
    mods = load_all_rels()
    by_name = {m.name: m for m in mods.values()}
    return [Script(by_name[fn], mods) for fn in SCRIPT_FILES]


# ── Other script engines ──────────────────────────────────────────────────

# Eikan Nine (sct_main.rel) runs the same kind of script with an interpreter of its own (sec1+0x22C18:
# script pointer at r31+0x200, 207 opcodes, jump table at sec5+0x32A0). Text mode, the waits, the name
# inserts and the conditions (0x00..0x66) are numbered as in Success Mode; the later opcodes are not.
# The lengths below were read off the handlers (how far each moves the script pointer) and parse the
# whole script with no error. The label table stands behind the script in the same section and is filled
# by the module's own relocations; five entry points are also addressed from sct_card.rel and sct_sugo.rel.
EIKAN_OP_LEN = {op: 1 for op in range(0x100)}
for _op in (0x69, 0x6A, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x74, 0x75, 0x76, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
            0x82, 0x83, 0x84, 0x85, 0x87, 0x88, 0x8A, 0x8D, 0x8E, 0x92, 0xA1, 0xA2, 0xA9, 0xAA, 0xAB, 0xAC,
            0xB3, 0xB4, 0xB9, 0xBA, 0xBC, 0xBD, 0xC1, 0xC2, 0xC6, 0xC7, 0xC8, 0xCB, 0xCD):
    EIKAN_OP_LEN[_op] = 2
for _op in list(range(0x26, 0x46)) + [0x89]:
    EIKAN_OP_LEN[_op] = 3
for _op in range(0x16, 0x26):
    EIKAN_OP_LEN[_op] = 4
# "region" = the script, "labels" = its label table (section offsets); "list" = the opcode that is
# followed by values up to a zero; "ends" = return and goto; "line" = cells a line may take (the Japanese rarely passes 18; not measured in game yet).
BLOCK_SCRIPTS = {"sct_main.rel": {"section": 5, "region": (14416, 189368), "labels": (189372, 210644),
                                  "op_len": EIKAN_OP_LEN, "list": 0x67, "ends": (0x01, 0x87), "max_op": 0xCE,
                                  "name_ops": tuple(range(0x4B, 0x51)), "line": 18}}

# The player's lines during a Success match (scs_comi.rel: "I'll hit a homer!", the answers to a sign) run on
# an interpreter of their own (sec1+0x1CF8: script pointer at r15+0x154, 141 opcodes, jump table at
# sec5+0x3DC), numbered like Success Mode. Lengths read off the handlers; 0x66 / 0x67 move the pointer in a
# helper (sec1+0x2B58 / 0x2C20). 0x75 goto and 0x76 call take a label number from the table that sec5+0x2D90
# points to (sec5+11672, 347 labels; the last entry, sec5+13064, is a lone ダミー run behind the table and
# stays as it is). 0x4B / 0x4C insert a name. Four halfwords behind a goto at +1846 are unreachable.
COMI_OP_LEN = {op: 1 for op in range(0x100)}
for _op in (0x5F, 0x60, 0x62, 0x63, 0x65, 0x66, 0x67, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x71, 0x72, 0x73, 0x75, 0x76,
            0x78, 0x88):
    COMI_OP_LEN[_op] = 2
for _op in list(range(0x26, 0x46)) + [0x77]:
    COMI_OP_LEN[_op] = 3
for _op in range(0x16, 0x26):
    COMI_OP_LEN[_op] = 4
BLOCK_SCRIPTS["scs_comi.rel"] = {"section": 5, "region": (1800, 11664), "labels": (11672, 13060),
                                 "op_len": COMI_OP_LEN, "list": 0x5D, "ends": (0x01, 0x75), "max_op": 0x8C,
                                 "name_ops": (0x4B, 0x4C), "line": 17, "dead": 4}


class BlockScript(Script):
    """A script that shares its section with other data (see BLOCK_SCRIPTS). Same attributes as Script.
    Halfwords of the region that no instruction covers are zero padding in front of a label (every label
    is at a multiple of 4 and follows a return or a goto); kind "dead" = other data nothing reaches."""

    def __init__(self, rel, spec):
        self.rel, self.spec, self.sec = rel, spec, spec["section"]
        self.region, self.ends, self.name_ops = spec["region"], spec["ends"], spec["name_ops"]
        d = rel.sec_data(self.sec)
        self.sec_file_offset = rel.sections[self.sec]["offset"]
        self.hw = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
        self.labels = collections.Counter()
        for (s, pos, typ, tm, ts, addend) in rel.relocs():
            if s == self.sec and typ == 1 and spec["labels"][0] <= pos < spec["labels"][1]:
                if (tm, ts) != (rel.mod_id, self.sec) or addend % 2 or not self.region[0] <= addend < self.region[1]:
                    raise ValueError("%s: label table entry at +%d points outside the script" % (rel.name, pos))
                self.labels[addend // 2] += 1
        self.kind, self.texts = {}, {}
        self.op_count, self.errors = collections.Counter(), collections.Counter()
        self._parse()
        lo, hi = self.region[0] // 2, self.region[1] // 2
        for i in range(lo, hi):             # one return that nothing reaches (sct_main.rel +90684): kept as it is
            if i not in self.kind and self.hw[i] and not any(a <= i * 2 < b for a, b in spec.get("islands", ())):
                self.kind[i] = "dead"
        if sum(k == "dead" for k in self.kind.values()) > spec.get("dead", 1):
            self.errors["data between the instructions"] += 1

    def op(self, i):
        return self.hw[i] & 0xFF

    def _length(self, i):
        hw, op = self.hw, self.hw[i] & 0xFF
        if op == OP_IF:
            return instruction_length(hw, i)
        if op == self.spec["list"]:
            j = i + 1
            while j < len(hw) and hw[j] != 0:
                j += 1
            return j + 1 - i
        return self.spec["op_len"][op]

    def _parse(self):
        hw, kind = self.hw, self.kind
        lo, hi = self.region[0] // 2, self.region[1] // 2
        work = sorted(self.labels)
        while work:
            i = work.pop()
            while True:
                if not lo <= i < hi:
                    self.errors["runs out of the script"] += 1
                    break
                if i in kind:
                    if kind[i] != "op":
                        self.errors["label lands mid-instruction"] += 1
                    break
                op = hw[i] & 0xFF
                self.op_count[op] += 1
                kind[i] = "op"
                if op == OP_TEXT:
                    r = unpack_text(hw, i + 1)
                    if r is None or r[1] > hi or not units_valid(r[0]):
                        self.errors["bad text run"] += 1
                        break
                    units, j = r
                    for k in range(i + 1, j):
                        kind[k] = "text"
                    self.texts[i] = (hw[i] >> 8, units, j)
                    i = j
                    continue
                if op > self.spec["max_op"]:
                    self.errors["unknown opcode"] += 1
                    break
                n = self._length(i)
                for k in range(i + 1, min(i + n, hi)):
                    kind[k] = "arg"
                if op in self.ends:
                    break
                i += n


# My Life (orepena.rel) has an engine of its own: the interpreter is ore_work.rel sec1+0x1CE4 (script pointer at
# r15+0x58, label table pointer at r15+0x4C), and sec1+0x3BE0 skips a block, which gives every length.
# An instruction is a whole halfword: 0000 text (the same 12-bit packing, read at sec1+0x3F30; line breaks
# are instructions, not units), 0001 new line, 0006 / 0007 wait for a button, 0008 return, 0018 window,
# 001C insert a name or number, 0032 call, 0033 / 0034 mark and jump back, 0035 goto, 0036 / 0037 if and
# 0038 else (followed by FFF0 .. FFF1 around a block, or by one label), 003C a list with its count.
# Jumps take a label number; the table (sec5+173464, 1,852 entries) is filled by the module's relocations
# and nothing else points into the script. Three islands of other data (tables with relocations of their
# own, debug strings) lie between the scenes and stay where they are.
ORE_OP_LEN = {0x04: 2, 0x09: 2, 0x17: 6, 0x18: 3, 0x19: 3, 0x1A: 3, 0x1B: 3, 0x1C: 5, 0x32: 2, 0x33: 2, 0x34: 2,
              0x35: 2, 0x36: 6, 0x37: 6, 0x38: 2, 0x39: 3, 0x3A: 4, 0x3B: 3, 0x3E: 2, 0x3F: 2, 0x41: 2, 0x42: 4,
              0x43: 5, 0x44: 5, 0x46: 2, 0x47: 4, 0x48: 6, 0x49: 8}
ORE_LIST, ORE_BLOCK, ORE_BLOCK_END = 0x3C, 0xFFF0, 0xFFF1
ORE_IF, ORE_ELSE, ORE_WINDOW = (0x36, 0x37), 0x38, 0x18
BLOCK_SCRIPTS["orepena.rel"] = {"engine": "ore", "section": 5, "region": (182584, 803170),
                                "labels": (173464, 180872),
                                "islands": ((187254, 189808), (228090, 229016), (779308, 780240)),
                                "ends": (0x08, 0x34, 0x35), "name_ops": (0x1C, 0x3F), "max_op": 0x49, "line": 16,
                                "marks": {0x01: "L", 0x06: "B", 0x07: "B"}, "dead": 400,
                                "annex_section": 5, "annex_from": 2168}


# English needs more room than the script has (its module cannot grow: the next ones start where it ends), so
# the build moves the scenes that do not fit to an annex behind the data of ore_work.rel, which it loads in
# the free memory above the plan. A label of such a scene is filled by a relocation against main.dol, that
# is an absolute address. The annex starts with ORE_ANNEX_MAGIC and its own address, so a built file can be
# read without the memory plan.
ORE_ANNEX_MODULE, ORE_ANNEX_MAGIC = "ore_work.rel", (0x4F52, 0x4558)

# The My Life Giants signing scene (and the other scenes of gdt_pn.rel) is run by the same interpreter: the
# script parses with ORE_OP_LEN, 61 labels in a table of its own (sec5+768). Its module cannot grow either
# (it shares its slot with gdt_o_c6 .. gdt_scc), so its overflow goes to a second annex behind the first one
# in ore_work.rel, marked "PNEX". Three returns behind a goto are unreachable (kept).
BLOCK_SCRIPTS["gdt_pn.rel"] = {"engine": "ore", "section": 5, "region": (1240, 7440), "labels": (768, 1012),
                               "islands": (), "ends": (0x08, 0x34, 0x35), "name_ops": (0x1C, 0x3F), "max_op": 0x49,
                               "line": 16, "marks": {0x01: "L", 0x06: "B", 0x07: "B"}, "dead": 3,
                               "annex_section": 5, "annex_from": 2168, "annex_magic": (0x504E, 0x4558)}


class OreScript(BlockScript):
    """The My Life script (see ORE_OP_LEN). Same attributes as BlockScript; an opcode is the whole halfword.
    With an annex (built files) the halfwords of the annex follow those of the section, from self.annex_at."""

    def __init__(self, rel, spec, annex_rel=None):
        self.rel, self.spec, self.sec = rel, spec, spec["section"]
        self.region, self.ends, self.name_ops = spec["region"], spec["ends"], spec["name_ops"]
        d = rel.sec_data(self.sec)
        self.sec_file_offset = rel.sections[self.sec]["offset"]
        hw = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
        self.annex_at, self.annex_base = len(hw), None
        if annex_rel is not None:
            # the annexes stand one behind the other from annex_from, each a multiple of 8 bytes long; a header
            # is its magic and its own address, so the first one dates the others
            a = annex_rel.sec_data(spec["annex_section"])[spec["annex_from"]:]
            magic = spec.get("annex_magic", ORE_ANNEX_MAGIC)
            first = struct.unpack_from(">I", a, 4)[0] if len(a) >= 8 and struct.unpack_from(">2H", a) in \
                [s.get("annex_magic", ORE_ANNEX_MAGIC) for s in BLOCK_SCRIPTS.values() if s.get("engine") == "ore"] \
                else None
            for p in range(0, len(a) - 7 if first is not None else 0, 8):
                if struct.unpack_from(">2H", a, p) == magic and struct.unpack_from(">I", a, p + 4)[0] == first + p:
                    self.annex_base = first + p + 8
                    hw += struct.unpack(">%dH" % (len(a) // 2 - p // 2 - 4), a[p + 8:len(a) // 2 * 2])
                    break
        self.hw = hw
        self.labels = collections.Counter()
        for (s, pos, typ, tm, ts, addend) in rel.relocs():
            if s == self.sec and typ == 1 and spec["labels"][0] <= pos < spec["labels"][1]:
                if (tm, ts) == (rel.mod_id, self.sec) and addend % 2 == 0 and self.region[0] <= addend < self.region[1]:
                    self.labels[addend // 2] += 1
                elif tm == 0 and self.annex_base is not None and addend % 2 == 0 \
                        and 0 <= addend - self.annex_base < (len(hw) - self.annex_at) * 2:
                    self.labels[self.annex_at + (addend - self.annex_base) // 2] += 1
                else:
                    raise ValueError("%s: label table entry at +%d points outside the script" % (rel.name, pos))
        self.kind, self.texts = {}, {}
        self.op_count, self.errors = collections.Counter(), collections.Counter()
        self._parse()
        for i in range(self.region[0] // 2, self.region[1] // 2):
            if i not in self.kind and self.hw[i] and not self.in_island(i * 2):
                self.kind[i] = "dead"
        if sum(k == "dead" for k in self.kind.values()) > spec["dead"]:
            self.errors["data between the instructions"] += 1

    def op(self, i):
        return self.hw[i]

    def in_island(self, off):
        return any(a <= off < b for a, b in self.spec["islands"])

    def inside(self, i):
        """True where an instruction may stand: the script without its islands, or the annex."""
        return (self.region[0] <= i * 2 < self.region[1] and not self.in_island(i * 2)) or \
            self.annex_at <= i < len(self.hw)

    def segments(self):
        """The stretches of the region between the islands, as (first, end) section offsets."""
        cuts = [self.region[0]] + [x for isl in self.spec["islands"] for x in isl] + [self.region[1]]
        return list(zip(cuts[0::2], cuts[1::2]))

    def label_table(self):
        """Halfword index of every label, in the order of the table (a jump names a label by its number)."""
        a, b = self.spec["labels"]
        at = {pos: addend // 2 for (s, pos, typ, tm, ts, addend) in self.rel.relocs()
              if s == self.sec and typ == 1 and a <= pos < b}
        return [at[pos] for pos in range(a, b, 4)]

    def routine_text(self, i, limit=40):
        """The text a routine prints before it returns (for the notes of the scene files)."""
        out, depth = [], 0
        while len(out) < limit and self.kind.get(i) == "op":
            op = self.hw[i]
            if i in self.texts:
                out.append(decode_units(self.texts[i][1]))
                i = self.texts[i][2]
                continue
            n = self._length(i)
            if op in self.name_ops:
                out.append("{name}")
            elif op == ORE_BLOCK or (op in ORE_IF + (ORE_ELSE,) and self.hw[i + n - 1] == ORE_BLOCK):
                depth += 1
            elif op == ORE_BLOCK_END:
                depth -= 1
            if op in self.ends and depth <= 0:
                break
            i += n
        return "".join(out)

    def _length(self, i):
        op = self.hw[i]
        return 2 + self.hw[i + 1] if op == ORE_LIST else ORE_OP_LEN.get(op, 1)

    def _parse(self):
        hw, kind = self.hw, self.kind
        for start in sorted(self.labels):
            i, depth = start, 0
            while True:
                if not self.inside(i):
                    self.errors["runs out of the script"] += 1
                    break
                if i in kind:
                    if kind[i] != "op":
                        self.errors["label lands mid-instruction"] += 1
                    break
                op = hw[i]
                self.op_count[op] += 1
                kind[i] = "op"
                if op == OP_TEXT:
                    r = unpack_text(hw, i + 1)
                    if r is None or not self.inside(r[1] - 1) or not units_valid(r[0]) \
                            or list(hw[i + 1:r[1]]) != pack_text(r[0]):
                        self.errors["bad text run"] += 1
                        break
                    units, j = r
                    for k in range(i + 1, j):
                        kind[k] = "text"
                    self.texts[i] = (0, units, j)
                    i = j
                    continue
                if self.spec["max_op"] < op < ORE_BLOCK:
                    self.errors["unknown opcode"] += 1
                    break
                n = self._length(i)
                for k in range(i + 1, min(i + n, len(hw))):
                    kind[k] = "arg"
                if op == ORE_BLOCK or (op in ORE_IF + (ORE_ELSE,) and hw[i + n - 1] == ORE_BLOCK):
                    depth += 1
                elif op == ORE_BLOCK_END:
                    depth -= 1
                    if depth < 0:
                        self.errors["block end without a block"] += 1
                        break
                if op in self.ends and depth == 0:
                    break
                i += n


def load_block_scripts(mods=None):
    mods = mods or load_all_rels()
    by_name = {m.name: m for m in mods.values()}
    return [OreScript(by_name[fn], spec, by_name.get(ORE_ANNEX_MODULE)) if spec.get("engine") == "ore"
            else BlockScript(by_name[fn], spec) for fn, spec in BLOCK_SCRIPTS.items()]


# ── extract ───────────────────────────────────────────────────────────────

def cmd_extract(args):
    scripts = load_scripts()
    tot = collections.Counter()
    samples, dump, spans = [], [], []
    print("%-13s %7s %7s %7s %8s %8s %9s %9s" % ("file", "labels", "runs", "empty", "glyphs",
                                                  "pages", "coverage", "roundtrip"))
    for sc in scripts:
        runs = empty = glyphs = rt_ok = invalid = 0
        controls = collections.Counter()
        # Page number in address order: a page ends at each wait-for-button command.
        page_of, page = {}, 0
        for i in sorted(k for k, v in sc.kind.items() if v == "op"):
            if i in sc.texts:
                page_of[i] = page
            elif sc.hw[i] & 0xFF in (OP_WAIT, OP_NEWLINE_WAIT):
                page += 1
        for i in sorted(sc.texts):
            window, units, j = sc.texts[i]
            runs += 1
            if not units:
                empty += 1
            glyphs += sum(1 for u in units if u <= MAX_GLYPH)
            for u in units:
                if u > MAX_GLYPH:
                    controls[u] += 1
            if list(sc.hw[i + 1:j]) == pack_text(units):
                rt_ok += 1
            if not units_valid(units):
                invalid += 1
                continue
            text = decode_units(units)
            if args.dump:
                dump.append({"file": sc.rel.name, "section": sc.sec, "file_offset": sc.offset_of(i),
                             "section_offset": i * 2, "page": page_of[i], "window": window,
                             "bytes": (j - i - 1) * 2,
                             "glyphs": len(units), "text": text})
            if 6 <= len(units) <= 16 and TEXT_NEWLINE not in units and is_quality_text(text):
                samples.append((sc.rel.name, sc.offset_of(i), text))
        pages = sc.op_count[OP_WAIT] + sc.op_count[OP_NEWLINE_WAIT]
        lo, hi = min(sc.kind), max(sc.kind) + 1
        cov = 100.0 * len(sc.kind) / (hi - lo)
        spans.append((sc.rel.name, sc.sec, sc.offset_of(lo), sc.offset_of(hi), lo * 2, hi * 2))
        print("%-13s %7d %7d %7d %8d %8d %8.1f%% %5d/%d" % (sc.rel.name, len(sc.labels), runs, empty,
                                                             glyphs, pages, cov, rt_ok, runs))
        if controls:
            print("    non-glyph units: " + ", ".join("0x%03X x%d" % kv for kv in controls.most_common(8)))
        if invalid or sc.errors:
            print("    invalid runs: %d  parse notes: %s" % (invalid, dict(sc.errors)))
        tot.update(runs=runs, empty=empty, glyphs=glyphs, pages=pages, rt=rt_ok)
    print("%-13s %7s %7d %7d %8d %8d %9s %5d/%d" % ("TOTAL", "", tot["runs"], tot["empty"], tot["glyphs"],
                                                    tot["pages"], "", tot["rt"], tot["runs"]))
    print("\nruns = text runs (one on-screen line each), pages = wait-for-button commands (0x49/0x4A)")
    print("labels = distinct script entry points, coverage = share of the script region reached\n")
    print("Script regions:")
    for name, sec, f0, f1, s0, s1 in spans:
        print("  %-13s sec%d+0x%06X..0x%06X  (file 0x%06X..0x%06X, %d KB)" % (name, sec, s0, s1, f0, f1, (s1 - s0) // 1024))

    if args.samples and samples:
        step = max(1, len(samples) // args.samples)
        print("\nSample lines (file, file offset, text):")
        for name, off, text in samples[step // 2::step][:args.samples]:
            print("  %-13s 0x%06X  %s" % (name, off, text))

    if args.dump:
        os.makedirs(WORK_DIR, exist_ok=True)
        path = os.path.join(WORK_DIR, "story_text.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(dump, f, ensure_ascii=False, indent=1)
        print("\nWrote %d runs to %s (git-ignored; do not commit)" % (len(dump), path))


# ── xref ──────────────────────────────────────────────────────────────────

def _capstone():
    try:
        from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
    except ImportError:
        sys.exit("xref needs capstone: pip install capstone")
    return Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)


class Code:
    """Disassembly of one executable section, with relocation annotations."""

    def __init__(self, rel, sec=1):
        self.rel, self.sec = rel, sec
        self.code = rel.sec_data(sec)
        self.md = _capstone()
        self.rmap = collections.defaultdict(list)
        for (s, pos, typ, tm, ts, addend) in rel.relocs():
            if s == sec:
                self.rmap[pos & ~3].append((typ, tm, ts, addend))

    def ins(self, a):
        i = next(self.md.disasm(self.code[a:a + 4], a), None)
        return (i.mnemonic, i.op_str) if i else (".long", "0x%08x" % struct.unpack_from(">I", self.code, a)[0])

    def line(self, a):
        mn, ops = self.ins(a)
        notes = "".join("  ; %s -> m%d:s%d+0x%x" % (RELOC_NAMES.get(t, t), tm, ts, ad)
                        for t, tm, ts, ad in self.rmap.get(a, []))
        return "  %06x: %s %s%s" % (a, mn, ops, notes)

    def show(self, start, end):
        for a in range(start, end, 4):
            print(self.line(a))


VM_EXITS = {0x39174, 0x39188, 0x39198, 0x35664, 0x34EF8}
VM_IP = "0x2d8(r15)"


def derive_op_advance(code, entry, limit=3000):
    """Follow a handler and collect how far it moves the script pointer (bytes after the
    opcode halfword), or 'J' when the pointer is replaced (jump/call/redirect)."""
    out, seen, steps = set(), set(), 0
    stack = [(entry, 0, (("r3", 0),))]     # at entry r3 = pointer just past the opcode
    volatile = ["r0"] + ["r%d" % i for i in range(3, 13)]
    while stack and steps < limit:
        a, cur, regs = stack.pop()
        reg = dict(regs)
        while steps < limit:
            key = (a, cur, tuple(sorted(reg.items())))
            if key in seen:
                break
            seen.add(key)
            steps += 1
            if a in VM_EXITS:
                out.add(cur)
                break
            mn, ops = code.ins(a)
            o = [x.strip() for x in ops.split(",")] if ops else []
            if mn == "lwz" and len(o) == 2 and o[1] == VM_IP:
                reg.pop(o[0], None)
                if cur != "J":
                    reg[o[0]] = cur
            elif mn == "stw" and len(o) == 2 and o[1] == VM_IP:
                cur = reg.get(o[0], "J")
            elif mn == "addi" and len(o) == 3 and o[1] in reg:
                reg[o[0]] = reg[o[1]] + int(o[2], 0)
            elif mn == "mr" and len(o) == 2 and o[1] in reg:
                reg[o[0]] = reg[o[1]]
            elif mn == "bl":
                for v in volatile:
                    reg.pop(v, None)
            elif mn == "b":
                a = int(o[0], 0)
                continue
            elif mn in ("blr", "bctr"):
                out.add(cur)
                break
            elif mn.startswith("b") and mn != "bctrl" and o and o[-1].startswith("0x"):
                stack.append((int(o[-1], 0), cur, tuple(sorted(reg.items()))))
            elif not mn.startswith(("st", "cmp")) and o and o[0] in reg:
                reg.pop(o[0], None)
            a += 4
    if steps >= limit:
        out.add("loop")
    return out


def cmd_xref(args):
    mods = load_all_rels()
    by_name = {m.name: m for m in mods.values()}
    main, work = by_name["scs_main.rel"], by_name["work_scs.rel"]
    code = Code(main)

    print("== 1. Text-mode switch: opcode 0x00 handler (scs_main sec1+0x0356B0)")
    print("   hi byte -> r15+0x19C (window type), 0 -> r15+0x1A0 (current opcode = text mode)")
    code.show(0x356B0, 0x356C0)

    print("\n== 2. 12-bit unit reader (scs_main sec1+0x034F08)")
    print("   phase at r15+0x1A2 picks 12 bits; 0xFFF -> 0xFFFF (end), 0xFFE -> line break")
    code.show(0x34F08, 0x34FAC)
    print("   phase/pointer advance (sec1+0x033360), end-of-run realignment (sec1+0x0351C8):")
    code.show(0x351C8, 0x3520C)

    print("\n== 3. Label lookup used by goto/call/if (scs_main sec1+0x05E3F0)")
    code.show(0x5E3F0, 0x5E460)
    print("   Label tables (scs_main sec5, all zero in the file, filled by relocations):")
    bases = [r[0][3] for r in (_data_relocs(main, 5, 0xD0870 + k * 4) for k in range(3))]
    for k, base in enumerate(bases):
        end = bases[k + 1] if k + 1 < len(bases) else LABEL_TABLES[1]
        n = collections.Counter()
        for off in range(base, end, 4):
            for (_, tm, ts, _) in _data_relocs(main, 5, off):
                n["%s sec%d" % (mods[tm].name, ts)] += 1
        print("   table %d at sec5+0x%X..0x%X: %s" % (k, base, end, ", ".join("%d -> %s" % (v, t) for t, v in n.items())))
    for fn in SCRIPT_FILES:
        m = by_name[fn]
        sec = m.script_section()
        if m is main:
            continue
        n = collections.Counter()
        for src in mods.values():
            for (s, _, typ, tm, ts, _) in src.relocs():
                if tm == m.mod_id and ts == sec:
                    n[(src.name, "sec%d" % s, RELOC_NAMES.get(typ, typ))] += 1
        print("   pointers into %s sec%d: %s" % (fn, sec, ", ".join("%s %s %s x%d" % (k + (v,))
                                                                  for k, v in n.most_common(4))))

    print("\n== 4. Opcode lengths re-derived from the 254 handlers (jump table sec5+0x0FF63C)")
    table = [code_reloc[0][3] if code_reloc else 0 for code_reloc in
             (_data_relocs(main, 5, 0x0FF63C + op * 4) for op in range(0xFE))]
    mismatch = []
    for op, entry in enumerate(table):
        adv = derive_op_advance(code, entry)
        ints = sorted(x for x in adv if isinstance(x, int) and x >= 0)
        if op in (OP_IF, OP_SKIPLIST):
            continue                       # variable length, handled in instruction_length()
        derived = (ints[-1] // 2 + 1) if ints else 2 if op in (0x9B, 0x9C, 0xA6, 0xDA) else 1
        if derived != OP_LEN[op]:
            mismatch.append("%02X: table %d, derived %d %s" % (op, OP_LEN[op], derived, sorted(map(str, adv))))
    print("   mismatches against OP_LEN: %s" % (mismatch or "none"))

    print("\n== 5. Who uses V+0x911C / V+0x91B0 (V = pointer at work_scs BSS+0x3460)")
    bss = [s["index"] for s in work.sections if s["bss"]][0]
    users = collections.Counter()
    for m in mods.values():
        for (_, _, _, tm, ts, addend) in m.relocs():
            if tm == work.mod_id and ts == bss and addend == 0x3460:
                users[m.name] += 1
    print("   modules referencing BSS+0x3460: " + ", ".join("%s x%d" % kv for kv in users.most_common(6)) + " ...")
    md = _capstone()
    for m in mods.values():
        for s in m.sections:
            if not (s["exec"] and s["size"]) or s["bss"]:
                continue
            d = m.sec_data(s["index"])
            for off in range(0, len(d) - 3, 4):
                if d[off + 2:off + 4] in (b"\x91\x1c", b"\x91\xb0"):
                    i = next(md.disasm(d[off:off + 4], off), None)
                    if i and re.search(r"-0x6e(e4|50)\b", i.op_str):
                        print("   %-13s sec%d+0x%06x: %s %s" % (m.name, s["index"], off, i.mnemonic, i.op_str))
    print("   Name generator writing V+0x911C from the scc_main surname table (sec1+0x009D90):")
    code.show(0x9D94, 0x9DC4)

    print("\n== 6. Callers of the 'scene setup' function scs_main sec1+0x033068")
    for m in mods.values():
        for (s, pos, typ, tm, ts, addend) in m.relocs():
            if tm == main.mod_id and ts == 1 and addend == 0x33068:
                print("   %s sec%d+0x%x (%s)" % (m.name, s, pos, RELOC_NAMES.get(typ, typ)))
    print("   It copies names (text copier, max 6 glyphs) from V+0x911C / V+0x91B0:")
    code.show(0x3324C, 0x33284)


def _data_relocs(rel, sec, off):
    if not hasattr(rel, "_dmap"):
        rel._dmap = collections.defaultdict(list)
        for (s, pos, typ, tm, ts, addend) in rel.relocs():
            rel._dmap[(s, pos)].append((typ, tm, ts, addend))
    return rel._dmap.get((sec, off), [])


# ── entropy ───────────────────────────────────────────────────────────────

def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(b).values())


def sampled_entropy(path, chunk=1 << 22):
    """Whole-file entropy; files over 12MB are sampled at start, middle and end."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        if size <= 3 * chunk:
            return entropy(f.read()), False
        parts = []
        for pos in (0, size // 2, size - chunk):
            f.seek(pos)
            parts.append(f.read(chunk))
        return entropy(b"".join(parts)), True


def cmd_entropy(args):
    win = 16384
    print("Section entropy, bits/byte (compressed or encrypted data is above ~7.5)\n")
    for fn in SCRIPT_FILES + ["work_scs.rel"]:
        rel = Rel(os.path.join(DATA_FILES, fn))
        for s in rel.sections:
            if not s["size"]:
                continue
            if s["bss"]:
                print("%-13s sec%-2d BSS   size 0x%06x (not stored in the file)" % (fn, s["index"], s["size"]))
                continue
            d = rel.sec_data(s["index"])
            ws = [entropy(d[a:a + win]) for a in range(0, len(d), win)]
            high = sum(1 for w in ws if w > 7.5)
            print("%-13s sec%-2d %-5s size 0x%06x  whole %.2f  16KB windows min %.2f max %.2f  high: %d"
                  % (fn, s["index"], "code" if s["exec"] else "data", s["size"], entropy(d), min(ws), max(ws), high))
    print("\nWhole-file entropy by type (* = sampled, large file)\n")
    by_ext = collections.defaultdict(list)
    for root, _, files in os.walk(DATA_FILES):
        for fn in files:
            ext = os.path.splitext(fn)[1].lower() or "(none)"
            if ext in (".thp", ".rsd"):
                continue
            path = os.path.join(root, fn)
            e, sampled = sampled_entropy(path)
            by_ext[ext].append((e, os.path.relpath(path, DATA_FILES), os.path.getsize(path), sampled))
    for ext, rows in sorted(by_ext.items()):
        es = [r[0] for r in rows]
        high = sorted((r for r in rows if r[0] > 7.5), reverse=True)
        print("%-8s files %4d  mean %.2f  max %.2f  above 7.5: %d" % (ext, len(rows), sum(es) / len(es), max(es), len(high)))
        for e, rel_path, size, sampled in high[:args.top]:
            print("      %.2f%s %-28s %d bytes" % (e, "*" if sampled else " ", rel_path, size))


# ── scan ──────────────────────────────────────────────────────────────────

def is_kana(u):
    return 282 <= u <= 450       # glyph rows for hiragana and katakana


def find_packed_text(data, min_units=5):
    """Heuristic search for 12-bit packed text in arbitrary data: a halfword XX00
    (XX <= 0x1F) followed by a kana-rich run of valid units, 0xFFF, and 0xF padding.
    It undercounts (short or kana-poor lines are skipped); use Script for real parsing."""
    n = len(data) // 2
    hw = struct.unpack(">%dH" % n, data[:n * 2])
    hits, skip_to = [], 0
    for m in re.finditer(rb"[\x00-\x1f]\x00", data):
        p = m.start()
        if p % 2 or p // 2 < skip_to:
            continue
        i = p // 2
        if i + 2 >= n or hw[i + 1] == 0:
            continue
        r = unpack_text(hw, i + 1, max_units=500, strict=True)
        if r is None:
            continue
        units, j = r
        if len(units) < min_units or not units_valid(units):
            continue
        if sum(map(is_kana, units)) < 0.4 * len(units):
            continue
        if list(hw[i + 1:j]) != pack_text(units):
            continue
        hits.append((p, units))
        skip_to = j
    return hits


def decompress_yaz0(d, pos):
    size = struct.unpack_from(">I", d, pos + 4)[0]
    if not 16 <= size <= 1 << 26:
        return None
    out, p = bytearray(), pos + 16
    try:
        while len(out) < size:
            flags = d[p]; p += 1
            for bit in range(8):
                if len(out) >= size:
                    break
                if flags & (0x80 >> bit):
                    out.append(d[p]); p += 1
                else:
                    b1, b2 = d[p], d[p + 1]; p += 2
                    dist = ((b1 & 0xF) << 8 | b2) + 1
                    n = b1 >> 4
                    if n == 0:
                        n = d[p] + 0x12; p += 1
                    else:
                        n += 2
                    if dist > len(out):
                        return None
                    for _ in range(n):
                        out.append(out[-dist])
    except IndexError:
        return None
    return bytes(out)


def decompress_lz(d, pos):
    """Nintendo LZ10 / LZ11 (header byte 0x10 / 0x11 + 24-bit little-endian size)."""
    kind = d[pos]
    size = d[pos + 1] | d[pos + 2] << 8 | d[pos + 3] << 16
    if kind not in (0x10, 0x11) or not 64 <= size <= 1 << 26:
        return None
    out, p = bytearray(), pos + 4
    try:
        while len(out) < size:
            flags = d[p]; p += 1
            for bit in range(8):
                if len(out) >= size:
                    break
                if not flags & (0x80 >> bit):
                    out.append(d[p]); p += 1
                    continue
                if kind == 0x10:
                    n = (d[p] >> 4) + 3
                    dist = ((d[p] & 0xF) << 8 | d[p + 1]) + 1; p += 2
                else:
                    ind = d[p] >> 4
                    if ind == 0:
                        n = ((d[p] & 0xF) << 4 | d[p + 1] >> 4) + 0x11
                        dist = ((d[p + 1] & 0xF) << 8 | d[p + 2]) + 1; p += 3
                    elif ind == 1:
                        n = ((d[p] & 0xF) << 12 | d[p + 1] << 4 | d[p + 2] >> 4) + 0x111
                        dist = ((d[p + 2] & 0xF) << 8 | d[p + 3]) + 1; p += 4
                    else:
                        n = ind + 1
                        dist = ((d[p] & 0xF) << 8 | d[p + 1]) + 1; p += 2
                if dist > len(out):
                    return None
                for _ in range(n):
                    out.append(out[-dist])
    except IndexError:
        return None
    if p - pos < 32 or len(out) < 2 * (p - pos) // 3:
        return None
    return bytes(out)


def count_16bit_text(data):
    """Count quality runs of plain 16-bit glyph text (the format used in REL data tables)."""
    n = len(data) // 2
    hw = struct.unpack(">%dH" % n, data[:n * 2])
    runs, cur = 0, []
    for v in hw:
        ch = glyph_to_char(v & 0x1FFF) if v not in (0, 0x1FFF, 0xFFFF) else None
        if ch:
            cur.append(ch)
            continue
        if len(cur) >= 4 and is_quality_text("".join(cur)) and sum(0x3040 <= ord(c) <= 0x30FF for c in cur) >= 2:
            runs += 1
        cur = []
    return runs


def cmd_scan(args):
    print("Packed 12-bit text and compressed-data scan of DATA/files")
    print("(skipping .thp/.rsd%s)\n" % ("" if args.all else " and sound/; use --all to include sound"))
    packed, comp, nfiles = [], [], 0
    for root, dirs, files in os.walk(DATA_FILES):
        if not args.all and os.path.basename(root) == "sound":
            dirs[:] = []
            continue
        for fn in sorted(files):
            if fn.lower().endswith((".thp", ".rsd")):
                continue
            path = os.path.join(root, fn)
            rel_path = os.path.relpath(path, DATA_FILES)
            nfiles += 1
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                chunk_no = 0
                while True:
                    data = f.read(1 << 24)
                    if not data:
                        break
                    hits = find_packed_text(data)
                    if hits:
                        packed.append((rel_path, len(hits), sum(len(u) for _, u in hits)))
                    # compressed-stream candidates: magic words anywhere, LZ headers at chunk start
                    cands = [(m.start(), "Yaz0") for m in re.finditer(rb"Yaz0", data)]
                    if chunk_no == 0 and size > 64 and data[0] in (0x10, 0x11):
                        cands.append((0, "LZ%02X" % data[0]))
                    if chunk_no == 0 and fn.endswith(".rel") and size > 0x40:
                        for s in Rel(path).sections:
                            o = s["offset"]
                            if o and s["size"] > 64 and data[o] in (0x10, 0x11):
                                cands.append((o, "LZ%02X" % data[o]))
                    for pos, kind in cands:
                        out = decompress_yaz0(data, pos) if kind == "Yaz0" else decompress_lz(data, pos)
                        if out:
                            comp.append((rel_path, pos, kind, len(out), len(find_packed_text(out)), count_16bit_text(out)))
                    chunk_no += 1
    print("Files scanned: %d\n" % nfiles)
    print("Files containing 12-bit packed text runs:")
    for rel_path, runs, glyphs in sorted(packed, key=lambda r: -r[1]):
        print("  %-28s runs %6d  glyphs %7d" % (rel_path, runs, glyphs))
    if not packed:
        print("  none")
    print("\nCompressed streams that decompress cleanly (Yaz0 / LZ10 / LZ11):")
    for rel_path, pos, kind, n, p12, p16 in comp:
        print("  %-28s +0x%x %s -> %d bytes, packed-text runs %d, 16-bit text runs %d" % (rel_path, pos, kind, n, p12, p16))
    if not comp:
        print("  none")


# ── main ──────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("extract", help="parse scripts, count lines, verify re-encoding")
    p.add_argument("--samples", type=int, default=8, help="sample lines to print (default 8)")
    p.add_argument("--dump", action="store_true", help="write all text to _work/story_text.json")
    p.set_defaults(func=cmd_extract)
    p = sub.add_parser("xref", help="code evidence (needs capstone)")
    p.set_defaults(func=cmd_xref)
    p = sub.add_parser("entropy", help="entropy map")
    p.add_argument("--top", type=int, default=5, help="high-entropy files to list per type")
    p.set_defaults(func=cmd_entropy)
    p = sub.add_parser("scan", help="search all files for packed text and compressed data")
    p.add_argument("--all", action="store_true", help="include the sound/ directory (slow)")
    p.set_defaults(func=cmd_scan)
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return
    if not os.path.isdir(DATA_FILES):
        sys.exit("Game files not found at %s" % DATA_FILES)
    args.func(args)


if __name__ == "__main__":
    main()
