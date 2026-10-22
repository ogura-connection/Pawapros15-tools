"""The story scripts of the modes other than Success Mode: Eikan Nine, the in-match player lines, and My Life.

Success Mode's script (pp15/script/scripts.py) lives in a section of its own. The scripts here run on interpreters of
their own and share their section with other data, so each is described by a "spec" (a dictionary in BLOCK_SCRIPTS)
giving the part of the section that holds the script ("region"), the table of entry points ("labels"), the length of
every opcode, which opcodes end a scene and which insert a player name.

  Eikan Nine (sct_main.rel)   Success Mode's second story, in the same instruction format.
  Match lines (scs_comi.rel)  what the player says during a Success match ("I'll hit a homer!", answers to a sign).
  My Life (orepena.rel, gdt_pn.rel, koukai.rel)  the career mode; its engine uses a whole 16-bit halfword as the opcode.

Public names:
  BLOCK_SCRIPTS                 the specs, keyed by module file name
  BlockScript                   a parsed script of the Success-Mode instruction format (Eikan Nine, match lines)
  OreScript                     a parsed My Life script (adds annex handling, see below)
  load_block_scripts(mods)      parse all of them
  ORE_* constants               My Life opcodes and the annex marker
"""
import collections
import struct
from typing import Dict, List, Optional

from pp15.script.packed_text import decode_units, pack_text, unpack_text, units_valid
from pp15.script.rel import Rel, load_all_rels
from pp15.script.scripts import OP_IF, OP_TEXT, Script, instruction_length, opcode_lengths

# ── Eikan Nine ────────────────────────────────────────────────────────────
# sct_main.rel runs the same kind of script with an interpreter of its own (section 1 offset 0x22C18: script pointer at
# r31+0x200, 207 opcodes, jump table at section 5 offset 0x32A0). Text mode, the waits, the name inserts and the
# conditions (0x00..0x66) are numbered as in Success Mode; the later opcodes are not. The lengths were read off the
# handlers (how far each moves the script pointer) and parse the whole script without error. The label table stands
# behind the script in the same section and is filled by the module's own relocations; five entry points are also
# addressed from sct_card.rel and sct_sugo.rel.
EIKAN_OP_LEN = opcode_lengths({
    2: [0x69, 0x6A, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x74, 0x75, 0x76, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x82, 0x83, 0x84, 0x85, 0x87, 0x88, 0x8A, 0x8D, 0x8E, 0x92, 0xA1, 0xA2, 0xA9, 0xAA, 0xAB, 0xAC,
        0xB3, 0xB4, 0xB9, 0xBA, 0xBC, 0xBD, 0xC1, 0xC2, 0xC6, 0xC7, 0xC8, 0xCB, 0xCD],
    3: list(range(0x26, 0x46)) + [0x89],
    4: list(range(0x16, 0x26)),
})

# ── Match lines ───────────────────────────────────────────────────────────
# The player's lines during a Success match (scs_comi.rel) run on an interpreter of their own (section 1 offset
# 0x1CF8: script pointer at r15+0x154, 141 opcodes, jump table at section 5 offset 0x3DC), numbered like Success Mode.
# Lengths were read off the handlers; 0x66 / 0x67 move the pointer in a helper (section 1 offsets 0x2B58 / 0x2C20).
# 0x75 goto and 0x76 call take a label number from the table that section 5 offset 0x2D90 points to (offset 11672,
# 347 labels; the last entry, offset 13064, is a lone dummy text run behind the table and stays as it is).
# 0x4B / 0x4C insert a name. Four halfwords behind a goto at offset 1846 are unreachable.
COMI_OP_LEN = opcode_lengths({
    2: [0x5F, 0x60, 0x62, 0x63, 0x65, 0x66, 0x67, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x71, 0x72, 0x73, 0x75, 0x76,
        0x78, 0x88],
    3: list(range(0x26, 0x46)) + [0x77],
    4: list(range(0x16, 0x26)),
})

# ── My Life ───────────────────────────────────────────────────────────────
# My Life (orepena.rel) has an engine of its own: the interpreter is ore_work.rel section 1 offset 0x1CE4 (script
# pointer at r15+0x58, label table pointer at r15+0x4C), and section 1 offset 0x3BE0 skips a block, which gives every
# length. An instruction is a whole halfword: 0000 text (the same 12-bit packing, read at section 1 offset 0x3F30; line
# breaks are instructions, not units), 0001 new line, 0006 / 0007 wait for a button, 0008 return, 0018 window,
# 001C insert a name or number, 0032 call, 0033 / 0034 mark and jump back, 0035 goto, 0036 / 0037 if and 0038 else
# (followed by FFF0 .. FFF1 around a block, or by one label), 003C a list with its count.
# Jumps take a label number; the table (section 5 offset 173464, 1,852 entries) is filled by the module's relocations
# and nothing else points into the script. Three "islands" of other data (tables with relocations of their own, debug
# strings) lie between the scenes and stay where they are.
ORE_OP_LEN = {0x04: 2, 0x09: 2, 0x17: 6, 0x18: 3, 0x19: 3, 0x1A: 3, 0x1B: 3, 0x1C: 5, 0x32: 2, 0x33: 2, 0x34: 2,
              0x35: 2, 0x36: 6, 0x37: 6, 0x38: 2, 0x39: 3, 0x3A: 4, 0x3B: 3, 0x3E: 2, 0x3F: 2, 0x41: 2, 0x42: 4,
              0x43: 5, 0x44: 5, 0x46: 2, 0x47: 4, 0x48: 6, 0x49: 8}
ORE_LIST, ORE_BLOCK, ORE_BLOCK_END = 0x3C, 0xFFF0, 0xFFF1
ORE_IF, ORE_ELSE, ORE_WINDOW = (0x36, 0x37), 0x38, 0x18

# English needs more room than the script has (its module cannot grow: the next ones start where it ends), so the
# build moves the scenes that do not fit to an "annex" behind the data of ore_work.rel, which the game loads in the
# free memory above the memory plan. A label of such a scene is filled by a relocation against main.dol, that is an
# absolute address. The annex starts with a four-letter marker (ORE_ANNEX_MAGIC, as two 16-bit values) and its own
# address, so a built file can be read without the memory plan. Modules that cannot grow get an annex each, one behind
# the other: "OREX" for orepena.rel, "PNEX" for gdt_pn.rel, "KKEX" for koukai.rel.
ORE_ANNEX_MODULE, ORE_ANNEX_MAGIC = "ore_work.rel", (0x4F52, 0x4558)
ORE_MARKS = {0x01: "L", 0x06: "B", 0x07: "B"}       # opcode -> layout mark (new line / new box), see translate.py


def _ore_spec(**changes) -> dict:
    """A My Life spec: the values the three My Life modules share, with `changes` on top."""
    spec = {"engine": "ore", "section": 5, "ends": (0x08, 0x34, 0x35), "name_ops": (0x1C, 0x3F), "max_op": 0x49,
            "line": 16, "marks": ORE_MARKS, "annex_section": 5, "annex_from": 2168}
    spec.update(changes)
    return spec


# Keys of a spec: "region" = the script, "labels" = its label table (section offsets); "list" = the opcode followed by
# values up to a zero; "ends" = opcodes that end a scene (return, goto); "max_op" = highest valid opcode; "name_ops" =
# opcodes that insert a name; "line" = cells a line may take; "dead" = how many halfwords of unreachable data are
# tolerated; "islands" = stretches of other data inside the region; "marks" = layout mark of an opcode.
BLOCK_SCRIPTS = {
    "sct_main.rel": {"section": 5, "region": (14416, 189368), "labels": (189372, 210644),
                     "op_len": EIKAN_OP_LEN, "list": 0x67, "ends": (0x01, 0x87), "max_op": 0xCE,
                     "name_ops": tuple(range(0x4B, 0x51)), "line": 18},     # the Japanese rarely passes 18 cells
    "scs_comi.rel": {"section": 5, "region": (1800, 11664), "labels": (11672, 13060),
                     "op_len": COMI_OP_LEN, "list": 0x5D, "ends": (0x01, 0x75), "max_op": 0x8C,
                     "name_ops": (0x4B, 0x4C), "line": 17, "dead": 4},
    "orepena.rel": _ore_spec(region=(182584, 803170), labels=(173464, 180872),
                             islands=((187254, 189808), (228090, 229016), (779308, 780240)), dead=400),
    # The Giants signing scene (and the other scenes of gdt_pn.rel) uses the same interpreter: 61 labels in a table of
    # its own (offset 768). Three returns behind a goto are unreachable (kept).
    "gdt_pn.rel": _ore_spec(region=(1240, 7440), labels=(768, 1012), islands=(), dead=3,
                            annex_magic=(0x504E, 0x4558)),
    # koukai.rel (a My Life module: it imports ore_work.rel and orepena.rel) holds a script of the same kind at the end
    # of its data: 32 labels in a table at offset 112, nothing else points into it.
    "koukai.rel": _ore_spec(region=(1328, 8672), labels=(112, 240), islands=(), dead=3,
                            annex_magic=(0x4B4B, 0x4558)),
}


class BlockScript(Script):
    """A script that shares its section with other data (see BLOCK_SCRIPTS). Same attributes as Script.

    Halfwords of the region that no instruction covers are zero padding in front of a label (every label is at a
    multiple of 4 and follows a return or a goto); kind "dead" marks other data that nothing reaches."""

    def __init__(self, rel: Rel, spec: dict):
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
        for i in range(lo, hi):             # sct_main.rel has one return at offset 90684 that nothing reaches: kept
            if i not in self.kind and self.hw[i] and not any(a <= i * 2 < b for a, b in spec.get("islands", ())):
                self.kind[i] = "dead"
        if sum(k == "dead" for k in self.kind.values()) > spec.get("dead", 1):
            self.errors["data between the instructions"] += 1

    def op(self, i: int) -> int:
        """Opcode of the instruction at halfword i (the low byte)."""
        return self.hw[i] & 0xFF

    def _length(self, i: int) -> int:
        hw, op = self.hw, self.hw[i] & 0xFF
        if op == OP_IF:
            return instruction_length(hw, i)
        if op == self.spec["list"]:
            j = i + 1
            while j < len(hw) and hw[j] != 0:
                j += 1
            return j + 1 - i
        return self.spec["op_len"][op]

    def _parse(self) -> None:
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


def find_annex(annex_rel: Rel, spec: dict):
    """Locate the annex of a built My Life module inside ore_work.rel.

    The annexes stand one behind the other from spec["annex_from"], each a multiple of 8 bytes long; a header is its
    marker and its own address, so the first one dates the others. Returns (the address the annex's text starts at,
    its halfwords), or (None, ()) when this module has no annex (an unbuilt file)."""
    a = annex_rel.sec_data(spec["annex_section"])[spec["annex_from"]:]
    magic = spec.get("annex_magic", ORE_ANNEX_MAGIC)
    all_magics = [s.get("annex_magic", ORE_ANNEX_MAGIC) for s in BLOCK_SCRIPTS.values() if s.get("engine") == "ore"]
    first = (struct.unpack_from(">I", a, 4)[0]
             if len(a) >= 8 and struct.unpack_from(">2H", a) in all_magics else None)
    for p in range(0, len(a) - 7 if first is not None else 0, 8):
        if struct.unpack_from(">2H", a, p) == magic and struct.unpack_from(">I", a, p + 4)[0] == first + p:
            return first + p + 8, struct.unpack(">%dH" % (len(a) // 2 - p // 2 - 4), a[p + 8:len(a) // 2 * 2])
    return None, ()


class OreScript(BlockScript):
    """The My Life script (see ORE_OP_LEN). Same attributes as BlockScript; an opcode is the whole halfword.

    With an annex (built files) the halfwords of the annex follow those of the section, from self.annex_at;
    annex_base is the memory address the annex's first halfword has when the game runs."""

    def __init__(self, rel: Rel, spec: dict, annex_rel: Optional[Rel] = None):
        self.rel, self.spec, self.sec = rel, spec, spec["section"]
        self.region, self.ends, self.name_ops = spec["region"], spec["ends"], spec["name_ops"]
        d = rel.sec_data(self.sec)
        self.sec_file_offset = rel.sections[self.sec]["offset"]
        hw = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
        self.annex_at, self.annex_base = len(hw), None
        if annex_rel is not None:
            self.annex_base, annex_halfwords = find_annex(annex_rel, spec)
            hw += annex_halfwords
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

    def op(self, i: int) -> int:
        """Opcode of the instruction at halfword i (the whole halfword in this engine)."""
        return self.hw[i]

    def in_island(self, off: int) -> bool:
        """True when section offset `off` lies in one of the stretches of other data inside the region."""
        return any(a <= off < b for a, b in self.spec["islands"])

    def inside(self, i: int) -> bool:
        """True where an instruction may stand: the script without its islands, or the annex."""
        return (self.region[0] <= i * 2 < self.region[1] and not self.in_island(i * 2)) or \
            self.annex_at <= i < len(self.hw)

    def segments(self) -> List[tuple]:
        """The stretches of the region between the islands, as (first, end) section offsets."""
        cuts = [self.region[0]] + [x for isl in self.spec["islands"] for x in isl] + [self.region[1]]
        return list(zip(cuts[0::2], cuts[1::2]))

    def label_table(self) -> List[int]:
        """Halfword index of every label, in the order of the table (a jump names a label by its number)."""
        a, b = self.spec["labels"]
        at = {pos: addend // 2 for (s, pos, typ, tm, ts, addend) in self.rel.relocs()
              if s == self.sec and typ == 1 and a <= pos < b}
        return [at[pos] for pos in range(a, b, 4)]

    def routine_text(self, i: int, limit: int = 40) -> str:
        """The text a routine (starting at halfword i) prints before it returns, for the notes of the scene files.
        Name inserts show as {name}; stops after `limit` pieces."""
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

    def _length(self, i: int) -> int:
        op = self.hw[i]
        return 2 + self.hw[i + 1] if op == ORE_LIST else ORE_OP_LEN.get(op, 1)

    def _parse(self) -> None:
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


def load_block_scripts(mods: Optional[Dict[int, Rel]] = None) -> List[BlockScript]:
    """Parse every script of BLOCK_SCRIPTS (in that order). mods defaults to load_all_rels()."""
    mods = mods or load_all_rels()
    by_name = {m.name: m for m in mods.values()}
    return [OreScript(by_name[fn], spec, by_name.get(ORE_ANNEX_MODULE)) if spec.get("engine") == "ore"
            else BlockScript(by_name[fn], spec) for fn, spec in BLOCK_SCRIPTS.items()]
