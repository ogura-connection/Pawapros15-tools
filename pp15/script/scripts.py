"""The Success Mode story script: what its instructions are and where the dialogue sits.

The story of Success Mode (the mode where you build a player through a school or team story, see docs/GLOSSARY.md) is a
list of small "scenes". Each scene is run by a little interpreter in scs_main.rel. The scenes themselves are
sequences of 16-bit instructions ("halfwords") stored in the scripts of scs_main.rel and scs_sce1/2/3.rel:

  * the low byte of an instruction is its opcode; the high byte is a small argument (for opcode 0 it selects the
    dialogue window);
  * opcode 0 switches to text mode: the 12-bit packed text that follows (pp15/script/packed_text.py) is the dialogue;
  * other opcodes wait for a button, break a line, change a colour, show a portrait, jump, call, test conditions, ...
    and take 0 to 3 more halfwords of operands (the table OP_LEN gives each opcode's length).
Jumps and calls name a numbered "label", never an address; the label tables are in scs_main.rel section 5 and are
filled in when the game loads, by relocations (docs/GLOSSARY.md, "Relocation").

`Script` parses one module by following the control flow from every label, so that data that merely looks like text is
never mistaken for dialogue.

Public names: Script, load_scripts(), instruction_length(hw, i), OP_LEN, the OP_* opcode constants, SCRIPT_FILES,
LABEL_TABLES.
"""
import collections
import struct
from typing import Dict, List, Sequence

from pp15.script.packed_text import unpack_text
from pp15.script.rel import Rel, load_all_rels

# Script modules: common events live in scs_main.rel itself, scenario scripts in scs_sce1/2/3.
SCRIPT_FILES = ["scs_main.rel", "scs_sce1.rel", "scs_sce2.rel", "scs_sce3.rel"]
# Label tables in scs_main.rel section 5 (zero in the file, filled by ADDR32 relocations at load).
# Section 5 offset 0xD0870 holds three table pointers; each table is 14,101 labels into scs_main section 5
# followed by the labels of one scenario module. These are the byte offsets where the label entries start and end.
LABEL_TABLES = (0xD0880, 0xFED88)


def opcode_lengths(longer: Dict[int, Sequence[int]]) -> Dict[int, int]:
    """Instruction length in halfwords for all 256 opcodes: 1 unless `longer` ({length: opcodes}) says otherwise."""
    table = {op: 1 for op in range(0x100)}
    for length, ops in longer.items():
        for op in ops:
            table[op] = length
    return table


# Instruction length in halfwords, opcode = low byte. Derived from the handlers in scs_main.rel (jump table at
# section 5 offset 0x0FF63C); `pp15 scan xref` re-derives the table from the code and checks it.
OP_LEN = opcode_lengths({
    2: [0x71, 0x72] + list(range(0x75, 0x82)) + list(range(0x83, 0x9A)) + [0x9B, 0x9C, 0x9E]
       + list(range(0x9F, 0xC7)) + [0xD5, 0xD6, 0xDA] + list(range(0xE5, 0xE9)) + list(range(0xEE, 0xF2)),
    3: list(range(0x26, 0x46)) + [0x9D],
    4: list(range(0x16, 0x26)),
})
OP_TEXT, OP_RETURN, OP_IF, OP_SKIPLIST, OP_GOTO = 0x00, 0x01, 0x02, 0x6E, 0x9B
OP_NEWLINE, OP_NEWLINE_WAIT, OP_WAIT = 0x46, 0x49, 0x4A   # meaning inferred from the handlers

# Operator halfwords inside an OP_IF condition list
IF_AND, IF_OR, IF_CLOSE = 0x14, 0x15, 0x03


def instruction_length(hw: Sequence[int], i: int) -> int:
    """Length in halfwords of the instruction at index i (the two variable-length ones are measured)."""
    op = hw[i] & 0xFF
    if op == OP_IF:
        # [expr, comparison, operand] repeated, joined by 0x14 (and) / 0x15 (or),
        # optionally closed by 0x03, then a label index.
        j = i + 1
        while True:
            j += 3
            if j >= len(hw):
                break
            if hw[j] == IF_CLOSE:
                j += 1
                break
            if hw[j] in (IF_AND, IF_OR):
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
    """One script module, parsed by following control flow from every label.

    Attributes:
      rel, sec          the module and the index of its script section
      hw                the section as a tuple of 16-bit halfwords
      sec_file_offset   file offset of the section
      labels            Counter of halfword indices that are entry points (label targets)
      kind              {halfword index: 'op' | 'arg' | 'text'} for every halfword reached
      texts             {index of a text-mode instruction: (window, units, index after the run)}
      op_count, errors  Counters of opcodes met and of parse problems"""

    def __init__(self, rel: Rel, all_mods: Dict[int, Rel], label_tables=LABEL_TABLES):
        self.rel = rel
        self.sec = rel.script_section()
        d = rel.sec_data(self.sec)
        self.sec_file_offset = rel.sections[self.sec]["offset"]
        self.hw = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
        # Labels: entries of the label tables in scs_main.rel section 5 that point into this
        # section. Jumps/calls/ifs take a label index, never a raw offset.
        self.labels = collections.Counter()
        main = next(m for m in all_mods.values() if m.name == "scs_main.rel")
        for (s, pos, typ, tm, ts, addend) in main.relocs():
            if (s == 5 and typ == 1 and label_tables[0] <= pos < label_tables[1]
                    and tm == rel.mod_id and ts == self.sec and addend % 2 == 0):
                self.labels[addend // 2] += 1
        self.kind = {}
        self.texts = {}
        self.op_count = collections.Counter()
        self.errors = collections.Counter()
        self._parse()

    def _parse(self) -> None:
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

    def offset_of(self, idx: int) -> int:
        """File offset of halfword idx."""
        return self.sec_file_offset + idx * 2


def load_scripts() -> List[Script]:
    """The four Success Mode script modules (SCRIPT_FILES), parsed."""
    mods = load_all_rels()
    by_name = {m.name: m for m in mods.values()}
    return [Script(by_name[fn], mods) for fn in SCRIPT_FILES]
