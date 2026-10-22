"""Machine-code evidence for the script format: `pp15 scan xref`.

The structure of the story scripts (instruction lengths, where labels live, how text is read) was worked out by reading the
PowerPC machine code of the game's own script interpreter in scs_main.rel. This module repeats that reading so that
anyone can check the claims in the code comments: it disassembles the relevant routines, lists who points at the label
tables, and re-derives the length of every opcode from its handler to compare with the table `OP_LEN`.
It needs the optional package `capstone` (pip install capstone).

Public names: Code (disassembly of one code section), derive_op_advance(code, entry), print_xref() (the whole report).
"""
import collections
import re
import struct
import sys
from typing import Dict, Set, Union

from pp15.script.rel import RELOC_NAMES, Rel, load_all_rels
from pp15.script.scripts import LABEL_TABLES, OP_IF, OP_LEN, OP_SKIPLIST, SCRIPT_FILES

# Where the interpreter's handlers return to the main loop (offsets in scs_main.rel section 1).
VM_EXITS = {0x39174, 0x39188, 0x39198, 0x35664, 0x34EF8}
VM_IP = "0x2d8(r15)"        # the memory slot of the interpreter state that holds the script pointer
OPCODE_COUNT = 0xFE         # handlers in the jump table
JUMP_TABLE = 0x0FF63C       # section 5 offset of the table of handler addresses
OPS_WITH_UNDETECTED_ARG = (0x9B, 0x9C, 0xA6, 0xDA)    # handlers that read their operand through a helper: 2 halfwords


def _capstone():
    """A PowerPC big-endian disassembler, or exit with a hint to install capstone."""
    try:
        from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
    except ImportError:
        sys.exit("xref needs capstone: pip install capstone")
    return Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)


class Code:
    """Disassembly of one executable section of a module, with relocation annotations on each instruction."""

    def __init__(self, rel: Rel, sec: int = 1):
        self.rel, self.sec = rel, sec
        self.code = rel.sec_data(sec)
        self.md = _capstone()
        self.rmap = collections.defaultdict(list)       # instruction offset -> relocations written into it
        for (s, pos, typ, tm, ts, addend) in rel.relocs():
            if s == sec:
                self.rmap[pos & ~3].append((typ, tm, ts, addend))

    def ins(self, a: int):
        """(mnemonic, operands) of the instruction at section offset a (".long" for a word that is not code)."""
        i = next(self.md.disasm(self.code[a:a + 4], a), None)
        return (i.mnemonic, i.op_str) if i else (".long", "0x%08x" % struct.unpack_from(">I", self.code, a)[0])

    def line(self, a: int) -> str:
        """One printable line: offset, instruction, and where its relocations point."""
        mn, ops = self.ins(a)
        notes = "".join("  ; %s -> m%d:s%d+0x%x" % (RELOC_NAMES.get(t, t), tm, ts, ad)
                        for t, tm, ts, ad in self.rmap.get(a, []))
        return "  %06x: %s %s%s" % (a, mn, ops, notes)

    def show(self, start: int, end: int) -> None:
        """Print the instructions from offset start up to end (exclusive)."""
        for a in range(start, end, 4):
            print(self.line(a))


def derive_op_advance(code: Code, entry: int, limit: int = 3000) -> Set[Union[int, str]]:
    """How far the handler at `entry` moves the script pointer, in bytes after the opcode halfword.

    The handler is followed through all of its branches, tracking which registers hold "script pointer plus a known
    amount". Returns the set of possible advances; 'J' stands for a handler that replaces the pointer (jump, call),
    'loop' for a search that did not finish within `limit` steps."""
    out, seen, steps = set(), set(), 0
    stack = [(entry, 0, (("r3", 0),))]     # at entry r3 = pointer just past the opcode
    volatile = ["r0"] + ["r%d" % i for i in range(3, 13)]       # registers a call may overwrite
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


def _xref_text_handlers(code: Code) -> None:
    print("== 1. Text-mode switch: opcode 0x00 handler (scs_main sec1+0x0356B0)")
    print("   hi byte -> r15+0x19C (window type), 0 -> r15+0x1A0 (current opcode = text mode)")
    code.show(0x356B0, 0x356C0)

    print("\n== 2. 12-bit unit reader (scs_main sec1+0x034F08)")
    print("   phase at r15+0x1A2 picks 12 bits; 0xFFF -> 0xFFFF (end), 0xFFE -> line break")
    code.show(0x34F08, 0x34FAC)
    print("   phase/pointer advance (sec1+0x033360), end-of-run realignment (sec1+0x0351C8):")
    code.show(0x351C8, 0x3520C)


def _xref_label_tables(code: Code, main: Rel, mods: Dict[int, Rel], by_name: Dict[str, Rel]) -> None:
    print("\n== 3. Label lookup used by goto/call/if (scs_main sec1+0x05E3F0)")
    code.show(0x5E3F0, 0x5E460)
    print("   Label tables (scs_main sec5, all zero in the file, filled by relocations):")
    bases = [r[0][3] for r in (main.data_relocs(5, 0xD0870 + k * 4) for k in range(3))]
    for k, base in enumerate(bases):
        end = bases[k + 1] if k + 1 < len(bases) else LABEL_TABLES[1]
        n = collections.Counter()
        for off in range(base, end, 4):
            for (_, tm, ts, _) in main.data_relocs(5, off):
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


def _xref_opcode_lengths(code: Code, main: Rel) -> None:
    print("\n== 4. Opcode lengths re-derived from the 254 handlers (jump table sec5+0x0FF63C)")
    table = [code_reloc[0][3] if code_reloc else 0 for code_reloc in
             (main.data_relocs(5, JUMP_TABLE + op * 4) for op in range(OPCODE_COUNT))]
    mismatch = []
    for op, entry in enumerate(table):
        adv = derive_op_advance(code, entry)
        ints = sorted(x for x in adv if isinstance(x, int) and x >= 0)
        if op in (OP_IF, OP_SKIPLIST):
            continue                       # variable length, measured by instruction_length()
        derived = (ints[-1] // 2 + 1) if ints else 2 if op in OPS_WITH_UNDETECTED_ARG else 1
        if derived != OP_LEN[op]:
            mismatch.append("%02X: table %d, derived %d %s" % (op, OP_LEN[op], derived, sorted(map(str, adv))))
    print("   mismatches against OP_LEN: %s" % (mismatch or "none"))


def _xref_name_buffers(code: Code, mods: Dict[int, Rel], work: Rel) -> None:
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


def _xref_scene_setup(code: Code, mods: Dict[int, Rel], main: Rel) -> None:
    print("\n== 6. Callers of the 'scene setup' function scs_main sec1+0x033068")
    for m in mods.values():
        for (s, pos, typ, tm, ts, addend) in m.relocs():
            if tm == main.mod_id and ts == 1 and addend == 0x33068:
                print("   %s sec%d+0x%x (%s)" % (m.name, s, pos, RELOC_NAMES.get(typ, typ)))
    print("   It copies names (text copier, max 6 glyphs) from V+0x911C / V+0x91B0:")
    code.show(0x3324C, 0x33284)


def print_xref() -> None:
    """Print the whole report (six numbered parts) to standard output."""
    mods = load_all_rels()
    by_name = {m.name: m for m in mods.values()}
    main, work = by_name["scs_main.rel"], by_name["work_scs.rel"]
    code = Code(main)
    _xref_text_handlers(code)
    _xref_label_tables(code, main, mods, by_name)
    _xref_opcode_lengths(code, main)
    _xref_name_buffers(code, mods, work)
    _xref_scene_setup(code, mods, main)
