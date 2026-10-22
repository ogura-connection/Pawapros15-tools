"""Build single PowerPC machine instructions (32-bit words) for the small code patches of the name tables.

The Wii's processor is a PowerPC. The surname table is wider than the original, so a few routines of the game
that read it are rewritten (see `pp15.names.table`). Those routines are written here as a list of words, each made
by one of the functions below, so a patch reads like assembly:  `addi(4, 4, 1)` is `addi r4, r4, 1`.

Registers are plain numbers (r3 -> 3). Branch targets are given as addresses; a branch word needs its own
address, so a list entry may be a function of that address, which `loop_words` calls.

Functions: addi, li, addis, cmplwi, cmpwi, lhzx, sthx, add, beq, blt, branch (the instruction `b`), loop_words.
Constants: BEQLR / BLR / NOP (fixed words), KEEP (marker: leave the original word).
"""
from typing import Callable, List, Optional, Tuple, Union

# Opcode numbers of the instruction forms used below (PowerPC "primary opcode", the top six bits of a word)
OP_CMPLWI = 10
OP_CMPWI = 11
OP_ADDI = 14
OP_ADDIS = 15
OP_BRANCH_CONDITIONAL = 16
OP_BRANCH = 18
OP_REGISTER_FORM = 31       # lhzx, sthx, add: the operation is in the extended opcode field

# Extended opcodes of the register-form instructions
XO_LHZX = 279               # load halfword (16 bits) indexed
XO_STHX = 407               # store halfword indexed
XO_ADD = 266

# Branch-condition fields: BO = 12 means "branch if the condition bit is set"; BI picks the bit of cr0
BO_IF_TRUE = 12
BI_LESS_THAN = 0
BI_EQUAL = 2

Word = Optional[int]
# A patch list entry: a ready word, a function of the word's own address, or KEEP
Entry = Union[int, Callable[[int], int], None]


def _d_form(opcode: int, rt: int, ra: int, imm: int) -> int:
    """Instruction with two registers and a 16-bit immediate (addi, cmpwi, ...)."""
    return opcode << 26 | rt << 21 | ra << 16 | imm & 0xFFFF


def _x_form(rt: int, ra: int, rb: int, extended_opcode: int) -> int:
    """Instruction with three registers (lhzx, sthx, add)."""
    return OP_REGISTER_FORM << 26 | rt << 21 | ra << 16 | rb << 11 | extended_opcode << 1


def _conditional_branch(bo: int, bi: int, here: int, to: int) -> int:
    """Branch to address `to` if a condition holds; `here` is the address of the word itself."""
    return OP_BRANCH_CONDITIONAL << 26 | bo << 21 | bi << 16 | (to - here) & 0xFFFC


def addi(rt: int, ra: int, imm: int) -> int:
    """rt = ra + imm. (With ra = 0 the register is read as the value 0, not r0.)"""
    return _d_form(OP_ADDI, rt, ra, imm)


def li(rt: int, imm: int) -> int:
    """rt = imm (load immediate; an `addi` from the value 0)."""
    return addi(rt, 0, imm)


def addis(rt: int, ra: int, imm: int) -> int:
    """rt = ra + (imm << 16)."""
    return _d_form(OP_ADDIS, rt, ra, imm)


def cmplwi(ra: int, imm: int) -> int:
    """Compare ra with imm as unsigned numbers."""
    return _d_form(OP_CMPLWI, 0, ra, imm)


def cmpwi(ra: int, imm: int) -> int:
    """Compare ra with imm as signed numbers."""
    return _d_form(OP_CMPWI, 0, ra, imm)


def lhzx(rt: int, ra: int, rb: int) -> int:
    """rt = the 16-bit value at address ra + rb."""
    return _x_form(rt, ra, rb, XO_LHZX)


def sthx(rs: int, ra: int, rb: int) -> int:
    """Store the low 16 bits of rs at address ra + rb."""
    return _x_form(rs, ra, rb, XO_STHX)


def add(rt: int, ra: int, rb: int) -> int:
    """rt = ra + rb."""
    return _x_form(rt, ra, rb, XO_ADD)


def beq(here: int, to: int) -> int:
    """Branch to `to` if the last comparison was equal."""
    return _conditional_branch(BO_IF_TRUE, BI_EQUAL, here, to)


def blt(here: int, to: int) -> int:
    """Branch to `to` if the last comparison was less-than."""
    return _conditional_branch(BO_IF_TRUE, BI_LESS_THAN, here, to)


def branch(here: int, to: int) -> int:
    """Unconditional branch (the instruction `b`) from address `here` to address `to`."""
    return OP_BRANCH << 26 | (to - here) & 0x3FFFFFC


BEQLR = 0x4D820020          # return from the routine if the last comparison was equal
BLR = 0x4E800020            # return from the routine
NOP = 0x60000000            # does nothing
KEEP = None                 # in a patch list: leave the original word (it carries a relocation)


def loop_words(at: int, words: List[Entry]) -> List[Tuple[int, Word]]:
    """Give every word of a patch its address.

    Arguments: `at`, the address of the first word; `words`, ready words or functions that take the word's own
    address and return the word (branches). Returns [(address, word)]."""
    return [(at + 4 * i, w(at + 4 * i) if callable(w) else w) for i, w in enumerate(words)]
