"""The 12-bit packed text of the story scripts, and the control numbers that can appear in it.

Story dialogue is not stored one 16-bit number per character. It is packed: every character ("unit") takes 12 bits, so
three units fit in two 16-bit halfwords. A unit below 3,744 is a glyph number (see pp15/glyphs.py); 0xFFF ends the run
and 0xFFE is a line break. The run is padded with 0xF nibbles up to a whole halfword.

A "nibble phase" 0..3 says which 12 bits of the current and next halfword the next unit uses:
  phase 0: bits 15-4 of halfword i            phase 1: bits 3-0 of i, then bits 15-8 of i+1
  phase 2: bits 7-0 of i, then bits 15-12 of i+1     phase 3: bits 11-0 of i+1 (then both halfwords are used up)
The game's own reader is scs_main.rel section 1 offset 0x034F08; this module does the same.

Public names: unpack_text, pack_text (inverse of each other), decode_units (units -> readable text), units_valid,
TEXT_END, TEXT_NEWLINE, MAX_GLYPH.
"""
from typing import List, Optional, Sequence, Tuple

from pp15.glyphs import MAX_GLYPH, glyph_to_char

TEXT_END = 0xFFF        # end of a text run
TEXT_NEWLINE = 0xFFE    # line break inside a run (becomes 0x1FFE in the display buffer)
PAD_NIBBLE = 0xF        # fills the last halfword of a run
CONTROL_FLOOR = 0xF00   # units from here up are control codes (colour, name insert), not glyphs


def unpack_text(hw: Sequence[int], i: int, max_units: Optional[int] = None,
                strict: bool = False) -> Optional[Tuple[List[int], int]]:
    """Read one packed text run that starts at halfword index i of the list hw.

    Returns (units, next halfword index after the run and its padding), or None when the data ends before a
    terminator. When scanning unknown data, max_units gives up on runs longer than that and strict gives up at the
    first impossible unit (between the last glyph and the control range)."""
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
        if strict and MAX_GLYPH < u < CONTROL_FLOOR:
            return None
        units.append(u)
        if phase:
            i += 1
        phase = (phase + 1) & 3
    return None


def pack_text(units: Sequence[int]) -> List[int]:
    """Inverse of unpack_text: units -> halfwords, terminator and padding included."""
    nib = []
    for u in list(units) + [TEXT_END]:
        nib += [u >> 8, (u >> 4) & 15, u & 15]
    while len(nib) % 4:
        nib.append(PAD_NIBBLE)
    return [(nib[k] << 12) | (nib[k + 1] << 8) | (nib[k + 2] << 4) | nib[k + 3]
            for k in range(0, len(nib), 4)]


def decode_units(units: Sequence[int]) -> str:
    """Readable text of a run: glyphs as characters, a line break as the two characters \\n, any other control code as
    <XXX> (three hex digits)."""
    out = []
    for u in units:
        if u == TEXT_NEWLINE:
            out.append("\\n")
            continue
        ch = glyph_to_char(u) if u <= MAX_GLYPH else None
        out.append(ch if ch else "<%03X>" % u)
    return "".join(out)


def units_valid(units: Sequence[int]) -> bool:
    """True when every unit is a glyph number or a control code (nothing in the gap between them)."""
    return all(u <= MAX_GLYPH or u >= CONTROL_FLOOR for u in units)
