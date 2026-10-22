"""Turn English text into the numbers the game's text cells hold.

What it is for: the game stores text as a list of 12-bit numbers ("units"), one per character cell. A Japanese
character is the number of its glyph. English is stored two letters per cell: every pair of letters that occurs
gets a glyph slot of its own (see font.py and docs/GLOSSARY.md "Pair font"), and the cell holds that slot's number.
This module does the encoding once the slots are known.

Public functions:
    encode_text(text, slots, narrow)   English string -> list of units
"""
from pp15.build import font
from pp15.build.pair_text import text_segments
from pp15.glyphs import char_to_glyph
from pp15.script.scan import TEXT_NEWLINE

BLANK_PAIR = "  "      # two spaces: an empty cell, stored as unit 0 (needs no glyph slot)


def encode_text(text: str, slots: dict, narrow: bool = False) -> list[int]:
    """English string -> list of 12-bit units.

    `slots` = {letter pair: glyph number}, as chosen by `font_assign.assign_pairs`. A line break becomes
    TEXT_NEWLINE; any other character (Japanese, a symbol) keeps its own glyph.
    `narrow`: use the narrow pairs for the first font.NARROW_CELLS cells (names the match score display shows).
    Raises ValueError when a character has no glyph, and KeyError when a pair has no slot.
    """
    units, n = [], 0
    for kind, value in text_segments(text):
        if kind == "newline":
            units.append(TEXT_NEWLINE)
        elif kind == "pair":
            n += 1
            if value == BLANK_PAIR:
                units.append(0)
            else:
                prefix = font.NARROW if narrow and n <= font.NARROW_CELLS else ""
                units.append(slots[prefix + value])
        else:
            glyph = char_to_glyph(value)
            if glyph is None:
                raise ValueError("no glyph for %r in %r" % (value, text))
            units.append(glyph)
    return units
