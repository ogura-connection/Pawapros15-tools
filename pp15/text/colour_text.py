"""Coloured text and cell counting for fixed-slot strings.

Plain strings are runs of 16-bit glyph numbers (see pp15/glyphs.py). A few strings carry a colour in the top four bits of
each number (glyph | colour << 12): for example the My Life title help lines end in a coloured "maximum 20 years". The
translation files write such a run as `{6:text}` (colour 6); the English writes it the same way and the build sets the
colour on every unit of the run.

The game's text has room for one wide Japanese character per cell, so English is set two letters per cell (the "pair
font", docs/GLOSSARY.md). `letters` counts the cells an English text takes with that rule.

Public names: units_text, colour_runs, plain, letters, is_coloured, coloured_text_ok, COLOUR_RUN.
"""
import re
from typing import List, Sequence, Tuple

from pp15.build.font import text_segments
from pp15.glyphs import MAX_GLYPH, glyph_to_char

COLOUR_RUN = re.compile(r"\{(\d{1,2}):([^{}]*)\}")
COLOUR_SHIFT = 12                   # colour = unit >> 12
MAX_COLOURED_TAIL = 64              # longest coloured tail looked for behind a plain run
FULL_WIDTH_SPACE = "　"
# Characters that may stand in a coloured tail besides kana and kanji: space, 、 。 ! ? : ・ ー ( ) and full-width digits
TAIL_PUNCTUATION = "　、。！？：・ー（）０１２３４５６７８９"


def is_kana_or_kanji(c: str) -> bool:
    """True for a hiragana, katakana or kanji character."""
    return 0x3040 <= ord(c) <= 0x30FF or 0x4E00 <= ord(c) <= 0x9FFF


def is_coloured(u: int) -> bool:
    """True when 16-bit unit u is a glyph with a colour in its top four bits."""
    return 0x1000 <= u < 0xF000 and (u & 0xFFF) <= MAX_GLYPH and glyph_to_char(u & 0xFFF) is not None


def coloured_text_ok(plain_units: Sequence[int], tail: Sequence[int]) -> bool:
    """A coloured tail counts only behind real text: the plain part has kana or kanji in most cells and the tail is
    kana, kanji, digits and punctuation of the font only."""
    def kind(u):
        c = glyph_to_char(u) or "?"
        return 2 if is_kana_or_kanji(c) else 1 if c in TAIL_PUNCTUATION else 0
    body = [kind(u) for u in plain_units if u]
    tail = [kind(u & 0xFFF) for u in tail]
    return len(body) >= 4 and sum(k == 2 for k in body) * 4 >= len(body) * 3 and all(tail) and tail.count(2) >= 2


def units_text(units: Sequence[int]) -> str:
    """The text of a string's units, coloured runs as {colour:text}, trailing full-width spaces cut (unless the string
    ends inside a coloured run)."""
    out, cur = [], None
    for u in units:
        c = u >> COLOUR_SHIFT if u > MAX_GLYPH else 0
        if c != cur:
            out.append("}" if cur else "")
            out.append("{%d:" % c if c else "")
            cur = c
        out.append(glyph_to_char(u & 0xFFF if c else u) or "?")
    if cur:
        out.append("}")
    text = "".join(out)
    return text.rstrip(FULL_WIDTH_SPACE) if not cur else text


def colour_runs(text: str) -> List[Tuple[int, str]]:
    """[(colour, text)] of a string with {colour:...} runs; colour 0 = plain. An empty string gives [(0, "")]."""
    out, pos = [], 0
    for m in COLOUR_RUN.finditer(text):
        out.append((0, text[pos:m.start()]))
        out.append((int(m.group(1)), m.group(2)))
        pos = m.end()
    out.append((0, text[pos:]))
    return [r for r in out if r[1]] or [(0, "")]


def plain(text: str) -> str:
    """The text with the colour marks taken out."""
    return COLOUR_RUN.sub(lambda m: m.group(2), text)


def letters(text: str) -> int:
    """Cells an English string takes: two ASCII letters per cell, other characters one each. A coloured run {6:...}
    starts its letter pairs again."""
    return sum(len(text_segments(part)) for _, part in colour_runs(text) if part)
