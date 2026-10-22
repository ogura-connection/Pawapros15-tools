"""Typeset English words as pixels for the Pawapuro 15 sprite pages: the entry point of the lettering tool.

The game draws most of its menu lettering as pictures, so translating a menu means drawing English words that look like
the Japanese ones. This tool does that in three steps, each in its own module:
  1. a font (pp15/art/lettering_fonts.py) turns text into `ink`: levels 0..6 per pixel plus the baseline row. The
     letters are cut from MLB Power Pros 2008 label art or drawn from a built-in table, so nothing is invented;
  2. a style (pp15/art/lettering_styles.py, named in pp15/art/named_styles.py and pp15/art/styles/) turns ink into
     palette indices of the target page: outline, shadow, plate, gradient;
  3. repack (pp15/art/repack.py) puts the finished words on the page and re-points the sprites.

  typeset(text, font, project)   (ink, baseline) of a word, a phrase or several lines, in a font
  RENDER                         style name -> style function (loaded on first use, see pp15/art/style_registry.py)
  FONTS, TTF                     font tables: name -> font function, name -> system font file
  ttf_ink                        text in a system font

The style helpers (grow, shift, banded, logo, ...) and the font tables are imported here because the style modules in
pp15/art/styles/ import them from this module (`from pp15.art.typeset import grow, shift, logo`).
"""
import numpy as np

# Names below that this module does not use itself are imported for the style modules (see the docstring).
from pp15.art.lettering_fonts import FONTS, TAG_DROP, TAG_GLYPHS, TTF, _fonts, ttf_ink
from pp15.art.lettering_styles import (badged, banded, boxed, called, captioned, dropped, haloed, logo, outlined,
                                       plated, ringed, shadowed, style_command, style_stat, tight, titled)
from pp15.art.pixel_ops import grow, shift
from pp15.art.style_registry import RENDER

LINE_GAP_ROWS = 3        # clear rows between stacked lines of a multi-line word
SLANT_EVERY_ROWS = 4     # font "tagi" leans the tag font one pixel to the right every this many rows going up


def _slanted(ink: np.ndarray, base: int) -> tuple:
    """The ink leaned to the right, one pixel every SLANT_EVERY_ROWS rows going up from the baseline."""
    h, w = ink.shape
    lean = [(base - 1 - y + 2) // SLANT_EVERY_ROWS for y in range(h)]
    low = min(lean)
    out = np.zeros((h, w + max(lean) - low), int)
    for y in range(h):
        out[y, lean[y] - low:lean[y] - low + w] = ink[y]
    return out, base


def _stacked(text: str, font: str, project) -> tuple:
    """Lines of text (split at newlines) typeset one under the other, each centred, LINE_GAP_ROWS clear rows apart.
    The baseline returned is that of the last line."""
    lines = [typeset(t, font, project) for t in text.split("\n")]
    w = max(i.shape[1] for i, _ in lines)
    rows, base = [], 0
    for k, (i, b) in enumerate(lines):
        x = (w - i.shape[1]) // 2
        rows.append(np.pad(i, ((0, 0), (x, w - i.shape[1] - x))))
        if k < len(lines) - 1:
            rows.append(np.zeros((max(LINE_GAP_ROWS - (i.shape[0] - b), 1), w), int))
        else:
            base = sum(r.shape[0] for r in rows[:-1]) + b
    return np.vstack(rows), base


def _from_glyphs(text: str, f: dict) -> tuple:
    """Set text letter by letter from a font's "glyphs" table: {letter: (ink, rows hanging below the baseline)}."""
    items, x = [], 0
    for ch in text:
        if ch == " ":
            x += f["space"]
            continue
        g, drop = f["glyphs"][ch]
        items.append((x, g, drop))
        x += g.shape[1] + f["gap"]
    width = x - f["gap"]
    up = max(g.shape[0] - drop for _, g, drop in items)
    down = max(max(drop for _, _, drop in items), 0)
    ink = np.zeros((up + down, width), int)
    for x, g, drop in items:
        top = up + drop - g.shape[0]
        ink[top:top + g.shape[0], x:x + g.shape[1]] = np.maximum(ink[top:top + g.shape[0], x:x + g.shape[1]], g)
    return ink, up


def typeset(text: str, font: str = "command", project=None) -> tuple:
    """(ink, baseline row) of a word or phrase. A phrase that MLB drew is returned as drawn.
    font = "command", "tag", or "ttf:<face>:<cap height>[:<slant>[:<squeeze>[:<bold>]]]" for a system font.
    "tagi" is the tag font leaned to the right; a text with newlines is set as stacked lines.
    `project` = path of the MLB project.bin the command font is cut from (default: config.MLB_PROJECT_BIN)."""
    if font == "tagi":
        return _slanted(*typeset(text, "tag", project))
    if "\n" in text:
        return _stacked(text, font, project)
    if font.startswith("ttf:"):
        a = font.split(":")
        return ttf_ink(text, a[1], int(a[2]), *[float(x) for x in a[3:6]])
    f = FONTS[font](project)
    if text in f["words"]:
        return f["words"][text]
    return _from_glyphs(text, f)
