"""Label styles of ore_sub.arc, second batch: r5_ut (vessel), r5_tsu (bonds), y3_prof (profile). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import banded, called

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))

def with_icon(style, icon, gap=1):
    """`style`'s art with a small picture (rows of palette digits, '.' = clear) kept at its left, centred in height."""
    ic = np.array([[0 if c == "." else int(c, 16) for c in row] for row in icon], np.uint8)
    def made(ink, base):
        art, b = style(ink, base)
        h, w = art.shape
        ih, iw = ic.shape
        H = max(h, ih)
        out = np.zeros((H, iw + gap + w), np.uint8)
        ty, iy = (H - h) // 2, (H - ih) // 2
        out[ty:ty + h, iw + gap:] = art
        sub = out[iy:iy + ih, :iw]
        sub[ic > 0] = ic[ic > 0]
        return out, b + ty
    return made

ICON_SW = ["..ffff..", ".ffffff.", ".ffeefff", "fff22dff", "ffd11bff", "fff87fff", ".fffffff", ".fffffff",
           "fff75fff", "ffd11bff", "fff43eff", ".fffffff"]
ICON_MENU = ["..4553..", ".577773.", "178dd75.", "279ff77.", "178ff77.", ".577775.", ".157751.", ".577773.",
             "178dd75.", "279ff77.", "178ff77.", ".577775.", ".157751."]

STYLES = {
    # lime headings, green outline and rings (palette 16 of r5_ut / r5_tsu): Vessel, Training, Bonds
    "o2head": called([15, 14, 13, 12], [9, 7], 6, 3, 1, [], 2, 1, 1),
    # purple letters, white band, blue rings (palette 34): Cancel
    "o2cancel": banded([0, 11, 12, 13, 14, 15, 15], [9, 2, 3]),
    # small dark teal letters in a pale mint ring (palette 8 of r5_ut): the display switches
    "o2mini": banded([0, 8, 10, 12, 13, 14, 15], [1]),
    # white letters, dark teal ring, paler ring, mint ring (palette 25): the list tabs
    "o2tab": banded([0, 12, 13, 14, 15, 15, 15], [7, 4, 2]),
    # navy letters, pale ring (palette 11): handedness
    "o2hand": banded([0, 7, 9, 11, 13, 14, 15], [4, 2]),
    # navy letters, white ring, pale blue outer ring (palette 10 of r5_ut): Age
    "o2age": banded([0, 9, 7, 5, 3, 2, 1], [15, 12]),
    # navy letters on white, the corner button kept (palette 10 of r5_tsu)
    "o2switch": with_icon(banded([0, 10, 7, 4, 2, 1, 1], [15, 15]), ICON_SW),
    # white letters in blue rings with the button picture (palette 8 of r5_tsu)
    "o2menu": with_icon(banded([0, 12, 13, 14, 15, 15, 15], [7, 1]), ICON_MENU),
    # gold / purple / green letters in a white band and blue rings (palettes 36, 43, 38)
    "o2btn": banded([0, 12, 13, 14, 15, 15, 15], [9, 5, 2], 1),
    # navy letters, white ring, lime glow (palette 74)
    "o2small": banded([0, 10, 12, 13, 14, 15, 15], [7, 2]),
    # profile: cyan heading (palette 9), pink heading (10), green heading (1), positions (15)
    "o2cyan": banded([0, 12, 13, 14, 15, 15, 15], [6, 9]),
    "o2pink": banded([0, 12, 13, 14, 15, 15, 15], [5, 3]),
    "o2green": called([12, 13, 14, 15], [8, 6], 4, 3, 1, [], 2, 1, 1),
    "o2pos": banded([0, 12, 13, 14, 15, 15, 15], [1, 6]),
}
