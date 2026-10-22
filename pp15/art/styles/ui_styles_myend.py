"""Label styles of myend.arc (My Life ending: banks y3_end, y3_se16, y3_se256). Loaded by pp15/art/typeset.py.

All styles are crisp: letters at ink level 3 and up are one fill (a vertical gradient of palette indices), solid one-pixel rings
round them, an optional shadow. `win_<style>_<k>` cuts column window k (128 columns) out of the whole word, so a word wider than a
part is drawn by two or three parts without a seam."""
import numpy as np
from pp15.art import typeset as ui_type
from pp15.art.typeset import dropped
from .ui_styles_ore_ini import ringfill

STYLES = {}

# y3_end: white letters, black shadow (palette 0)
STYLES["me_white"] = dropped([0, 0, 0, 15, 15, 15, 15], [1])

# y3_se16, palettes 16 (team names, W / L / T): white to pale blue letters, blue rings
_BLUE = [11, 12, 13, 14, 15, 15, 14, 13, 12, 11, 10]
STYLES["me_team"] = ringfill(_BLUE, [6, 5, 3], [])
STYLES["me_team"] = ringfill(_BLUE, [5, 3], [])
STYLES["me_wlt"] = ringfill(_BLUE, [6, 5, 5, 3], [])
# banners, 32 rows high: orange (17), violet (18), pink (22); stat words, green (19)
STYLES["me_ban17"] = ringfill([10, 11, 12, 13, 14, 15, 14, 13, 12, 11, 10], [5, 5, 3], [])
STYLES["me_ban18"] = ringfill([10, 11, 12, 13, 14, 15, 14, 13, 12, 11, 10], [5, 5, 3], [])
STYLES["me_ban22"] = ringfill([10, 11, 12, 13, 14, 15, 14, 13, 12, 11, 10], [2, 2, 3], [])
STYLES["me_stat"] = ringfill([11, 12, 13, 14, 14, 13, 12, 11, 10, 9], [5, 5, 3], [])

# y3_se256 (8-bit pages): chrome letters, blue outline, pale band, deep blue shadow
_CHROME = [209, 211, 215, 176, 174, 171, 169, 167, 166, 60, 58, 55, 52]
STYLES["me_chrome"] = ringfill(_CHROME, [106, 106, 219, 219, 219, 219], [111] * 6)
STYLES["me_slate"] = ringfill([252], [160, 160, 190], [111, 111])
_GOLD = [172, 179, 186, 192, 201, 206, 213, 214, 233, 234, 254, 251, 248]
STYLES["me_burn"] = ringfill(_GOLD, [104, 123, 123, 160], [111] * 6)


def window(style, k, size=128):
    """The columns k * size .. (k + 1) * size of the whole word as `style` draws it."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, k * size:(k + 1) * size]
        if out.shape[1] == 0:
            out = np.zeros((1, 1), np.uint8)
        return out, b
    return cut


for _name in ("me_chrome", "me_slate", "me_burn", "me_ban17", "me_ban18", "me_ban22", "me_team"):
    for _k in range(3):
        STYLES["win_%s_%d" % (_name, _k)] = window(STYLES[_name], _k)
