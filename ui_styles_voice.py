"""Label styles of arevoice.arc (the voice settings screen, bank m3_onsei). Loaded by ui_type.py.

Every style is crisp: letters at ink level 3 and up are one fill (flat, or a vertical gradient of palette indices),
inside solid one-pixel rings and an optional shadow (ui_styles_ore_ini.ringfill). The colours are read from the Japanese
lettering of each palette (_work/ui_pages/tools/roles.py). `win(style, c0, c1)` returns only the columns c0..c1 of the
whole word, so a word can be shared out over parts that stand side by side."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}


def win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


def flat(ramp, cut=1):
    """Letters only, no ring: ink level k (1..6) -> palette index ramp[k]; pixels below `cut` are clear."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        out = np.where(ink >= cut, ramp[ink], 0).astype(np.uint8)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


# --- buttons (palettes 68-72): flat fill, white ring, blue ring, blue extrusion down and to the right
def button(fill):
    return ringfill([fill], [9, 9, 5], [4, 3, 3])


STYLES["v_btn_olive"] = button(15)       # 54 Save, 59 Type Reading (palette 68)
STYLES["v_btn_green"] = button(15)       # 58 Pick from List (palette 69)
STYLES["v_btn_orange"] = button(15)      # 64 Next (palette 70)
STYLES["v_btn_purple"] = button(15)      # 5a Cancel, 65 Quit (palette 72)

# --- small list / type tags (27 28 29 2a): gradient letters in a dark violet ring
STYLES["v_tag57"] = ringfill([15, 14, 12, 11], [1, 3])
STYLES["v_tag58"] = ringfill([15, 14, 12, 10], [1, 3])
STYLES["v_tag82"] = ringfill([15, 14, 13, 10, 8], [1, 3])
STYLES["v_tag83"] = ringfill([15, 13, 12, 11, 9], [1, 3])

# --- yes / no and the questions (palette 89, 107): navy letters, white ring, grey-blue shadow
STYLES["v_yn89"] = ringfill([1], [15, 15], [6, 4])
STYLES["v_q89"] = ringfill([1], [15, 15], [6, 4])
STYLES["v_q107"] = ringfill([1], [14, 14], [9, 6])

# --- prompts (yellow gradient, violet ring)
STYLES["v_p66"] = ringfill([15, 14, 13, 11], [1, 3])
STYLES["v_p87"] = ringfill([15, 14, 12, 11], [1, 3])
STYLES["v_p99"] = ringfill([15, 14, 13, 11], [1, 3])
STYLES["v_p153"] = ringfill([15, 14, 13, 12, 9, 7], [1, 2])
STYLES["v_p43"] = ringfill([15, 14, 13, 11, 10], [1, 3])

# --- titles (palettes 32, 45): orange gradient, white ring, blue rings, blue shadow
STYLES["v_title"] = ringfill([13, 13, 14, 14, 15, 15], [8, 5, 3, 2], [1, 1])
