"""Label styles of option.arc (the match options screen, bank g3_ops). Loaded by ui_type.py. See _work/ui_pages/gen_option_spec.py.

Every style is crisp (ui_styles_ore_ini.ringfill: flat or gradient letters inside solid one-pixel rings and an optional
shadow). Colours are read from the Japanese lettering of each palette (_work/ui_pages/tools/roles.py):
  palette 16  the tab buttons (round plate): navy-to-blue letters, a white ring, a pale blue outer ring
  palette 7   the values on the blue plates (and Cancel): white letters, navy ring, blue shadow
  palette 8   the red A of "A Type": white letters, red ring
  palette 24  the help sentences: dark blue letters, a mid and a pale blue ring
  palette 21  the blue bars "STARTボタンで決定": white letters on a bar whose rounded ends are cut from the original art
"help" styles hlp<W> paint a line of the help text on a fixed canvas W wide and 15 rows high with the baseline on a
fixed row, left aligned, so a sprite's lines (cut into strips by ui_type) stand on one baseline and start in one column."""
import os
import numpy as np
import ui_type
from ui_styles_ore_ini import ringfill

STYLES = {}

# --- tab buttons (palette 16)
_TAB = [6, 5, 4, 3, 2, 1, 1]
STYLES["opt_tab"] = ringfill(_TAB, [15, 15, 11])
STYLES["opt_tab2"] = ringfill([4, 3, 3, 2, 2, 1, 1], [15, 12])                  # the two-line tabs: smaller letters, one ring less

# --- values on the blue plates (palette 7)
STYLES["opt_val"] = ringfill([15, 15, 15, 14], [8, 7], [5])
STYLES["opt_val_s"] = ringfill([15, 15, 15, 14], [8], [5])      # small letters: a single navy ring
STYLES["opt_a"] = ringfill([15], [8, 6], [4])                   # the red A (palette 8)


# --- help text (palette 24)
def canvas(inner, width, height=16, base=12):
    """`inner` painted on a canvas width x height: first column left, baseline on row `base`."""
    def style(ink, b):
        art, ab = inner(ink, b)
        out = np.zeros((height, width), np.uint8)
        top = base - ab
        for r in range(art.shape[0]):
            y = top + r
            if 0 <= y < height:
                n = min(art.shape[1], width)
                out[y, :n] = art[r, :n]
        return out, base
    return style


def thin(inner, cut):
    """`inner` on the ink with every level below `cut` taken away: thin strokes stay one crisp pixel wide."""
    def style(ink, base):
        return inner(np.where(ink >= cut, ink, 0), base)
    return style


_HLP = thin(ringfill([15], [7]), 3)
STYLES["hlp_raw"] = _HLP
for _w in range(16, 200):
    STYLES["hlp%d" % _w] = canvas(_HLP, _w, 15, 11)              # cap 9, 15 rows, baseline on row 11
    STYLES["hlq%d" % _w] = canvas(_HLP, _w, 17, 12)              # cap 10, 17 rows, baseline on row 12


# --- the blue bars (palette 21): 224 wide, 16 high, the rounded ends of the original bar
_bar_cache = {}


def _bar_ends():
    if not _bar_cache:
        import scan_story as S
        import ui_textures as U
        path = os.path.join(U.ORIG_ARC_DIR, "option.arc")
        if not os.path.exists(path):
            path = os.path.join(S.DATA_FILES, "option.arc")
        d = open(path, "rb").read()
        b = next(x for x in U.banks(d, U.elf_symbols(d)) if x["name"] == "g3_ops")
        pg = U.decode_indices(d, *b["pages"][2])
        left = pg[0:16, 0:128]
        right = pg[16:32, 0:96]
        _bar_cache["left"] = left[:, :12].copy()
        _bar_cache["right"] = right[:, 84:96].copy()
        _bar_cache["mid"] = left[:, 20].copy()
    return _bar_cache


def bar(width=224, height=16, letter=15, cut=3):
    def style(ink, base):
        e = _bar_ends()
        full = np.zeros((height, width), np.uint8)
        full[:, :] = e["mid"][:, None]
        full[:, :12] = e["left"]
        full[:, width - 12:] = e["right"]
        h, w = ink.shape
        x0 = (width - w) // 2
        # the capitals sit on the middle of the bar: baseline row so that base - h/2 is centred
        top = (height - h) // 2
        for y in range(h):
            for x in range(w):
                if ink[y, x] >= cut and 0 <= top + y < height:
                    full[top + y, x0 + x] = letter
        return full, top + base
    return style


STYLES["opt_bar"] = bar()
