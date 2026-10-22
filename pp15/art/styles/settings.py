"""Styles for settings screens: match options, voice settings, the Cheer Song menu and the Data Corner (password entry and display, jersey names, stats settings).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): option, arevoice, arekore, chrsong, main_prg, m_logo, rec_room, orepena.
"""
import os
import numpy as np
from pp15.art.typeset import grow, shift
from pp15.art import typeset as ui_type
from .common import ringfill, flat

STYLES = {}


# ---- option.arc: the match options screen (bank g3_ops) --------------------------------------------------------------

ui_type.TTF.setdefault("avm", ("/System/Library/Fonts/Avenir Next Condensed.ttc", 5))      # Avenir Next Condensed Medium: the help text

# --- tab buttons (palette 16)
_TAB = [4, 3, 3, 2, 2, 1, 1]
STYLES["opt_tab"] = ringfill(_TAB, [15, 15, 11])
STYLES["opt_tab2"] = ringfill([3, 3, 2, 2, 1, 1, 1], [15, 12])                  # the two-line tabs: smaller letters, one ring less

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


_HLP = thin(ringfill([15], [4]), 2)
STYLES["hlp_raw"] = _HLP
for _w in range(16, 200):
    STYLES["hlp%d" % _w] = canvas(_HLP, _w, 16, 11)              # cap 9, 16 rows, baseline on row 11
    for _h in range(12, 17):                                     # exact canvases: height, baseline row
        for _b in range(8, 12):
            STYLES["hlp%d_%d_%d" % (_w, _h, _b)] = canvas(_HLP, _w, _h, _b)


# --- the blue bars (palette 21): 224 wide, 16 high, the rounded ends of the original bar
_bar_cache = {}


def _bar_ends():
    if not _bar_cache:
        from pp15.script import scan as S
        from pp15.art import textures as U
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


# ---- arevoice.arc: the voice settings screen (bank m3_onsei) ---------------------------------------------------------

def win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


# --- buttons (palettes 68-72): flat fill, white ring, blue ring, blue extrusion down and to the right
def button(fill):
    return ringfill([fill], [9, 9, 5], [4, 3, 3])


STYLES["v_btn_olive"] = button(15)       # 54 Save, 59 Type Reading (palette 68)
STYLES["v_btn_green"] = button(15)       # 58 Pick from List (palette 69)
STYLES["v_btn_orange"] = button(15)      # 64 Next (palette 70)
STYLES["v_btn_purple"] = button(15)      # 5a Cancel, 65 Quit (palette 72)

# --- small list / type tags (27 28 29 2a): gradient letters in a dark violet ring
STYLES["v_tag57"] = ringfill([15, 14, 12, 11], [1])
STYLES["v_tag58"] = ringfill([15, 14, 12, 10], [1])
STYLES["v_tag82"] = ringfill([15, 14, 13, 10, 8], [1])
STYLES["v_tag83"] = ringfill([15, 13, 12, 11, 9], [1])

# --- yes / no and the questions (palette 89, 107): navy letters, white ring, grey-blue shadow
STYLES["v_yn89"] = ringfill([1], [15, 15], [6, 4])
STYLES["v_q89"] = ringfill([1], [15, 15], [6, 4])
STYLES["v_q107"] = ringfill([1], [14, 14], [9, 6])

# --- prompts (yellow gradient, violet ring)
STYLES["v_p66"] = ringfill([15, 14, 13, 11], [1, 3])
STYLES["v_p87"] = ringfill([15, 14, 12, 11], [1, 3])
STYLES["v_p99"] = ringfill([15, 14, 13, 11], [1, 3])
STYLES["v_p153"] = ringfill([15, 14, 13, 12, 9, 7], [1, 3])
STYLES["v_p43"] = ringfill([15, 14, 13, 11, 10], [1, 3])

# --- titles (palettes 32, 45): orange gradient, white ring, blue rings, blue shadow
STYLES["v_title"] = ringfill([13, 13, 14, 14, 15, 15], [8, 4, 2], [1])

# --- 現在の設定 and its kin: pale letters, violet ring
STYLES["v_cur56"] = ringfill([15, 15, 14, 14, 13, 13], [1])
STYLES["v_cur86"] = ringfill([15, 15, 14, 14, 13, 13], [1])
STYLES["v_new81"] = ringfill([15, 14, 13, 12, 11, 10], [1])
STYLES["v_new44"] = ringfill([15, 14, 13, 12, 11, 10], [1])
# --- the test lines: dark letters on the plate (palette 56), pale letters in a violet ring (palette 101)
STYLES["v_t56"] = flat([0, 11, 8, 5, 3, 2, 1])
STYLES["v_t101"] = ringfill([15, 15, 14, 14], [1, 3])
# --- Choose a player (palette 50): navy letters, white ring, grey-blue shadow
STYLES["v_q50"] = ringfill([1], [15], [8])
# --- voice names (palettes 111, 102): teal / magenta letters, white ring, blue ring
STYLES["v_ann111"] = ringfill([14, 15, 15, 15], [9, 6, 3])
STYLES["v_pa102"] = ringfill([13, 14, 15, 15], [9, 6, 3])

# a word wider than one page is shown by two pieces: columns 0..split and the rest
STYLES["v_q50_a"] = win(STYLES["v_q50"], 0, 128)
STYLES["v_q50_b"] = win(STYLES["v_q50"], 128, 4096)
STYLES["v_p66_a"] = win(STYLES["v_p66"], 0, 104)
STYLES["v_p66_b"] = win(STYLES["v_p66"], 104, 4096)
STYLES["v_pa102_a"] = win(STYLES["v_pa102"], 0, 56)
STYLES["v_pa102_b"] = win(STYLES["v_pa102"], 56, 4096)


# ---- chrsong.arc: the Cheer Song menu (r3_okf) -----------------------------------------------------------------------

STYLES["cheer_title"] = ringfill([12, 12, 13, 14, 15, 15], [9, 9, 4, 4], [7, 7, 3])
STYLES["cheer_b03"] = ringfill([15]*6, [9, 9, 3, 3], [3])
STYLES["cheer_b04"] = ringfill([15]*6, [9, 9, 4, 4], [3])
STYLES["cheer_b05"] = ringfill([15]*6, [9, 9, 4, 1], [3])
STYLES["cheer_b39"] = ringfill([15]*6, [9, 8, 5], [3])
STYLES["cheer_b3a"] = ringfill([15]*6, [9, 9, 4, 1], [3])


# ---- arekore.arc, main_prg.arc, m_logo.arc and other leftovers (names d9_*) ------------------------------------------

def d9_ellipse(plate, core, W, H, rims=(4, 2)):
    """letters `core` on an ellipse plate `plate` (rim indices `rims`, outer first), W x H (grown if the letters need more)"""
    def style(ink, base):
        h, w = ink.shape
        W2, H2 = max(W, w + 8), max(H, h + 4)
        out = np.zeros((H2, W2), np.uint8)
        yy, xx = np.mgrid[0:H2, 0:W2] + 0.5
        r = H2 / 2.0
        cx = np.clip(xx, r, W2 - r)
        d = np.sqrt((xx - cx) ** 2 + (yy - r) ** 2)
        out[d <= r] = rims[1]
        out[d <= r - 1] = rims[0]
        out[d <= r - 2] = plate
        oy, ox = (H2 - h) // 2, (W2 - w) // 2
        sl = out[oy:oy + h, ox:ox + w]
        sl[ink >= 3] = core
        return out, base + oy
    return style

# ---- arekore
STYLES["d9_ak_01"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 3, 3], [4])
STYLES["d9_ak_02"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 3, 5], [4])
STYLES["d9_ak_03"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 3, 5], [4])
STYLES["d9_ak_04"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 5, 3], [5])
STYLES["d9_ak_05"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 3], [5, 4])
STYLES["d9_ak_06"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 2], [5, 4])
STYLES["d9_ak_07"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 3], [5, 4])
STYLES["d9_ak_00_logo"] = ui_type.logo(**{'fill': [12, 12, 11, 11, 10, 10], 'outline': 1, 'white': 15, 'rim': 9, 'shadow': [1, 6, 6, 2, 2, 2], 'soft': []})      # learn_logo
# ---- m_logo
STYLES["d9_ml_btn"] = ringfill([8, 8, 8, 8, 8, 8], [1, 1, 1])
STYLES["d9_ml_msg_logo"] = ui_type.logo(fill=[8, 8, 10, 11, 14, 14], outline=1, white=6, rim=6, shadow=[], soft=[])
# ---- main_prg
STYLES["d9_np_pos"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [8])
STYLES["d9_np_possm"] = ringfill([15] * 6, [8], [8])
STYLES["d9_np_hand"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [8, 4])
STYLES["d9_np_type"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [8])
# ---- order
STYLES["d9_od_name"] = ringfill([15, 15, 15, 15, 15, 15], [5, 5], [5])
STYLES["d9_od_thin"] = ringfill([15] * 6, [5], [5])
# ---- orepena
STYLES["d9_m16_plate"] = d9_ellipse(5, 15, 48, 20)
# ---- rec_room
STYLES["d9_rr_npk28"] = flat([0] + [14] * 6, cut=3)
