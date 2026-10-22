"""Styles for more pages of the Records Room (season and career records).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): rec_room.
"""
import numpy as np
from .common import ringfill

STYLES = {}


def flat(c):
    def style(ink, base):
        out = np.where(ink >= 2, c, 0).astype(np.uint8)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


def sil(front, c):
    def style(ink, base):
        out, bb = STYLES[front](ink, base)
        return np.where(out > 0, c, 0).astype(np.uint8), bb
    return style


def comp(inner, blob, h, w, cx, cy):
    import zlib, base64
    bg = np.frombuffer(zlib.decompress(base64.b64decode(blob)), np.uint8).reshape(h, w).copy()
    def style(ink, base):
        art, b = STYLES[inner](ink, base)
        out = bg.copy()
        ah, aw = art.shape
        top = max(0, min(h - ah, int(round(cy - ah / 2.0)))); left = max(0, min(w - aw, int(round(cx - aw / 2.0))))
        sl = out[top:top + ah, left:left + aw]
        sl[art > 0] = art[art > 0]
        return out, b + top
    return style


def win(style, c0, c1):
    def f(ink, base):
        out, b = style(ink, base)
        return out[:, c0:c1], b
    return f


STYLES["c8_000"] = flat(15)
STYLES["c8_001"] = flat(1)
STYLES["c8_002"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["c8_003"] = ringfill([10, 1, 10, 1, 1, 1], [12], [])
STYLES["c8_004"] = ringfill([15, 15, 15, 15, 15, 15], [11], [])
STYLES["c8_005"] = ringfill([12, 12, 12, 12, 12, 12], [1])    # 1/1 votes, e.g. rec_room g2_km#2+g3_sm#3 49
STYLES["c8_006"] = ringfill([10, 10, 10, 10, 10, 10], [13], [])
STYLES["c8_007"] = flat(10)
STYLES["c8_008"] = ringfill([15, 15, 15, 15, 15, 15], [3, 6])    # 1/1 votes, e.g. rec_room g3_gk#17+g3_ndn#18 00
STYLES["c8_009"] = ringfill([11, 12, 12, 11, 11, 10], [8, 1], [1])
STYLES["c8_010"] = ringfill([12, 12, 11, 10, 11, 10], [1, 14], [8])
STYLES["c8_011"] = ringfill([12, 12, 11, 10, 11, 10], [8], [8])
STYLES["c8_012"] = ringfill([2, 2, 12, 11, 2, 2], [8], [])
STYLES["c8_013"] = ringfill([12, 12, 12, 12, 12, 12], [1], [1])
STYLES["c8_014"] = flat(12)
STYLES["c8_015"] = ringfill([12, 12, 12, 10, 10, 10], [8], [])
STYLES["c8_016"] = ringfill([1, 1, 1, 1, 1, 1], [5], [])
STYLES["c8_017"] = ringfill([15, 15, 15, 15, 15, 15], [11, 1], [13])
STYLES["c8_019"] = ringfill([9, 9, 9, 9, 8, 8], [3, 3], [12])
STYLES["c8_020"] = ringfill([7, 8, 10, 10, 8, 7], [1, 1], [15])
STYLES["c8_021"] = ringfill([9, 9, 8, 7, 6, 6], [12, 15], [])
STYLES["c8_022"] = ringfill([87, 54, 54, 54, 54, 54], [147, 147], [98])
STYLES["c8_023"] = ringfill([12, 12, 12, 12, 12, 12], [1, 15])    # 1/1 votes, e.g. rec_room g3_ndn#18+g3_tbk#19 00
STYLES["c8_024"] = ringfill([4, 4, 3, 4, 4, 4], [15], [14])
STYLES["c8_025"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15])
STYLES["c8_026"] = ringfill([7, 7, 7, 7, 8, 8], [1, 1], [14])
STYLES["c8_027"] = ringfill([11, 11, 7, 6, 5, 5], [1, 1], [8])
STYLES["c8_028"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [1])
STYLES["c8_029"] = ringfill([1, 1, 1, 1, 1, 1], [11, 11])    # 2/3 votes, e.g. rec_room g3_tbk#19+g3_npk#20 00
STYLES["c8_030"] = ringfill([2, 1, 1, 1, 1, 1], [8, 8], [15])
STYLES["c8_031"] = ringfill([1, 1, 1, 1, 1, 1], [8])    # 2/2 votes, e.g. rec_room g3_tbk#19+g3_npk#20 04
STYLES["c8_032"] = ringfill([15, 15, 15, 15, 15, 15], [9, 1], [10])
STYLES["c8_033"] = ringfill([15, 15, 15, 15, 15, 15], [10, 1], [])
STYLES["c8_034"] = ringfill([15, 15, 15, 15, 15, 15], [1, 6], [])
STYLES["c8_035"] = ringfill([13, 13, 15, 15, 15, 13], [1, 1], [])
STYLES["c8_036"] = ringfill([15, 15, 15, 15, 15, 15], [4, 1], [])
STYLES["c8_037"] = ringfill([2, 15, 15, 15, 15, 15], [1], [])
STYLES["c8_038"] = ringfill([7, 1, 1, 7, 7, 1], [15], [])
STYLES["c8_039"] = ringfill([7, 1, 1, 1, 7, 1], [4, 15], [])
STYLES["c8_040"] = ringfill([6, 9, 9, 10, 6, 6], [3, 3], [3])
STYLES["c8_041"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [7])    # 32/42 votes, e.g. rec_room g3_sm#3+g3_top#4 04
STYLES["c8_042"] = ringfill([9, 15, 15, 15, 15, 15], [7], [])
STYLES["c8_sil_c8_010_10"] = sil("c8_010", 10)
STYLES["c8_sil_c8_010_12"] = sil("c8_010", 12)
