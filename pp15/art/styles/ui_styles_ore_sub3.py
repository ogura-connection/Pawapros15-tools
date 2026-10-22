"""Label styles of ore_sub.arc banks y3_kine (trophy room) and y3_pmoji (profile words). Loaded by pp15/art/typeset.py."""
import numpy as np
from pp15.art import typeset as ui_type
from pp15.art.typeset import banded, dropped

def uniform(style, rows):
    """`style`'s art padded evenly above and below to at least `rows` high (equal shelves for the page packer)"""
    def made(ink, base):
        art, b = style(ink, base)
        h, w = art.shape
        if h >= rows: return art, b
        top = (rows - h) // 2
        out = np.zeros((rows, w), np.uint8)
        out[top:top + h] = art
        return out, b + top
    return made

STYLES = {
    # y3_pmoji palette 0: navy letters with a pale-blue shadow three pixels deep, down and to the right
    "o3pmraw": dropped([0, 11, 12, 13, 14, 14, 14], [6, 4, 2]),
    "o3pm": uniform(dropped([0, 11, 12, 13, 14, 14, 14], [6, 4, 2]), 20),
    # y3_kine palette 18: white letters, a dark ring and a thin brown one, a one-pixel shadow
    "o3stadraw": banded([0, 10, 12, 14, 15, 15, 15], [3, 1], 2),
    "o3stad": banded([0, 10, 12, 14, 15, 15, 15], [3, 1], 2),
    # y3_kine palette 16: the green sign of the trophy room: yellow letters in pale green, dark green and bright green rings
    "o3memo": banded([0, 12, 13, 14, 15, 15, 15], [9, 5, 4, 2], 0),
    # no art at all (a plate copied by a "paint" entry with "copy")
    "o3none": lambda ink, base: (np.zeros((1, 1), np.uint8), base),
}
