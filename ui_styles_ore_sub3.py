"""Label styles of ore_sub.arc banks y3_kine (trophy room) and y3_pmoji (profile words). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import banded, dropped

STYLES = {
    # y3_pmoji palette 0: navy letters with a pale-blue shadow three pixels deep, down and to the right
    "o3pm": dropped([0, 11, 12, 13, 14, 14, 14], [6, 4, 2]),
    # y3_kine palette 18: white letters, two dark rings and a thin brown one, a one-pixel shadow
    "o3stad": banded([0, 10, 12, 14, 15, 15, 15], [3, 3, 1], 2),
    # y3_kine palette 16: the green sign of the trophy room: yellow letters in pale green, dark green and bright green rings
    "o3memo": banded([0, 12, 13, 14, 15, 15, 15], [9, 5, 4, 2], 0),
    # no art at all (a plate copied by a "paint" entry with "copy")
    "o3none": lambda ink, base: (np.zeros((1, 1), np.uint8), base),
}
