"""Label styles of the ore_sub.arc schedule screen (bank y3_yotei). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import banded, logo, dropped, outlined, grow, shift

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))

STYLES = {
    # big yellow headings with blue ring and white band (palette 21)
    "yhead": logo([10, 11, 12, 13], [8, 7], 9, 3, 2, [5, 4], 2, 2),
    # white letters, dark blue ring, paler ring (stadium names, palette 16)
    "stad": banded([0, 12, 13, 14, 15, 15, 15], [5, 9]),
    # navy place names with a pale ring (palette 36)
    "city": banded([0, 9, 11, 13, 14, 15, 15], [3]),
}
