"""Label styles of art run 1, agent E: scorebook tags, team initials, plates, shift editor (see ui_type.py)."""
import numpy as np
import ui_type
from ui_type import banded, outlined, tight, grow

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def crisp(style, thr=3):
    """The style applied to ink cut at `thr`: every letter pixel full ink, no half tones."""
    def s(ink, base):
        return style(np.where(ink >= thr, 6, 0), base)
    return s


STYLES = {
    # scorebook tags (g3_nk, g3_tij): white letters, navy ring, a blue outer ring (palettes 7-10 share indices 3..f)
    "e_tag": crisp(tight(banded([0, 15, 15, 15, 15, 15, 15], [4, 6]))),
}
