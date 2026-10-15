"""Label styles of ctrler.arc (controller settings and control guide screens). Loaded by ui_type.py.
Colours come from the Japanese lettering of each palette (_work/ui_pages/tools/roles.py)."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}


def flat(ramp, cut=1):
    """Letters only, no ring: ink level k (1..6) -> palette index ramp[k]; pixels below `cut` are clear."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        out = np.where(ink >= cut, ramp[ink], 0).astype(np.uint8)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


# black body text of the guides (palette 23: index 1 black ... 13 light grey, soft edge onto a white plate)
STYLES["ctl_black"] = flat([0, 0, 9, 5, 3, 2, 1], cut=2)
# the same with a white halo (base names on the blue diamond panel)
STYLES["ctl_black_halo"] = ringfill([1], [15, 15])
