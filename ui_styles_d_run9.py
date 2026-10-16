"""Label styles of art run 9, agent D (names d9_*), read from the Japanese lettering by gen_d9_styles.add.
Keep importable at every moment."""
import ui_type
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat
import numpy as np

STYLES = {}

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
