"""Label styles of art run 9, agent A (leftover pages of scs_main / scs_data / scs_rens / scs_make). Read from the
Japanese lettering with style_reader; assembled from run9/A/styles_<stem>.txt by gen_r9a_lib.assemble(). Keep importable."""
import ui_type
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat
from ui_styles_c_run1 import win
import numpy as np

def bandeco(fill, inner, shadow, outer, edge=3):
    """Banner lettering: letters filled top to foot from `fill`, a thin `inner` ring, a dark extrusion `shadow` (near to far, down and
    to the right of the ring) and the `outer` rings (nearest first) round letters and extrusion together."""
    from ui_type import grow, shift
    fill = list(fill)

    def style(ink, base):
        pad = len(inner) + len(shadow) + len(outer) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        ring = letters
        rings = []
        for _ in inner:
            ring = grow(ring, 1, diagonal=False) if rings else grow(ring, 1)
            rings.append(ring)
        body = rings[-1]
        sh = np.zeros(big.shape, bool)
        for k in range(1, len(shadow) + 1):
            sh |= shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
        whole = body | sh
        out = np.zeros(big.shape, np.uint8)
        o = whole
        orings = []
        for _ in outer:
            o = grow(o, 1, diagonal=False) if orings else grow(o, 1)
            orings.append(o)
        for m, v in zip(orings[::-1], outer[::-1]):
            out[m] = v
        for k in range(len(shadow), 0, -1):
            mk = shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
            out[mk] = shadow[k - 1]
        for m, v in zip(rings[::-1], inner[::-1]):
            out[m] = v
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        row = np.broadcast_to(row, big.shape)
        out[letters] = np.where(big >= edge, row, inner[0])[letters]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style

STYLES = {}

# styles_scs_main.txt
STYLES["a9_smi_8a"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
STYLES["a9_smi_8b"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
STYLES["a9_ai_0f"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_24"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_39"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_3a"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_3b"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_smj_a"] = ringfill([1, 1, 1, 1, 1, 1], [8, 15, 15, 14])
STYLES["a9_smj_b"] = ringfill([1, 1, 1, 1, 1, 1], [15, 15, 15, 14])
STYLES["a9_smj_c"] = ringfill([1, 1, 1, 1, 1, 1], [14, 14, 14, 15])
STYLES["a9_smj_d"] = ringfill([1, 1, 1, 1, 1, 1], [9, 14, 14, 15])
# styles_scs_main_win.txt
STYLES["a9_smj_a~0_61"] = win(STYLES["a9_smj_a"], 0, 61)
STYLES["a9_smj_a~61_115"] = win(STYLES["a9_smj_a"], 61, 115)
STYLES["a9_smj_a~115_169"] = win(STYLES["a9_smj_a"], 115, 169)
STYLES["a9_smj_a~169_184"] = win(STYLES["a9_smj_a"], 169, 184)
STYLES["a9_smj_a~184_223"] = win(STYLES["a9_smj_a"], 184, 223)
STYLES["a9_smj_b~0_62"] = win(STYLES["a9_smj_b"], 0, 62)
STYLES["a9_smj_b~62_115"] = win(STYLES["a9_smj_b"], 62, 115)
STYLES["a9_smj_b~115_146"] = win(STYLES["a9_smj_b"], 115, 146)
STYLES["a9_smj_b~146_169"] = win(STYLES["a9_smj_b"], 146, 169)
STYLES["a9_smj_b~169_223"] = win(STYLES["a9_smj_b"], 169, 223)
STYLES["a9_smj_c~0_40"] = win(STYLES["a9_smj_c"], 0, 40)
STYLES["a9_smj_c~40_89"] = win(STYLES["a9_smj_c"], 40, 89)
STYLES["a9_smj_c~89_143"] = win(STYLES["a9_smj_c"], 89, 143)
STYLES["a9_smj_c~143_147"] = win(STYLES["a9_smj_c"], 143, 147)
STYLES["a9_smj_c~147_191"] = win(STYLES["a9_smj_c"], 147, 191)
STYLES["a9_smj_c~191_244"] = win(STYLES["a9_smj_c"], 191, 244)
STYLES["a9_smj_d~0_22"] = win(STYLES["a9_smj_d"], 0, 22)
STYLES["a9_smj_d~22_52"] = win(STYLES["a9_smj_d"], 22, 52)
STYLES["a9_smj_d~52_106"] = win(STYLES["a9_smj_d"], 52, 106)
