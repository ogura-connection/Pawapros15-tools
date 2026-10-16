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
STYLES["a9_smj_a"] = bandeco([7, 8, 9, 10, 11, 11], [3], [1, 1, 1], [15, 15, 14])
STYLES["a9_smj_b"] = bandeco([7, 8, 9, 10, 11, 11], [3], [1, 1, 1], [15, 15, 14])
STYLES["a9_smj_c"] = bandeco([5, 6, 7, 9, 10, 10], [1], [1, 1, 1], [14, 14, 14, 15])
STYLES["a9_smj_d"] = bandeco([5, 6, 7, 9, 10, 10], [1], [1, 1, 1], [14, 14, 14, 15])
STYLES["a9_tem"] = ringfill([9, 9, 8, 8, 7, 7], [1, 1, 13, 13, 14], [15])
STYLES["a9_snm"] = ringfill([15, 15, 15, 15, 15, 15], [4, 4], [4, 4])
# styles_scs_main_win.txt
STYLES["a9_smj_a~0_64"] = win(STYLES["a9_smj_a"], 0, 64)
STYLES["a9_smj_a~64_119"] = win(STYLES["a9_smj_a"], 64, 119)
STYLES["a9_smj_a~119_175"] = win(STYLES["a9_smj_a"], 119, 175)
STYLES["a9_smj_a~175_191"] = win(STYLES["a9_smj_a"], 175, 191)
STYLES["a9_smj_a~191_231"] = win(STYLES["a9_smj_a"], 191, 231)
STYLES["a9_smj_b~0_61"] = win(STYLES["a9_smj_b"], 0, 61)
STYLES["a9_smj_b~61_117"] = win(STYLES["a9_smj_b"], 61, 117)
STYLES["a9_smj_b~117_149"] = win(STYLES["a9_smj_b"], 117, 149)
STYLES["a9_smj_b~149_172"] = win(STYLES["a9_smj_b"], 149, 172)
STYLES["a9_smj_b~172_226"] = win(STYLES["a9_smj_b"], 172, 226)
STYLES["a9_smj_c~0_40"] = win(STYLES["a9_smj_c"], 0, 40)
STYLES["a9_smj_c~40_85"] = win(STYLES["a9_smj_c"], 40, 85)
STYLES["a9_smj_c~85_138"] = win(STYLES["a9_smj_c"], 85, 138)
STYLES["a9_smj_c~138_146"] = win(STYLES["a9_smj_c"], 138, 146)
STYLES["a9_smj_c~146_193"] = win(STYLES["a9_smj_c"], 146, 193)
STYLES["a9_smj_c~193_249"] = win(STYLES["a9_smj_c"], 193, 249)
STYLES["a9_smj_d~0_24"] = win(STYLES["a9_smj_d"], 0, 24)
STYLES["a9_smj_d~24_55"] = win(STYLES["a9_smj_d"], 24, 55)
STYLES["a9_smj_d~55_109"] = win(STYLES["a9_smj_d"], 55, 109)
STYLES["a9_tem~0_32"] = win(STYLES["a9_tem"], 0, 32)
STYLES["a9_tem~32_68"] = win(STYLES["a9_tem"], 32, 68)
STYLES["a9_tem~68_84"] = win(STYLES["a9_tem"], 68, 84)
STYLES["a9_tem~84_116"] = win(STYLES["a9_tem"], 84, 116)
STYLES["a9_tem~116_164"] = win(STYLES["a9_tem"], 116, 164)
STYLES["a9_tem~164_212"] = win(STYLES["a9_tem"], 164, 212)
STYLES["a9_tem~212_255"] = win(STYLES["a9_tem"], 212, 255)
STYLES["a9_tem~255_303"] = win(STYLES["a9_tem"], 255, 303)
STYLES["a9_tem~303_335"] = win(STYLES["a9_tem"], 303, 335)
STYLES["a9_tem~335_351"] = win(STYLES["a9_tem"], 335, 351)
