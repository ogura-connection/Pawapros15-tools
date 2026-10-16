"""Label styles of art run 8, agent D (record.arc: g3_kn, g3_ke, g3_kekx). Written by gen_record_spec.py styles
(read from the Japanese lettering). Keep importable at every moment."""
import numpy as np
import ui_type
from ui_styles_ore_ini import ringfill

STYLES = {}


def plated(inner, W, H, idx):
    """`inner` art centred on a W x H rounded plate of index `idx` (the plate was part of the Japanese art)."""
    def f(ink, base):
        art, b = inner(ink, base)
        h, w = art.shape
        W2, H2 = max(W, w + 6), max(H, h + 2)
        out = np.zeros((H2, W2), np.uint8)
        r = H2 / 2.0
        yy, xx = np.mgrid[0:H2, 0:W2] + 0.5
        cx = np.clip(xx, r, W2 - r)
        out[(xx - cx) ** 2 + (yy - r) ** 2 <= r * r] = idx
        oy, ox = (H2 - h) // 2, (W2 - w) // 2
        sl = out[oy:oy + h, ox:ox + w]
        sl[art > 0] = art[art > 0]
        return out, b + oy
    return f


def flat(style, idx):
    """The same art as `style`, all one index (a flat shadow of the lettering)."""
    def f(ink, base):
        art, b = style(ink, base)
        return np.where(art > 0, idx, 0).astype(np.uint8), b
    return f
STYLES["d8_g3_kekx_02"] = ui_type.logo(**{'fill': [252, 250, 248, 244, 242, 240], 'outline': 87, 'white': 255, 'rim': 125, 'shadow': [139, 153, 153, 153, 167], 'soft': [], 'thick': 2, 'band': 2})      # learn_logo
STYLES["d8_g3_kekx_04"] = ui_type.logo(**{'fill': [253, 251, 235, 245, 243, 134], 'outline': 87, 'white': 255, 'rim': 166, 'shadow': [153, 153], 'soft': [], 'thick': 1, 'band': 1})      # learn_logo
STYLES["d8_g3_kekx_08"] = ui_type.logo(**{'fill': [253, 251, 235, 245, 243, 134], 'outline': 87, 'white': 255, 'rim': 166, 'shadow': [153, 153, 153, 140, 153], 'soft': [], 'thick': 2, 'band': 2})      # learn_logo
STYLES["d8_g3_kekx_05"] = ui_type.logo(**{'fill': [253, 251, 235, 245, 243, 134], 'outline': 87, 'white': 255, 'rim': 166, 'shadow': [153, 153], 'soft': [], 'thick': 1, 'band': 1})      # learn_logo
STYLES["d8_g3_kn_09"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [13]
STYLES["d8_g3_kn_0a"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [10, 13]
STYLES["d8_g3_kn_0b"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7, 9, 10]
STYLES["d8_g3_kn_0c"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7, 10, 12]
STYLES["d8_g3_kn_0d"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7, 13]
STYLES["d8_g3_kn_0e"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7, 10]
STYLES["d8_g3_kn_0f"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7, 10]
STYLES["d8_g3_kn_10"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7]
STYLES["d8_g3_kn_11"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7, 8, 10, 11, 13]
STYLES["d8_g3_kn_12"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7, 10, 13]
STYLES["d8_g3_kn_13"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [3, 7]
STYLES["d8_g3_kn_14"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [7, 9]
STYLES["d8_g3_kn_15"] = ringfill([15, 15, 15, 15, 14, 14], [7], [4, 2])      # fill [13]
STYLES["d8_g3_kn_34"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [11, 14, 15]
STYLES["d8_g3_kn_35"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [10, 11, 12, 15]
STYLES["d8_g3_kn_2a"] = ringfill([15, 15, 15, 15, 14, 14], [7, 7])      # fill [7, 9, 13]
STYLES["d8_g3_kn_31"] = ringfill([15, 15, 15, 15, 14, 14], [7, 7])      # fill [7, 9, 13]
STYLES["d8_g3_kn_40"] = ringfill([15, 15, 15, 15, 14, 14], [7, 7])      # fill [7, 9, 13]
STYLES["d8_g3_ke_03"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [11, 13, 14, 15]
STYLES["d8_g3_ke_04"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [11, 14, 15]
STYLES["d8_g3_ke_05"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [13, 15]
STYLES["d8_g3_ke_08"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [13, 15]
STYLES["d8_g3_ke_09"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [13, 15]
STYLES["d8_g3_ke_06"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [11, 15]
STYLES["d8_g3_ke_07"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [11, 13, 15]
STYLES["d8_g3_ke_0a"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [11, 15]
STYLES["d8_g3_ke_0b"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [15]
STYLES["d8_g3_ke_0c"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [13, 15]
STYLES["d8_g3_ke_0d"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [13, 15]
STYLES["d8_g3_ke_0e"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [15]
STYLES["d8_g3_ke_0f"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [11, 15]
STYLES["d8_g3_ke_10"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [13, 15]
STYLES["d8_g3_ke_15"] = ringfill([15, 15, 15, 14, 14, 13], [8])      # fill [12]
STYLES["d8_g3_ke_16"] = ringfill([15, 15, 15, 14, 14, 13], [8])      # fill [10, 11, 12, 15]
STYLES["d8_g3_ke_17"] = ringfill([15, 15, 15, 14, 14, 13], [8])      # fill [10, 13, 15]
STYLES["d8_g3_ke_18"] = ringfill([15, 15, 15, 14, 14, 13], [8])      # fill [10]
STYLES["d8_g3_ke_20_in"] = ringfill([15, 15, 15, 14, 14, 13], [4])
STYLES["d8_g3_ke_20"] = plated(ringfill([15, 15, 15, 14, 14, 13], [4]), 370, 31, 4)      # fill [4]
STYLES["d8_g3_ke_23"] = ui_type.logo(**{'fill': [14, 14, 13, 13, 12, 12], 'outline': 1, 'white': 15, 'rim': 7, 'shadow': [2, 8, 8, 7, 4, 8], 'soft': [], 'thick': 2, 'band': 2})      # learn_logo
STYLES["d8_g3_ke_35_in"] = ringfill([15, 15, 15, 14, 14, 14], [7])
STYLES["d8_g3_ke_35"] = plated(ringfill([15, 15, 15, 14, 14, 14], [7]), 66, 20, 7)      # fill [7]
STYLES["d8_g3_ke_44_in"] = ringfill([15, 15, 15, 14, 14, 14], [7])
STYLES["d8_g3_ke_44"] = plated(ringfill([15, 15, 15, 14, 14, 14], [7]), 117, 23, 7)      # fill [7, 13]
STYLES["d8_g3_ke_4d"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 9, 10, 13]
STYLES["d8_g3_ke_4f_in"] = ringfill([15, 15, 15, 14, 14, 14], [7])
STYLES["d8_g3_ke_4f"] = plated(ringfill([15, 15, 15, 14, 14, 14], [7]), 121, 21, 7)      # fill [7, 13]
STYLES["d8_g3_ke_61"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [10, 11, 15]
STYLES["d8_g3_ke_62"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [11, 15]
STYLES["d8_g3_ke_63"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [10, 11, 15]
STYLES["d8_g3_ke_64"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [11, 13, 15]
STYLES["d8_g3_ke_9c"] = ringfill([15, 15, 15, 14, 14, 13], [1])      # fill [1, 4, 6]
STYLES["d8_g3_ke_8a"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [15]
STYLES["d8_g3_ke_8b"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [12, 15]
STYLES["d8_g3_ke_8c"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [10, 15]
STYLES["d8_g3_ke_8d"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [12, 15]
STYLES["d8_g3_ke_8e"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [1, 12, 13, 15]
STYLES["d8_g3_ke_8f"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [15]
STYLES["d8_g3_ke_90"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [15]
STYLES["d8_g3_ke_91"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [10, 12, 15]
STYLES["d8_g3_ke_92"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [10, 12, 15]
STYLES["d8_g3_ke_93"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [10, 15]
STYLES["d8_g3_ke_94"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [10, 15]
STYLES["d8_g3_ke_95"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [10, 15]
STYLES["d8_g3_ke_96"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [12, 15]
STYLES["d8_g3_ke_97"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [12, 15]
STYLES["d8_g3_ke_98"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [10, 15]
STYLES["d8_g3_ke_99"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [15]
STYLES["d8_g3_ke_9a"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [13, 15]
STYLES["d8_g3_ke_9b"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [15]
STYLES["d8_g3_ke_a5"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [15]
STYLES["d8_g3_ke_a6"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [12, 15]
STYLES["d8_g3_ke_a7"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [10, 13, 15]
STYLES["d8_g3_ke_aa"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [10, 13, 15]
STYLES["d8_g3_ke_ab"] = ringfill([8, 8, 8, 9, 9, 5], [15])      # fill [12, 15]
STYLES["d8_g3_ke_a0"] = ringfill([15, 15, 15, 15, 15, 15], [12])      # fill [14]
STYLES["d8_g3_ke_a1"] = ringfill([15, 15, 15, 15, 15, 15], [12])      # fill [13, 14]
STYLES["d8_g3_ke_a2"] = ringfill([15, 15, 15, 15, 15, 15], [12])      # fill [12, 13, 14]
STYLES["d8_g3_ke_a3"] = ringfill([15, 15, 15, 15, 15, 15], [12])      # fill [12, 13, 14]
STYLES["d8_g3_ke_a4"] = ringfill([15, 15, 15, 15, 15, 15], [12])      # fill [12, 13, 14]
STYLES["d8_g3_ke_ad"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 11]
STYLES["d8_g3_ke_ae"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 10]
STYLES["d8_g3_kn_cell"] = ringfill([15, 15, 15, 15, 14, 14], [7, 7])      # fill [7, 8, 12, 13]
STYLES["d8_g3_ke_w12"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [11, 12, 15]
STYLES["d8_g3_ke_l12"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [11, 12, 14, 15]
STYLES["d8_g3_ke_sv12"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [10, 15]
STYLES["d8_g3_ke_hr13"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [11, 13, 15]
STYLES["d8_g3_ke_31a"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7]
STYLES["d8_g3_ke_31b"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [9, 10, 11]
STYLES["d8_g3_ke_31c"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 13]
STYLES["d8_g3_ke_31d"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 9]
STYLES["d8_g3_ke_31e"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 13]
STYLES["d8_g3_ke_31f"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 9, 10]
STYLES["d8_g3_ke_31g"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 10]
STYLES["d8_g3_ke_37a_in"] = ringfill([15, 15, 15, 14, 14, 14], [7])
STYLES["d8_g3_ke_37a"] = plated(ringfill([15, 15, 15, 14, 14, 14], [7]), 66, 22, 7)      # fill [12, 13]
STYLES["d8_g3_ke_37b"] = ringfill([7] * 6, [7])      # fill [7]
STYLES["d8_g3_ke_37c"] = ringfill([7] * 6, [7])      # fill [3, 6, 7]
STYLES["d8_g3_ke_51a"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 13]
STYLES["d8_g3_ke_51b"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [10, 13]
STYLES["d8_g3_ke_51c"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 13]
STYLES["d8_g3_ke_51d"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [13]
STYLES["d8_g3_ke_58a"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7]
STYLES["d8_g3_ke_58b"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 10]
STYLES["d8_g3_ke_58c"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 10, 12, 13]
STYLES["d8_g3_ke_58d"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7]
STYLES["d8_g3_ke_58e"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 10]
STYLES["d8_g3_ke_58f"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [1, 4, 5, 7]
STYLES["d8_g3_ke_5ba"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 10, 12]
STYLES["d8_g3_ke_5bb"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [15]
STYLES["d8_g3_ke_5bc"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 9, 10]
STYLES["d8_g3_ke_5bd"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 12, 13]
STYLES["d8_g3_ke_5be"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 10]
STYLES["d8_g3_ke_5da"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 13]
STYLES["d8_g3_ke_5db"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [7, 13]
STYLES["d8_g3_ke_5dc"] = ringfill([15, 15, 15, 14, 14, 14], [7])      # fill [10, 13]
STYLES["d8_g3_ke_n68"] = ringfill([15, 15, 15, 14, 14, 13], [1])      # fill [1, 12]
STYLES["d8_g3_ke_rival1"] = ringfill([8, 8, 8, 7, 7, 9], [15])      # fill [10, 12, 13, 14, 15]
STYLES["d8_g3_ke_a8a"] = ringfill([8, 8, 8, 6, 6, 5], [15])      # fill [5, 12, 14, 15]
STYLES["d8_g3_ke_a9a"] = ringfill([8, 8, 8, 6, 6, 5], [15])      # fill [5, 12, 14, 15]
STYLES["d8_g3_ke_dai"] = ringfill([8, 8, 8, 7, 7, 5], [15])      # fill [10, 13, 14, 15]
STYLES["d8_g3_kekx_03"] = flat(STYLES["d8_g3_kekx_02"], 255)      # the silhouette index of palette 32
