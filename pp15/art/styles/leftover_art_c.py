"""Styles for the art banks the earlier runs missed, group C (2026-10-22): the Arrange "Power Pros Portable Link" screens
of are_psp.arc (menu titles, the send-a-player messages, Success / Failed) and the Pennant ending banner of o_ending.arc
(優勝 -> Champions!, 日本一 -> No. 1 in Japan!).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow. Colours are palette indices read from the Japanese lettering of the same sprite.

Used by: specs/are_psp.json, specs/o_ending.json (groups "lo_c ...").
"""
import numpy as np
from .common import ringfill, win

STYLES = {}


def _on_plate(inner, w, h, bg, dy=0):
    """The art of `inner` centred on a plate w x h of colour `bg` (the Japanese message boxes of mp1_bd carry the colour of
    the window behind them, so the English keeps the plate). The letters sit `dy` rows below the plate's middle."""
    def style(ink, base):
        art, b = inner(ink, base)
        out = np.full((h, w), bg, np.uint8)
        ah, aw = art.shape
        y = (h - ah) // 2 + dy
        x = (w - aw) // 2
        sy0, sx0 = max(0, -y), max(0, -x)
        dy0, dx0 = max(0, y), max(0, x)
        hh, ww = min(ah - sy0, h - dy0), min(aw - sx0, w - dx0)
        a = art[sy0:sy0 + hh, sx0:sx0 + ww]
        out[dy0:dy0 + hh, dx0:dx0 + ww] = np.where(a > 0, a, out[dy0:dy0 + hh, dx0:dx0 + ww])
        return out, b + y
    return style


# ---- are_psp.arc m3_psp00 (4-bit pages, colours of pal_m3_psp00)
STYLES["lo_c_psp_pick"] = ringfill([1, 1, 1, 1, 1, 1], [15, 15], [5, 5])            # 01 送信する選手を選んでください (pal 2): dark green, white ring, green drop
STYLES["lo_c_psp_ask"] = ringfill([1, 1, 1, 1, 1, 1], [15, 15, 15], [7, 9])         # 03 この選手を送信しますか / はい / いいえ (pal 4): blue, white ring, pale blue drop
STYLES["lo_c_psp_sent"] = ringfill([1, 1, 3, 3, 2, 2], [8, 8, 12], [13, 14])        # 04 選手の送信が完了しました (pal 5): green, blue outline, pale ring
for _c0, _c1 in ((0, 128), (128, 4096)):
    STYLES["lo_c_psp_ask~%d_%d" % (_c0, _c1)] = win(STYLES["lo_c_psp_ask"], _c0, _c1)

# ---- are_psp.arc s4_pspz00 (8-bit pages; palette numbers 0 / 16 / 32 / 48): menu titles, gradient fill top to foot
STYLES["lo_c_psp_t00"] = ringfill([132, 120, 113, 98, 85, 55], [255, 255, 255, 8], [1, 1, 146])      # パワプロポータブル通信: orange, white, blue
STYLES["lo_c_psp_t01"] = ringfill([238, 232, 222, 212, 202, 190], [1, 1, 255, 255, 255], [172, 172, 172])  # 選手を送る: yellow -> orange, maroon, white
STYLES["lo_c_psp_t02"] = ringfill([244, 232, 224, 216, 208, 199], [1, 1, 255, 255, 255], [156, 156, 156])  # 応援曲を受けとる: yellow -> green
STYLES["lo_c_psp_t05"] = ringfill([245, 230, 221, 204, 183, 165], [1, 1, 255, 255, 255], [174, 174, 174])  # 応援曲を送る: pale -> green

# ---- are_psp.arc mp1_bd: 成功しました / 失敗しました on the colour of the window behind them (4-bit, pal 3 / pal 4)
STYLES["lo_c_psp_ok"] = _on_plate(ringfill([1, 1, 1, 1, 1, 1], [15, 15, 15], [9, 9]), 184, 40, 13)
STYLES["lo_c_psp_ng"] = _on_plate(ringfill([1, 1, 1, 1, 1, 1], [15, 15, 15], [5, 5]), 200, 40, 12)

# ---- o_ending.arc i3_yuu (8-bit pages, palette 0): the big banners of the Pennant ending, navy outline, white ring
STYLES["lo_c_end_win"] = ringfill([81, 72, 210, 232, 236, 236, 231, 212, 208, 73, 81, 92, 88],
                                  [156, 156, 156, 2, 2, 2, 2])                     # 優勝: red-orange, yellow middle, red foot
STYLES["lo_c_end_japan"] = ringfill([59, 62, 66, 67, 255, 253, 251, 250, 248, 245],
                                    [156, 156, 156, 2, 2, 2, 2])                   # 日本一: orange -> yellow
