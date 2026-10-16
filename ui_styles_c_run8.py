"""Label styles of art run 8, agent C (rec_room.arc part 3), read from the Japanese lettering by run8/C/c8_lib.py."""
import numpy as np
from ui_styles_ore_ini import ringfill


def flat(c):
    def style(ink, base):
        out = np.where(ink >= 2, c, 0).astype(np.uint8)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


def sil(front, c):
    def style(ink, base):
        out, bb = STYLES[front](ink, base)
        return np.where(out > 0, c, 0).astype(np.uint8), bb
    return style


def comp(inner, blob, h, w, cx, cy):
    import zlib, base64
    bg = np.frombuffer(zlib.decompress(base64.b64decode(blob)), np.uint8).reshape(h, w).copy()
    def style(ink, base):
        art, b = STYLES[inner](ink, base)
        out = bg.copy()
        ah, aw = art.shape
        top = max(0, min(h - ah, int(round(cy - ah / 2.0)))); left = max(0, min(w - aw, int(round(cx - aw / 2.0))))
        sl = out[top:top + ah, left:left + aw]
        sl[art > 0] = art[art > 0]
        return out, b + top
    return style


def win(style, c0, c1):
    def f(ink, base):
        out, b = style(ink, base)
        return out[:, c0:c1], b
    return f


STYLES = {}
STYLES["c8_000"] = ringfill([54, 54, 54, 54, 54, 54], [87, 87], [])
STYLES["c8_001"] = ringfill([54, 54, 54, 54, 54, 54], [87, 147], [107])
STYLES["c8_002"] = ringfill([54, 54, 54, 54, 54, 54], [87, 147], [])
STYLES["c8_comp_g3_kkm_00"] = comp("c8_000", "eNrtmEtrG1cUx7MIFFI6o7G88DpklU2ycrsopbsWCt11Ec3jmoEG8gFmsDVW6VcQV1gIS7F20ieSLZFEWC9UVZ7ZZtlz7p3HHT1c+REo9PxkEzK6L//+594Z6ckTgiAIgiAIgiAIgiAIgiAIgiAIgiAIgiAIgiAIgiAIgiAIgiAIgiAIgiAIgiCI/xe1Wv2s0Wi3W61ms9Md9Pu9y+FwNBpPOeeH23nGr5ipe6cJZX17+9eHh/jeT8i3eOGcc9dlb8wDzs+Vdm9hiBsXsAoG558OD39AxFsce7iMmZx/UHo8l9ddVwwkJvgOr3/i/Hexntff/4b8Ipv/ivwsVvSCt4vHk/6g22k2W612u9E4q9dqX0BvHeRetJpgFsSOxpPpLAqj8M8KcLrGbRbROb9mpuanzX0NfPBXyfsvnx6uuPk6+y8qcVy2Z6B1hbq47tp2QTv+g/O3WY/UuX6jWv+K85q4bsFA73ITfINBbF//C85bufWjBLQRzaaT8Wh42YM8mq0LCKN+tyhqZ412qwOKh6PJLIIBN8ndhrS4nWvXVivdCwwLL7+UcJ5Zf8VrXLUulTCroOmlvPUBGHSOwHkQGAPFeuY8OD7JrMPl99iDlYzClWJdTpCzDpvtXAnxKTh37T3d/1cNlYpIYjIaQgydVrtxVtus+qI56A0n8yi8i+RVEotbnaN0PxcSA7l1yUrr9+5HsC45F0ocqLMg0C3muDkc29rXfA9GA+vPJNI59NDLXlAoKOP+JetcD3TzKp3gg5zAZoxn2T9XKuIdR+f5otkV2A/RfDLsDZoXsf52pzedRw8wvVLqq0byeti+plYKGnQbCTeKGjwC0HrCCXa2jLJ3CsHm5wCDRQ1UeGXDusp6JG49XFVBvSzrf6X5iQzPYsoaxPmVVgTeOuyDHSr9Nv/hfNrrL8LTR8TbUIcqR1Yh8O/Q/mPCgYNK0Dm4xaSYk7xcVtLloFDS1nWCcAvvxBvQcdSUTLyOl9MJCsK5oRkldqNstqwiruKemvdgS/2F+CesPJZ2UbsO2/xy4egte2vtGRiBTuDVddRd4cBb6hliBF7cx7QUzHRMTzt4wxS3JV32wDRS645t45kjmhfs3CFVDPxALymTrsBY3PP+YI3Hx8sylf5Q/VCHOSN54BjwNrQHDwxetg2WswK2zIJpQwxHmAUDJceJW1CTEfipBxys5MZdkjpPrMe7A8Y14pSwuW0fxc2Fc7yWsw4LcRznRywJhmkF9zlTKulxUlnC8SLvo9X0RrpY5o73MKzc9caaN5In8L2N7c04J1PNC/7AQNvDGARwMO1QY6gx6aFWpZftDjzOvTSkg7S5ZchQAxxCBgSVYFmObGHjErSd6hwfJdVTuxItF+mNtLr+GFPNPTIulsto/ZlRJFF5xBuBrwWfA/FTDvIJBVpx3xQUjV2cY4TF4j5SLOYMZbWgJu+V1yfAa2n4pmGkYRW11aIRdsNww8PKcrnIPTJW7/DUXt3w4QiSgChu2wKR3CCPEIwHrvz4x9u5C7T+DL/eTinB6eTjbzlr7vnlJHl4RNUSjoO1gg5RL/hd/3BUfeyPqdVtXwNMptPZfL4QG0Sav++WCFMqKeLv3Lqj48KTpL2j+z3YxYNEomQXf89nU9Q6GqLY1a8Bqv+Zb2dgi2AumAxEA9k0O51udzCAgPq9HmaEKQHj8WQCWSGzGSQGkQmWCVFKPoIVhOGUtHc8GowLo8tpYL7xWMyNi7iE1cCaYGXdbgdkgk3Q2caln9XrX8boP43Z5EU=", 55, 373, 192, 20)
STYLES["c8_comp_g3_kkm_00~-11_117"] = win(STYLES["c8_comp_g3_kkm_00"], -11, 117)
STYLES["c8_comp_g3_kkm_00~117_245"] = win(STYLES["c8_comp_g3_kkm_00"], 117, 245)
STYLES["c8_comp_g3_kkm_00~245_4096"] = win(STYLES["c8_comp_g3_kkm_00"], 245, 4096)
STYLES["c8_comp_g3_kkm_01"] = comp("c8_001", "eNrtmM1um0oYhrOr1Epg15suzirLblp10YsJP4OQTqVeACgCI/UWrKG2rOKGHb4iJ1iqrPhPPogD2y7PNzM2BvxzmiZEXXyPE8vCw3jmfd9vZuyLCwRBEARBEARBEARBEARBEARBEARBEARBEARBEARBEARBEARBEARBEARBEARBEORPxPcH/eEwDEejIIjG0zie3M5m8/liuVqtN5s8yb5kuZdlXpc9BLZ0R+mrz4KPJS4ppb4J+JQWF99/rEKpqavtbh1auoW3otAPUWW71uqwsyvZ7fSh/eX+8ifKeENMQydEkRw2AZhHluSbzXq1Wi7m89nsdhLH03EUBKNRGA6H/YHvNyTxAAS+GQWgLojLpF3nMJgvHtB9CJYj39GCYrYfKOj9L9PdMMT191z1S1p25yXX6kB4W6oo/4rrrpPOtXXOnne8s9a1pMCA/P2YBvD/FxuJScA79xfmxERgauRrZgszZToORjdgyODhdvj9YTiKQObZfLnOodMHCnwat317J4AZvhV8+0rpdz5ZXVNVuP5B8IJ+pZ8LQPd7CPKB8Jbbhlte7nX/wQPfdqwzhQG693lnrqyQ77TE1DS3uiuyaz1ipp7H3VjOZ2BFNAqHff+03DfBdDJbbvLsyYQ+zGdL204N4iXYrjI8ZK22UlKhIgnozkJ6pEulFFmhO+lI9pHCKPBBd94Z1KBCiFkHRqLIzpPOHOoi3yxnk2lwU7IgjCarTd6U2pXFRnoNyuvwMIc7/tZF3DUIGUTQ3/GPeVfinrU5XGqgiuSr+4ruOqS1HnhRGAX9ojOWea2iOqzumtJybaspEbxss5pE4cVFnGTd54IrD1MDNKJXQ9aSQC5XVivXyxhafc8UmspXldQaats9Vhi1aLP1iA+opeom0bcPGJaqtH5peX8cWRLHiXjlPZPyHUWgEmLoPP2E17YImdsuKQ9v6AZrwp6IobWOrrs15bWWZB9rVFVe1xXRDIxT1BJv5AbTLpTmz0m8XWrSQvhGLbAsx7Xdn657zYpcg4Rp6l52fvRRiblNn6ZqZA+riROnJYXsQmtoryXHOtEIettG29SVXawt25X3uLbThOyw2RYv0+1SI+gVm2uSVpZ7OMo2s9mCEiJqilIJWSmBHXlXHgzYMq2TZVQktiOdUM6pJFuRnCZzzY6Z5RXcy9Ok2Fx7x483vcpxMknT/PA8yd14pB2WLbHkw59kWZXruwS6UBu7Nj8d27LOldH/JraebOvpFM6yI4eYNE0qx8neA0/1vSNfoMANsONcKeSiULxn2TgazG33qK5l2TMmMWh8+AWq18TX2d75nwwSXihC/d8tjazAKxBinFRJBFBQ3J3/dpJZJzmPbnL+J4PeH/VrDpQK84a5A/aAP0EUjcfTKZgUTybMJ+YUsFgsl+AXY70G18A2TrojL6jaUIOrXFDcve0N+oXexcfA5y0W/LPZIG5hNDAmGNl4HIGgoChIGrKh9weD5lT9DxsVZCk=", 55, 377, 186, 20)
STYLES["c8_comp_g3_kkm_01~-3_125"] = win(STYLES["c8_comp_g3_kkm_01"], -3, 125)
STYLES["c8_comp_g3_kkm_01~125_253"] = win(STYLES["c8_comp_g3_kkm_01"], 125, 253)
STYLES["c8_comp_g3_kkm_01~253_4096"] = win(STYLES["c8_comp_g3_kkm_01"], 253, 4096)
STYLES["c8_comp_g3_kkm_02"] = comp("c8_002", "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", 70, 377, 166, 31)
STYLES["c8_comp_g3_kkm_02~-3_125"] = win(STYLES["c8_comp_g3_kkm_02"], -3, 125)
STYLES["c8_comp_g3_kkm_02~125_253"] = win(STYLES["c8_comp_g3_kkm_02"], 125, 253)
STYLES["c8_comp_g3_kkm_02~253_4096"] = win(STYLES["c8_comp_g3_kkm_02"], 253, 4096)
