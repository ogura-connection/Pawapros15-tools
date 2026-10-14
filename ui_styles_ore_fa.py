"""Label styles of ore_fa.arc (My Life free agency screen, bank y3_fa). Loaded by ui_type.py.
crisp(fill, rings, shadow, cut): letters (ink >= cut of 6) filled from `fill` (a list is a ramp from the top row of the
letters to the foot), solid one-pixel rings (innermost first), a shadow (near to far, one pixel a colour) cast down and
right. Colours are palette indices read from the Japanese lettering."""
import numpy as np
import ui_type
from ui_type import grow, shift

ui_type.TTF["din"] = ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0)


def crisp(fill, rings, shadow=(), cut=3):
    fill = list(fill) if isinstance(fill, (list, tuple)) else [fill]

    def style(ink, base):
        pad = len(rings) + len(shadow) + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big >= cut
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        edge = masks[-1]
        for k in range(len(shadow), 0, -1):
            out[shift(edge, k, k) | shift(edge, k, k - 1) | shift(edge, k - 1, k)] = shadow[k - 1]
        for mk, v in zip(masks[::-1], rings[::-1]):
            out[mk] = v
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        out[letters] = np.broadcast_to(row, big.shape)[letters]
        ys = np.nonzero(out.any(1))[0]
        xs = np.nonzero(out.any(0))[0]
        r0, r1, c0, c1 = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
        return out[r0:r1, c0:c1], base + pad - r0
    return style


STYLES = {
    # FA / destination heading (palette 7): blue ramp, white ring
    "fa_head": crisp([5, 5, 4, 4, 3, 3, 2, 2], [15]),
    # the purple labels of the status box (palettes 4 and 5): fill f, white ring 6, blue shadow 9 / 1 / 3
    "fa_label": crisp(15, [6], [9, 1, 3]),
    # the team-choice prompt on the green bar (palette 11): dark green, white ring
    "fa_prompt": crisp(11, [4, 4]),
    # Yes / No and the question (palette 21): deep blue, white ring, pale blue shadow
    "fa_ask": crisp([3, 2, 1, 1, 1], [15, 15], [10, 5, 5]),
}


# ---- the plate of "条件提示" (sprite 11, page 3 rect 0,72,72,104 of y3_fa, palette 2): lettering painted on the plate.
import os
import ui_textures as _U
import scan_story as _S

_PLATE = {}


def _old_plate():
    if "p" not in _PLATE:
        path = os.path.join(_U.ORIG_ARC_DIR, "ore_fa.arc")
        if not os.path.exists(path):
            path = os.path.join(_S.DATA_FILES, "ore_fa.arc")
        d = open(path, "rb").read()
        b = next(x for x in _U.banks(d, _U.elf_symbols(d)) if x["name"] == "y3_fa")
        _PLATE["p"] = _U.decode_indices(d, *b["pages"][3])[72:104, 0:72].copy()
    return _PLATE["p"].copy()


def _bg(r, c):
    """Plate colour at row r, column c of the 条件提示 band: pale 'e' (14) to row 15, a dither of e / d (13) from 16 to
    22, 'd' below."""
    if r <= 15 or r == 17:
        return 14
    return {16: 14 if c % 2 == 0 else 13, 18: 13 if c % 2 == 0 else 14, 19: 14 if c % 2 == 0 else 13,
            20: 13 if c % 2 == 0 else 14, 22: 14 if c % 2 == 0 else 13}.get(r, 13)


def offerplate(fill, rings, cx=27, cy=18):
    """The old 72x32 plate with its lettering (columns 0-58, rows 6-28) painted over with the plate colours and the
    English centred at (cx, cy). Use with "left": 0, "baseline": 0."""
    inner = crisp(fill, rings)

    def style(ink, base):
        pic = _old_plate()
        for r in range(6, 29):
            for c in range(0, 59):
                pic[r, c] = _bg(r, c)
        art, b = inner(ink, base)
        h, w = art.shape
        x, y = cx - w // 2, cy - h // 2
        sub = pic[y:y + h, x:x + w]
        sub[art > 0] = art[art > 0]
        return pic, 0
    return style


def offerleft(ink, base):
    """Page 1 rect (0,0,72,80) of y3_fa: the plate end, with the right edge of the 条 painted out (columns 62-71, rows 8-28)."""
    path = os.path.join(_U.ORIG_ARC_DIR, "ore_fa.arc")
    if not os.path.exists(path):
        path = os.path.join(_S.DATA_FILES, "ore_fa.arc")
    d = open(path, "rb").read()
    b = next(x for x in _U.banks(d, _U.elf_symbols(d)) if x["name"] == "y3_fa")
    pic = _U.decode_indices(d, *b["pages"][1])[0:80, 0:72].copy()
    for r in range(8, 29):
        for c in range(62, 72):
            pic[r, c] = _bg(r, c)
    return pic, 0


STYLES["fa_offer"] = offerplate(15, [3, 3])
STYLES["fa_offerleft"] = offerleft
