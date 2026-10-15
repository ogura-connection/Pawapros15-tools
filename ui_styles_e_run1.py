"""Label styles of art run 1, agent E: scorebook tags, team initials, plates, shift editor (see ui_type.py)."""
import numpy as np
import ui_type
from ui_type import banded, outlined, tight, grow, logo

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def crisp(style, thr=3):
    """The style applied to ink cut at `thr`: every letter pixel full ink, no half tones."""
    def s(ink, base):
        return style(np.where(ink >= thr, 6, 0), base)
    return s


def scm_style(ink, base):
    """Team initials of the scoreboard (g3_scm, palette 0): white letters whose lower edge turns grey, a dark green
    outline that is cast two pixels down and to the right, a green fringe on that shadow."""
    pad = 4
    ink = np.where(ink >= 3, 6, 0)
    h, w = ink.shape
    big = np.zeros((h + 2 * pad, w + 2 * pad), int)
    big[pad:pad + h, pad:pad + w] = ink
    letters = big > 0
    ring = grow(letters, 1)
    body = ring | ui_type.shift(ring, 1, 1) | ui_type.shift(ring, 2, 2) | ui_type.shift(ring, 1, 2) | ui_type.shift(ring, 2, 1)
    fringe = (ui_type.shift(body, 1, 0) | ui_type.shift(body, 0, 1) | ui_type.shift(body, 1, 1)) & ~body
    out = np.zeros(big.shape, np.uint8)
    out[fringe] = 6
    out[body] = 7
    out[letters] = 15
    low = letters & ~ui_type.shift(letters, -1, 0)                  # no letter pixel below: the foot of a stroke
    out[low] = 11
    low2 = letters & ~ui_type.shift(letters, -2, 0) & ~low
    out[low2] = 13
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()


# ---- plates whose lettering is part of the picture: the plate is cleaned and the English drawn over it ----
_plates = {}


def _orig_sprite(bank, sid):
    """Palette indices (h, w) of a sprite as the game composes it, from the untouched original file."""
    key = (bank, sid)
    if key not in _plates:
        import os
        import ui_textures as U
        path = os.path.join(U.ORIG_ARC_DIR, "main_prg.arc")
        d = open(path if os.path.exists(path) else os.path.join(U.S.DATA_FILES, "main_prg.arc"), "rb").read()
        b = next(x for x in U.banks(d, U.elf_symbols(d)) if x["name"] == bank)
        ps = next(v for n, v in b["sprites"].items() if n.endswith("_" + sid))
        w = max(p.x + p.x1 - p.x0 for p in ps)
        h = max(p.y + p.y1 - p.y0 for p in ps)
        im = np.zeros((h, w), np.uint8)
        for p in ps:
            idx = U.decode_indices(d, *b["pages"][p.page])[p.y0:p.y1, p.x0:p.x1]
            im[p.y:p.y + idx.shape[0], p.x:p.x + idx.shape[1]] = idx
        _plates[key] = im
    return _plates[key].copy()


def inpaint(im, mask):
    """Pixels of `mask` take the colour of the nearest pixel outside it (rows and columns, nearest first)."""
    out = im.copy()
    ys, xs = np.nonzero(~mask & (im > 0))
    pts = np.stack([ys, xs], 1)
    for y, x in zip(*np.nonzero(mask)):
        d2 = ((pts - (y, x)) ** 2).sum(1)
        out[y, x] = im[tuple(pts[d2.argmin()])]
    return out


def plated_text(bank, sid, clean, ramp, rings, centre, sharp=False):
    """A style that returns the whole plate: its original art, `clean`ed of the Japanese, with the ink drawn over
    it (letters shaded with `ramp`, ink 0..6, solid `rings`; `sharp` = no half tones), centred on `centre` (x, y)."""
    inner = banded(ramp, rings)

    def style(ink, base):
        orig = _orig_sprite(bank, sid)
        plate = clean(orig.copy())
        art, _ = tight(inner)(np.where(ink >= 3, 6, 0) if sharp else ink, base)
        cx, cy = centre
        h, w = art.shape
        x0, y0 = cx - w // 2, cy - h // 2
        area = plate[y0:y0 + h, x0:x0 + w]
        assert area.shape == art.shape, (sid, art.shape, plate.shape)
        area[art > 0] = art[art > 0]
        return plate, 0
    return style


def clean_box(*boxes, fill):
    def clean(im):
        for x0, y0, x1, y1 in boxes:
            im[y0:y1, x0:x1] = fill
        return im
    return clean


def clean_all(fill):
    def clean(im):
        im[im > 0] = fill
        return im
    return clean


def clean_inpaint(letters, box=None):
    def clean(im):
        mask = np.isin(im, letters)
        if box:
            keep = np.zeros_like(mask)
            x0, y0, x1, y1 = box
            keep[y0:y1, x0:x1] = True
            mask &= keep
        return inpaint(im, mask)
    return clean


STYLES = {
    "e_scm": scm_style,
    "e_pl_bb": plated_text("r4_12h", "bb", clean_box((4, 7, 31, 25), fill=15), [0, 8, 5, 3, 2, 1, 1], [], (17, 16)),      # League (palette 84)
    "e_pl_e1": plated_text("r4_12h", "e1", clean_box((14, 12, 39, 39), fill=10), [0, 15, 15, 15, 15, 15, 15], [1, 3], (26, 25), True),
    "e_pl_e2": plated_text("r4_12h", "e2", clean_box((9, 8, 26, 26), fill=10), [0, 15, 15, 15, 15, 15, 15], [1, 3], (17, 17), True),
    "e_pl_e3": plated_text("r4_12h", "e3", clean_all(7), [0, 1, 1, 1, 1, 1, 1], [15, 11], (13, 16), True),
    "e_pl_bc": plated_text("r4_12h", "bc", clean_box((4, 7, 31, 24), (4, 24, 32, 25), (7, 25, 32, 28), fill=15), [0, 9, 6, 4, 2, 1, 1], [], (17, 16)),       # All-Time (palette 85)
    # team-type plates of r4_12h (palettes 32, 34, 37 share their indices): white letters, a dark ring, a lighter ring
    "e_plate": crisp(tight(banded([0, 11, 11, 11, 11, 11, 11], [1, 3]))),
    # Baseball School & Practice (g3_rt): yellow shading to orange in a brown outline, a white band, blue rim and glow
    "e_rt_title": crisp(logo([12, 12, 14, 14, 13, 13], [1], 3, 15, 4, [6, 8], 2, 2)),
    # the two tabs (palette 2): the same in orange
    "e_rt_tab": crisp(logo([14, 14, 13, 12, 12], [1], 3, 15, 4, [6, 8], 2, 2)),
    # scorebook tags (g3_nk, g3_tij): white letters, navy ring, a blue outer ring (palettes 7-10 share indices 3..f)
    "e_tag": crisp(tight(banded([0, 15, 15, 15, 15, 15, 15], [4, 6]))),
}
