"""Styles for the art banks the earlier runs missed, group B (2026-10-22): Eikan Nine grade plates (sct_comd.arc), the
Success sound-effect words (scs_main.arc m3_gmoji), the Success club application form lying on the desk
(scs_make.arc y5_make_bg_opd) and the Eikan Nine story pictures (sct_main.arc n4_bg_*).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow. Colours are palette indices read from the Japanese lettering of the same sprite.

Photo styles ("lo_b_photo_<label>@<part>"): lettering that is part of a painted picture (a form on a desk, a magazine
cover) and lies at an angle. The style rebuilds the picture from the untouched .arc file (pp15/art/original_arc.py),
wipes the Japanese (the dark pixels inside the label's wipe boxes are filled in from the paper round them), draws the
English letters turned and leaned like the paper, and hands back the pixels of one page piece of the label's box
(index 0 = leave the pixel as it is). The paint entry that names the style gives the word ("text", "font"), its "rect"
is that page piece and its "copy" is the same rectangle (the untouched pixels). See PHOTO for the labels.

Used by: specs/sct_comd.json (group "lo_b gmp years"), specs/scs_make.json (paint entries named "lo_b form").
"""
import functools

import numpy as np
from PIL import Image

from .common import ringfill, flat

STYLES = {}

# ---- sct_comd.arc tex_z4_gmp00 (opd_z4_gmp_0): 1年 2年 3年 on the blue / green / yellow plates. White letters (15) whose
# soft edge runs down the palette toward the dark plate colour (indices 14 .. 5); no outline.
STYLES["lo_b_grade"] = flat([0, 6, 9, 11, 13, 14, 15])


# ---- photo lettering ------------------------------------------------------------------------------------------------------

# How the pages of a picture bank are laid out: (page, page rectangle x0 y0 x1 y1, picture x y) per piece.
LAYOUTS = {
    "grid4": tuple((k, (0, 0, 128, 128), ((k % 4) * 128, (k // 4) * 128)) for k in range(16)),
    # sct_main.arc n4_bg_*: what the sprite of n4_newvram_bg draws (three pages over three strips of the fourth)
    "newvram": ((0, (0, 0, 128, 128), (0, 0)), (1, (0, 0, 128, 128), (128, 0)), (2, (0, 0, 104, 128), (256, 0)),
                (3, (0, 0, 128, 40), (0, 128)), (3, (0, 40, 128, 80), (128, 128)), (3, (0, 80, 104, 120), (256, 128))),
}


@functools.lru_cache(None)
def _picture(arc, bank, layout):
    """(palette index picture, (256, 3) colours, indices allowed for new pixels) of the untouched picture."""
    from pp15.art import original_arc, textures
    a = original_arc.Arc(arc)
    b = next(x for x in a.banks if x["name"] == bank)
    lay = LAYOUTS[layout]
    W = max(px + r[2] - r[0] for _, r, (px, py) in lay)
    H = max(py + r[3] - r[1] for _, r, (px, py) in lay)
    idx = np.zeros((H, W), np.uint8)
    for k, (x0, y0, x1, y1), (px, py) in lay:
        idx[py:py + y1 - y0, px:px + x1 - x0] = textures.decode_indices(a.data, *b["pages"][k])[y0:y1, x0:x1]
    colours = textures.palette_colours(a.data, b["pal"])[:256, :3].astype(float)
    used = tuple(sorted(set(np.unique(idx).tolist()) - {0, 1, 2}))
    return idx, colours, used


def _frame(lab):
    """Unit vectors of the label's baseline (e1) and of its upright strokes going down (e2), in picture pixels."""
    a, t = np.radians(lab["angle"]), np.radians(lab.get("lean", -lab["angle"]))
    return np.array([np.cos(a), np.sin(a)]), np.array([np.sin(t), np.cos(t)])


def _to_frame(lab, xs, ys):
    """Picture points -> (u, v) in the label's frame (u along the baseline, v down the strokes, 0 at the centre)."""
    e1, e2 = _frame(lab)
    cx, cy = lab["centre"]
    det = e1[0] * e2[1] - e1[1] * e2[0]
    dx, dy = xs - cx, ys - cy
    return (dx * e2[1] - dy * e2[0]) / det, (e1[0] * dy - e1[1] * dx) / det


def _shift(a, dy, dx):
    """a moved by (dy, dx), the edge repeated."""
    p = np.pad(a, ((1, 1), (1, 1)) + ((0, 0),) * (a.ndim - 2), mode="edge")
    return p[1 + dy:1 + dy + a.shape[0], 1 + dx:1 + dx + a.shape[1]]


def _grow(m, n):
    for _ in range(n):
        m = m | _shift(m, 1, 0) | _shift(m, -1, 0) | _shift(m, 0, 1) | _shift(m, 0, -1)
    return m


def _inpaint(rgb, mask, iters=300):
    """Fill the masked pixels from the pixels round them: onion peeling, then smoothing (a membrane over the hole)."""
    out = rgb.copy()
    known = ~mask
    while not known.all():
        acc = np.zeros_like(out); cnt = np.zeros(mask.shape)
        for dy, dx in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            k = _shift(known, dy, dx)
            acc += _shift(out, dy, dx) * k[..., None]; cnt += k
        new = ~known & (cnt > 0)
        out[new] = acc[new] / cnt[new][:, None]
        known = known | new
    for _ in range(iters):
        avg = (_shift(out, 1, 0) + _shift(out, -1, 0) + _shift(out, 0, 1) + _shift(out, 0, -1)) / 4
        out[mask] = avg[mask]
    return out


def _alpha(lab, ink, base, xs, ys, ss=4):
    """Letter coverage (0..1) at the picture pixels (xs, ys): the ink set in the label's frame, sampled ss x ss per pixel."""
    a = ink.astype(float) / max(1, ink.max())
    rows = np.nonzero(a.max(1) > 0)[0]
    top = rows.min() if len(rows) else 0
    big = np.asarray(Image.fromarray(a.astype(np.float32), "F").resize((a.shape[1] * ss, a.shape[0] * ss), Image.BILINEAR))
    u0, v0 = a.shape[1] / 2.0, (top + base) / 2.0 + lab.get("drop", 0)     # the middle of the capitals is the centre
    acc = np.zeros(xs.shape)
    for i in range(ss):
        for j in range(ss):
            u, v = _to_frame(lab, xs + (j + 0.5) / ss - 0.5, ys + (i + 0.5) / ss - 0.5)
            u = u * lab.get("stretch", 1.0)
            iu = np.floor((u + u0) * ss).astype(int); iv = np.floor((v + v0) * ss).astype(int)
            ok = (iu >= 0) & (iv >= 0) & (iu < big.shape[1]) & (iv < big.shape[0])
            acc[ok] += big[iv[ok], iu[ok]]
    return np.clip(acc / (ss * ss) * lab.get("gain", 1.25), 0, 1)


def _hex(h):
    h = h.lstrip("#")
    return np.array([int(h[i:i + 2], 16) for i in (0, 2, 4)], float)


def _label_mask(lab, rgb, X0, Y0):
    """The pixels of the label's window to wipe: inside its wipe boxes (frame) or erase boxes (picture), the lettering
    (pixels darker than the paper and their blur) or, with "mode": "all", the whole boxes."""
    H, W = rgb.shape[:2]
    ys, xs = np.mgrid[Y0:Y0 + H, X0:X0 + W].astype(float)
    u, v = _to_frame(lab, xs, ys)
    inside = np.zeros((H, W), bool)
    for u0, v0, u1, v1 in lab.get("wipe", ()):
        inside |= (u >= u0) & (u <= u1) & (v >= v0) & (v <= v1)
    whole = np.zeros((H, W), bool)                   # erase boxes: tight boxes round small marks, wiped whole
    for x0, y0, x1, y1 in lab.get("erase", ()):
        whole |= (xs >= x0) & (xs < x1) & (ys >= y0) & (ys < y1)
    mode = lab.get("mode", "dark")
    if mode not in ("dark", "light") or not inside.any():
        return inside | whole
    lum = rgb @ np.array([0.3, 0.59, 0.11])
    if mode == "light":                              # light lettering on a darker ground: brighter than `above`
        return (_grow(inside & (lum >= lab["above"]), lab.get("halo", 1)) & _grow(inside, 1)) | whole
    below = lab.get("below")                         # lettering = darker than this (the paper, bands and ruled lines are not)
    if below is None:
        below = np.percentile(lum[inside], 90) - lab.get("thr", 18)
    return (_grow(inside & (lum < below), lab.get("halo", 2)) & _grow(inside, 1)) | whole


def _fill_along(lab, rgb, mask, X0, Y0, reach=200):
    """Fill the masked pixels along the label's baseline: each from the nearest unmasked pixels before and after it on
    its own slanted row (bands and ruled lines that run with the text stay whole)."""
    H, W = mask.shape
    e1, _ = _frame(lab)
    ys, xs = np.nonzero(mask)
    out = rgb.copy()
    found = {}
    for sgn in (1, -1):
        col = np.zeros((len(ys), 3)); dist = np.full(len(ys), np.inf)
        todo = np.ones(len(ys), bool)
        for k in range(1, reach):
            if not todo.any():
                break
            px = np.rint(xs + sgn * k * e1[0]).astype(int); py = np.rint(ys + sgn * k * e1[1]).astype(int)
            ok = todo & (px >= 0) & (py >= 0) & (px < W) & (py < H)
            hit = np.zeros(len(ys), bool)
            hit[ok] = ~mask[py[ok], px[ok]]
            col[hit] = rgb[py[hit], px[hit]]; dist[hit] = k
            todo &= ~hit
        found[sgn] = (col, dist)
    (c1, d1), (c2, d2) = found[1], found[-1]
    w1 = np.where(np.isfinite(d1), 1 / d1, 0); w2 = np.where(np.isfinite(d2), 1 / d2, 0)
    tot = w1 + w2
    good = tot > 0
    val = (c1 * w1[:, None] + c2 * w2[:, None])[good] / tot[good][:, None]
    out[ys[good], xs[good]] = val
    rest = mask.copy(); rest[ys[good], xs[good]] = False
    return _inpaint(out, rest) if rest.any() else out


@functools.lru_cache(None)
def _ink(text, font):
    from pp15.art.typeset import typeset
    ink, base = typeset(text, font)
    return ink, base


@functools.lru_cache(None)
def _composite(picture):
    """The whole picture with every label of PHOTO on it wiped and lettered: palette indices, 0 where unchanged."""
    labs = [(n, l) for n, l in PHOTO.items() if l["picture"] == picture]
    arc, bank, layout = PICTURES[picture]
    idx, colours, used = _picture(arc, bank, layout)
    rgb = colours[idx]
    changed = np.zeros(idx.shape, bool)
    inks = []
    for name, lab in labs:                           # wipe every label (each from the paper round it)
        X0, Y0, X1, Y1 = lab["box"]
        win = rgb[Y0:Y1, X0:X1]
        mask = _label_mask(lab, win, X0, Y0)
        if lab.get("text"):
            colour = lab.get("colour", "auto")
            if colour == "auto":                     # the Japanese ink: the darkest pixels of the wiped lettering
                lum = win @ np.array([0.3, 0.59, 0.11])
                col = win[mask & (lum <= np.percentile(lum[mask], 6))].mean(0)
            else:
                col = _hex(colour)
            inks.append((name, lab, col))
        if lab.get("fill", "membrane") == "along":
            rgb[Y0:Y1, X0:X1] = _fill_along(lab, win, mask, X0, Y0)
        else:
            rgb[Y0:Y1, X0:X1] = _inpaint(win, mask)
        changed[Y0:Y1, X0:X1] |= mask
    for name, lab, col in inks:                      # then the English
        X0, Y0, X1, Y1 = lab["box"]
        ys, xs = np.mgrid[Y0:Y1, X0:X1].astype(float)
        ink, base = _ink(lab["text"], lab["font"])
        al = _alpha(lab, ink, base, xs, ys)
        if (al[[0, -1], :] > 0.02).any() or (al[:, [0, -1]] > 0.02).any():
            raise ValueError("%s: the English runs out of its box %s" % (name, lab["box"]))
        rgb[Y0:Y1, X0:X1] = rgb[Y0:Y1, X0:X1] * (1 - al[..., None]) + col * al[..., None]
        changed[Y0:Y1, X0:X1] |= al > 0.02
    pal = colours[list(used)]
    out = np.zeros(idx.shape, np.uint8)
    ys, xs = np.nonzero(changed)
    best = ((rgb[ys, xs][:, None, :] - pal[None, :, :]) ** 2).sum(-1).argmin(1)
    out[ys, xs] = np.asarray(used, np.uint8)[best]
    out[out == idx] = 0                              # unchanged after all: leave
    return out


def pieces(name):
    """[(style name, page, page rectangle)] of a photo label: its box cut by the pieces of the picture's layout."""
    lab = PHOTO[name]
    X0, Y0, X1, Y1 = lab["box"]
    out = []
    for n, (k, (x0, y0, x1, y1), (px, py)) in enumerate(LAYOUTS[PICTURES[lab["picture"]][2]]):
        a0, b0 = max(X0, px), max(Y0, py)
        a1, b1 = min(X1, px + x1 - x0), min(Y1, py + y1 - y0)
        if a0 < a1 and b0 < b1:
            out.append(("lo_b_photo_%s@%d" % (name, n), k, [x0 + a0 - px, y0 + b0 - py, x0 + a1 - px, y0 + b1 - py],
                        [a0, b0, a1, b1]))
    return out


def _photo_style(name, n):
    """The style for piece n of the layout of label `name`: the finished picture inside that piece of the label's box.
    The paint entry's word and font must be the label's (the picture is drawn from PHOTO, so that every label of it sees
    the others where their boxes overlap)."""
    def style(ink, base):
        lab = PHOTO[name]
        want, _ = _ink(lab["text"], lab["font"]) if lab.get("text") else (None, None)
        if want is not None and (want.shape != ink.shape or (want != ink).any()):
            raise ValueError("%s: the paint entry's text / font are not %r %s" % (name, lab["text"], lab["font"]))
        out = _composite(lab["picture"])
        _, _, _, (a0, b0, a1, b1) = next(p for p in pieces(name) if p[0].endswith("@%d" % n))
        return out[b0:b1, a0:a1].copy(), 0
    return style


# The labels. centre: middle of the English (picture pixels); angle: slope of the baseline (degrees, negative = rising to
# the right); lean: slope of the upright strokes; wipe: boxes (u0, v0, u1, v1) round the Japanese in the label's frame;
# box: the picture rectangle the label may change (x0, y0, x1, y1); colour: the letters ("auto" = the Japanese ink).
PICTURES = {"form": ("scs_make.arc", "y5_make_bg_opd", "grid4")}
_F = dict(picture="form", angle=-8.0, lean=9.0, below=205, fill="along")
PHOTO = {
    # scs_make.arc y5_make_bg_opd: the club application form on the desk at the start of Success (as the flat form y5_cmc)
    "form_title": dict(_F, text="Baseball Club Application", font="ttf:times-bold:10:0:0.9:0.0", centre=(316, 103), angle=-6.8,
                       wipe=[(-80, -10, 80, 9)], erase=[(390, 107, 403, 118), (288, 124, 312, 134)],
                       box=(228, 76, 405, 137)),                                  # also wipes 平成 and 日 of the date line
    "form_year": dict(_F, text="/", font="ttf:tahoma:10:0:1.0:0.3", centre=(347, 122), wipe=[(-6, -5, 6, 5)],
                      box=(336, 112, 360, 133)),                                  # 年 -> "/"
    "form_date": dict(_F, text="Date", font="ttf:tahoma:7:0:1.0:0.2", centre=(229.5, 141), wipe=[(-17, -5, 17, 5)],
                      box=(208, 130, 252, 152)),                                  # 申請日
    "form_name": dict(_F, text="Name", font="ttf:tahoma:10:0:1.0:0.2", centre=(234.5, 164), wipe=[(-17, -9, 17, 9)],
                      box=(212, 150, 258, 180)),                                  # 名前
    "form_hand": dict(_F, text="Hand", font="ttf:tahoma:10:0:1.0:0.2", centre=(258.5, 220.5), wipe=[(-24, -9, 24, 9)],
                      box=(230, 203, 290, 238)),                                  # 利き腕
    "form_pos": dict(_F, text="Position", font="ttf:tahoma:10:0:1.0:0.2", centre=(265.5, 252.5), wipe=[(-30, -10, 30, 10)],
                     box=(232, 236, 300, 270)),                                   # 守備位置
    "form_form": dict(_F, text="Form", font="ttf:tahoma:10:0:1.0:0.2", centre=(276, 286), wipe=[(-32, -10, 32, 10)],
                      box=(242, 268, 312, 305)),                                  # フォーム
    "form_notes": dict(_F, text="Notes", font="ttf:tahoma:8:0:1.0:0.2", centre=(274, 315.5), wipe=[(-40, -9, 40, 9)],
                       box=(250, 296, 336, 332)),                                 # 備考（補足欄）
    "form_photo": dict(_F, text="Photo\nHere", font="ttf:tahoma:12:0:1.0:0.3", centre=(484, 331), angle=-11.0, lean=18.0,
                       mode="light", above=234, fill="membrane", colour="#ffffff", gain=0.85,
                       wipe=[(-26, -25, 27, 26)], box=(448, 296, 512, 370)),     # 写真 / 添付 in the photo box
}

for _name in PHOTO:
    for _s, _k, _r, _b in pieces(_name):
        STYLES[_s] = _photo_style(_name, int(_s.rsplit("@", 1)[1]))
