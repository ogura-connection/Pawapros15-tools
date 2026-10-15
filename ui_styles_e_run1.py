"""Label styles of art run 1, agent E: scorebook tags, team initials, plates, shift editor (see ui_type.py)."""
import numpy as np
import ui_type
from ui_type import banded, outlined, tight, grow, logo, called

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


# ---- the scorebook tag font: ui_type's pixel tag font (capitals 11 high, two-pixel stems, every B with its bar) plus the
# 1, 3 and Q it lacks and narrower w and g, so that K-Swing fits one line ----
ETAG_EXTRA = {
    "1": ["..##", ".###", "####", "..##", "..##", "..##", "..##", "..##", "..##", "..##", "..##"],
    "3": ["+####+", "######", "##..##", "....##", "..###+", "..###+", "....##", "##..##", "##..##", "######", "+####+"],
    "Q": ["+####+", "######", "##..##", "##..##", "##..##", "##..##", "##.+##", "##.###", "##+###", "######", "+#####"],
    "w": ["##.#.#", "##.#.#", "##.#.#", "##.#.#", "##.#.#", "######", "######", "+#+.+#"],
    "g": ["+###+", "##.##", "##.##", "##.##", "+####", "...##", "...##", "...##", "...##", "##.##", "+###+"],
}


def etag_font(project=None):
    if "etag" not in ui_type._fonts:
        level = {".": 0, "+": 3, "#": 6}
        rows = dict(ui_type.TAG_GLYPHS)
        rows.update(ETAG_EXTRA)
        ui_type._fonts["etag"] = {"words": {}, "space": 5, "gap": 1, "glyphs": {
            ch: (np.array([[level[c] for c in row] for row in r]), ui_type.TAG_DROP.get(ch, 0))
            for ch, r in rows.items()}}
    return ui_type._fonts["etag"]


ui_type.FONTS["etag"] = etag_font


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


def _orig_rect(arc, bank, page, rect):
    """Palette indices of a rectangle of a page, from the untouched original file (or the installed one)."""
    import os
    import ui_textures as U
    key = (arc, bank, page)
    if key not in _plates:
        path = os.path.join(U.ORIG_ARC_DIR, arc)
        d = open(path if os.path.exists(path) else os.path.join(U.S.DATA_FILES, arc), "rb").read()
        b = next(x for x in U.banks(d, U.elf_symbols(d)) if x["name"] == bank)
        _plates[key] = U.decode_indices(d, *b["pages"][page]).copy()
    x0, y0, x1, y1 = rect
    return _plates[key][y0:y1, x0:x1].copy()


def gem_text(page, rect, glyph, box, well, centre):
    """The batter mark on the jewels of the shift editor: the original face with the glyph's box (x0, y0, x1, y1)
    filled with the well colour `well`, and the new letter in white with a black shadow below and to the right."""
    def style(ink, base):
        im = _orig_rect("shift_ed.arc", "r4_syu", page, rect)
        out = im.copy()
        x0, y0, x1, y1 = box
        out[y0:y1, x0:x1] = well                                    # the glyph and its halo: the well's own dark
        letters = np.where(ink >= 3, 1, 0).astype(bool)
        h, w = letters.shape
        art = np.zeros((h + 2, w + 2), np.uint8)
        shadow = ui_type.shift(np.pad(letters, ((0, 2), (0, 2))), 1, 1) | ui_type.shift(np.pad(letters, ((0, 2), (0, 2))), 1, 0) \
            | ui_type.shift(np.pad(letters, ((0, 2), (0, 2))), 0, 1)
        art[shadow] = 15
        art[:h, :w][letters] = 11
        cx, cy = centre
        ah, aw = art.shape
        area = out[cy - ah // 2:cy - ah // 2 + ah, cx - aw // 2:cx - aw // 2 + aw]
        area[art > 0] = art[art > 0]
        ys, xs = np.nonzero(im)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], 0
    return style


_WHITE = [0, 15, 15, 15, 15, 15, 15]
STYLES = {
    # the shift editor (shift_ed.arc r4_syu): screen title, orange to pink letters in a white band with a blue rim and shadow
    "e_sh_title": crisp(logo([12, 12, 13, 13, 14, 14, 15, 15], [10], 9, 9, 3, [2, 1, 1], 3, 1)),
    # the headings (palettes 27 yellow, 28 green, 29 cream share their indices): letters shading down in three steps,
    # navy outline, a one-pixel teal edge with a darker teal shadow below
    "e_sh_head": crisp(called([12, 12, 12, 13, 13, 13, 14, 14, 14], [7, 6], 5, 5, 4, [3, 2], thick=2, wide=0, bandw=1, drop=(1, 0))),
    # Show Infield / Show Outfield (palette 24): dark blue letters, a white band, a teal edge
    "e_sh_show": crisp(tight(banded(_WHITE, [5, 5, 3]))),
    # column heads of the two gauges (palettes 98 and 99): dark blue letters in white, a dark edge
    "e_sh_h98": crisp(tight(banded(_WHITE, [9, 9, 3]))),
    "e_sh_h99": crisp(tight(banded([0, 5, 5, 5, 5, 5, 5], [13, 13, 4]))),
    # the small plates (palettes 81, 82, 83): white letters, a dark blue ring
    "e_sh_plate": crisp(tight(banded(_WHITE, [4]))),
    # the buttons (palettes 21, 22, 23): coloured letters, a white band two pixels wide, blue and light blue edges
    "e_sh_btn": crisp(tight(banded(_WHITE, [8, 8, 3, 5]))),
    # Starter Avg. (palette 102): white letters, a navy band, a teal edge
    "e_sh_avg": crisp(tight(banded(_WHITE, [8, 8, 6]))),
    "e_scm": scm_style,
    # team-type plates of r4_12h, as the Japanese lettering: white letters, a light inner ring, a thick dark ring in the
    # plate's colour (palettes 32, 34, 37 share their indices: 8 light, 1 dark)
    "e_plate2": crisp(tight(banded([0, 11, 11, 11, 11, 11, 11], [8, 1, 1]))),
    # side marks on the digit font (g3_suuzi page 1): white letters, a black two-pixel outline
    "e_suuzi": crisp(banded([0, 1, 1, 1, 1, 1, 1], [15, 15])),
    # Mii choice plates (r4w_mi): green letters in a white halo; the game draws the same art again as a light blue silhouette
    "e_mi": tight(banded([0, 8, 6, 4, 3, 2, 2], [15, 15])),
    # 残り時間 (s4_clo00): blue letters shading to pale at the edge, a one-pixel white halo
    "e_clo": tight(banded([0, 10, 7, 5, 3, 1, 1], [15])),
    "e_pl_bb": plated_text("r4_12h", "bb", clean_box((4, 7, 31, 25), fill=15), [0, 8, 5, 3, 2, 1, 1], [], (17, 16)),      # League (palette 84)
    "e_pl_e1": plated_text("r4_12h", "e1", clean_box((14, 12, 39, 39), fill=10), [0, 15, 15, 15, 15, 15, 15], [1, 3], (26, 25), True),
    "e_pl_e2": plated_text("r4_12h", "e2", clean_box((9, 8, 26, 26), fill=10), [0, 15, 15, 15, 15, 15, 15], [1, 3], (17, 17), True),
    "e_pl_e3": plated_text("r4_12h", "e3", clean_all(7), [0, 1, 1, 1, 1, 1, 1], [15, 11], (13, 16), True),
    "e_sh_gem": gem_text(13, (0, 104, 24, 128), [10, 11, 12, 13, 14, 15], (4, 6, 22, 22), 1, (13, 14)),
    "e_pl_bc": plated_text("r4_12h", "bc", clean_box((4, 7, 31, 24), (4, 24, 32, 25), (7, 25, 32, 28), fill=15), [0, 9, 6, 4, 2, 1, 1], [], (17, 16)),       # All-Time (palette 85)
    # team-type plates of r4_12h (palettes 32, 34, 37 share their indices): white letters, a dark ring, a lighter ring
    "e_plate": crisp(tight(banded([0, 11, 11, 11, 11, 11, 11], [1, 3]))),
    # Baseball School & Practice (g3_rt): yellow shading to orange in a brown outline, a white band, blue rim and glow
    "e_rt_title": crisp(logo([12, 12, 14, 14, 13, 13], [1], 3, 15, 4, [6, 8], 2, 2)),
    # the two tabs (palette 2): the same in orange
    "e_rt_tab": crisp(logo([14, 14, 13, 12, 12], [1], 3, 15, 4, [6, 8], 2, 2)),
    # scorebook tags (g3_nk, g3_tij): white letters, navy ring, a blue outer ring (palettes 7-10 share indices 3..f)
    "e_tag": crisp(tight(banded([0, 15, 15, 15, 15, 15, 15], [4])), 4),
}
