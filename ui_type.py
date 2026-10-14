#!/usr/bin/env python3
"""Typeset English UI words with letters taken from the MLB Power Pros 2008 sheets, and repack sprite pages.

Used by ui_labels.py for the "repack" entries of a spec. Nothing here draws a typeface of its own:
the letters are cut out of MLB label art, a word that exists in MLB is used whole (same letters, same
spacing), and other words are set from single letters of the same lettering. The few letters MLB never
drew in a style are derived from its nearest letter and listed in DERIVED.

Fonts
  command    the Success command words (ScsComMain texture 0): rounded letters with a soft edge.
             The sheet stores a brightness ramp (palette 9..15), which is kept as 6 ink levels, so the
             letters come out anti-aliased like the Japanese ones, not thresholded.

Styles (how ink becomes palette indices of the Pawapuro 15 page)
  command    violet letters on a white plate with a green rim and a dark green shadow to the lower
             right, as on y5_smi pages 1 and 2 (palette 28).
  stat       the stat labels: MLB's letters (cut whole from ScsParamPlate) in white with two rings.
  tag, money, motivation   letters with a one-pixel outline, in the colours of the HUD tags.
  pitch, calendar, weather, glow, hint   the same letters in the colours of other labels (see RENDER).

Font "tag" is the one exception to "nothing is drawn here": MLB has no small bold lettering, so the 13
letters the HUD tags need are defined in TAG_GLYPHS.

Repacking: an English word is wider than the Japanese label it replaces (練習 is two characters), so the
labels of a page are laid out again at their natural width inside the areas named in the spec, and the
sprite parts that showed the old rectangles are pointed at the new ones. A group can also list
"blank" rectangles (cleared, never drawn into: the second half of a label that came in two pieces),
or give that half as a label {"from": [...], "empty": true}: its parts are pointed at an empty cell and the
rectangle can be an area again,
"gap" (clear pixels between labels, across and down, default [1, 1]),
"under" (rows of the Japanese art below the foot of its letters, default 4) and, per label, "align":
"left" (keep the left edge, not the centre), "valign": "centre" (middle of the old art, not its baseline) or "centre_x"
(where the middle of the new label goes, measured from the left of the old rectangle). "baseline" and
"left" put the label on a fixed row and column of its sprite instead (a list of names that the game
shows one at a time in the same place: the Japanese ones differ by a pixel or two). A sprite that also
draws a plate or an icon names its lettering parts with "pages" and / or "palettes"; "layers": 2 is a
sprite that draws the same lettering twice (a shadow under a coloured copy). The parts are
pointed at the new ones (page, rectangle and offset
are rewritten in place; nothing moves inside the file and no size changes). The new label keeps the
old label's horizontal centre and sits on the old baseline.
"""
import numpy as np

import ui_labels as L
import ui_textures as U

COMMAND_WORDS = ["Progress", "Practice", "Free Time", "Boost", "Use", "Equip", "Data", "System",
                 "Weight", "TOP SPD", "Accuracy", "B.Ball", "Fielding", "Batting", "ARM STR", "Shop",
                 "Steak", "Hotdog", "SC", "Food", "Park", "Lake", "Mountains", "Lookout",
                 "Vicinage", "Hospital", "Street", "Run", "Yes", "No"]
# letter -> (word it is cut from, which occurrence of the letter in that word)
COMMAND_GLYPHS = {
    "B": ("Boost", 0), "C": ("SC", 0), "D": ("Data", 0), "E": ("Equip", 0), "F": ("Food", 0),
    "H": ("Hotdog", 0), "L": ("Lake", 0), "N": ("No", 0), "P": ("Park", 0), "R": ("Run", 0),
    "S": ("Shop", 0), "T": ("Free Time", 0), "U": ("Use", 0), "W": ("Weight", 0), "Y": ("Yes", 0),
    "a": ("Lake", 0), "c": ("Practice", 0), "d": ("Food", 0), "e": ("Lake", 0), "g": ("Hotdog", 0),
    "h": ("Shop", 0), "i": ("Equip", 0), "k": ("Park", 0), "l": ("Fielding", 0), "m": ("System", 0),
    "n": ("Run", 0), "o": ("Boost", 0), "p": ("Shop", 0), "q": ("Equip", 0), "r": ("Practice", 0),
    "s": ("Use", 0), "t": ("Boost", 0), "u": ("Run", 0), "y": ("System", 0),
}
DERIVED = {"G": "C of 'SC' with a crossbar", "I": "the l of 'Fielding'",
           "J": "U of 'Use' without the top of its left stem", "b": "d of 'Food' mirrored"}
G_ROWS = {7: "5561.35553", 8: "5561.35565", 9: "5661...265", 10: "4662..1565", 11: "266522565.",
          12: ".5666664.."}


def sheet_ink(idx):
    """Ink level 0..6 of every pixel of the command-word sheet: letters are indices 10..15 on the
    teal plate (9), plus the white highlights (8) enclosed in them; the rim of each plate is dropped."""
    v = idx.astype(int)
    h, w = v.shape
    low = v < 9
    outside = np.zeros_like(low)
    stack = [(y, x) for y in range(h) for x in (0, w - 1) if low[y, x]]
    stack += [(y, x) for x in range(w) for y in (0, h - 1) if low[y, x]]
    for p in stack:
        outside[p] = True
    while stack:
        y, x = stack.pop()
        for yy, xx in ((y + 1, x), (y - 1, x), (y, x + 1), (y, x - 1)):
            if 0 <= yy < h and 0 <= xx < w and low[yy, xx] and not outside[yy, xx]:
                outside[yy, xx] = True
                stack.append((yy, xx))
    near = grow(outside, 1, edge=True)
    ink = np.clip(v - 9, 0, 6)
    ink[low & ~outside] = 6
    ink[near] = 0
    return ink


def grow(mask, n=1, diagonal=True, edge=False):
    """The mask grown by n pixels (8 directions, or 4 with diagonal=False)."""
    m = mask.copy()
    for _ in range(n):
        p = np.pad(m, 1, constant_values=edge)
        out = m.copy()
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if (dy or dx) and (diagonal or not (dy and dx)):
                    out |= p[1 + dy:1 + dy + m.shape[0], 1 + dx:1 + dx + m.shape[1]]
        m = out
    return m


def shift(mask, dy, dx):
    out = np.zeros_like(mask)
    h, w = mask.shape
    out[max(dy, 0):h + min(dy, 0), max(dx, 0):w + min(dx, 0)] = \
        mask[max(-dy, 0):h + min(-dy, 0), max(-dx, 0):w + min(-dx, 0)]
    return out


def segment(ink, n, minw=2, maxw=12):
    """Cut the ink of a word into n letters: [(start, end)] columns. The cuts go where the columns
    carry the least ink (dynamic programme), so letters that touch are split at their thinnest point."""
    cols = ink.sum(0).astype(float)
    xs = np.nonzero(cols)[0]
    x0, x1 = xs.min(), xs.max() + 1
    cols = cols[x0:x1]
    width = len(cols)
    inf = 1e9
    dp = [[inf] * (width + 2) for _ in range(n + 1)]
    back = [[None] * (width + 2) for _ in range(n + 1)]
    dp[0][0] = 0
    for k in range(1, n + 1):
        for end in range(1, width + 1):
            for w in range(minw, maxw + 1):
                start = end - w
                if start < 0:
                    break
                for gap in (0, 1):                  # 1 = the column before the letter is the cut
                    prev = start - gap
                    if prev < 0 or dp[k - 1][prev] >= inf or (k == 1 and prev != 0):
                        continue
                    cost = dp[k - 1][prev] + (cols[prev] if gap else
                                              (0 if k == 1 else min(cols[start - 1], cols[start]) * 1.5 + 3))
                    if cost < dp[k][end]:
                        dp[k][end], back[k][end] = cost, (prev, start)
    end, out = width, []
    for k in range(n, 0, -1):
        prev, start = back[k][end]
        out.append((start + x0, end + x0))
        end = prev
    return out[::-1]


def clean(ink):
    """Drop stray pixels: pieces (8-way) of 1 or 2 pixels, and any piece that never reaches ink
    level 4 (the soft edge of a neighbouring letter that a cut left behind)."""
    solid = ink > 0
    seen = np.zeros_like(solid)
    out = ink.copy()
    h, w = ink.shape
    for y0, x0 in zip(*np.nonzero(solid)):
        if seen[y0, x0]:
            continue
        stack, pts = [(y0, x0)], []
        seen[y0, x0] = True
        while stack:
            y, x = stack.pop()
            pts.append((y, x))
            for yy in range(max(y - 1, 0), min(y + 2, h)):
                for xx in range(max(x - 1, 0), min(x + 2, w)):
                    if solid[yy, xx] and not seen[yy, xx]:
                        seen[yy, xx] = True
                        stack.append((yy, xx))
        if len(pts) <= 2 or max(ink[p] for p in pts) < 4:
            for p in pts:
                out[p] = 0
    return out


def trim(ink):
    ys, xs = np.nonzero(ink)
    return ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1], ys.min(), ys.max() + 1


_fonts = {}


def command_font(project=None):
    """{"words": {word: (ink, baseline row)}, "glyphs": {letter: (ink, rows below the baseline)}}"""
    if "command" in _fonts:
        return _fonts["command"]
    idx, _, _ = L.mlb_texture("ScsComMain", 0, project)
    ink_all = sheet_ink(idx)
    words, cut = {}, {}
    for word, (l, t, r, b) in zip(COMMAND_WORDS, L.find_boxes(idx, 9)):
        ink = clean(ink_all[t:b, l:r])
        letters = word.replace(" ", "")
        segs = segment(ink, len(letters))
        tops = [(ch, np.nonzero(ink[:, a:e].sum(1))[0]) for ch, (a, e) in zip(letters, segs)]
        bottoms = [rows.max() + 1 for ch, rows in tops if len(rows) and ch not in "gpqy.,"]
        base = max(set(bottoms), key=bottoms.count)
        body, top, _ = trim(ink)
        words[word] = (body, base - top)
        seen = {}
        for ch, (a, e) in zip(letters, segs):
            k = seen.get(ch, 0)
            seen[ch] = k + 1
            g = clean(ink[:, a:e])
            if g.any():
                g, gt, gb = trim(g)
                cut[(ch, word, k)] = (g, gb - base)
    glyphs = {ch: cut[(ch, word, k)] for ch, (word, k) in COMMAND_GLYPHS.items()}
    c, drop = glyphs["C"]
    g = c.copy()
    for row, text in G_ROWS.items():
        g[row] = [0 if ch == "." else int(ch) for ch in text]
    glyphs["G"] = (g, drop)
    stem, drop = glyphs["l"]
    glyphs["I"] = (stem, drop)
    u, drop = glyphs["U"]
    j = u.copy()
    j[:8, :5] = 0
    j[8, :5] = [1, 4, 4, 1, 0]
    glyphs["J"] = (j, drop)
    dd, drop = glyphs["d"]
    glyphs["b"] = (dd[:, ::-1].copy(), drop)
    _fonts["command"] = {"words": words, "glyphs": glyphs, "space": 4, "gap": 1}
    return _fonts["command"]


# The small bold letters of the HUD tags. MLB has no lettering in this style (its own Vitality,
# Money and Motivation are thin letters baked into a textured plate), so these are drawn here:
# 2-pixel stems, capitals 11 high, lower case 8, '+' = a half-tone corner pixel. It is also used for
# the pitch names, which MLB only has as abbreviations (SLD, CB) in another style.
TAG_GLYPHS = {
    "A": ["..+#+..", "..###..", ".+###+.", ".##.##.", ".##.##.", "+##.##+", "#######", "#######", "##...##",
          "##...##", "##...##"],
    "B": ["#####+", "######", "##..##", "##..##", "#####+", "######", "##..##", "##..##", "##..##", "######",
          "#####+"],
    "C": ["+####+", "######", "##..##", "##....", "##....", "##....", "##....", "##....", "##..##", "######",
          "+####+"],
    "D": ["####+.", "#####+", "##.+##", "##..##", "##..##", "##..##", "##..##", "##..##", "##.+##", "#####+",
          "####+."],
    "E": ["#####", "#####", "##...", "##...", "####.", "####.", "##...", "##...", "##...", "#####", "#####"],
    "F": ["#####", "#####", "##...", "##...", "####.", "####.", "##...", "##...", "##...", "##...", "##..."],
    "G": ["+####+", "######", "##..##", "##....", "##....", "##.###", "##.###", "##..##", "##..##", "######",
          "+####+"],
    "H": ["##..##", "##..##", "##..##", "##..##", "######", "######", "##..##", "##..##", "##..##", "##..##",
          "##..##"],
    "I": ["##", "##", "##", "##", "##", "##", "##", "##", "##", "##", "##"],
    "K": ["##..##", "##.+##", "##.##+", "##+##.", "####..", "###+..", "####..", "##+##.", "##.##+", "##.+##",
          "##..##"],
    "L": ["##...", "##...", "##...", "##...", "##...", "##...", "##...", "##...", "##...", "#####", "#####"],
    "M": ["##...##", "###.###", "#######", "#######", "##+#+##", "##.#.##", "##...##", "##...##", "##...##",
          "##...##", "##...##"],
    "N": ["##..##", "###.##", "###.##", "######", "######", "##+###", "##.###", "##.###", "##..##", "##..##",
          "##..##"],
    "O": ["+####+", "######", "##..##", "##..##", "##..##", "##..##", "##..##", "##..##", "##..##", "######",
          "+####+"],
    "P": ["#####+", "######", "##..##", "##..##", "##..##", "######", "#####+", "##....", "##....", "##....",
          "##...."],
    "R": ["#####+", "######", "##..##", "##..##", "######", "#####+", "##+##.", "##.##.", "##.+##", "##..##",
          "##..##"],
    "S": ["+####+", "######", "##..##", "##+...", "+###+.", ".+###+", "...+##", "##..##", "##..##", "######",
          "+####+"],
    "T": ["######", "######", "..##..", "..##..", "..##..", "..##..", "..##..", "..##..", "..##..", "..##..",
          "..##.."],
    "U": ["##..##", "##..##", "##..##", "##..##", "##..##", "##..##", "##..##", "##..##", "##..##", "######",
          "+####+"],
    "V": ["##...##", "##...##", "##...##", "##...##", "+##.##+", ".##.##.", ".##.##.", ".+###+.", "..###..",
          "..###..", "..+#+.."],
    "W": ["##.##.##", "##.##.##", "##.##.##", "##.##.##", "##.##.##", "##.##.##", "##.##.##", "########",
          "########", "+##++##+", ".##..##."],
    "Y": ["##..##", "##..##", "##..##", "+####+", ".####.", ".+##+.", "..##..", "..##..", "..##..", "..##..",
          "..##.."],
    "2": ["+####+", "######", "##..##", "....##", "...+##", "..+##+", ".+##+.", "+##+..", "##+...", "######",
          "######"],
    "-": ["....", "....", "....", "....", "....", "####", "####", "....", "....", "....", "...."],
    ".": ["..", "..", "..", "..", "..", "..", "..", "..", "..", "##", "##"],
    "!": ["##", "##", "##", "##", "##", "##", "##", "##", "..", "##", "##"],
    "a": ["+###+", "##+##", "...##", "+####", "##+##", "##.##", "##+##", "+####"],
    "b": ["##...", "##...", "##...", "####+", "#####", "##+##", "##.##", "##.##", "##+##", "#####", "####+"],
    "c": ["+###+", "##+##", "##...", "##...", "##...", "##...", "##+##", "+###+"],
    "d": ["...##", "...##", "...##", "+####", "#####", "##+##", "##.##", "##.##", "##+##", "#####", "+####"],
    "e": ["+###+", "##+##", "##.##", "#####", "##...", "##...", "##+##", "+###+"],
    "f": [".+##", ".###", ".##.", "####", "####", ".##.", ".##.", ".##.", ".##.", ".##.", ".##."],
    "g": ["+####", "#####", "##+##", "##.##", "##.##", "##+##", "#####", "+####", "...##", "#####", "####+"],
    "h": ["##...", "##...", "##...", "####+", "#####", "##+##", "##.##", "##.##", "##.##", "##.##", "##.##"],
    "i": ["##", "##", "..", "##", "##", "##", "##", "##", "##", "##", "##"],
    "k": ["##...", "##...", "##...", "##.##", "##+##", "####.", "###..", "####.", "##+##", "##.##", "##.##"],
    "l": ["##", "##", "##", "##", "##", "##", "##", "##", "##", "##", "##"],
    "m": ["#######+", "########", "##+##+##", "##.##.##", "##.##.##", "##.##.##", "##.##.##", "##.##.##"],
    "n": ["####+", "#####", "##+##", "##.##", "##.##", "##.##", "##.##", "##.##"],
    "o": ["+###+", "##+##", "##.##", "##.##", "##.##", "##.##", "##+##", "+###+"],
    "p": ["####+", "#####", "##+##", "##.##", "##.##", "##+##", "#####", "####+", "##...", "##...", "##..."],
    "r": ["##+#", "####", "##+.", "##..", "##..", "##..", "##..", "##.."],
    "s": ["+####", "##+..", "##...", "####+", "+####", "...##", "..+##", "####+"],
    "t": [".##.", ".##.", "####", "####", ".##.", ".##.", ".##.", ".##.", ".##+", ".+##"],
    "u": ["##.##", "##.##", "##.##", "##.##", "##.##", "##+##", "#####", "+####"],
    "v": ["##..##", "##..##", "##..##", "##..##", "+####+", ".####.", ".+##+.", "..##.."],
    "w": ["##.##.##", "##.##.##", "##.##.##", "##.##.##", "##.##.##", "########", "+##++##+", ".##..##."],
    "y": ["##..##", "##..##", "##..##", "##..##", "+####+", ".####.", ".+##+.", "..##..", ".+##..", "###+..",
          "##+..."],
    "z": ["#####", "#####", "...##", "..+#+", ".+#+.", "+#+..", "#####", "#####"],
    "j": [".##", ".##", "...", ".##", ".##", ".##", ".##", ".##", ".##", ".##", ".##", "+##", "##+"],
    "q": ["+####", "#####", "##+##", "##.##", "##.##", "##+##", "#####", "+####", "...##", "...##", "...##"],
    "x": ["##.##", "##.##", "+###+", ".###.", ".###.", "+###+", "##.##", "##.##"],
    "J": ["...##", "...##", "...##", "...##", "...##", "...##", "...##", "##.##", "##.##", "#####", "+###+"],
}
TAG_DROP = {"y": 3, "g": 3, "p": 3, "q": 3, "j": 2}


def tag_font(project=None):
    if "tag" not in _fonts:
        level = {".": 0, "+": 3, "#": 6}
        _fonts["tag"] = {"words": {}, "space": 3, "gap": 1, "glyphs": {
            ch: (np.array([[level[c] for c in row] for row in rows]), TAG_DROP.get(ch, 0))
            for ch, rows in TAG_GLYPHS.items()}}
    return _fonts["tag"]


TTF = {"rounded": ("/System/Library/Fonts/Supplemental/Arial Rounded Bold.ttf", 0),
       "narrow": ("/System/Library/Fonts/Supplemental/Arial Narrow Bold.ttf", 0),
       "black": ("/System/Library/Fonts/Supplemental/Arial Black.ttf", 0),
       "serif-italic": ("/System/Library/Fonts/Supplemental/Times New Roman Bold Italic.ttf", 0),
       "sans-italic": ("/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf", 0)}
_faces = {}


def ttf_ink(text, face="rounded", cap=14, slant=0.0, squeeze=1.0, bold=0.0, over=4):
    """(ink, baseline row) of text drawn with a system font: capitals `cap` pixels high, sheared by
    `slant` (0.2 = italic), widths scaled by `squeeze`, strokes thickened by `bold` pixels a side.
    Drawn `over` times too large and averaged
    down, which gives the 6 ink levels of a soft edge. For lettering larger than the tag font, where
    a drawn pixel font would look coarse next to the Japanese."""
    from PIL import Image, ImageDraw, ImageFont
    path, index = TTF[face]
    key = (face, cap, over)
    if key not in _faces:
        probe = ImageFont.truetype(path, 400, index=index)
        top, bottom = probe.getbbox("H")[1], probe.getbbox("H")[3]
        _faces[key] = ImageFont.truetype(path, round(400 * cap * over / (bottom - top)), index=index)
    font = _faces[key]
    l, t, r, b = font.getbbox(text, anchor="ls")                 # relative to the baseline
    pad = 4 * over
    stroke = round(bold * over)
    h_up, h_down = -t + pad, b + pad
    img = Image.new("L", (r - l + 2 * pad + int(slant * (h_up + h_down)) + 4 * over, h_up + h_down), 0)
    ImageDraw.Draw(img).text((pad - l, h_up), text, fill=255, font=font, anchor="ls",
                             stroke_width=stroke, stroke_fill=255)
    if slant:
        img = img.transform(img.size, Image.AFFINE, (1, slant, -slant * h_up, 0, 1, 0), Image.BICUBIC)
    w = max(1, round(img.width * squeeze / over))
    h = (h_up + h_down) // over
    img = img.resize((img.width, h * over)).resize((w * over, h * over), Image.BICUBIC) if squeeze != 1 else img
    small = np.asarray(img.resize((max(1, img.width // over), h), Image.BOX), dtype=np.float32)
    ink = np.rint(small * 6 / 255).astype(int)
    ys, xs = np.nonzero(ink)
    base = h_up // over
    return ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


FONTS = {"command": command_font, "tag": tag_font}


def typeset(text, font="command", project=None):
    """(ink, baseline row) of a word or phrase. A phrase that MLB drew is returned as drawn.
    font = "command", "tag", or "ttf:<face>:<cap height>[:<slant>[:<squeeze>[:<bold>]]]" for a system font."""
    if font == "tagi":                               # the tag font, slanted one pixel every four rows
        ink, base = typeset(text, "tag", project)
        h, w = ink.shape
        lean = [(base - 1 - y + 2) // 4 for y in range(h)]
        low = min(lean)
        out = np.zeros((h, w + max(lean) - low), int)
        for y in range(h):
            out[y, lean[y] - low:lean[y] - low + w] = ink[y]
        return out, base
    if "\n" in text:                                 # lines stacked and centred, 3 clear rows between them
        lines = [typeset(t, font, project) for t in text.split("\n")]
        w = max(i.shape[1] for i, _ in lines)
        rows, base = [], 0
        for k, (i, b) in enumerate(lines):
            x = (w - i.shape[1]) // 2
            rows.append(np.pad(i, ((0, 0), (x, w - i.shape[1] - x))))
            if k < len(lines) - 1:
                rows.append(np.zeros((max(3 - (i.shape[0] - b), 1), w), int))
            else:
                base = sum(r.shape[0] for r in rows[:-1]) + b
        return np.vstack(rows), base
    if font.startswith("ttf:"):
        a = font.split(":")
        return ttf_ink(text, a[1], int(a[2]), *[float(x) for x in a[3:6]])
    f = FONTS[font](project)
    if text in f["words"]:
        return f["words"][text]
    items, x = [], 0
    for ch in text:
        if ch == " ":
            x += f["space"]
            continue
        g, drop = f["glyphs"][ch]
        items.append((x, g, drop))
        x += g.shape[1] + f["gap"]
    width = x - f["gap"]
    up = max(g.shape[0] - drop for _, g, drop in items)
    down = max(max(drop for _, _, drop in items), 0)
    ink = np.zeros((up + down, width), int)
    for x, g, drop in items:
        top = up + drop - g.shape[0]
        ink[top:top + g.shape[0], x:x + g.shape[1]] = np.maximum(ink[top:top + g.shape[0], x:x + g.shape[1]], g)
    return ink, up


# ── Styles ───────────────────────────────────────────────────────────────────────────────

def style_command(ink, base):
    """Palette indices (0 = clear) and baseline row of a command word: letters 9..13 (the page's
    white-to-violet ramp) on a white plate (8), green rim (4 inside, 5 outside), dark shadow (1)."""
    pad = 4
    h, w = ink.shape
    big = np.zeros((h + 2 * pad, w + 2 * pad), int)
    big[pad:pad + h, pad:pad + w] = ink
    letters = big >= 2
    plate = grow(grow(letters, 1, diagonal=False), 1)          # 2 pixels, corners rounded
    rim1 = grow(plate, 1, diagonal=False) & ~plate
    rim2 = grow(plate | rim1, 1) & ~plate & ~rim1
    shadow = (shift(plate, 1, 1) | shift(plate, 2, 2)) & (rim1 | rim2)
    out = np.zeros(big.shape, np.uint8)
    out[rim2] = 5
    out[rim1] = 4
    out[shadow] = 1
    out[plate] = 8
    ramp = np.array([8, 9, 10, 11, 12, 13, 13], np.uint8)
    out[big > 0] = np.maximum(ramp[big[big > 0]], out[big > 0])
    out[(big > 0) & ~plate & ~rim1 & ~rim2] = 0                 # faint ink outside everything
    return out, base + pad


def outlined(ramp, ring, corner):
    """A style: letters drawn with `ramp` (palette index for ink 0..6), a one-pixel outline `ring`
    on the four sides of every letter pixel and `corner` (0 = none) on the diagonals."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        side = grow(letters, 1, diagonal=False) & ~letters
        diag = grow(letters, 1) & ~letters & ~side
        out = np.zeros(big.shape, np.uint8)
        out[diag] = corner
        out[side] = ring
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def style_stat(ink, base):
    """The stat labels (palette 58, blue to white): white letters shading to light blue at the foot,
    a blue ring (2) and a lighter outer ring (5), both solid."""
    pad = 2
    h, w = ink.shape
    big = np.zeros((h + 2 * pad, w + 2 * pad), int)
    big[pad:pad + h, pad:pad + w] = ink
    letters = big > 0
    ring1 = grow(letters, 1) & ~letters
    ring2 = grow(letters, 2) & ~letters & ~ring1
    out = np.zeros(big.shape, np.uint8)
    out[ring2] = 5
    out[ring1] = 2
    shade = np.rint(15 - 3 * np.arange(h) / max(h - 1, 1)).astype(np.uint8)
    out[pad:pad + h][letters[pad:pad + h]] = np.broadcast_to(shade[:, None], (h, w + 2 * pad))[letters[pad:pad + h]]
    return out, base + pad


def shadowed(ramp, ring, shadow, depth):
    """A style: letters drawn with `ramp`, a one-pixel outline `ring` all round, and a `shadow`
    `depth` pixels down and to the right."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        h, w = ink.shape
        big = np.zeros((h + 2 + depth, w + 2 + depth), int)
        big[1:1 + h, 1:1 + w] = ink
        letters = big > 0
        body = grow(letters, 1)
        cast = np.zeros_like(body)
        for k in range(1, depth + 1):
            cast |= shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
        out = np.zeros(big.shape, np.uint8)
        out[cast & ~body] = shadow
        out[body] = ring
        out[letters] = ramp[big[letters]]
        return out, base + 1
    return style


def ringed(ramp, rings):
    """A style: letters drawn with `ramp` inside solid one-pixel rings (first value innermost)."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = len(rings)
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        out = np.zeros(big.shape, np.uint8)
        for k in range(pad, 0, -1):
            out[grow(letters, k)] = rings[k - 1]
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def haloed(ramp, band, glow, width=2, fill=None, light=None):
    """A style: letters drawn with `ramp` in a solid band `width` pixels wide, inside a one-pixel glow whose
    colour runs through `glow` from the top row to the bottom row; below and to the right the glow is
    two pixels (a soft shadow). The tab and field labels of the Data screen.
    With `fill` (palette indices from the top row of the letters to the bottom row) the letters are a
    vertical gradient instead, and their soft edge runs from the fill towards index `light` (the
    palette must be a ramp between the two)."""
    ramp, glow = np.array(ramp if ramp else [0], np.uint8), np.array(glow, np.uint8)

    def style(ink, base):
        pad = width + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        body = grow(grow(letters, width - 1), 1, diagonal=False) if width > 1 else grow(letters, 1)
        near = grow(body, 1, diagonal=False)
        far = near | shift(near, 1, 1)
        rows = np.nonzero(far.any(1))[0]
        frac = (np.arange(big.shape[0]) - rows.min()) / max(rows.max() - rows.min(), 1)
        shade = glow[np.rint(frac * (len(glow) - 1)).astype(int).clip(0, len(glow) - 1)]
        out = np.zeros(big.shape, np.uint8)
        out[far] = np.broadcast_to(shade[:, None], big.shape)[far]
        out[body] = band
        if fill:
            ys = np.nonzero(letters.any(1))[0]
            f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
            row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
            out[letters] = np.rint(row + (light - row) * (1 - big / 6.0))[letters].astype(np.uint8)
        else:
            out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def banded(ramp, rings, shadow=0):
    """A style: letters drawn with `ramp` inside solid one-pixel rings (first value innermost, corners
    rounded from the second ring on), with a one-pixel `shadow` below and to the right of the last ring."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = len(rings) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        if shadow:
            out[shift(masks[-1], 1, 1)] = shadow
        for m, value in zip(masks[::-1], rings[::-1]):
            out[m] = value
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def titled(ramp, white, shadow, rim, plate=3):
    """A style: the screen titles of the Data screen. Letters with a dark outline (`ramp`[0]) and a fill
    that goes from the brightest colour (`ramp`[-1]) at the top to the one before it at the foot, on a
    white plate `plate` pixels wide; the letters cast a grey shadow (`shadow`: near, far) on the plate, and
    the plate has a rim of two pixels (`rim`: inner, outer)."""
    def style(ink, base):
        pad = plate + 4
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        body = grow(letters, 1)                                  # letters and their outline
        board = grow(grow(body, plate - 1), 1, diagonal=False)
        out = np.zeros(big.shape, np.uint8)
        out[grow(board, 2, diagonal=False)] = rim[1]
        out[grow(board, 1, diagonal=False)] = rim[0]
        out[board] = white
        out[shift(body, 2, 2) & board] = shadow[1]
        out[shift(body, 1, 1) & board] = shadow[0]
        out[body] = ramp[0]
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        top = np.where(f < 0.55, len(ramp) - 1, len(ramp) - 2)[:, None]        # position on the ramp per row
        level = np.rint(top * big / 6.0).astype(int)
        out[letters] = np.array(ramp, np.uint8)[level][letters]
        return out, base + pad
    return style


def badged(fill, soft, outline, white, glow):
    """A style: the large names on the ratings page. Letters filled from `fill`[0] at the top to `fill`[-1]
    at the foot, with an outline two pixels wide (`soft` = the colours between outline and fill, for the
    soft edge of the letters), a white band two pixels wide and a `glow` (near, far) below and to the right."""
    def style(ink, base):
        pad = 6
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        dark = grow(grow(letters, 1), 1, diagonal=False)
        band = grow(grow(dark, 1), 1, diagonal=False)
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(glow), 0, -1):
            out[shift(band, k, k)] = glow[k - 1]
        out[band] = white
        out[dark] = outline
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        edge = np.array([outline] + list(soft) + [0], np.uint8)[np.rint(big * (len(soft) + 1) / 6.0).astype(int)]
        out[letters] = np.where(big >= 6, np.broadcast_to(row, big.shape), edge)[letters]
        return out, base + pad
    return style


def boxed(ramp, pad=(3, 4), size=(0, 0), rim=None):
    """A style: letters drawn with `ramp` on a filled box of colour `ramp`[0] with its four corner pixels
    cut off, `pad` (across, down) pixels larger than the letters and at least `size`; `rim` = the colour
    of a one-pixel edge round the box. The button hints."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        h, w = ink.shape
        bw, bh = max(w + 2 * pad[0], size[0]), max(base + 2 * pad[1], h + 2, size[1])
        x, y = (bw - w) // 2, (bh - base) // 2
        out = np.full((bh, bw), ramp[0], np.uint8)
        out[y:y + h, x:x + w] = ramp[ink]
        for cy, cx in ((0, 0), (0, -1), (-1, 0), (-1, -1)):
            out[cy, cx] = 0
        if rim is not None:
            out = np.pad(out, 1, constant_values=rim)
            for cy, cx in ((0, 0), (0, -1), (-1, 0), (-1, -1)):
                out[cy, cx] = 0
            y += 1
        return out, base + y
    return style


def dropped(ramp, shadow):
    """A style: letters drawn with `ramp` and nothing round them but a `shadow` (near to far, one pixel a
    colour) cast below and to the right."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        h, w = ink.shape
        depth = len(shadow)
        big = np.zeros((h + depth, w + depth), int)
        big[:h, :w] = ink
        letters = big > 0
        out = np.zeros(big.shape, np.uint8)
        for k in range(depth, 0, -1):
            out[shift(letters, k, k) | shift(letters, k, k - 1) | shift(letters, k - 1, k)] = shadow[k - 1]
        out[letters] = ramp[big[letters]]
        return out, base
    return style


def logo(fill, soft, outline, white, rim, shadow, band=2, thick=1):
    """A style: the shop titles. Letters filled from `fill`[0] at the top to `fill`[-1] at the foot (`soft` =
    the colours between outline and fill), an `outline` `thick` pixels wide, a white band `band` pixels wide
    with a one-pixel `rim`, and a `shadow` (near to far) cast below and to the right of the whole."""
    def style(ink, base):
        pad = band + 1 + thick + len(shadow)
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        dark = grow(letters, 1)
        for _ in range(thick - 1):
            dark = grow(dark, 1, diagonal=False)
        plate = grow(grow(dark, band - 1), 1, diagonal=False) if band > 1 else grow(dark, 1, diagonal=False)
        edge = grow(plate, 1, diagonal=False)
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(shadow), 0, -1):
            out[shift(edge, k, k) | shift(edge, k, k - 1) | shift(edge, k - 1, k)] = shadow[k - 1]
        out[edge] = rim
        out[plate] = white
        out[dark] = outline
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        low = np.array([outline] + list(soft) + [0], np.uint8)[np.rint(big * (len(soft) + 1) / 6.0).astype(int)]
        out[letters] = np.where(big >= 6, np.broadcast_to(row, big.shape), low)[letters]
        return out, base + pad
    return style


def called(fill, soft, outline, white, band, shadow, thick=2, wide=2, bandw=3, drop=(1, 0)):
    """A style: the umpire's calls of a match (gameplay.arc h3_stf_0). Letters filled from `fill`[0] at the
    top to `fill`[-1] at the foot (`soft` = colours between outline and fill), an `outline` `thick` pixels
    wide, a `white` band `wide` pixels, a coloured `band` `bandw` pixels round everything, and a `shadow`
    (near to far) cast below it: each step moves drop[0] down and drop[1] right."""
    def style(ink, base):
        pad = thick + wide + bandw + len(shadow) * max(drop) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        dark = grow(letters, thick)
        plate = grow(dark, wide)
        outer = grow(plate, bandw)
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(shadow), 0, -1):
            out[shift(outer, k * drop[0], k * drop[1])] = shadow[k - 1]
        out[outer] = band
        out[plate] = white
        out[dark] = outline
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        low = np.array([outline] + list(soft) + [0], np.uint8)[np.rint(big * (len(soft) + 1) / 6.0).astype(int)]
        out[letters] = np.where(big >= 6, np.broadcast_to(row, big.shape), low)[letters]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


def tight(style):
    """The same style without the empty rows and columns round its art."""
    def trimmed(ink, base):
        out, b = style(ink, base)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], b - ys.min()
    return trimmed


def captioned(ramp, outline, soft, ring=2, depth=2):
    """A style: the scene captions. Letters drawn with `ramp` in a solid `outline` `ring` pixels wide that is
    also cast `depth` pixels down and to the right; `soft` colours the inner corners of the outer edge."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = ring + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad + depth, w + 2 * pad + depth), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        body = grow(letters, 1)
        for _ in range(ring - 1):
            body = grow(body, 1, diagonal=False)
        dark = body.copy()
        for k in range(1, depth + 1):
            dark |= shift(body, k, k)
        dark |= shift(dark, -1, 0) & shift(dark, 0, -1)          # close the steps the cast leaves
        near = sum(shift(dark, dy, dx).astype(int) for dy, dx in ((1, 0), (-1, 0), (0, 1), (0, -1)))
        out = np.zeros(big.shape, np.uint8)
        out[~dark & (near >= 2)] = soft
        out[dark] = outline
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def plated(ramp, shadow, size):
    """A style: letters drawn with `ramp` on a filled rectangle `size` (w, h) of colour `ramp`[0], with a
    `shadow` one pixel down and to the right. Pieces of one plate that stand side by side."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        h, w = ink.shape
        bw, bh = max(size[0], w + 2), max(size[1], h + 2)
        big = np.zeros((bh, bw), int)
        x, y = (bw - w) // 2, max((bh - base) // 2, 0)           # capitals in the middle, whatever hangs below
        big[y:y + h, x:x + w] = ink
        out = np.full(big.shape, ramp[0], np.uint8)
        out[shift(big > 2, 1, 1)] = shadow
        out[big > 0] = ramp[big[big > 0]]
        return out, y + base
    return style


RENDER = {
    "command": style_command,
    # the ability plates (palette 8 of g3_tn00 in are_abi.arc): white letters, dark blue outline, a paler ring
    "plate": banded([0, 9, 10, 11, 13, 14, 15], [7, 3]),
    # the names on the ratings page (palettes 147-150 of y5_mh): Kantoku, Scout, Teammates, Bucho
    "rater147": badged([8, 9, 10], [2, 3, 5, 6, 7], 1, 11, [12, 14, 13]),
    "rater148": badged([12, 13, 14, 15], [2, 3, 4, 5], 1, 11, [8, 7, 6]),
    "rater149": badged([11, 12, 13, 14, 15], [8, 9, 10], 7, 1, [2, 3, 4]),
    "rater150": badged([14, 13, 12, 8, 7, 6, 5], [2, 3, 4], 1, 15, [13, 10, 11]),
    # the screen titles (palettes 22-28 of z3_dts; every palette has its own order of colours)
    "title22": titled([1, 2, 3, 4, 5, 6, 7], 10, [8, 9], [13, 15], 2),
    "title23": titled([1, 2, 3, 4, 5, 6, 7], 15, [8, 9], [12, 10], 2),
    "title24": titled([1, 2, 3, 4, 5, 6, 8, 7], 13, [15, 14], [12, 10], 2),
    "title25": titled([1, 2, 3, 4, 5, 6, 7, 8], 9, [12, 11], [13, 15], 2),
    "title26": titled([1, 2, 3, 6, 4, 5], 12, [8, 15], [11, 9], 2),
    "title27": titled([1, 2, 3, 4, 5, 6, 7], 15, [8, 11], [12, 9], 2),
    "title28": titled([1, 2, 3, 4, 5, 6, 7, 8], 11, [13, 12], [14, 15], 2),
    # Data screen (scs_data.arc, scs_sys.arc). White letters, dark outline, a shadow one step lighter: the
    # ability tabs (palettes 56-59 of z3_dt), handedness and form names (72), trait plates (104, 105)
    "data": banded([0, 6, 8, 10, 12, 14, 15], [4, 3], 2),
    # dark letters in a white band with a pink glow: B/T, Form, Growth (palette 64 of z3_dt)
    "datafield": haloed([0, 7, 6, 5, 3, 2, 1], 8, [9, 8, 8, 8, 10, 11, 12, 13, 14, 15]),
    # dark letters in a white band with a blue glow: the screen buttons (palettes 32-36 of z3_dts)
    "databutton": haloed([0, 7, 6, 5, 3, 2, 1], 8, [10, 10, 11, 11, 12, 12, 13, 14, 15]),
    # letters shading from light at the top to dark at the foot, white band, pale blue glow: the stat names and
    # tags of the team-mate list (palettes 116-125 of z3_dtn), the equipment headers (82 of z3_dt)
    "datastat": haloed(None, 8, [8, 9, 10, 11, 12, 13, 14, 15], fill=[5, 4, 4, 3, 3, 2, 2, 1, 1], light=8),
    "datastat1": haloed(None, 8, [8, 9, 10, 11, 12, 13, 14, 15], 1, fill=[3, 3, 2, 2, 1, 1], light=8),
    # blue letters in a white band, pale blue glow: the lists of the equipment page (palette 82 of z3_dt)
    "datahead": haloed([0, 7, 6, 5, 4, 3, 2], 8, [8, 9, 10, 11, 12, 13, 14, 15]),
    # white letters in one dark ring: a trait name that lies across the two colours of its plate
    "dataflat": banded([0, 6, 8, 10, 12, 14, 15], [4, 4]),
    # dark blue at the top to light blue at the foot, white band: 装備中アイテム (palette 80 of z3_dt)
    "dataequip": haloed(None, 15, [15, 15, 15, 14, 13, 12, 11, 10], fill=[1, 2, 3, 4, 5, 6, 7], light=15),
    # the rank plate of scenario 1 (y5_siba_1): 平社員 grey with a white outline (palette 19), 係長 dark with a white
    # outline (20), 課長 orange in white and blue (21); 役職 white with a dark outline (20)
    "rank0": ringed([0, 12, 11, 9, 7, 5, 4], [15, 15]),
    "rank1": ringed([0, 12, 10, 8, 5, 3, 1], [15, 15]),
    "rank2": ringed([0, 13, 15, 6, 5, 4, 3], [11, 2, 1]),
    "ranktag": outlined([0, 8, 10, 12, 13, 14, 15], 2, 3),
    # navy letters, white outline, light blue shadow: the pitch names (palette 32 of z3_nph_scs)
    "pitch": shadowed([0, 7, 6, 4, 3, 2, 1], 8, 14, 2),
    # white letters, navy outline and shadow: 年目 / 月 / 週 of the date (palette 22 of y5_ten)
    "calendar": shadowed([0, 9, 11, 13, 14, 15, 15], 3, 4, 1),
    # yellow letters, purple outline: the 天気 tag (palette 56 of y5_np)
    "weather": outlined([0, 9, 10, 11, 12, 14, 15], 7, 5),
    # white letters in a red glow: 熱血発動中 (palette 47 of y5_npm)
    "glow": ringed([0, 9, 11, 12, 13, 14, 15], [4, 2]),
    # white letters, black outline: the button hints (palette 60 of y5_npm, a grey ramp)
    "hint": outlined([0, 8, 10, 12, 13, 14, 15], 1, 2),
    # plain black letters, no outline (palette 82 of z3_smr, light grey to black)
    "plain": outlined([0, 3, 6, 9, 11, 13, 15], 0, 0),
    # the shop (scs_item.arc, z3_shp): tab names, dark blue shading to light at the foot, in a white band with a
    # lilac glow (palette 24); 所持金 (72); the Cancel button (53, drawn again as a shadow with 50 / 51);
    # the 購入 / 所持 tags, white with a dark outline (60, 61); the − hint, white on a black box (44);
    # the screen title, pink in a blue outline on a white band with a dark shadow (54, 55)
    "shoptab": haloed(None, 8, [9, 10, 11, 12, 13, 14, 15], fill=[1, 1, 2, 3, 3, 4, 4, 5, 5], light=8),
    "shopmoney": haloed([0, 7, 6, 4, 3, 2, 1], 8, [13, 12, 12, 11, 11, 10, 12, 14]),
    "shopcancel": haloed([0, 12, 11, 7, 5, 3, 1], 14, [8, 10, 9, 9, 9, 9, 8], 1),
    "shoptag": outlined([0, 9, 10, 12, 13, 14, 15], 8, 8),
    "shophint": boxed([1, 4, 7, 9, 11, 13, 15], (3, 4), (31, 21)),
    "shoptitle": logo([12, 12, 13, 13, 15, 15, 14], [14], 2, 10, 8, [1, 1]),
    # 売り切れ！: green letters, lighter at the top, in a dark outline on a white band, lilac shadow (palette 63)
    "shopsold": logo([7, 7, 7, 6, 6, 6, 5, 5, 4, 3], [2, 3], 1, 15, 13, [8, 9]),
    # the gear names on the item icons (m4_item1, palette 13, a grey ramp): white, black outline, grey shadow
    "gear": shadowed([0, 4, 7, 10, 12, 14, 15], 1, 9, 1),
    # the settings list of the System screen (scs_sys.arc, pages z3_sys): row names, yellow shading from orange,
    # in a violet outline with a paler edge (palette 161); values, dark at the top to light at the foot, white
    # band, blue shadow (162-170, one colour each); 難度, yellow-green on a blue box (160)
    "sysheader": haloed(None, 9, [12, 11, 11, 10, 10, 10, 10, 11, 12, 13], fill=[3, 3, 3, 2, 2, 2, 1, 1, 1], light=9),
    "sysvalue": haloed(None, 8, [8, 8, 8, 9, 10, 12, 14, 15, 15, 15], fill=[1, 1, 1, 2, 2, 3, 3, 3, 4, 4, 5], light=8),
    "sysbox": boxed([9, 8, 7, 6, 5, 3, 2], (3, 4), (0, 0), 11),
    # the item list (scs_main.arc, z3_itw): tab names, blue shading to pale at the foot, white band (palettes 50, 51)
    "itemtab": haloed(None, 15, [14, 14, 14, 14, 13, 12, 10, 9, 8, 7, 7, 7],
                      fill=[1, 1, 2, 2, 3, 3, 4, 5, 5, 6, 6, 7, 8], light=15),
    # scene captions of scs_main.arc (r3_ai, palette 160): white letters, navy outline and cast shadow
    "caption": captioned([15, 15, 14, 12, 11, 10, 8], 15, 13),
    # position words of the main screen (y5_np_0 pages 3 and 7, palettes 32-35): white in a double ring
    "position": banded([3, 5, 7, 9, 11, 13, 15], [3, 3], 2),
    # the before / after panel of the Equip page (scs_data.arc z3_ikp_0): stat names in palette 2,
    # Before / After in palettes 14 and 15 (green and yellow letters on a white band)
    "equipstat": banded([4, 6, 8, 10, 12, 14, 15], [4, 3]),
    "equipbefore": logo([15, 15, 14, 14, 13, 13, 12, 12, 11], [9, 10], 8, 1, 2, [4, 5]),
    # league plates of the standings (scs_data.arc z4_dtj_0, palettes 90-92): white on the plate colour
    "league44": plated([8, 8, 10, 10, 13, 15, 15], 6, (44, 20)),
    "league36": plated([8, 8, 10, 10, 13, 15, 15], 6, (36, 20)),
    # team names of the standings (palette 87, black on the board): two grey levels only, as the Japanese has,
    # so that the compressed pages stay inside their slots
    "team": outlined([0, 0, 4, 7, 15, 15, 15], 0, 0),
    "month": logo([15], [15], 15, 8, 7, [4, 1], 3),     # navy on a white band, blue cast: the month banner
    "stat": style_stat,
    # white letters, dark blue outline: the 体力 / 熱血 tags (palette 58, a blue-to-white ramp)
    "tag": outlined([0, 5, 7, 10, 12, 14, 15], 1, 3),
    # dark blue letters, white outline: 所持金 (palette 19, dark blue to white)
    "money": outlined([0, 12, 10, 8, 5, 3, 2], 15, 15),
    # blue letters, white outline: やる気 (palette 50; the game draws a shadow copy with palette 30)
    "motivation": outlined([0, 12, 10, 8, 5, 2, 1], 15, 15),
    # the Success start screen (scs_titl.arc, y5_scs_tit_0). The three buttons: yellow letters in a thick brown
    # outline (palette 17), pink in dark magenta (18), light green in dark green (19), each on a white band
    # with a pale rim and a blue shadow
    "titlestart": logo([6], [2, 3, 4, 5], 1, 13, 11, [9, 8], 2, 2),
    "titleview": logo([12, 12, 12, 13, 14, 15], [4, 5, 6], 3, 10, 8, [2, 1], 2, 2),
    "titlelink": logo([6, 6, 6, 6, 5, 5], [2, 3, 4], 1, 14, 12, [9, 8], 2, 2),
    # New Game / Continue / the lists: white letters in a blue outline that is cast down and to the right (22)
    "titleitem": captioned([4, 10, 11, 12, 13, 14, 15], 5, 3),
    # the counts line: white letters in a navy ring (26)
    "titlecount": banded([0, 5, 7, 9, 11, 13, 15], [1]),
    # Cleared / Turned Pro: navy letters on a white band with a grey shadow (45)
    "titleclear": banded([0, 12, 10, 9, 1, 2, 3], [15, 15], 5),
    # the overwrite warning (r4_sta): red lines (palette 27) and black lines (28), each a ramp to white, in a
    # white band; the heading, yellow in a thick blue outline on white (25; palette 26 draws it again in one
    # colour as its shadow)
    "warnline": banded([0, 12, 9, 7, 4, 2, 1], [15, 15, 15]),
    "warnhead": logo([10, 10, 11, 11, 12, 12], [15, 14, 9], 1, 7, 7, [], 2, 2),
    # Cleared on the album page: green letters on a white band inside blue rings (1); the movie button: white
    # letters in thick navy (2)
    "albumclear": banded([0, 9, 8, 6, 4, 2, 1], [10, 10, 12, 14, 15]),
    "albummovie": banded([0, 6, 8, 10, 12, 14, 15], [3, 3, 3]),
    # the scenario's team name on the start screen (y5_sge_0, palette 4): white letters in two blue rings
    "titleteam": banded([0, 10, 11, 12, 13, 14, 15], [4, 5]),
    # the profile screens (scs_make.arc, y5_cmk_0): headings, cream shading from orange in a thick blue outline
    # with a lilac rim (palette 30); the lists, dark grey letters with a pale shadow (26)
    "makehead": logo([9, 9, 10, 11, 12], [5], 1, 1, 14, [], 1, 2),
    "makeitem": dropped([0, 11, 11, 13, 13, 15, 15], [7, 5]),
    # the view hint of the form screens: lilac letters on a white band with a pale shadow (16)
    "makehint": banded([0, 13, 5, 3, 2, 1, 1], [15, 15], 7),
    # the difficulty screen (y5_nan_0): Normal, green fading to white at the foot in a dark green outline on a
    # white band (palette 24); Rookie, the same in orange (23, another order of colours). Palette 31 draws
    # each again in black as its shadow.
    "nannormal": logo([10, 9, 8, 7, 6, 5, 4], [13, 11], 15, 3, 2, [], 2, 2),
    "nanrookie": logo([9, 11, 12, 13, 14, 15, 4], [6, 8], 5, 4, 2, [], 2, 2),
    # name entry (namein.arc, s3_nam): headings, yellow in a thick blue outline on a white band with a lilac
    # shadow (palette 14); the button words, dark letters on a white band in blue rings (25, 26, 28)
    "namehead": logo([13, 13, 11, 11, 10, 10], [8], 3, 15, 14, [7, 6], 2, 2),
    "namebutton": banded([0, 10, 11, 12, 13, 14, 15], [9, 9, 7, 5]),
    # the umpire's calls of a match (gameplay.arc h3_stf_0), one per palette of the bank
    "call0": called([15, 14, 13, 12, 11], [3, 7], 1, 10, 2, [6, 6, 6, 6]),      # blue: Play Ball, Time, Ball
    "call1": called([15, 14, 13, 12], [2, 3], 1, 11, 4, [6, 7, 7, 7]),          # yellow on olive: Strike, Foul
    "call2": called([9, 10, 11, 13], [6, 7], 5, 14, 1, [4, 4, 4, 4]),           # green: Walk, Safe, Hit ...
    "call3": called([9, 10, 11, 12, 13], [2, 3], 1, 15, 4, [6, 7, 7, 7]),       # pink: Out, Change, Game Set
    "call5": called([6, 7, 8, 9], [2, 4], 1, 10, 15, [13, 12, 12, 12]),         # yellow on pink: home runs
    # the pause menu of a match (gameplay.arc h3_tim_0, palettes 6..11 share one layout)
    "pausemenu": called([15, 14, 13, 12, 11], [8, 9, 10], 6, 6, 4, [6, 2], thick=1, wide=0, bandw=1),
    # pitch names of the match's pitch chart (main_prg.arc g3_np2, palette 14): white in a solid blue ring
    "pitchchart": tight(banded([0, 1, 1, 7, 7, 7, 7], [1])),
    # the player panel of a match (main_prg.arc g3_np, palette 13): navy in a white ring, a teal shadow
    "panel": tight(banded([0, 5, 6, 7, 8, 8, 8], [4, 4], 12)),
    # the substitution screen of a match (time.arc g3_tim)
    "subhead": tight(banded([0, 7, 6, 5, 3, 2, 1], [8, 8])),                 # column headers: navy in a white ring
    "subtab": tight(banded([0, 5, 4, 3, 2, 1, 1], [15, 13])),                # Batter / Bench: white in navy, italic
    "submenu": called([15, 15], [9, 11, 13], 8, 8, 4, [3, 2], thick=1, wide=0, bandw=1),   # palettes 55..60
}


def art_ink(art, project=None):
    """(ink, baseline row) of lettering cut from an MLB sheet: {"pack", "tex", "box", "style", "role"}.
    The pixels of one role (see ui_labels.STYLES) become full ink."""
    mask, cls = L.source_classes(dict(art, drop=[r for r in ("fill", "ring", "outer", "letter", "plate",
                                                         "edge_dark", "edge_light")
                                               if r != art.get("role", "fill")]), project)
    grid = L.despeckle(mask.astype(int))
    ink = np.where(grid > 0, 6, 0)
    ys, xs = np.nonzero(ink)
    ink = ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    return ink, art.get("base", ink.shape[0])


# ── Repacking ────────────────────────────────────────────────────────────────────────────

def art_box(page, rect):
    """Bounding box (x0, y0, x1, y1) of the pixels inside a rectangle, in page coordinates."""
    x0, y0, x1, y1 = rect
    ys, xs = np.nonzero(page[y0:y1, x0:x1])
    return x0 + xs.min(), y0 + ys.min(), x0 + xs.max() + 1, y0 + ys.max() + 1


def shelf_pack(sizes, areas, gap=(1, 1)):
    """Place (w, h) boxes into areas [(page, x0, y0, x1, y1)]: {index: (page, x, y)}. Tallest boxes
    first; a box goes on the lowest open shelf that is high enough and has room, or opens a new
    shelf of its own height. `gap` = clear pixels left between boxes (across, down), so a neighbour
    never bleeds in when the game filters the texture."""
    free = [[page, x0, y0, x1, y1] for page, x0, y0, x1, y1 in areas]     # unshelved part of each area
    shelves = []                                                          # [page, x, y, x1, height]
    placed = {}
    for i in sorted(range(len(sizes)), key=lambda i: (-sizes[i][1], -sizes[i][0])):
        w, h = sizes[i]
        fits = [s for s in shelves if s[4] >= h and s[3] - s[1] >= w]
        if fits:
            s = min(fits, key=lambda s: (s[4], s[3] - s[1]))
        else:
            room = [a for a in free if a[4] - a[2] >= h and a[3] - a[1] >= w]
            if not room:
                raise ValueError("no room for a label %dx%d" % (w, h))
            a = min(room, key=lambda a: a[3] - a[1])
            s = [a[0], a[1], a[2], a[3], h]
            shelves.append(s)
            a[2] += h + gap[1]
        placed[i] = (s[0], s[1], s[2])
        s[1] += w + gap[0]
    return placed


def ribbon_pack(widths, height, areas, gap=1, empty=4):
    """Pour lines of art (all `height` rows high) into the rows of the areas, cutting a line where a row
    ends. Returns ({line: [(page, x, y, c0, c1)]}, (page, x, y) of an empty empty x empty cell). Widest
    first, with as few cuts as possible: a line wider than a row takes whole empty rows and its rest goes
    where it fills a row best; a line that fits no row whole is cut over the rows with the most room."""
    rows = []                                                     # [page, x, y, x1, x0]
    for pg, x0, y0, x1, y1 in areas:
        y = y0
        while y + height <= y1:
            rows.append([pg, x0, y, x1, x0])
            y += height + gap
    out = {}

    def put(i, r, c, take):
        out[i].append((r[0], r[1], r[2], c, c + take))
        r[1] += take + gap
    for i in sorted(range(len(widths)), key=lambda i: -widths[i]):
        c, w = 0, widths[i]
        out[i] = []
        while c < w:
            fits = [r for r in rows if r[3] - r[1] >= w - c]
            if fits:                                              # the rest fits a row whole
                put(i, min(fits, key=lambda r: r[3] - r[1]), c, w - c)
                break
            empty_rows = [r for r in rows if r[1] == r[4]]
            r = empty_rows[0] if empty_rows else max(rows, key=lambda r: r[3] - r[1])
            take = min(w - c, r[3] - r[1])
            if take < min(12, w - c):
                raise ValueError("no room for %d more columns of a line" % (w - c))
            put(i, r, c, take)
            c += take
    for pg, x0, y0, x1, y1 in areas:                              # an empty cell: below the rows, or a row's end
        n = (y1 - y0 + gap) // (height + gap)
        if y1 - (y0 + n * (height + gap)) >= empty and x1 - x0 >= empty:
            return out, (pg, x0, y1 - empty)
    r = max(rows, key=lambda r: r[3] - r[1])
    if r[3] - r[1] < empty:
        raise ValueError("no room for the empty cell")
    return out, (r[0], r[1], r[2])


def repack_ribbon(group, d, bank, pages, patches, project=None):
    """A group of sprite labels set as lines of big lettering ("ribbon": true; the umpire's calls). Each
    label is a sprite; its text (lines split by \\n) is styled line by line, the lines are poured into the
    areas by ribbon_pack, and part n of the sprite shows piece n (the rest show an empty cell). A line
    drawn twice in the same style (HOME RUN in the two-run homer) is stored once. The label is centred on
    the old art; lines stand `step` rows apart (default: line height - "overlap", 8)."""
    def page(n):
        if n not in pages:
            pages[n] = U.decode_indices(d, *bank["pages"][n]).copy()
        return pages[n]
    gap = group.get("gap", [1, 1])[0]
    labels, lines, keys = group["labels"], [], {}
    plan = []                                    # per label: (parts, screen box, [(line, dx, dy)], W, H)
    for lab in labels:
        mine = next(ps for name, ps in bank["sprites"].items() if name.endswith("_" + lab["sprite"]))
        box = None
        for p in mine:
            ys, xs = np.nonzero(page(p.page)[p.y0:p.y1, p.x0:p.x1])
            if len(xs):
                b = (p.x + xs.min(), p.y + ys.min(), p.x + xs.max() + 1, p.y + ys.max() + 1)
                box = b if box is None else (min(box[0], b[0]), min(box[1], b[1]), max(box[2], b[2]), max(box[3], b[3]))
        style = RENDER[lab.get("style", group.get("style"))]
        font = lab.get("font", group.get("font"))
        mine_lines = []
        for t in lab["text"].split("\n"):
            key = (lab.get("style", group.get("style")), font, t)
            if key not in keys:
                keys[key] = len(lines)
                lines.append(style(*typeset(t, font, project))[0])
            mine_lines.append(keys[key])
        hs = [lines[n].shape[0] for n in mine_lines]
        step = lab.get("line_step", hs[0] - lab.get("overlap", 8))
        W = max(lines[n].shape[1] for n in mine_lines)
        H = step * (len(hs) - 1) + hs[-1]
        plan.append((mine, box, [(n, (W - lines[n].shape[1]) // 2, k * step) for k, n in enumerate(mine_lines)], W, H))
    height = max(a.shape[0] for a in lines)
    owned = {(p.page, p.x0, p.y0, p.x1, p.y1) for mine, *_ in plan for p in mine}
    areas = [tuple(a) for a in group["areas"]]
    clear = areas + sorted(owned)
    for p in (p for ps in bank["sprites"].values() for p in ps):
        key = (p.page, p.x0, p.y0, p.x1, p.y1)
        if key not in owned and any(key[0] == r[0] and key[1] < r[3] and r[1] < key[3] and key[2] < r[4]
                                    and r[2] < key[4] for r in clear):
            raise ValueError("sprite %s uses x %d-%d y %d-%d of page %d, which this group clears"
                             % (p.sprite, p.x0, p.x1, p.y0, p.y1, p.page))
    where, (ep, ex, ey) = ribbon_pack([a.shape[1] for a in lines], height, areas, gap)
    for pg, x0, y0, x1, y1 in clear:
        page(pg)[y0:y1, x0:x1] = 0
    for n, a in enumerate(lines):
        for pg, x, y, c0, c1 in where[n]:
            page(pg)[y:y + a.shape[0], x:x + c1 - c0] = a[:, c0:c1]
    rows = []
    for lab, (mine, box, ls, W, H) in zip(labels, plan):
        left = (box[0] + box[2]) // 2 - W // 2 + lab.get("dx", 0)
        top = (box[1] + box[3]) // 2 - H // 2 + lab.get("dy", 0)
        pieces = [(pg, x, y, c0, c1, n, dx, dy) for n, dx, dy in ls for pg, x, y, c0, c1 in where[n]]
        if len(pieces) > len(mine):
            raise ValueError("%r needs %d parts, its sprite has %d" % (lab["text"], len(pieces), len(mine)))
        for k, p in enumerate(mine):
            if k < len(pieces):
                pg, x, y, c0, c1, n, dx, dy = pieces[k]
                data = U.pack_part(pg, p.flags, p.palette, top + dy, left + dx + c0, y, x, y + lines[n].shape[0], x + c1 - c0)
            else:
                data = U.pack_part(ep, 0, p.palette, p.y, p.x, ey, ex, ey + 4, ex + 4)
            patches.append((p.offset, data))
        rows.append((lab["text"].replace("\n", " / "), "%dx%d" % (box[2] - box[0], box[3] - box[1]),
                     "%dx%d" % (W, H), "%d pieces" % len(pieces), len(mine)))
    return rows


def repack(group, d, bank, pages, patches, project=None):
    """Lay out the labels of one repack group. `pages` {page: index array} are edited in place;
    `patches` collects (file offset, 10 bytes) for the sprite parts. Returns report rows.

    A label is found by "from" (a rectangle [page, x0, y0, x1, y1]: every part showing it is
    re-pointed and keeps its place; with "sprites": [ids] only the parts of those sprites, and the label
    without "sprites" for the same rectangle leaves them alone) or by "sprite" (the end of an opd_ name: the whole sprite is one
    label, however many pieces it was drawn from; its first part shows the new art, the others are
    pointed at an empty cell)."""
    if group.get("ribbon"):
        return repack_ribbon(group, d, bank, pages, patches, project)
    areas = [tuple(a) for a in group["areas"]]

    def opt(lab, key, default=None):                 # a label can override the group's settings
        return lab.get(key, group.get(key, default))

    def page(n):
        if n not in pages:
            pages[n] = U.decode_indices(d, *bank["pages"][n]).copy()
        return pages[n]

    parts = [p for ps in bank["sprites"].values() for p in ps]
    labels = group["labels"]
    blanks = {tuple(r) for r in group.get("blank", ())}
    old, owned = [], set()                 # per label: (parts, screen box of the art or None)
    for lab in labels:
        if "sprite" in lab:
            mine = next(ps for name, ps in bank["sprites"].items() if name.endswith("_" + lab["sprite"]))
            pgs, pls = opt(lab, "pages"), opt(lab, "palettes")   # the parts that are lettering, not plate or icon
            mine = [p for p in mine if (pgs is None or p.page in pgs) and (pls is None or p.palette in pls)]
            box = None
            for p in mine[:len(mine) // opt(lab, "layers", 1)]:  # the art as it stands on screen
                ys, xs = np.nonzero(page(p.page)[p.y0:p.y1, p.x0:p.x1])
                if len(xs):
                    b = (p.x + xs.min(), p.y + ys.min(), p.x + xs.max() + 1, p.y + ys.max() + 1)
                    box = b if box is None else (min(box[0], b[0]), min(box[1], b[1]),
                                                 max(box[2], b[2]), max(box[3], b[3]))
            old.append((mine, box))
        else:
            pg, x0, y0, x1, y1 = lab["from"]
            mine = [p for p in parts if (p.page, p.x0, p.y0, p.x1, p.y1) == (pg, x0, y0, x1, y1)]
            if "sprites" in lab:               # only these sprites' parts (a piece one sprite uses another way)
                mine = [p for p in mine if p.sprite.rsplit("_", 1)[1] in lab["sprites"]]
            else:                              # less the parts a label with "sprites" takes for the same piece
                taken = {s for o in labels if o.get("from") == lab["from"] for s in o.get("sprites", ())}
                mine = [p for p in mine if p.sprite.rsplit("_", 1)[1] not in taken]
            ax0, ay0, ax1, ay1 = art_box(page(pg), (x0, y0, x1, y1))
            old.append((mine, (ax0 - x0, ay0 - y0, ax1 - x0, ay1 - y0)))     # relative to the rectangle
        owned |= {(p.page, p.x0, p.y0, p.x1, p.y1) for p in mine}
    clear = areas + sorted(blanks) + sorted(owned)

    def overlaps(key, r):
        return key[0] == r[0] and key[1] < r[3] and r[1] < key[3] and key[2] < r[4] and r[2] < key[4]
    for p in parts:                                              # nothing else may live in what is cleared
        key = (p.page, p.x0, p.y0, p.x1, p.y1)
        if key not in owned and key not in blanks and any(overlaps(key, r) for r in clear):
            raise ValueError("sprite %s uses x %d-%d y %d-%d of page %d, which this group clears"
                             % (p.sprite, p.x0, p.x1, p.y0, p.y1, p.page))
    art = []
    sliced = {}                                # label index: ([(dx, dy) of each strip], width, height)
    seen, alias = {}, {}                       # strips of sliced labels: art -> first place; extra index -> that place
    extra = []                                 # (label index, art) of the second and later pieces of a label
    for k, (lab, (mine, box)) in enumerate(zip(labels, old)):
        style = RENDER[opt(lab, "style", "command")]
        if "pieces" in lab:                    # coloured pieces side by side: one part and one palette each
            arts = [style(*typeset(pc["text"], opt(lab, "font", "command"), project)) for pc in lab["pieces"]]
            art.append(arts[0])
            extra += [(k, a) for a in arts[1:]]
        elif "text" in lab and lab.get("slices"):  # wider than a part: cut into strips, one part each
            lines = [style(*typeset(t, opt(lab, "font", "command"), project)) for t in lab["text"].split("\n")]
            step = lab.get("line_step", lines[0][0].shape[0] - lab.get("overlap", 8))
            W = max(a.shape[1] for a, _ in lines)
            H = step * (len(lines) - 1) + lines[-1][0].shape[0]
            strips = []                        # (art, dx, dy) from the top left of the whole label
            for li, (a, b) in enumerate(lines):
                cuts = list(range(0, a.shape[1], lab.get("slice_width", U.PAGE))) + [a.shape[1]]
                strips += [(a[:, c0:c1], (W - a.shape[1]) // 2 + c0, li * step) for c0, c1 in zip(cuts, cuts[1:])]
            sliced[k] = ([(dx, dy) for _, dx, dy in strips], W, H)
            art.append((strips[0][0], lines[0][1]))
            seen.setdefault((strips[0][0].shape, strips[0][0].tobytes()), ("main", k))
            for a, _, _ in strips[1:]:         # a strip drawn before (HOME RUN of the two-run homer) is shared
                key = (a.shape, a.tobytes())
                if key in seen:
                    alias[len(extra)] = seen[key]
                    extra.append((k, (np.zeros((1, 1), np.uint8), lines[0][1])))
                else:
                    seen[key] = ("extra", len(extra))
                    extra.append((k, (a, lines[0][1])))
        elif "text" in lab:
            art.append(style(*typeset(lab["text"], opt(lab, "font", "command"), project)))
        elif "art" in lab:
            art.append(style(*art_ink(lab["art"], project)))
        elif lab.get("empty"):                                   # a piece that is not needed any more
            art.append((np.zeros((1, 1), np.uint8), None))
        else:                                                    # keep the Japanese label as it is
            pg, x0, y0, x1, y1 = lab["from"]
            art.append((page(pg)[y0 + box[1]:y0 + box[3], x0 + box[0]:x0 + box[2]].copy(), None))
    same = {}                                  # a label whose art another label already has: stored once
    first = {}
    for k, (lab, (a, b)) in enumerate(zip(labels, art)):
        if "text" in lab and "pieces" not in lab and k not in sliced and not lab.get("empty"):
            key = (a.shape, a.tobytes(), b)
            if key in first:
                same[k] = first[key]
            else:
                first[key] = k
    sizes = [(1, 1) if k in same else (a.shape[1], a.shape[0]) for k, (a, _) in enumerate(art)]
    spare = any("sprite" in lab and len(mine) > opt(lab, "layers", 1) for lab, (mine, _) in zip(labels, old))
    placed = shelf_pack(sizes + [(4, 4)] + [(a.shape[1], a.shape[0]) for _, (a, _) in extra], areas,
                        tuple(group.get("gap", (1, 1))))
    for pg, x0, y0, x1, y1 in clear:
        page(pg)[y0:y1, x0:x1] = 0
    rows = []
    for i, (lab, (mine, box)) in enumerate(zip(labels, old)):
        img, base = art[i]
        pg, x, y = placed[same.get(i, i)]
        h, w = img.shape
        page(pg)[y:y + h, x:x + w] = img
        if lab.get("empty"):                                     # its parts show the empty cell from now on
            sp, sx, sy = placed[len(labels)]
            patches.extend((p.offset, U.pack_part(sp, 0, p.palette, p.y, p.x, sy, sx, sy + 4, sx + 4)) for p in mine)
            rows.append(("(emptied)", "%dx%d" % (box[2] - box[0], box[3] - box[1]), "-", "-", len(mine)))
            continue
        under = opt(lab, "under", 4)       # rows of the Japanese art below the foot of its letters
        centre = lab.get("centre_x", (box[0] + box[2]) // 2)     # keep the horizontal centre
        if lab.get("align") == "left":                           # or the left edge
            centre = box[0] + w // 2
        if lab.get("align") == "right":                          # or the right edge
            centre = box[2] - w + w // 2
        top = (box[3] - under - base) if base is not None else box[1]   # sit on the old baseline
        if opt(lab, "valign") == "centre" and base is not None:  # or in the middle of the old art
            top = (box[1] + box[3]) // 2 - h // 2
        left = centre - w // 2
        if opt(lab, "baseline") is not None and base is not None:    # a fixed row and column of the sprite,
            top = opt(lab, "baseline") - base                        # for a list of names set in one line
        if opt(lab, "left") is not None:
            left = opt(lab, "left")
        per = len(mine) // opt(lab, "layers", 1) if "sprite" in lab else 1
        if i in sliced:                                          # strip n is drawn by part n of the sprite
            offs, W, H = sliced[i]
            def spot(j):
                kind, n = alias.get(j, ("extra", j))
                if kind == "main":
                    return placed[n] + (art[n][0],)
                return placed[len(labels) + 1 + n] + (extra[n][1][0],)
            spots = [(pg, x, y, img)] + [spot(j) for j, (li, a) in enumerate(extra) if li == i]
            if len(spots) > len(mine):
                raise ValueError("%s needs %d parts, its sprite has %d" % (lab["text"], len(spots), len(mine)))
            left = opt(lab, "left", lab.get("centre_x", (box[0] + box[2]) // 2) - W // 2)
            top = (box[1] + box[3]) // 2 - H // 2 + lab.get("dy", 0)
            for n, p in enumerate(mine):
                if n < len(spots):
                    sp, sx, sy, a = spots[n]
                    page(sp)[sy:sy + a.shape[0], sx:sx + a.shape[1]] = a
                    data = U.pack_part(sp, p.flags, p.palette, top + offs[n][1], left + offs[n][0],
                                       sy, sx, sy + a.shape[0], sx + a.shape[1])
                else:
                    sp, sx, sy = placed[len(labels)]
                    data = U.pack_part(sp, 0, p.palette, p.y, p.x, sy, sx, sy + 4, sx + 4)
                patches.append((p.offset, data))
            rows.append((lab["text"].replace("\n", " / "), "%dx%d" % (box[2] - box[0], box[3] - box[1]),
                         "%dx%d" % (W, H), "page %d x %d y %d +%d strips" % (pg, x, y, len(spots) - 1), len(mine)))
            continue
        if "pieces" in lab:                                      # piece n is drawn by part n, left to right
            more = [(placed[len(labels) + 1 + j], a) for j, (li, a) in enumerate(extra) if li == i]
            join = opt(lab, "join", 0)                           # pixels a piece overlaps the one before
            total = w + sum(a[0].shape[1] - join for _, a in more)
            x_on = (box[0] + box[2]) // 2 - total // 2
            for n, p in enumerate(mine):
                pal = lab["pieces"][n]["palette"] if n < len(lab["pieces"]) else p.palette
                if n == 0:
                    data = U.pack_part(pg, p.flags, pal, top, x_on, y, x, y + h, x + w)
                    x_on += w - join
                elif n <= len(more):
                    (mp, mx, my), (mimg, mbase) = more[n - 1]
                    page(mp)[my:my + mimg.shape[0], mx:mx + mimg.shape[1]] = mimg
                    data = U.pack_part(mp, p.flags, pal, top + base - mbase, x_on, my, mx,
                                       my + mimg.shape[0], mx + mimg.shape[1])
                    x_on += mimg.shape[1] - join
                else:
                    sp, sx, sy = placed[len(labels)]
                    data = U.pack_part(sp, 0, p.palette, p.y, p.x, sy, sx, sy + 4, sx + 4)
                patches.append((p.offset, data))
            rows.append(("".join(pc["text"] for pc in lab["pieces"]), "%dx%d" % (box[2] - box[0], box[3] - box[1]),
                         "%dx%d" % (total, h), "page %d x %d y %d" % (pg, x, y), len(mine)))
            continue
        for k, p in enumerate(mine):
            if "sprite" in lab:                                  # box is in screen coordinates
                if k % per == 0:                                 # the first piece of each layer shows the new art
                    dx = min(q.x for q in mine[k:k + per]) - min(q.x for q in mine[:per])
                    dy = min(q.y for q in mine[k:k + per]) - min(q.y for q in mine[:per])
                    data = U.pack_part(pg, p.flags, p.palette, top + dy, left + dx, y, x, y + h, x + w)
                else:
                    sp, sx, sy = placed[len(labels)]
                    data = U.pack_part(sp, 0, p.palette, p.y, p.x, sy, sx, sy + 4, sx + 4)
            else:                                                # box is relative to the old rectangle
                data = U.pack_part(pg, p.flags, p.palette, p.y + top, p.x + left, y, x, y + h, x + w)
            patches.append((p.offset, data))
        rows.append((lab.get("text") or lab.get("name") or "(kept)", "%dx%d" % (box[2] - box[0], box[3] - box[1]),
                     "%dx%d" % (w, h), "page %d x %d y %d" % (pg, x, y), len(mine)))
    return rows
