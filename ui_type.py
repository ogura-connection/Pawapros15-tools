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


RENDER = {
    "command": style_command,
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
    "stat": style_stat,
    # white letters, dark blue outline: the 体力 / 熱血 tags (palette 58, a blue-to-white ramp)
    "tag": outlined([0, 5, 7, 10, 12, 14, 15], 1, 3),
    # dark blue letters, white outline: 所持金 (palette 19, dark blue to white)
    "money": outlined([0, 12, 10, 8, 5, 3, 2], 15, 15),
    # blue letters, white outline: やる気 (palette 50; the game draws a shadow copy with palette 30)
    "motivation": outlined([0, 12, 10, 8, 5, 2, 1], 15, 15),
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


def repack(group, d, bank, pages, patches, project=None):
    """Lay out the labels of one repack group. `pages` {page: index array} are edited in place;
    `patches` collects (file offset, 10 bytes) for the sprite parts. Returns report rows.

    A label is found by "from" (a rectangle [page, x0, y0, x1, y1]: every part showing it is
    re-pointed and keeps its place) or by "sprite" (the end of an opd_ name: the whole sprite is one
    label, however many pieces it was drawn from; its first part shows the new art, the others are
    pointed at an empty cell)."""
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
    extra = []                                 # (label index, art) of the second and later pieces of a label
    for k, (lab, (mine, box)) in enumerate(zip(labels, old)):
        style = RENDER[opt(lab, "style", "command")]
        if "pieces" in lab:                    # coloured pieces side by side: one part and one palette each
            arts = [style(*typeset(pc["text"], opt(lab, "font", "command"), project)) for pc in lab["pieces"]]
            art.append(arts[0])
            extra += [(k, a) for a in arts[1:]]
        elif "text" in lab:
            art.append(style(*typeset(lab["text"], opt(lab, "font", "command"), project)))
        elif "art" in lab:
            art.append(style(*art_ink(lab["art"], project)))
        else:                                                    # keep the Japanese label as it is
            pg, x0, y0, x1, y1 = lab["from"]
            art.append((page(pg)[y0 + box[1]:y0 + box[3], x0 + box[0]:x0 + box[2]].copy(), None))
    sizes = [(a.shape[1], a.shape[0]) for a, _ in art]
    spare = any("sprite" in lab and len(mine) > opt(lab, "layers", 1) for lab, (mine, _) in zip(labels, old))
    placed = shelf_pack(sizes + [(4, 4)] + [(a.shape[1], a.shape[0]) for _, (a, _) in extra], areas,
                        tuple(group.get("gap", (1, 1))))
    for pg, x0, y0, x1, y1 in clear:
        page(pg)[y0:y1, x0:x1] = 0
    rows = []
    for i, (lab, (mine, box)) in enumerate(zip(labels, old)):
        img, base = art[i]
        pg, x, y = placed[i]
        h, w = img.shape
        page(pg)[y:y + h, x:x + w] = img
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
