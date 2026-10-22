"""The letter shapes used to set English words: the MLB command font, the small tag font and system TrueType fonts.

Each "font" turns text into `ink`: a 2-D array of numbers 0 to 6 (0 = clear, 6 = full ink, the levels in between give
the letters a soft edge like the Japanese ones) plus the row the letters stand on (the baseline). Styles in
pp15/art/typeset.py then turn ink into palette colours. Nothing here knows about game files except `command_font`,
which cuts its letters out of an MLB Power Pros 2008 label sheet through pp15/art/labels.py.

  command_font(project)   cut the command words ("Practice", "Free Time", ...) and single letters out of the MLB sheet
  tag_font(project)       the small bold pixel font of the HUD tags, drawn from TAG_GLYPHS below
  ttf_ink(text, ...)      text drawn with a font installed on the Mac, anti-aliased down to ink levels
  FONTS                   name -> font function ("command", "tag", plus any a style module registers)
  TTF                     name -> (font file, index inside the file) for ttf_ink; style modules add more

The helper functions (sheet_ink, segment, clean, trim) and the constants keep the names and text they had in typeset.py
because tests/test_registry.py fingerprints the fonts by their byte code and the global names they read.
"""
import numpy as np
from PIL import Image, ImageDraw, ImageFont

from pp15.art import labels as L          # only mlb_texture and find_boxes are used; the name L is part of the font fingerprint
from pp15.art.pixel_ops import grow
from pp15.art.style_registry import OnDemandDict


# The 30 labels of the MLB sheet ScsComMain texture 0, in the reading order find_boxes() returns them.
COMMAND_WORDS = ["Progress", "Practice", "Free Time", "Boost", "Use", "Equip", "Data", "System",
                 "Weight", "TOP SPD", "Accuracy", "B.Ball", "Fielding", "Batting", "ARM STR", "Shop",
                 "Steak", "Hotdog", "SC", "Food", "Park", "Lake", "Mountains", "Lookout",
                 "Vicinage", "Hospital", "Street", "Run", "Yes", "No"]
# letter -> (word it is cut from, which occurrence of the letter in that word). Words are set from single letters
# when MLB did not draw the whole word; the letters MLB never drew are derived (see DERIVED, G_ROWS).
COMMAND_GLYPHS = {
    "B": ("Boost", 0), "C": ("SC", 0), "D": ("Data", 0), "E": ("Equip", 0), "F": ("Food", 0),
    "H": ("Hotdog", 0), "L": ("Lake", 0), "N": ("No", 0), "P": ("Park", 0), "R": ("Run", 0),
    "S": ("Shop", 0), "T": ("Free Time", 0), "U": ("Use", 0), "W": ("Weight", 0), "Y": ("Yes", 0),
    "a": ("Lake", 0), "c": ("Practice", 0), "d": ("Food", 0), "e": ("Lake", 0), "g": ("Hotdog", 0),
    "h": ("Shop", 0), "i": ("Equip", 0), "k": ("Park", 0), "l": ("Fielding", 0), "m": ("System", 0),
    "n": ("Run", 0), "o": ("Boost", 0), "p": ("Shop", 0), "q": ("Equip", 0), "r": ("Practice", 0),
    "s": ("Use", 0), "t": ("Boost", 0), "u": ("Run", 0), "y": ("System", 0),
}
# how the letters that are missing from the sheet are made (documentation of command_font; not read by code)
DERIVED = {"G": "C of 'SC' with a crossbar", "I": "the l of 'Fielding'",
           "J": "U of 'Use' without the top of its left stem", "b": "d of 'Food' mirrored"}
# rows 7..12 of the derived capital G, one character per ink level ("." = clear), replacing those of the C it starts from
G_ROWS = {7: "5561.35553", 8: "5561.35565", 9: "5661...265", 10: "4662..1565", 11: "266522565.",
          12: ".5666664.."}


def sheet_ink(idx: np.ndarray) -> np.ndarray:
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


def segment(ink: np.ndarray, n: int, minw: int = 2, maxw: int = 12) -> list:
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


def clean(ink: np.ndarray) -> np.ndarray:
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


# (ink cropped to its bounding box, first inked row, one past the last inked row). Comment, not docstring: this
# function's text is part of the font fingerprint.
def trim(ink: np.ndarray) -> tuple:
    ys, xs = np.nonzero(ink)
    return ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1], ys.min(), ys.max() + 1


# font name -> the font once built (the command font is cut from a game file, so it is made only once)
_fonts = {}


def command_font(project: str = None) -> dict:
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
# rows by which these letters hang below the baseline
TAG_DROP = {"y": 3, "g": 3, "p": 3, "q": 3, "j": 2}


# {"words": {}, "glyphs": {letter: (ink, rows below the baseline)}, "space": 3, "gap": 1}: built from TAG_GLYPHS, where
# "." is clear, "+" a half-tone corner pixel and "#" solid ink. No docstring, because it is part of the font fingerprint.
def tag_font(project: str = None) -> dict:
    if "tag" not in _fonts:
        level = {".": 0, "+": 3, "#": 6}
        _fonts["tag"] = {"words": {}, "space": 3, "gap": 1, "glyphs": {
            ch: (np.array([[level[c] for c in row] for row in rows]), TAG_DROP.get(ch, 0))
            for ch, rows in TAG_GLYPHS.items()}}
    return _fonts["tag"]



# Fonts installed with macOS, for lettering larger than the tag font (a drawn pixel font would look coarse next to the
# Japanese). name -> (file, index of the face inside a .ttc collection). Style modules add their own entries.
TTF = OnDemandDict({"rounded": ("/System/Library/Fonts/Supplemental/Arial Rounded Bold.ttf", 0),
       "narrow": ("/System/Library/Fonts/Supplemental/Arial Narrow Bold.ttf", 0),
       "black": ("/System/Library/Fonts/Supplemental/Arial Black.ttf", 0),
       "serif-italic": ("/System/Library/Fonts/Supplemental/Times New Roman Bold Italic.ttf", 0),
       "sans-italic": ("/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf", 0),
       "gothic": ("/System/Library/Fonts/ヒラギノ角ゴシック W6.ttc", 0)})     # symbols Arial lacks (★)
_faces = {}                    # (face name, capital height, oversampling) -> loaded PIL font, sized once

INK_LEVELS = 6                 # ink runs 0 (clear) to 6 (solid), the scale every font and style shares
PROBE_SIZE = 400               # point size used to measure how tall a capital H is, to size a face by capital height
PAD = 4                        # clear pixels (before oversampling) left round the drawn text


def ttf_ink(text: str, face: str = "rounded", cap: int = 14, slant: float = 0.0, squeeze: float = 1.0,
            bold: float = 0.0, over: int = 4) -> tuple:
    """(ink, baseline row) of text drawn with a system font: capitals `cap` pixels high, sheared by
    `slant` (0.2 = italic), widths scaled by `squeeze`, strokes thickened by `bold` pixels a side.
    Drawn `over` times too large and averaged down, which gives the 6 ink levels of a soft edge.

    Returns (ink array, rows from the top of the ink to the baseline). Needs the font file named in TTF[face]."""
    path, index = TTF[face]
    key = (face, cap, over)
    if key not in _faces:
        probe = ImageFont.truetype(path, PROBE_SIZE, index=index)
        top, bottom = probe.getbbox("H")[1], probe.getbbox("H")[3]
        _faces[key] = ImageFont.truetype(path, round(PROBE_SIZE * cap * over / (bottom - top)), index=index)
    font = _faces[key]
    l, t, r, b = font.getbbox(text, anchor="ls")                 # relative to the baseline
    pad = PAD * over
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
    ink = np.rint(small * INK_LEVELS / 255).astype(int)
    ys, xs = np.nonzero(ink)
    base = h_up // over
    return ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


def art_ink(art: dict, project=None) -> tuple:
    """(ink, baseline row) of lettering cut from an MLB sheet: {"pack", "tex", "box", "style", "role"}.
    The pixels of one role (see pp15.art.labels.SOURCE_STYLES) become full ink."""
    mask, cls = L.source_classes(dict(art, drop=[r for r in ("fill", "ring", "outer", "letter", "plate",
                                                         "edge_dark", "edge_light")
                                               if r != art.get("role", "fill")]), project)
    grid = L.despeckle(mask.astype(int))
    ink = np.where(grid > 0, 6, 0)
    ys, xs = np.nonzero(ink)
    ink = ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    return ink, art.get("base", ink.shape[0])


# name -> function(project) returning {"words", "glyphs", "space", "gap"}; style modules add fonts of their own
FONTS = OnDemandDict({"command": command_font, "tag": tag_font})
