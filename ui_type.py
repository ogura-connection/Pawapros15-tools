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

Repacking: an English word is wider than the Japanese label it replaces (練習 is two characters), so the
labels of a page are laid out again at their natural width inside the areas named in the spec, and the
sprite parts that showed the old rectangles are pointed at the new ones (page, rectangle and offset
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
    "n": ("Run", 0), "o": ("Boost", 0), "p": ("Shop", 0), "q": ("Equip", 0), "r": ("Park", 0),
    "s": ("Use", 0), "t": ("Boost", 0), "u": ("Run", 0), "y": ("System", 0),
}
DERIVED = {"G": "C of 'SC' with a crossbar", "I": "the l of 'Fielding'"}
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
    """Drop stray pixels: pieces (8-way) of at most 3 pixels that never reach ink level 5."""
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
        if len(pts) <= 3 and max(ink[p] for p in pts) < 5:
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
    _fonts["command"] = {"words": words, "glyphs": glyphs, "space": 4, "gap": 1}
    return _fonts["command"]


FONTS = {"command": command_font}


def typeset(text, font="command", project=None):
    """(ink, baseline row) of a word or phrase. A phrase that MLB drew is returned as drawn."""
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


RENDER = {"command": style_command}


# ── Repacking ────────────────────────────────────────────────────────────────────────────

def art_box(page, rect):
    """Bounding box (x0, y0, x1, y1) of the pixels inside a rectangle, in page coordinates."""
    x0, y0, x1, y1 = rect
    ys, xs = np.nonzero(page[y0:y1, x0:x1])
    return x0 + xs.min(), y0 + ys.min(), x0 + xs.max() + 1, y0 + ys.max() + 1


def shelf_pack(sizes, areas):
    """Place (w, h) boxes into areas [(page, x0, y0, x1, y1)]: {index: (page, x, y)}. Shelves are as
    high as the tallest box; widest boxes first."""
    height = max(h for _, h in sizes)
    shelves = []
    for page, x0, y0, x1, y1 in areas:
        for y in range(y0, y1 - height + 1, height):
            shelves.append([page, x0, y, x1])
    placed = {}
    for i in sorted(range(len(sizes)), key=lambda i: -sizes[i][0]):
        w, _ = sizes[i]
        fits = [s for s in shelves if s[3] - s[1] >= w]
        if not fits:
            raise ValueError("no room for a label %d pixels wide" % w)
        s = min(fits, key=lambda s: s[3] - s[1])                # tightest shelf
        placed[i] = (s[0], s[1], s[2])
        s[1] += w
    return placed


def repack(group, d, bank, pages, patches, project=None):
    """Lay out the labels of one repack group. `pages` {page: index array} are edited in place;
    `patches` collects (file offset, 10 bytes) for the sprite parts. Returns report rows."""
    areas = [tuple(a) for a in group["areas"]]
    style = RENDER[group.get("style", "command")]
    font = group.get("font", "command")
    for p in {a[0] for a in areas}:
        if p not in pages:
            pages[p] = U.decode_indices(d, *bank["pages"][p]).copy()
    parts = [p for ps in bank["sprites"].values() for p in ps]
    labels = group["labels"]
    old = {}
    for i, lab in enumerate(labels):
        page, x0, y0, x1, y1 = lab["from"]
        old[i] = (page, (x0, y0, x1, y1), art_box(pages[page], (x0, y0, x1, y1)))

    def inside(page, x0, y0, x1, y1):
        return any(a[0] == page and a[1] <= x0 and a[2] <= y0 and x1 <= a[3] and y1 <= a[4] for a in areas)

    def touches(page, x0, y0, x1, y1):
        return any(a[0] == page and x0 < a[3] and a[1] < x1 and y0 < a[4] and a[2] < y1 for a in areas)

    froms = {(o[0],) + o[1] for o in old.values()}
    for i, (page, rect, _) in old.items():
        if not inside(page, *rect):
            raise ValueError("label %r is not inside the repack areas" % labels[i].get("text"))
    for p in parts:                                              # nothing else may live in the areas
        if touches(p.page, p.x0, p.y0, p.x1, p.y1) and (p.page, p.x0, p.y0, p.x1, p.y1) not in froms:
            raise ValueError("sprite %s uses x %d-%d y %d-%d of page %d, inside a repack area"
                             % (p.sprite, p.x0, p.x1, p.y0, p.y1, p.page))
    art = []
    for i, lab in enumerate(labels):
        if "text" in lab:
            ink, base = typeset(lab["text"], font, project)
            art.append(style(ink, base))
        else:                                                    # keep the Japanese label as it is
            page, rect, (ax0, ay0, ax1, ay1) = old[i]
            art.append((pages[page][ay0:ay1, ax0:ax1].copy(), None))
    height = max(a.shape[0] for a, _ in art)
    placed = shelf_pack([(a.shape[1], height) for a, _ in art], areas)
    for page, x0, y0, x1, y1 in areas:
        pages[page][y0:y1, x0:x1] = 0
    rows = []
    for i, lab in enumerate(labels):
        img, base = art[i]
        page, x, y = placed[i]
        h, w = img.shape
        pages[page][y:y + h, x:x + w] = img
        opage, (ox0, oy0, ox1, oy1), (ax0, ay0, ax1, ay1) = old[i]
        dx = (ax0 + ax1) // 2 - ox0 - w // 2                      # keep the horizontal centre
        dy = (ay1 - 4 - oy0 - base) if base is not None else ay0 - oy0   # sit on the old baseline
        n = 0
        for p in parts:
            if (p.page, p.x0, p.y0, p.x1, p.y1) == (opage, ox0, oy0, ox1, oy1):
                patches.append((p.offset, U.pack_part(page, p.flags, p.palette, p.y + dy, p.x + dx,
                                                      y, x, y + h, x + w)))
                n += 1
        rows.append((lab.get("text", "(kept)"), "%dx%d" % (ax1 - ax0, ay1 - ay0), "%dx%d" % (w, h),
                     "page %d x %d y %d" % (page, x, y), n))
    return rows
