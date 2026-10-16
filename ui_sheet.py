#!/usr/bin/env python3
"""Lettering painted into a picture that is cut over several pages (the Success bench sheets, scs_main.arc
z4_sod_*: one 512x360 picture on 12 compressed 8-bit pages, headings on gradients running across page edges).

A spec's "sheet" entries (read by ui_labels.render):
  {"pages": "tex_z4_sodk",          the bank whose first page name starts so (two banks may share a name)
   "cols": 4,                        page n of the bank sits at (128 * (n % cols), 128 * (n // cols))
   "items": [{"box": [x0, y0, x1, y1],   picture pixels rebuilt (end exclusive)
              "bg": "rows",               background: per row, from the pixel left of the box to the one right of
                                          it ("cols": per column, above to below; "mode": the commonest colour
                                          of the box, for a flat cell; "keep": leave it;
                                          "clear_ends": true keeps rows with transparent ends transparent)
              "text": "Bullpen", "font": "ttf:...", "centre": [x, y] (default: the middle of the box),
              "colour": "#203040",        letter colour; the ink levels blend it into what is behind
                                          ("crisp": true draws solid letters, which pack smaller)
              "rings": ["#ffffff"],       solid rings round the letters, innermost first (optional)
              "shadow": ["#7090b0", 1, 1]}]}   one copy of the letters and rings behind them, moved (optional)
Colours are taken to the nearest colour the picture already uses, so nothing outside its palette appears.
The pages go back into the file as byte patches; a page that no longer fits its compressed slot is an error.

  ui_sheet.py preview SPEC.json OUT.png [PAGES]   the pictures of the spec's sheets, before and after"""
import json, os, sys
import numpy as np
import ui_textures as U
import ui_type

PAGE = U.PAGE
ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def bank_by_pages(banks, prefix):
    return next(b for b in banks if b.get("page_names") and b["page_names"][0].startswith(prefix))


def canvas(d, b, cols):
    n = len(b["pages"])
    rows = (n + cols - 1) // cols
    big = np.zeros((rows * PAGE, cols * PAGE), np.uint8)
    for k, pg in enumerate(b["pages"]):
        big[(k // cols) * PAGE:(k // cols + 1) * PAGE, (k % cols) * PAGE:(k % cols + 1) * PAGE] = U.decode_indices(d, *pg)
    return big


def rgb(h):
    h = h.lstrip("#")
    return np.array([int(h[i:i + 2], 16) for i in (0, 2, 4)], float)


def nearest(colours, allowed):
    """Index map function: RGB array (..., 3) -> nearest palette index among `allowed`."""
    pal = colours[allowed].astype(float)
    def q(a):
        flat = a.reshape(-1, 3)
        dist = ((flat[:, None, :] - pal[None, :, :]) ** 2).sum(-1)
        return np.asarray(allowed)[dist.argmin(1)].reshape(a.shape[:-1]).astype(np.uint8)
    return q


def draw(item, img, project=None):
    """Paint one item into the RGB picture `img` (H, W, 3 floats)."""
    x0, y0, x1, y1 = item["box"]
    bg = item.get("bg", "rows")
    if bg == "rows":
        a, b = img[y0:y1, x0 - 1], img[y0:y1, x1]
        t = (np.arange(x1 - x0) + 1)[None, :, None] / (x1 - x0 + 1)
        img[y0:y1, x0:x1] = a[:, None, :] * (1 - t) + b[:, None, :] * t
    elif bg == "mode":                                   # a flat cell: its commonest colour
        cols, n = np.unique(img[y0:y1, x0:x1].reshape(-1, 3), axis=0, return_counts=True)
        img[y0:y1, x0:x1] = cols[n.argmax()]
    elif bg == "cols":
        a, b = img[y0 - 1, x0:x1], img[y1, x0:x1]
        t = (np.arange(y1 - y0) + 1)[:, None, None] / (y1 - y0 + 1)
        img[y0:y1, x0:x1] = a[None, :, :] * (1 - t) + b[None, :, :] * t
    if not item.get("text"):
        return
    ink, base = ui_type.typeset(item["text"], item["font"], project)
    rings = item.get("rings", [])
    sh = item.get("shadow")
    pad = len(rings) + (max(abs(sh[1]), abs(sh[2])) if sh else 0) + 1
    h, w = ink.shape
    level = np.zeros((h + 2 * pad, w + 2 * pad))
    level[pad:pad + h, pad:pad + w] = ink / max(1, ink.max())
    letters = level > 0
    masks, m = [], letters
    for k in range(len(rings)):
        m = ui_type.grow(m, 1, diagonal=(k == 0))
        masks.append(m)
    body = masks[-1] if masks else letters
    cx, cy = item.get("centre", ((x0 + x1) // 2, (y0 + y1) // 2))
    top, left = cy - level.shape[0] // 2, cx - level.shape[1] // 2
    area = img[top:top + level.shape[0], left:left + level.shape[1]]
    if area.shape[:2] != level.shape:
        raise ValueError("%r runs off the picture" % item["text"])
    if sh:
        s = ui_type.shift(body, sh[2], sh[1])
        area[s] = rgb(sh[0])
    for mk, c in zip(masks[::-1], rings[::-1]):
        area[mk] = rgb(c)
    col = rgb(item["colour"])
    if rings or item.get("crisp"):                      # solid letters (packs smaller on a compressed page)
        a = np.where(level >= (0.5 if item.get("crisp") else 0.01), 1.0, 0.0)[..., None]
    else:
        a = level[..., None]
    area[:] = area * (1 - a) + col * a


def paint(entry, d, banks, patches, project=None, pictures=None, pages=None):
    """pages: ui_labels.render's {(bank name, page): index array} of pages already redrawn (repack groups): painted on
    top of those and written back there, so a page is never patched twice (the later patch would undo the other)."""
    b = bank_by_pages(banks, entry["pages"])
    cols = entry.get("cols", 4)
    idx = canvas(d, b, cols)
    mine = {}
    for (name, k), arr in (pages or {}).items():
        if U.bank_named(banks, name) is b:
            mine[k] = name
            idx[(k // cols) * PAGE:(k // cols + 1) * PAGE, (k % cols) * PAGE:(k % cols + 1) * PAGE] = arr
    colours = U.palette_colours(d, b["pal"])[:256, :3].astype(float)
    used = sorted(set(np.unique(idx).tolist()) - {0, 1, 2})
    img = colours[idx].copy()
    new = idx.copy()
    q = nearest(colours, used)
    for item in entry["items"]:
        before = img.copy()
        draw(item, img, project)
        changed = np.abs(img - before).sum(-1) > 0
        x0, y0, x1, y1 = item["box"]
        if item.get("bg", "rows") != "keep":
            changed[y0:y1, x0:x1] = True                   # the rebuilt background, even where it matched
        if not changed.any():
            continue
        ys, xs = np.nonzero(changed)
        r = (slice(ys.min(), ys.max() + 1), slice(xs.min(), xs.max() + 1))
        sub = q(img[r])
        new[r] = np.where(changed[r], sub, new[r])
        if item.get("clear_ends"):                         # rows with nothing either side of the box stay transparent
            for y in range(y0, y1):
                if idx[y, x0 - 1] == 0 and idx[y, x1] == 0:
                    new[y, x0:x1] = 0
        img[r] = colours[new[r]]
    if pictures is not None:
        pictures.append((entry["pages"], colours[idx], colours[new]))
    for k, (off, size) in enumerate(b["pages"]):
        ry, rx = (k // cols) * PAGE, (k % cols) * PAGE
        page = new[ry:ry + PAGE, rx:rx + PAGE]
        if k in mine:
            pages[(mine[k], k)] = page.copy()
            continue
        if not np.array_equal(page, idx[ry:ry + PAGE, rx:rx + PAGE]):
            try:
                patches.append((off, U.encode_indices(page, size, U.page_bits(d, off, size))))
            except ValueError as e:
                raise ValueError("%s page %d: %s" % (entry["pages"], k, e))


def main():
    a = sys.argv[1:]
    if a[:1] != ["preview"] or len(a) < 3:
        sys.exit(__doc__)
    import ui_labels as L
    from PIL import Image
    spec = L.load_spec(a[1])
    d = open(spec["source"], "rb").read()
    banks = U.banks(d, U.elf_symbols(d))
    pics = []
    for entry in spec.get("sheet", ()):
        if len(a) > 3 and entry["pages"] not in a[3:]:
            continue
        paint(entry, d, banks, [], spec.get("project"), pics)
    rows = [np.concatenate([o[:360], n[:360]], 1) for _, o, n in pics]
    Image.fromarray(np.concatenate(rows, 0).astype(np.uint8)).save(a[2])
    print(a[2], len(pics))


if __name__ == "__main__":
    main()
