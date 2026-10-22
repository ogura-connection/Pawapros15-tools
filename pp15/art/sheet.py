"""Paint English lettering into a picture that is cut over several pages (the Success bench sheets, scs_main.arc
z4_sod_*: one 512x360 picture on 12 compressed 8-bit pages, headings on gradients running across page edges).

A spec's "sheet" entries (read by pp15/art/spec_render.py):
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

  pp15 sheet preview SPEC.json OUT.png [PAGES ...]   the pictures of the spec's sheets, before and after

  paint(entry, d, banks, patches, project, pictures, pages)   draw one "sheet" entry; the pages go to `patches`
  canvas(d, bank, cols)                                       the whole picture of a bank as one index array
  draw(item, img, project)                                    paint one item into an RGB picture
"""
import argparse
import sys

import numpy as np
from PIL import Image

from pp15.art import textures
from pp15.art.spec_io import load_spec
from pp15.art.typeset import TTF, grow, shift, typeset

PAGE = textures.PAGE
PREVIEW_ROWS = 360        # rows of the picture shown in a preview (the bench sheets are 512 x 360)
TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))      # the font the headings use


def bank_by_pages(banks: list, prefix: str) -> dict:
    """The bank whose first page name starts with `prefix` (two banks of a file may share a bank name)."""
    return next(b for b in banks if b.get("page_names") and b["page_names"][0].startswith(prefix))


def canvas(d: bytes, bank: dict, cols: int) -> np.ndarray:
    """The whole picture of a bank: its pages laid out `cols` to a row, as one array of palette indices."""
    rows = (len(bank["pages"]) + cols - 1) // cols
    big = np.zeros((rows * PAGE, cols * PAGE), np.uint8)
    for k, pg in enumerate(bank["pages"]):
        big[(k // cols) * PAGE:(k // cols + 1) * PAGE, (k % cols) * PAGE:(k % cols + 1) * PAGE] = textures.decode_indices(d, *pg)
    return big


def hex_to_rgb(h: str) -> np.ndarray:
    """'#rrggbb' -> array of three floats 0..255."""
    h = h.lstrip("#")
    return np.array([int(h[i:i + 2], 16) for i in (0, 2, 4)], float)


def nearest(colours: np.ndarray, allowed: list):
    """A function that maps an RGB array (..., 3) to the index of the nearest colour among the palette entries `allowed`."""
    pal = colours[allowed].astype(float)

    def to_index(rgb):
        flat = rgb.reshape(-1, 3)
        dist = ((flat[:, None, :] - pal[None, :, :]) ** 2).sum(-1)
        return np.asarray(allowed)[dist.argmin(1)].reshape(rgb.shape[:-1]).astype(np.uint8)
    return to_index


def _rebuild_background(item: dict, img: np.ndarray) -> None:
    """Replace the pixels of item["box"] by a background that hides the old lettering. "bg" says how: "rows" blends
    from the pixel left of the box to the one right of it, row by row; "cols" does the same from above to below;
    "mode" fills the box with its commonest colour (a flat cell); "keep" leaves it."""
    x0, y0, x1, y1 = item["box"]
    bg = item.get("bg", "rows")
    if bg == "rows":
        left, right = img[y0:y1, x0 - 1], img[y0:y1, x1]
        t = (np.arange(x1 - x0) + 1)[None, :, None] / (x1 - x0 + 1)
        img[y0:y1, x0:x1] = left[:, None, :] * (1 - t) + right[:, None, :] * t
    elif bg == "mode":
        colours, counts = np.unique(img[y0:y1, x0:x1].reshape(-1, 3), axis=0, return_counts=True)
        img[y0:y1, x0:x1] = colours[counts.argmax()]
    elif bg == "cols":
        above, below = img[y0 - 1, x0:x1], img[y1, x0:x1]
        t = (np.arange(y1 - y0) + 1)[:, None, None] / (y1 - y0 + 1)
        img[y0:y1, x0:x1] = above[None, :, :] * (1 - t) + below[None, :, :] * t


def draw(item: dict, img: np.ndarray, project=None) -> None:
    """Paint one item into the RGB picture `img` (H, W, 3 floats): first its background, then its text with rings and a
    shadow if the item has them."""
    x0, y0, x1, y1 = item["box"]
    _rebuild_background(item, img)
    if not item.get("text"):
        return
    ink, base = typeset(item["text"], item["font"], project)
    rings = item.get("rings", [])
    shadow = item.get("shadow")                 # [colour, dx, dy]
    pad = len(rings) + (max(abs(shadow[1]), abs(shadow[2])) if shadow else 0) + 1
    h, w = ink.shape
    level = np.zeros((h + 2 * pad, w + 2 * pad))
    level[pad:pad + h, pad:pad + w] = ink / max(1, ink.max())
    letters = level > 0
    masks, grown = [], letters
    for k in range(len(rings)):
        grown = grow(grown, 1, diagonal=(k == 0))
        masks.append(grown)
    body = masks[-1] if masks else letters
    centre_x, centre_y = item.get("centre", ((x0 + x1) // 2, (y0 + y1) // 2))
    top, left = centre_y - level.shape[0] // 2, centre_x - level.shape[1] // 2
    area = img[top:top + level.shape[0], left:left + level.shape[1]]
    if area.shape[:2] != level.shape:
        raise ValueError("%r runs off the picture" % item["text"])
    if shadow:
        area[shift(body, shadow[2], shadow[1])] = hex_to_rgb(shadow[0])
    for mask, colour in zip(masks[::-1], rings[::-1]):
        area[mask] = hex_to_rgb(colour)
    if rings or item.get("crisp"):                      # solid letters (packs smaller on a compressed page)
        alpha = np.where(level >= (0.5 if item.get("crisp") else 0.01), 1.0, 0.0)[..., None]
    else:
        alpha = level[..., None]
    area[:] = area * (1 - alpha) + hex_to_rgb(item["colour"]) * alpha


def paint(entry: dict, d: bytes, banks: list, patches: list, project=None, pictures=None, pages=None) -> None:
    """Paint the items of one "sheet" entry into the picture of its bank and queue the changed pages as byte patches.

    patches   list that receives (file offset, page bytes); a page that no longer fits its compressed slot raises
    pictures  optional list that receives (entry["pages"], picture before, picture after) as RGB arrays, for previews
    pages     {(bank name, page): index array} of pages that repack groups already redrew: the sheet is painted on top
              of those and written back there, so a page is never patched twice (the later patch would undo the other)."""
    bank = bank_by_pages(banks, entry["pages"])
    cols = entry.get("cols", 4)
    idx = canvas(d, bank, cols)
    redrawn = {}                                    # page number -> bank name, for pages taken from `pages`
    for (name, k), arr in (pages or {}).items():
        if textures.bank_named(banks, name) is bank:
            redrawn[k] = name
            idx[(k // cols) * PAGE:(k // cols + 1) * PAGE, (k % cols) * PAGE:(k % cols + 1) * PAGE] = arr
    colours = textures.palette_colours(d, bank["pal"])[:256, :3].astype(float)
    used = sorted(set(np.unique(idx).tolist()) - {0, 1, 2})      # entries 0..2 are transparent / system colours
    img = colours[idx].copy()
    new = idx.copy()
    to_index = nearest(colours, used)
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
        region = (slice(ys.min(), ys.max() + 1), slice(xs.min(), xs.max() + 1))
        new[region] = np.where(changed[region], to_index(img[region]), new[region])
        if item.get("clear_ends"):                         # rows with nothing either side of the box stay transparent
            for y in range(y0, y1):
                if idx[y, x0 - 1] == 0 and idx[y, x1] == 0:
                    new[y, x0:x1] = 0
        img[region] = colours[new[region]]
    if pictures is not None:
        pictures.append((entry["pages"], colours[idx], colours[new]))
    for k, (off, size) in enumerate(bank["pages"]):
        row, col = (k // cols) * PAGE, (k % cols) * PAGE
        page = new[row:row + PAGE, col:col + PAGE]
        if k in redrawn:
            pages[(redrawn[k], k)] = page.copy()
            continue
        if not np.array_equal(page, idx[row:row + PAGE, col:col + PAGE]):
            try:
                patches.append((off, textures.encode_indices(page, size, textures.page_bits(d, off, size))))
            except ValueError as e:
                raise ValueError("%s page %d: %s" % (entry["pages"], k, e))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="pp15 sheet", description="Preview the pictures a spec's \"sheet\" entries paint.")
    sub = ap.add_subparsers(dest="command")
    p = sub.add_parser("preview", help="the pictures of the spec's sheets, before and after, side by side")
    p.add_argument("spec", help="a spec (specs/*.json) with \"sheet\" entries")
    p.add_argument("out", help="PNG file to write")
    p.add_argument("pages", nargs="*", metavar="PAGES", help="only the sheets whose \"pages\" prefix is listed")
    args = ap.parse_args(sys.argv[1:] if argv is None else list(argv))
    if args.command != "preview":
        ap.print_help()
        return
    spec = load_spec(args.spec)
    with open(spec["source"], "rb") as f:
        d = f.read()
    banks = textures.banks(d, textures.elf_symbols(d))
    pics = []
    for entry in spec.get("sheet", ()):
        if args.pages and entry["pages"] not in args.pages:
            continue
        paint(entry, d, banks, [], spec.get("project"), pics)
    rows = [np.concatenate([o[:PREVIEW_ROWS], n[:PREVIEW_ROWS]], 1) for _, o, n in pics]
    Image.fromarray(np.concatenate(rows, 0).astype(np.uint8)).save(args.out)
    print(args.out, len(pics))


if __name__ == "__main__":
    main()
