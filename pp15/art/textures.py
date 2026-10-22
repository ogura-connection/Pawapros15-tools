"""Read, export and write back the picture pages of the Pawapuro 15 menu screens (the .arc files).

Almost all painted menu lettering of the game lives in .arc files. This module is the command line tool for looking at
them and the place the other art tools import the page and bank functions from; the code that parses and decodes them is
split over pp15/art/arc_banks.py (symbols, banks, sprite parts) and pp15/art/page_codec.py (page bytes).

  pp15 textures export [OUT_DIR]     one sheet per .arc in OUT_DIR (default _work/ui_scan), plus pages.tsv
  pp15 textures parts ARC [BANK [PAGE]]   sprite parts (screen offset and page rectangle) of a bank
  pp15 textures page ARC BANK PAGE OUT.png [PALETTE]   one page as RGBA with its palette
  pp15 textures import ARC BANK PAGE IMAGE.png [PALETTE]   write a 128x128 page back, same offset and size
  pp15 textures check [ARC ...]      round trip: every page decoded, re-encoded and compared (no files written);
                                      the compressed pages of the named files are also packed again (slow)

The .arc files are ELF objects. Their .data holds sprite banks, named by symbol:
  tex_<bank>NN     texture page: 8,192 bytes = 128x128, 4 bits per pixel (GX C4, 8x8 tiles), or
                   16,384 bytes = 128x128, 8 bits per pixel (GX C8, 8x4 tiles). Any other size is a
                   compressed page (see page_codec.decompress_page): the same 128x128 picture, stored row by
                   row and packed with the rectangle code the font glyphs use.
  pal_<bank>       RGB5A3 colours, 16 per palette for the 4-bit pages
  opd_<bank>_NN    one sprite: a 10-byte header (byte 0 = number of parts) followed by that many
                   10-byte parts: page (bit 7 = mirrored, bit 6 = another flag), palette,
                   offset on screen from the sprite's anchor (y, x as s16), then the
                   rectangle on the page as rows y0 to y1 and columns x0 to x1 (byte order y0, x0, y1, x1).
                   Page numbers count the tex_ symbols of the bank in file order (the numbers in
                   the symbol names can start at 1).
Each page is drawn with the palette that most of its sprite parts use, so a page shared by
differently coloured sprites shows only one of the colourings.
Import quantises an image to the 16 colours of one palette; pixels that already equal the
decoded original keep their original index, so an unchanged page re-encodes byte for byte.
The sheets are game data: they go to _work/ (git-ignored).

Functions other modules use (they live in the modules named above and are importable from here):
  Part, banks, bank_named, split_merged, elf_symbols, pack_part, palette_colours, decode_indices, encode_indices, page_bits, raw_size,
  compress_page, PAGE.
Defined here: page_colours, page_image, page_palette_use, quantise, import_page, sprite_image, backup_orig, ORIG_ARC_DIR.
"""
import argparse
import collections
import glob
import os
import shutil
import sys

import numpy as np
from PIL import Image

from pp15 import config
# Imported so that `textures.banks`, `textures.decode_indices`, ... keep working for the style modules and other tools.
from pp15.art.arc_banks import Part, bank_named, banks, elf_symbols, pack_part, palette_colours, split_merged
from pp15.art.page_codec import (PAGE, RAW_SIZE_4BIT, compress_page, decode_indices, decompress_page, encode_indices,
                                 is_compressed, page_bits, raw_size)

# The style modules read `textures.S.DATA_FILES` (they were written when this name was the scan module). config has the
# same attribute, so the name keeps working whether or not pp15.script.scan still re-exports DATA_FILES.
S = config

ORIG_ARC_DIR = config.ORIG_ARC_DIR      # not _work/orig: pp15/build/rebuild.py installs that whole folder
SHEET_COLUMNS = 8                       # pages per row of an exported contact sheet
SHEET_BACKGROUND = (70, 70, 70, 255)


def page_colours(pal: np.ndarray, index: int, size: int) -> np.ndarray:
    """The colours a page is drawn with: 16 entries of palette number `index` (4-bit pages), or for an 8-bit page
    the 256 entries starting at 16 x `index` (the game loads the colour table from there; seen on scc_tops.arc
    y5_tic and gameplay.arc pages). Entries past the end of the table are transparent.
    `size` is the unpacked size (raw_size): 8192 for any 4-bit page."""
    if size == RAW_SIZE_4BIT:
        colours = pal[index * 16:index * 16 + 16]
        return colours if len(colours) == 16 else pal[:16]
    colours = pal[index * 16:index * 16 + 256]
    if len(colours) < 256:
        colours = np.concatenate([colours, np.zeros((256 - len(colours), 4), np.uint8)])
    return colours


def page_image(d: bytes, off: int, size: int, pal: np.ndarray, index: int) -> Image.Image:
    """A page as an RGBA picture, in palette number `index`. If the palette is too short for the page's indices, the
    page is shown in greys instead."""
    idx = decode_indices(d, off, size)
    colours = page_colours(pal, index, raw_size(d, off, size))
    if len(colours) <= int(idx.max()):
        grey = (np.arange(256) * (255 // max(1, int(idx.max())))).clip(0, 255).astype(np.uint8)
        colours = np.stack([grey, grey, grey, np.full(256, 255, np.uint8)], -1)
    return Image.fromarray(np.ascontiguousarray(colours[idx]), "RGBA")


def page_palette_use(bank: dict) -> dict:
    """{page: Counter of palette numbers} over every sprite part of the bank."""
    use = collections.defaultdict(collections.Counter)
    for parts in bank["sprites"].values():
        for p in parts:
            use[p.page][p.palette] += 1
    return use


def commonest_palette(use: collections.Counter) -> int:
    """The palette number most sprite parts of a page use (0 for a page no sprite shows)."""
    return use.most_common(1)[0][0] if use else 0


def sprite_image(d: bytes, bank: dict, parts: list, bg: tuple = (96, 96, 96, 255), only=None) -> Image.Image:
    """One sprite as an RGBA picture: its parts (a list of Part) drawn at their screen offsets on a `bg` background,
    mirrored where the part's flags say so. `only` = indices of the parts to draw (default: all)."""
    pal = palette_colours(d, bank["pal"])
    x0 = min(p.x for p in parts)
    y0 = min(p.y for p in parts)
    x1 = max(p.x + p.x1 - p.x0 for p in parts)
    y1 = max(p.y + p.y1 - p.y0 for p in parts)
    im = Image.new("RGBA", (x1 - x0, y1 - y0), bg)
    cache = {}
    for k, p in enumerate(parts):
        if only is not None and k not in only:
            continue
        if p.page not in cache:
            cache[p.page] = decode_indices(d, *bank["pages"][p.page])
        idx = cache[p.page][p.y0:p.y1, p.x0:p.x1]
        col = page_colours(pal, p.palette, raw_size(d, *bank["pages"][p.page]))[idx]      # 4-bit or 8-bit page
        t = Image.fromarray(np.ascontiguousarray(col), "RGBA")
        if p.flags & 0x80:
            t = t.transpose(Image.FLIP_LEFT_RIGHT)
        if p.flags & 0x40:
            t = t.transpose(Image.FLIP_TOP_BOTTOM)
        im.alpha_composite(t, (p.x - x0, p.y - y0))
    return im


def quantise(image: Image.Image, colours: np.ndarray, keep=None) -> np.ndarray:
    """Indices of the entries of `colours` (n, 4) nearest to each pixel of an RGBA image.
    Where `keep` = (decoded original RGBA, original indices) and the pixel is unchanged, the original
    index is kept. Transparent pixels (alpha < 128) go to the most transparent entry."""
    px = np.asarray(image.convert("RGBA"), dtype=np.int32)
    pal = colours.astype(np.int32)
    ca, pa = px[..., 3:4], pal[None, None, :, 3]
    rgb = ((px[..., None, :3] - pal[None, None, :, :3]) ** 2).sum(-1)
    cost = rgb * np.minimum(ca, pa) // 255 + 3 * (ca - pa) ** 2
    out = cost.argmin(-1).astype(np.uint8)
    clear = px[..., 3] < 128
    if clear.any():
        out[clear] = int(np.argmin(pal[:, 3]))
    if keep is not None:
        same = (px == keep[0].astype(np.int32)).all(-1)
        out[same] = keep[1][same]
    return out


def import_page(d: bytes, off: int, size: int, image: Image.Image, colours: np.ndarray) -> bytes:
    """The .arc bytes with the page at (off, size) replaced by `image` (128x128)."""
    if image.size != (PAGE, PAGE):
        raise ValueError("page images are %dx%d, got %dx%d" % ((PAGE, PAGE) + image.size))
    old = decode_indices(d, off, size)
    new = quantise(image, colours, (colours[old.clip(max=len(colours) - 1)], old))
    return d[:off] + encode_indices(new, size, page_bits(d, off, size)) + d[off + size:]


def backup_orig(path: str) -> None:
    """Keep the first, untouched copy of an .arc of DATA/files in ORIG_ARC_DIR before it is written to.
    Files outside DATA/files are not backed up; an existing backup is never overwritten."""
    if os.path.dirname(os.path.abspath(path)) != os.path.abspath(config.DATA_FILES):
        return
    os.makedirs(ORIG_ARC_DIR, exist_ok=True)
    dst = os.path.join(ORIG_ARC_DIR, os.path.basename(path))
    if not os.path.exists(dst):
        shutil.copy2(path, dst)


def restore_orig(arc: str) -> bool:
    """Copy the saved original of an .arc back over DATA/files/<arc>. False if no original was saved."""
    src = os.path.join(ORIG_ARC_DIR, os.path.basename(arc))
    if not os.path.exists(src):
        return False
    shutil.copy2(src, os.path.join(config.DATA_FILES, os.path.basename(arc)))
    return True


# ── Command line ─────────────────────────────────────────────────────────────────────────

def _arc_path(arc: str) -> str:
    """The file a command-line ARC argument names: a path that exists, else DATA/files/<arc>."""
    return arc if os.path.exists(arc) else os.path.join(config.DATA_FILES, arc)


def _read_arc(arc: str) -> bytes:
    with open(_arc_path(arc), "rb") as f:
        return f.read()


def find_page(arc: str, bank: str, page: int) -> tuple:
    """(file bytes, path, bank dict, (offset, size)) for a page of DATA/files/<arc>. Exits if the bank is missing."""
    path = _arc_path(arc)
    with open(path, "rb") as f:
        d = f.read()
    for b in banks(d, elf_symbols(d)):
        if b["name"] == bank:
            return d, path, b, b["pages"][page]
    sys.exit("no bank %s in %s" % (bank, arc))


def cmd_export(out_dir: str) -> None:
    """Write one contact sheet PNG per .arc of DATA/files and a pages.tsv that says where each page sits on it."""
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for path in sorted(glob.glob(os.path.join(config.DATA_FILES, "*.arc"))):
        with open(path, "rb") as f:
            d = f.read()
        images = []
        for b in banks(d, elf_symbols(d)):
            pal = palette_colours(d, b["pal"])
            use = page_palette_use(b)
            for n, (off, size) in enumerate(b["pages"]):
                index = commonest_palette(use[n])
                try:
                    images.append(page_image(d, off, size, pal, index))
                except ValueError:                  # a few 16,400-byte pages are in another format
                    continue
                rows.append((os.path.basename(path), b["name"], n, size, index, sum(use[n].values()),
                             len(images) - 1))
        if images:
            cols = SHEET_COLUMNS
            sheet = Image.new("RGBA", (PAGE * cols, PAGE * ((len(images) + cols - 1) // cols)), SHEET_BACKGROUND)
            for k, im in enumerate(images):
                sheet.alpha_composite(im, ((k % cols) * PAGE, (k // cols) * PAGE))
            sheet.convert("RGB").save(os.path.join(out_dir, os.path.basename(path)[:-4] + ".png"))
    with open(os.path.join(out_dir, "pages.tsv"), "w") as f:
        f.write("arc\tbank\tpage\tbytes\tpalette\tsprite parts\tposition on the sheet\n")
        for r in rows:
            f.write("%s\t%s\t%d\t%d\t%d\t%d\t%d\n" % r)
    print("%d pages from %d files -> %s" % (len(rows), len({r[0] for r in rows}), out_dir))


def cmd_parts(arc: str, bank: str = None, page: int = None) -> None:
    """Print the banks of an .arc; with a bank name also its sprite parts (optionally only those on one page)."""
    d = _read_arc(arc)
    for b in banks(d, elf_symbols(d)):
        if bank is not None and b["name"] != bank:
            continue
        print("bank %s: %d pages %s, %d sprites" % (
            b["name"], len(b["pages"]), [s for _, s in b["pages"]], len(b["sprites"])))
        if bank is None:
            continue
        for name, parts in b["sprites"].items():
            for p in parts:
                if page is not None and p.page != page:
                    continue
                print("%s page %d%s pal %d at (%d,%d) rect x %d-%d y %d-%d (%dx%d)" % (
                    name[4:], p.page, " flags %02x" % p.flags if p.flags else "", p.palette, p.x, p.y,
                    p.x0, p.x1, p.y0, p.y1, p.x1 - p.x0, p.y1 - p.y0))


def cmd_page(arc: str, bank: str, page: int, out: str, palette: int = None) -> None:
    """Save one page as a PNG, drawn with palette number `palette` (default: the one most sprite parts use)."""
    d, _, b, (off, size) = find_page(arc, bank, page)
    pal = palette_colours(d, b["pal"])
    index = palette if palette is not None else commonest_palette(page_palette_use(b)[page])
    page_image(d, off, size, pal, index).save(out)


def cmd_import(arc: str, bank: str, page: int, image: str, palette: int = None) -> None:
    """Replace a 4-bit page of DATA/files/<arc> with a 128x128 PNG (the original is saved first)."""
    d, path, b, (off, size) = find_page(arc, bank, page)
    if page_bits(d, off, size) != 4:
        sys.exit("only 4-bit pages can be imported")
    index = palette if palette is not None else commonest_palette(page_palette_use(b)[page])
    colours = page_colours(palette_colours(d, b["pal"]), index, RAW_SIZE_4BIT)
    try:
        new = import_page(d, off, size, Image.open(image), colours)
    except ValueError as e:
        sys.exit(str(e))
    backup_orig(path)
    with open(path, "wb") as f:
        f.write(new)
    print("%s %s page %s written with palette %d" % (os.path.basename(path), bank, page, index))


def _check_one_file(path: str, packed_arcs) -> dict:
    """Round-trip the pages of one .arc; returns the counters cmd_check adds up."""
    n = dict(pages=0, same=0, rgba_same=0, dup=0, packed=0, unpacked=0, odd=0, again=0, fits=0)
    with open(path, "rb") as f:
        d = f.read()
    out = bytearray(d)
    for b in banks(d, elf_symbols(d)):
        pal = palette_colours(d, b["pal"])
        use = page_palette_use(b)
        for k, (off, size) in enumerate(b["pages"]):
            if is_compressed(size):
                n["packed"] += 1
                try:
                    raw, width, used = decompress_page(d[off:off + size])
                except ValueError:
                    n["odd"] += 1
                    continue
                n["unpacked"] += size - 16 < used <= size
                if os.path.basename(path) in packed_arcs:
                    new = compress_page(raw, width)
                    n["again"] += decompress_page(new + bytes(16))[0] == raw
                    n["fits"] += len(new) <= size
                continue
            n["pages"] += 1
            idx = decode_indices(d, off, size)
            n["same"] += encode_indices(idx, size) == d[off:off + size]
            if size == RAW_SIZE_4BIT:
                index = commonest_palette(use[k])
                colours = page_colours(pal, index, size)
                if len(colours) > int(idx.max()):
                    n["dup"] += len({tuple(c) for c in colours}) < 16
                    out[off:off + size] = import_page(d, off, size, page_image(d, off, size, pal, index),
                                                      colours)[off:off + size]
    n["rgba_same"] += bytes(out) == d
    return n


def cmd_check(packed_arcs=()) -> None:
    """Decode and re-encode every 128x128 page of every .arc; also import each decoded image unchanged.
    Compressed pages are unpacked; those of the files named in `packed_arcs` are also packed again."""
    paths = sorted(glob.glob(os.path.join(config.DATA_FILES, "*.arc")))
    total = collections.Counter()
    for path in paths:
        total.update(_check_one_file(path, packed_arcs))
    print("%d pages: %d re-encode identical; %d of %d files identical after export -> import of the "
          "unchanged images (%d pages have repeated palette colours)"
          % (total["pages"], total["same"], total["rgba_same"], len(paths), total["dup"]))
    print("%d compressed pages: %d unpack to exactly their size, %d are in another format"
          % (total["packed"], total["unpacked"], total["odd"]))
    if packed_arcs:
        print("packed again (%s): %d give the same picture, %d fit their slot"
              % (", ".join(packed_arcs), total["again"], total["fits"]))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pp15 textures", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command")
    p = sub.add_parser("export", help="one contact sheet per .arc, plus pages.tsv")
    p.add_argument("out_dir", nargs="?", default=os.path.join(config.WORK_DIR, "ui_scan"),
                   help="folder for the sheets (default: _work/ui_scan)")
    p = sub.add_parser("parts", help="banks of an .arc, or the sprite parts of one bank")
    p.add_argument("arc", help="file name in DATA/files, or a path")
    p.add_argument("bank", nargs="?", help="bank name: list its sprite parts")
    p.add_argument("page", nargs="?", type=int, help="only the parts on this page")
    p = sub.add_parser("page", help="save one page as a PNG")
    p.add_argument("arc")
    p.add_argument("bank")
    p.add_argument("page", type=int)
    p.add_argument("out", help="PNG file to write")
    p.add_argument("palette", nargs="?", type=int, help="palette number (default: the one most sprite parts use)")
    p = sub.add_parser("import", help="write a 128x128 PNG back as a 4-bit page (the original .arc is saved first)")
    p.add_argument("arc")
    p.add_argument("bank")
    p.add_argument("page", type=int)
    p.add_argument("image", help="128x128 PNG")
    p.add_argument("palette", nargs="?", type=int, help="palette number (default: the one most sprite parts use)")
    p = sub.add_parser("check", help="round trip of every page (no files written)")
    p.add_argument("arcs", nargs="*", metavar="ARC", help="files whose packed pages are also packed again (slow)")
    return ap


def main(argv=None) -> None:
    ap = build_parser()
    args = ap.parse_args(sys.argv[1:] if argv is None else list(argv))
    if args.command == "export":
        cmd_export(args.out_dir)
    elif args.command == "parts":
        cmd_parts(args.arc, args.bank, args.page)
    elif args.command == "page":
        cmd_page(args.arc, args.bank, args.page, args.out, args.palette)
    elif args.command == "import":
        cmd_import(args.arc, args.bank, args.page, args.image, args.palette)
    elif args.command == "check":
        cmd_check(args.arcs)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
