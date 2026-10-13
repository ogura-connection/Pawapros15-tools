#!/usr/bin/env python3
"""Export the UI sprite pages of Pawapuro 15 (the .arc files) as PNG sheets.

  ui_textures.py export [OUT_DIR]     one sheet per .arc in OUT_DIR (default _work/ui_scan), plus pages.tsv
  ui_textures.py parts ARC [BANK [PAGE]]   sprite parts (screen offset and page rectangle) of a bank
  ui_textures.py page ARC BANK PAGE OUT.png [PALETTE]   one page as RGBA with its palette
  ui_textures.py import ARC BANK PAGE IMAGE.png [PALETTE]   write a 128x128 page back, same offset and size
  ui_textures.py check                round trip: every page decoded, re-encoded and compared (no files written)

The .arc files are ELF objects. Their .data holds sprite banks, named by symbol:
  tex_<bank>NN     texture page: 8,192 bytes = 128x128, 4 bits per pixel (GX C4, 8x8 tiles), or
                   16,384 bytes = 128x128, 8 bits per pixel (GX C8, 8x4 tiles). Other sizes are
                   not pages and are skipped here.
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
"""
import collections
import glob
import os
import re
import shutil
import struct
import sys

import numpy as np
from PIL import Image

import mlb_assets as G          # GX block and colour helpers
import scan_story as S

PAGE = 128


def elf_symbols(d):
    """{name: (offset in file, size)} for the symbols of an ELF object with .data at its address."""
    if d[:4] != b"\x7fELF":
        return {}
    shoff = struct.unpack_from(">I", d, 0x20)[0]
    entsize, count, _ = struct.unpack_from(">HHH", d, 0x2E)
    secs = [struct.unpack_from(">10I", d, shoff + i * entsize) for i in range(count)]
    syms = {}
    for s in secs:
        if s[1] != 2:
            continue
        strtab = secs[s[6]]
        for k in range(s[5] // 16):
            name, value, size, _, _, shndx = struct.unpack_from(">IIIBBH", d, s[4] + k * 16)
            if name and 0 < shndx < count:
                end = d.index(b"\0", strtab[4] + name)
                sec = secs[shndx]
                syms[d[strtab[4] + name:end].decode("latin1")] = (value - sec[3] + sec[4], size)
    return syms


Part = collections.namedtuple("Part", "sprite page flags palette y x y0 x0 y1 x1 offset")


def banks(d, syms):
    """Sprite banks of an ELF object in file order:
    [{"name", "pal": (offset, size) or None, "pages": [(offset, size)], "sprites": {opd name: [Part]}}]; Part.offset = file offset of the 10 bytes.
    A bank is the run of opd_, pal_*_tbl, tex_ symbols that ends at its pal_ colour table."""
    out, cur = [], None
    for name in sorted(syms, key=lambda n: syms[n][1] and syms[n][0]):
        off, size = syms[name]
        kind = name[:4]
        if kind not in ("opd_", "pal_", "tex_"):
            continue
        if cur is None:
            cur = {"name": None, "pal": None, "pages": [], "sprites": {}, "page_names": []}
        if kind == "opd_":
            if size >= 20 and size == 10 + 10 * d[off]:
                cur["sprites"][name] = [
                    Part(name, d[o] & 0x3F, d[o] & 0xC0, d[o + 1], *struct.unpack_from(">hhBBBB", d, o + 2), o)
                    for o in range(off + 10, off + size, 10)]
        elif kind == "tex_":
            if not name.endswith("_tbl"):
                cur["pages"].append((off, size))
                cur["page_names"].append(name)
        elif name.endswith("_tbl"):
            cur["name"] = cur["name"] or name[4:-4]
        else:
            cur["pal"] = (off, size)
            if cur["sprites"]:
                cur["name"] = re.sub(r"_[0-9a-f]{2}$", "", next(iter(cur["sprites"]))[4:])
            else:
                cur["name"] = name[4:]
            out.append(cur)
            cur = None
    if cur and cur["pages"]:
        cur["name"] = cur["name"] or re.sub(r"\d\d$", "", cur["page_names"][0][4:])
        out.append(cur)
    return [b for b in out if b["pages"]]


def pack_part(page, flags, palette, y, x, y0, x0, y1, x1):
    """The 10 bytes of a sprite part."""
    return struct.pack(">BBhhBBBB", page | flags, palette, y, x, y0, x0, y1, x1)


def palette_colours(d, pal):
    """RGBA colours (n, 4) of a bank's palette table."""
    return G._rgb5a3(np.frombuffer(d, dtype=">u2", count=pal[1] // 2, offset=pal[0])) if pal \
        else np.zeros((0, 4), np.uint8)


def decode_indices(d, off, size):
    """Palette indices of a page as a 128x128 uint8 array (C4 tiles of 8x8, or C8 tiles of 8x4)."""
    raw = np.frombuffer(d, dtype=np.uint8, count=size, offset=off)
    if size == 8192:
        return G._blocks(np.stack([raw >> 4, raw & 15], -1).reshape(-1), PAGE, PAGE, 8, 8)
    return G._blocks(raw, PAGE, PAGE, 4, 8)


def encode_indices(idx, size):
    """Inverse of decode_indices: the page bytes for a 128x128 index array."""
    idx = np.ascontiguousarray(idx, dtype=np.uint8)
    if size == 8192:
        t = idx.reshape(PAGE // 8, 8, PAGE // 8, 8).swapaxes(1, 2).reshape(-1)
        return ((t[0::2] << 4) | t[1::2]).astype(np.uint8).tobytes()
    return idx.reshape(PAGE // 4, 4, PAGE // 8, 8).swapaxes(1, 2).reshape(-1).tobytes()


def page_colours(pal, index, size, n_used=0):
    """The colours a page is drawn with: 16 entries of palette number `index` (C4) or all 256 (C8)."""
    if size == 8192:
        colours = pal[index * 16:index * 16 + 16]
        return colours if len(colours) == 16 else pal[:16]
    return pal[:256]


def page_image(d, off, size, pal, index):
    idx = decode_indices(d, off, size)
    colours = page_colours(pal, index, size)
    if len(colours) <= int(idx.max()):
        grey = (np.arange(256) * (255 // max(1, int(idx.max())))).clip(0, 255).astype(np.uint8)
        colours = np.stack([grey, grey, grey, np.full(256, 255, np.uint8)], -1)
    return Image.fromarray(np.ascontiguousarray(colours[idx]), "RGBA")


def page_palette_use(bank):
    """{page: Counter of palette numbers} over every sprite part of the bank."""
    use = collections.defaultdict(collections.Counter)
    for parts in bank["sprites"].values():
        for p in parts:
            use[p.page][p.palette] += 1
    return use


def quantise(image, colours, keep=None):
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


def import_page(d, off, size, image, colours):
    """The .arc bytes with the page at (off, size) replaced by `image` (128x128)."""
    if image.size != (PAGE, PAGE):
        raise ValueError("page images are %dx%d, got %dx%d" % ((PAGE, PAGE) + image.size))
    old = decode_indices(d, off, size)
    new = quantise(image, colours, (colours[old.clip(max=len(colours) - 1)], old))
    return d[:off] + encode_indices(new, size) + d[off + size:]


def cmd_export(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for path in sorted(glob.glob(os.path.join(S.DATA_FILES, "*.arc"))):
        with open(path, "rb") as f:
            d = f.read()
        images = []
        for b in banks(d, elf_symbols(d)):
            pal = palette_colours(d, b["pal"])
            use = page_palette_use(b)
            for n, (off, size) in enumerate(b["pages"]):
                if size not in (8192, 16384):
                    continue
                index = use[n].most_common(1)[0][0] if use[n] else 0
                images.append(page_image(d, off, size, pal, index))
                rows.append((os.path.basename(path), b["name"], n, size, index, sum(use[n].values())))
        if images:
            cols = 8
            sheet = Image.new("RGBA", (PAGE * cols, PAGE * ((len(images) + cols - 1) // cols)), (70, 70, 70, 255))
            for k, im in enumerate(images):
                sheet.alpha_composite(im, ((k % cols) * PAGE, (k // cols) * PAGE))
            sheet.convert("RGB").save(os.path.join(out_dir, os.path.basename(path)[:-4] + ".png"))
    with open(os.path.join(out_dir, "pages.tsv"), "w") as f:
        f.write("arc\tbank\tpage\tbytes\tpalette\tsprite parts\n")
        for r in rows:
            f.write("%s\t%s\t%d\t%d\t%d\t%d\n" % r)
    print("%d pages from %d files -> %s" % (len(rows), len({r[0] for r in rows}), out_dir))


def find_page(arc, bank, page):
    """(file bytes, path, bank dict, (offset, size)) for a page of DATA/files/<arc>."""
    path = arc if os.path.exists(arc) else os.path.join(S.DATA_FILES, arc)
    with open(path, "rb") as f:
        d = f.read()
    for b in banks(d, elf_symbols(d)):
        if b["name"] == bank:
            return d, path, b, b["pages"][page]
    sys.exit("no bank %s in %s" % (bank, arc))


def cmd_parts(args):
    d, _, = (open(args[0] if os.path.exists(args[0]) else os.path.join(S.DATA_FILES, args[0]), "rb").read(), 0)
    for b in banks(d, elf_symbols(d)):
        if len(args) > 1 and b["name"] != args[1]:
            continue
        print("bank %s: %d pages %s, %d sprites" % (
            b["name"], len(b["pages"]), [s for _, s in b["pages"]], len(b["sprites"])))
        if len(args) < 2:
            continue
        for name, parts in b["sprites"].items():
            for p in parts:
                if len(args) > 2 and p.page != int(args[2]):
                    continue
                print("%s page %d%s pal %d at (%d,%d) rect x %d-%d y %d-%d (%dx%d)" % (
                    name[4:], p.page, " flags %02x" % p.flags if p.flags else "", p.palette, p.x, p.y,
                    p.x0, p.x1, p.y0, p.y1, p.x1 - p.x0, p.y1 - p.y0))


def cmd_page(args):
    d, _, b, (off, size) = find_page(args[0], args[1], int(args[2]))
    pal = palette_colours(d, b["pal"])
    index = int(args[4]) if len(args) > 4 else (page_palette_use(b)[int(args[2])] or {0: 1}).most_common(1)[0][0] \
        if page_palette_use(b)[int(args[2])] else 0
    page_image(d, off, size, pal, index).save(args[3])


def cmd_import(args):
    d, path, b, (off, size) = find_page(args[0], args[1], int(args[2]))
    if size != 8192:
        sys.exit("only 4-bit (8,192 byte) pages can be imported")
    use = page_palette_use(b)[int(args[2])]
    index = int(args[4]) if len(args) > 4 else (use.most_common(1)[0][0] if use else 0)
    colours = page_colours(palette_colours(d, b["pal"]), index, size)
    new = import_page(d, off, size, Image.open(args[3]), colours)
    backup_orig(path)
    with open(path, "wb") as f:
        f.write(new)
    print("%s %s page %s written with palette %d" % (os.path.basename(path), args[1], args[2], index))


ORIG_ARC_DIR = os.path.join(S.WORK_DIR, "orig_arc")      # not _work/orig: rebuild_scripts installs that whole folder


def backup_orig(path):
    """Keep the first, untouched copy of an .arc of DATA/files before it is written to."""
    if os.path.dirname(os.path.abspath(path)) != os.path.abspath(S.DATA_FILES):
        return
    os.makedirs(ORIG_ARC_DIR, exist_ok=True)
    dst = os.path.join(ORIG_ARC_DIR, os.path.basename(path))
    if not os.path.exists(dst):
        shutil.copy2(path, dst)


def cmd_check():
    """Decode and re-encode every 128x128 page of every .arc; also import each decoded image unchanged."""
    pages = same = rgba_same = dup = 0
    for path in sorted(glob.glob(os.path.join(S.DATA_FILES, "*.arc"))):
        with open(path, "rb") as f:
            d = f.read()
        out = bytearray(d)
        for b in banks(d, elf_symbols(d)):
            pal = palette_colours(d, b["pal"])
            use = page_palette_use(b)
            for n, (off, size) in enumerate(b["pages"]):
                if size not in (8192, 16384):
                    continue
                pages += 1
                idx = decode_indices(d, off, size)
                same += encode_indices(idx, size) == d[off:off + size]
                if size == 8192:
                    index = use[n].most_common(1)[0][0] if use[n] else 0
                    colours = page_colours(pal, index, size)
                    if len(colours) > int(idx.max()):
                        dup += len({tuple(c) for c in colours}) < 16
                        out[off:off + size] = import_page(d, off, size, page_image(d, off, size, pal, index),
                                                          colours)[off:off + size]
        rgba_same += bytes(out) == d
    print("%d pages: %d re-encode identical; %d of %d files identical after export -> import of the "
          "unchanged images (%d pages have repeated palette colours)"
          % (pages, same, rgba_same, len(glob.glob(os.path.join(S.DATA_FILES, "*.arc"))), dup))


def main():
    a = sys.argv[1:]
    if a[:1] == ["export"]:
        cmd_export(a[1] if len(a) > 1 else os.path.join(S.WORK_DIR, "ui_scan"))
    elif a[:1] == ["parts"] and len(a) >= 2:
        cmd_parts(a[1:])
    elif a[:1] == ["page"] and len(a) >= 5:
        cmd_page(a[1:])
    elif a[:1] == ["import"] and len(a) >= 5:
        cmd_import(a[1:])
    elif a[:1] == ["check"]:
        cmd_check()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
