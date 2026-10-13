#!/usr/bin/env python3
"""Export the UI sprite pages of Pawapuro 15 (the .arc files) as PNG sheets.

  ui_textures.py export [OUT_DIR]     one sheet per .arc in OUT_DIR (default _work/ui_scan), plus pages.tsv

The .arc files are ELF objects. Their .data holds sprite banks, named by symbol:
  tex_<bank>NN     texture page: 8,192 bytes = 128x128, 4 bits per pixel (GX C4, 8x8 tiles), or
                   16,384 bytes = 128x128, 8 bits per pixel (GX C8, 8x4 tiles). Other sizes are
                   not pages and are skipped here.
  pal_<bank>       RGB5A3 colours, 16 per palette for the 4-bit pages
  opd_<bank>_NN    one sprite part, 20 bytes: byte 10 = page, byte 11 = palette,
                   bytes 12-15 = offset on screen (x, y as s16), bytes 16-19 = u0, v0, u1, v1
Each page is drawn with the palette that most of its sprite parts use, so a page shared by
differently coloured sprites shows only one of the colourings.
The sheets are game data: they go to _work/ (git-ignored).
"""
import collections
import glob
import os
import re
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


def banks(d, syms):
    """{bank: {"pages": {n: offset, size}, "pal": (offset, size), "parts": [(page, palette)]}}"""
    out = collections.defaultdict(lambda: {"pages": {}, "pal": None, "parts": []})
    for name, (off, size) in syms.items():
        if name.endswith("_tbl"):
            continue
        if name.startswith("pal_"):
            out[name[4:]]["pal"] = (off, size)
        elif name.startswith("opd_") and size == 20:
            out[name[4:].rsplit("_", 1)[0]]["parts"].append((d[off + 10], d[off + 11]))
    for name, (off, size) in syms.items():
        m = re.match(r"tex_(.+?)(\d\d)$", name)
        if m and size in (8192, 16384):
            bank = m.group(1) if m.group(1) in out else m.group(1).rstrip("_")
            out[bank]["pages"][int(m.group(2))] = (off, size)
    return {k: v for k, v in out.items() if v["pages"]}


def page_image(d, off, size, pal, index):
    if size == 8192:
        raw = np.frombuffer(d, dtype=np.uint8, count=size, offset=off)
        idx = G._blocks(np.stack([raw >> 4, raw & 15], -1).reshape(-1), PAGE, PAGE, 8, 8)
        colours = pal[index * 16:index * 16 + 16]
        if len(colours) < 16:
            colours = pal[:16]
    else:
        idx = G._blocks(np.frombuffer(d, dtype=np.uint8, count=size, offset=off), PAGE, PAGE, 4, 8)
        colours = pal[:256]
    if len(colours) <= int(idx.max()):
        grey = (np.arange(256) * (255 // max(1, int(idx.max())))).clip(0, 255).astype(np.uint8)
        colours = np.stack([grey, grey, grey, np.full(256, 255, np.uint8)], -1)
    return Image.fromarray(np.ascontiguousarray(colours[idx]), "RGBA")


def cmd_export(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for path in sorted(glob.glob(os.path.join(S.DATA_FILES, "*.arc"))):
        with open(path, "rb") as f:
            d = f.read()
        images = []
        for bank, b in sorted(banks(d, elf_symbols(d)).items()):
            pal = (G._rgb5a3(np.frombuffer(d, dtype=">u2", count=b["pal"][1] // 2, offset=b["pal"][0]))
                   if b["pal"] else np.zeros((0, 4), np.uint8))
            use = collections.defaultdict(collections.Counter)
            for page, palette in b["parts"]:
                use[page][palette] += 1
            for n, (off, size) in sorted(b["pages"].items()):
                index = use[n].most_common(1)[0][0] if use[n] else 0
                images.append(page_image(d, off, size, pal, index))
                rows.append((os.path.basename(path), bank, n, size, index, sum(use[n].values())))
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


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "export":
        cmd_export(sys.argv[2] if len(sys.argv) > 2 else os.path.join(S.WORK_DIR, "ui_scan"))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
