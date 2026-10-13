#!/usr/bin/env python3
"""Read the MLB Power Pros (Wii) discs as a reference: files inside project.bin and their textures.

  mlb_assets.py list PROJECT.BIN [text]          file names and sizes (filtered by text)
  mlb_assets.py sheet PROJECT.BIN NAME OUT.png   contact sheet of the textures in one .pack file
  mlb_assets.py text DISC_FILES_DIR OUT_DIR      every English string of the disc to OUT_DIR/text.tsv

project.bin: 16 big-endian words of header (word 3 = record count, 5 = record table, 10 = index
table, 11 = name table, 13 = start of data, sector size 0x800). The index table holds
(id, start sector) pairs; record id + 1 is 7 words: 0, name offset, sectors, 0x800, 0, 0, bytes.
.pack files start with "PACKWII ". Textures have a header of height, width (u16), GX format (u32)
and a pointer (0x40000000 + file offset) to the pixels; a palette (RGB5A3) sits just before the
pixels when the texture has its own. Formats seen in the UI: 8 (C4) and 9 (C8).
The extracted discs are game data: keep them outside this repository.
"""
import struct, os, sys


class Project:
    def __init__(self, path):
        self.f = open(path, 'rb'); d = self.f.read(0x100000)
        H = struct.unpack_from('>16I', d, 0)
        n, t_rec, t_idx, t_name, self.data0 = H[3], H[5], H[10], H[11], H[13]
        offs = struct.unpack_from('>%dI' % n, d, 0x800)
        self.files = {}
        for k in range((t_name - t_idx) // 8):
            i, sec = struct.unpack_from('>II', d, t_idx + k * 8)
            if not i: continue
            r = struct.unpack_from('>7I', d, t_rec + offs[i + 1])
            e = d.index(b'\0', t_name + r[1]); name = d[t_name + r[1]:e].decode('latin1')
            self.files[name] = (self.data0 + sec * 0x800, r[6])
    def read(self, name):
        o, sz = self.files[name]; self.f.seek(o); return self.f.read(sz)
from PIL import Image
def rgb5a3(v):
    if v & 0x8000: return ((v >> 10 & 31) * 255 // 31, (v >> 5 & 31) * 255 // 31, (v & 31) * 255 // 31, 255)
    return ((v >> 8 & 15) * 17, (v >> 4 & 15) * 17, (v & 15) * 17, (v >> 12 & 7) * 255 // 7)
def textures(d):
    """[(offset, Image)] for the C4/C8 textures of a PACKWII file."""
    out, last = [], {}
    for o in range(0, len(d) - 44, 4):
        h, w, fmt, ptr = struct.unpack_from('>HHII', d, o)
        p = ptr & 0xFFFFFFF
        if not (fmt in (8, 9) and 8 <= w <= 1024 and 8 <= h <= 1024 and w % 8 == 0 and h % 4 == 0
                and ptr >> 28 == 4 and o < p < len(d) and p - o <= 64 + 512): continue
        n = {8: 16, 9: 256}[fmt]
        if p - o >= 64 + n * 2:
            last[fmt] = [rgb5a3(x) for x in struct.unpack_from('>%dH' % n, d, p - n * 2)]
        pal = last.get(fmt) or [(i * 255 // (n - 1),) * 3 + (255,) for i in range(n)]
        im = Image.new('RGBA', (w, h)); px = im.load(); i = p
        bw, bh = 8, (8 if fmt == 8 else 4)
        try:
            if fmt == 9:
                for by in range(0, h, 4):
                    for bx in range(0, w, 8):
                        for y in range(4):
                            for x in range(8):
                                px[bx + x, by + y] = pal[d[i]]; i += 1
            else:
                k = p * 2
                for by in range(0, h, 8):
                    for bx in range(0, w, 8):
                        for y in range(8):
                            for x in range(8):
                                px[bx + x, by + y] = pal[(d[k // 2] >> (4 if k % 2 == 0 else 0)) & 15]; k += 1
        except IndexError:
            continue
        out.append((o, im))
    return out
def sheet(images, path, cols=4, bg=(60, 60, 60, 255)):
    if not images: return
    w = max(i.width for i in images); h = max(i.height for i in images)
    rows = (len(images) + cols - 1) // cols
    s = Image.new('RGBA', (w * cols, h * rows), bg)
    for k, im in enumerate(images): s.alpha_composite(im, ((k % cols) * w, (k // cols) * h))
    s.convert('RGB').save(path)


def glyph_strings(data, table, min_letters=2):
    """[(offset, text)] for 0xFFFF-terminated runs of 16-bit glyphs that read as Latin text.
    Glyph numbers are those of Pawapuro 15 (0 = space, 220 = A, 252 = a); values from 0xF000 are
    control codes and are written as {XXXX}."""
    import numpy as np, unicodedata
    a = np.frombuffer(data[:len(data) // 2 * 2], dtype='>u2')
    ok = (a <= 281) | ((a >= 0xF000) & (a != 0xFFFF))
    edge = np.flatnonzero(np.diff(np.r_[False, ok, False].astype(np.int8)))
    out = []
    for s, e in zip(edge[::2], edge[1::2]):
        if e >= len(a) or a[e] != 0xFFFF or e - s < 2:
            continue
        seg = a[s:e]
        letters = int(((seg >= 220) & (seg <= 277)).sum())
        glyphs = int((seg <= 281).sum())
        if letters < min_letters or letters * 2 < glyphs - int((seg == 0).sum()):
            continue
        text = ''.join(table[x] if x <= 281 else '{%04X}' % x for x in seg)
        out.append((int(s) * 2, unicodedata.normalize('NFKC', text).strip()))
    return out


def scan_text(disc, out_dir):
    """Write every English string of a disc to out_dir/text.tsv: file, offset, text."""
    import bisect
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import pawapuro15_text_tools as T
    table = [T.glyph_to_char(i) for i in range(282)]
    table[0] = ' '
    os.makedirs(out_dir, exist_ok=True)
    proj = Project(os.path.join(disc, 'project.bin'))
    starts = sorted((off, name) for name, (off, size) in proj.files.items())
    rows = []
    for fn in ('ovl_main.rel', 'project.bin'):
        with open(os.path.join(disc, fn), 'rb') as f:
            data = f.read()
        for off, text in glyph_strings(data, table):
            name = fn
            if fn == 'project.bin':
                k = bisect.bisect_right(starts, (off, '~')) - 1
                name = starts[k][1] if k >= 0 else fn
                off -= starts[k][0] if k >= 0 else 0
            rows.append((name, off, text))
    with open(os.path.join(out_dir, 'text.tsv'), 'w', encoding='utf-8') as f:
        for r in rows:
            f.write('%s\t%d\t%s\n' % r)
    return rows


if __name__ == '__main__':
    import sys
    a = sys.argv[1:]
    if len(a) >= 2 and a[0] == 'list':
        for name, (off, size) in sorted(Project(a[1]).files.items()):
            if len(a) < 3 or a[2].lower() in name.lower():
                print('%9d  %s' % (size, name))
    elif len(a) == 4 and a[0] == 'sheet':
        sheet([im for _, im in textures(Project(a[1]).read(a[2]))], a[3])
    elif len(a) == 3 and a[0] == 'text':
        print(len(scan_text(a[1], a[2])), 'strings')
    else:
        print(__doc__)
