#!/usr/bin/env python3
"""Export the UI sprite pages of Pawapuro 15 (the .arc files) as PNG sheets.

  ui_textures.py export [OUT_DIR]     one sheet per .arc in OUT_DIR (default _work/ui_scan), plus pages.tsv
  ui_textures.py parts ARC [BANK [PAGE]]   sprite parts (screen offset and page rectangle) of a bank
  ui_textures.py page ARC BANK PAGE OUT.png [PALETTE]   one page as RGBA with its palette
  ui_textures.py import ARC BANK PAGE IMAGE.png [PALETTE]   write a 128x128 page back, same offset and size
  ui_textures.py check [ARC ...]      round trip: every page decoded, re-encoded and compared (no files written);
                                      the compressed pages of the named files are also packed again (slow)

The .arc files are ELF objects. Their .data holds sprite banks, named by symbol:
  tex_<bank>NN     texture page: 8,192 bytes = 128x128, 4 bits per pixel (GX C4, 8x8 tiles), or
                   16,384 bytes = 128x128, 8 bits per pixel (GX C8, 8x4 tiles). Any other size is a
                   compressed page (see decompress_page): the same 128x128 picture, stored row by
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
"""
import collections
import glob
import heapq
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
    return [s for b in hand_over_pages([b for b in out if b["pages"]]) for s in split_merged(b)]


def bank_named(banks, ref):
    """The bank `ref` names: "name" = the first bank of that name; "name#k" = banks[k] (k = place in the list
    banks() returns; for files whose sprite tables the reader files one bank too late, e.g. sct_comd.arc, where
    the sprites of bank k draw the pages of bank k - 1: a repack group then says "bank": "z4_eg_0#1",
    "sprites": "z4_egp_0#2")."""
    if "#" in ref:
        name, k = ref.rsplit("#", 1)
        b = banks[int(k)]
        if b["name"] != name:
            raise KeyError("bank %d is %s, not %s" % (int(k), b["name"], name))
        return b
    return next(x for x in banks if x["name"] == ref)


# merged gameplay.arc banks that are split by sprite set (split_by_prefix, hand_over_pages); other files are untouched
SPLIT_BY_SET = {"h3_tnm_0", "y4_dem_1", "g3_hk"}


def hand_over_pages(out):
    """A page group that ends one bank (gameplay.arc tex_g3_hk00, listed after the pages of y4_dem_1 / h3_dem_2)
    belongs to a sprite set of the next bank when no set of its own bank is named like it, a set of the next bank
    is named exactly like it (opd_g3_hk_00..) and that set uses exactly the pages 0..n-1 of the n moved pages:
    the group moves to the front of the next bank's pages."""
    for i in range(len(out) - 1):
        a, nxt = out[i], out[i + 1]
        if a["name"] not in SPLIT_BY_SET or nxt["name"] not in SPLIT_BY_SET or not a["sprites"] or len(a["page_names"]) < 2:
            continue
        pre = re.sub(r"\d\d$", "", a["page_names"][-1][4:])
        n = 0
        while n < len(a["page_names"]) - 1 and re.sub(r"\d\d$", "", a["page_names"][-1 - n][4:]) == pre:
            n += 1
        sets_a = {re.sub(r"_[0-9a-f]{2}$", "", k[4:]) for k in a["sprites"]}
        if any(s.startswith(pre) for s in sets_a) or any(re.sub(r"\d\d$", "", pn[4:]) == pre for pn in nxt["page_names"]):
            continue
        used = {p.page for k, ps in nxt["sprites"].items() if re.sub(r"_[0-9a-f]{2}$", "", k[4:]) == pre for p in ps}
        if not used or used != set(range(n)):
            continue
        nxt["pages"] = a["pages"][-n:] + nxt["pages"]
        nxt["page_names"] = a["page_names"][-n:] + nxt["page_names"]
        a["pages"], a["page_names"] = a["pages"][:-n], a["page_names"][:-n]
    return out


def split_merged(b):
    out = split_merged_old(b)
    if len(out) == 1 and out[0] is b:
        out = split_by_prefix(b)
    return out


def split_by_prefix(b):
    """The split for a bank whose page groups are each named after one sprite set (tex_h3_nxt00..07 for
    opd_h3_nxt_ps2, tex_h3_her00..06 for h3_her_0, tex_h3_rs00..06 for h3_rs_0) while one set has no pages of its
    own (h3_tnm_0: its page table is empty; the old reading, the next set's pages, is kept) or its pages were
    counted wrongly by split_by_order. Only when every page group is named by exactly one set, each such set uses
    pages inside its group, and the sets without a group are followed by a set with one (a set at the end
    without pages, gameplay.arc h3_cat_0 whose pages are stored under pal_ names, is dropped); else [b]."""
    groups = []
    for k, pn in enumerate(b["page_names"]):
        pre = re.sub(r"\d\d$", "", pn[4:])
        if groups and groups[-1][0] == pre:
            groups[-1][1].append(k)
        else:
            groups.append((pre, [k]))
    sets = {}
    for n in b["sprites"]:
        sets.setdefault(re.sub(r"_[0-9a-f]{2}$", "", n[4:]), []).append(n)
    if b["name"] not in SPLIT_BY_SET or len(sets) < 2 or len({g for g, _ in groups}) != len(groups):
        return [b]
    first = {s: min(p.offset for n in sets[s] for p in b["sprites"][n]) for s in sets}
    order = sorted(sets, key=first.get)
    owner = {}
    for s in order:
        fits = [i for i, (g, _) in enumerate(groups) if s.startswith(g)]
        if fits:
            owner[s] = max(fits, key=lambda i: len(groups[i][0]))
    if len(owner) == len(sets) or sorted(owner.values()) != list(range(len(groups))):
        return [b]
    for s, i in owner.items():
        used = [p.page for n in sets[s] for p in b["sprites"][n]]
        if used and max(used) >= len(groups[i][1]):
            return [b]
    pages_of = {}
    for k, s in enumerate(order):
        if s in owner:
            pages_of[s] = owner[s]
        else:
            later = [t for t in order[k + 1:] if t in owner]
            if later:
                pages_of[s] = owner[later[0]]
    out = []
    for s in order:
        if s not in pages_of:
            continue
        idx = groups[pages_of[s]][1]
        out.append(dict(b, name=s, pages=[b["pages"][k] for k in idx], page_names=[b["page_names"][k] for k in idx],
                        sprites={n: b["sprites"][n] for n in sets[s]}))
    return out if len(out) > 1 else [b]


def split_merged_old(b):
    """Some files merge several sprite sets into one bank (ore_ini.arc y3_mym + y3_mys + y3_myk + y3_kzo,
    gdt_ore.arc, ore_ren.arc): the pages run tex_<set1>00.., tex_<set2>00.., and the sprites of every set
    count their pages from 0 again. Such a bank is returned as one bank per set, each with its own pages;
    the palette is shared. A bank whose sprites number the pages straight through is left whole."""
    groups = []                                     # [(page prefix, [indices into the bank's pages])]
    for k, pn in enumerate(b["page_names"]):
        pre = re.sub(r"\d\d$", "", pn[4:])
        if groups and groups[-1][0] == pre:
            groups[-1][1].append(k)
        else:
            groups.append((pre, [k]))
    sets = {}
    for n in b["sprites"]:
        sets.setdefault(re.sub(r"_[0-9a-f]{2}$", "", n[4:]), []).append(n)
    if len(sets) < 2:
        return [b]
    owner = {}                                      # set -> group index (the longest page prefix of its name)
    for s in sets:
        fits = [i for i, (g, _) in enumerate(groups) if s.startswith(g)]
        if not fits:
            break
        owner[s] = max(fits, key=lambda i: len(groups[i][0]))
    if len(groups) < 2 or len({g for g, _ in groups}) != len(groups) or len(owner) != len(sets) \
            or sorted(owner.values()) != list(range(len(groups))):
        return split_by_order(b, sets)
    for s, i in owner.items():
        used = [p.page for n in sets[s] for p in b["sprites"][n]]
        start, count = groups[i][1][0], len(groups[i][1])
        if used and max(used) >= count:             # pages beyond the set's own: numbered straight through
            return [b]
        if i and used and min(used) >= start:       # fits both ways: keep the old reading
            return [b]
    out = []
    for i, (pre, idx) in sorted(enumerate(groups), key=lambda t: t[0]):
        s = next(s for s, j in owner.items() if j == i)
        out.append(dict(b, name=s, pages=[b["pages"][k] for k in idx], page_names=[b["page_names"][k] for k in idx],
                        sprites={n: b["sprites"][n] for n in sets[s]}))
    return out


def split_by_order(b, sets):
    """The same split when the page names do not tell the sets apart (gameplay.arc h3_ap_ps2: tex_h3_ap00..05 and
    ap08 for h3_ap_ps2, ap06 / ap07 for h3_sc_ps2, mmk00..02 for h3_mmk_0): the sets, in file order of their
    sprites, take the pages in file order, each as many as it uses. Only when every set uses each of its pages
    0..n-1 and the counts add up to the bank's pages exactly; otherwise the bank stays whole."""
    order = sorted(sets, key=lambda s: min(p.offset for n in sets[s] for p in b["sprites"][n]))
    counts = []
    for s in order:
        used = {p.page for n in sets[s] for p in b["sprites"][n]}
        if not used or used != set(range(max(used) + 1)):
            return [b]
        counts.append(max(used) + 1)
    if sum(counts) != len(b["pages"]) or counts[0] == len(b["pages"]):
        return [b]
    out, k = [], 0
    for s, c in zip(order, counts):
        out.append(dict(b, name=s, pages=b["pages"][k:k + c], page_names=b["page_names"][k:k + c],
                        sprites={n: b["sprites"][n] for n in sets[s]}))
        k += c
    return out


def pack_part(page, flags, palette, y, x, y0, x0, y1, x1):
    """The 10 bytes of a sprite part."""
    return struct.pack(">BBhhBBBB", page | flags, palette, y, x, y0, x0, y1, x1)


def palette_colours(d, pal):
    """RGBA colours (n, 4) of a bank's palette table."""
    return G._rgb5a3(np.frombuffer(d, dtype=">u2", count=pal[1] // 2, offset=pal[0])) if pal \
        else np.zeros((0, 4), np.uint8)


# ── Compressed pages ──────────────────────────────────────────────────────
# u16 little-endian header: low 13 bits = number of flag bytes, bit 14 = 4 bits per pixel (rows of
# 64 bytes, two pixels each), clear = 8 bits per pixel (rows of 128 bytes). Flag bytes follow, then the
# literal bytes; the symbol is padded to 16 bytes. Rows are plain raster rows, not GX tiles. Going
# through the page left to right, top to bottom, every byte not already covered takes one flag bit:
# 0 = one literal byte; 1 = a rectangle (width, height as 2 bits for 1..3, or 00 + 4 bits for 4..19)
# filled with one literal byte. The font glyphs of fonttex2.rel use the same code (pair_font.py).

def is_compressed(size):
    return size not in (8192, 16384)


def decompress_page(data):
    """Compressed page -> (raw bytes, row width 64 or 128, bytes of `data` used)."""
    hdr = data[0] | data[1] << 8
    nflags, width = hdr & 0x1FFF, 64 if hdr & 0x4000 else 128
    pos, lit, end = 0, 2 + nflags, nflags * 8

    def bits(n):
        nonlocal pos
        v = 0
        for _ in range(n):
            v = v * 2 + (data[2 + pos // 8] >> (7 - pos % 8) & 1 if pos < end else 0)
            pos += 1
        return v

    def varlen():
        return bits(2) or 4 + bits(4)

    if not hdr & 0x2000 or lit >= len(data):
        raise ValueError("not a compressed page")
    grid, left, value = bytearray(), [0] * width, [0] * width
    for _ in range(PAGE):
        for x in range(width):
            if left[x]:
                left[x] -= 1
            else:
                if bits(1):
                    w, rows = varlen(), varlen()
                    for k in range(x, min(x + w, width)):
                        left[k], value[k] = rows, data[lit]
                    left[x] -= 1
                else:
                    value[x] = data[lit]
                lit += 1
            grid.append(value[x])
    if (pos + 7) // 8 != nflags or lit > len(data):
        raise ValueError("compressed page does not end where its header says")
    return bytes(grid), width, lit


def _varlen(bits, v):
    bits += [v >> 1, v & 1] if v <= 3 else [0, 0] + [(v - 4) >> k & 1 for k in (3, 2, 1, 0)]


def _rectangles(g, width, tall, by_column):
    """Cover the page with one-colour rectangles of up to 19x19, largest area first (what the game's
    own packer does, to judge by its output). Returns {(y, x): (w, rows)} for rectangles of 2+ cells."""
    run = np.ones((PAGE, width), np.int32)                  # equal cells to the right, capped at 19
    for x in range(width - 2, -1, -1):
        run[:, x] = np.where(g[:, x] == g[:, x + 1], np.minimum(run[:, x + 1] + 1, 19), 1)
    best, minrun, alive = run.copy(), run.copy(), np.ones((PAGE, width), bool)
    for r in range(2, 20):                                  # best area anchored at every cell
        below, same = np.zeros_like(run), np.zeros((PAGE, width), bool)
        below[:PAGE - r + 1] = run[r - 1:]
        same[:PAGE - r + 1] = g[r - 1:] == g[:PAGE - r + 1]
        alive &= same
        minrun = np.where(alive, np.minimum(minrun, below), 0)
        best = np.maximum(best, minrun * r)
    gl, runl = g.tolist(), run.tolist()
    free = [[True] * width for _ in range(PAGE)]
    key = (lambda y, x: (x, y)) if by_column else (lambda y, x: (y, x))
    heap = [(-int(best[y, x]), key(y, x), y, x) for y in range(PAGE) for x in range(width) if best[y, x] >= 2]
    heapq.heapify(heap)
    rects = {}
    while heap:
        area, _, y, x = heapq.heappop(heap)
        if not free[y][x]:
            continue
        v, w_ok, now = gl[y][x], 19, (1, 1, 1)              # the best rectangle still free at this cell
        for r in range(1, 20):
            yy = y + r - 1
            if yy >= PAGE or gl[yy][x] != v or not free[yy][x]:
                break
            row, w, limit = free[yy], 1, min(w_ok, runl[yy][x])
            while w < limit and row[x + w]:
                w += 1
            w_ok = w
            if w * r > now[0] or (tall and w * r == now[0]):
                now = (w * r, w, r)
        if now[0] != -area:
            if now[0] >= 2:
                heapq.heappush(heap, (-now[0], key(y, x), y, x))
            continue
        rects[(y, x)] = now[1:]
        for yy in range(y, y + now[2]):
            free[yy][x:x + now[1]] = [False] * now[1]
    return rects


def compress_page(raw, width):
    """Raw page bytes (128 rows of `width`) -> compressed page, not padded. Tries four tie-break
    rules and returns the smallest result; that comes out within 0.1% of the original pages' size."""
    assert len(raw) == width * PAGE and width in (64, 128)
    g = np.frombuffer(raw, dtype=np.uint8).reshape(PAGE, width)
    out = None
    for tall in (True, False):
        for by_column in (True, False):
            rects = _rectangles(g, width, tall, by_column)
            bits, lits, left = [], bytearray(), [0] * width
            for y in range(PAGE):
                for x in range(width):
                    if left[x]:
                        left[x] -= 1
                        continue
                    if (y, x) in rects:
                        w, rows = rects[(y, x)]
                        bits.append(1)
                        _varlen(bits, w)
                        _varlen(bits, rows)
                        left[x:x + w] = [rows] * w
                        left[x] -= 1
                    else:
                        bits.append(0)
                    lits.append(raw[y * width + x])
            bits += [0] * (-len(bits) % 8)
            flags = bytes(sum(v << (7 - k) for k, v in enumerate(bits[i:i + 8])) for i in range(0, len(bits), 8))
            assert len(flags) < 0x2000
            packed = bytes([len(flags) & 255, len(flags) >> 8 | (0x60 if width == 64 else 0x20)]) + flags + bytes(lits)
            if out is None or len(packed) < len(out):
                out = packed
    return out


def page_bits(d, off, size):
    """4 or 8 bits per pixel."""
    if is_compressed(size):
        return 4 if d[off + 1] & 0x40 else 8
    return 4 if size == 8192 else 8


def raw_size(d, off, size):
    """Size of the page once unpacked: 8192 (4 bits per pixel) or 16384."""
    return 8192 if page_bits(d, off, size) == 4 else 16384


def decode_indices(d, off, size):
    """Palette indices of a page as a 128x128 uint8 array (C4 tiles of 8x8, C8 tiles of 8x4, or a
    compressed page in raster order)."""
    if is_compressed(size):
        raw, width, _ = decompress_page(d[off:off + size])
        raw = np.frombuffer(raw, dtype=np.uint8)
        return (np.stack([raw >> 4, raw & 15], -1) if width == 64 else raw).reshape(PAGE, PAGE)
    raw = np.frombuffer(d, dtype=np.uint8, count=size, offset=off)
    if size == 8192:
        return G._blocks(np.stack([raw >> 4, raw & 15], -1).reshape(-1), PAGE, PAGE, 8, 8)
    return G._blocks(raw, PAGE, PAGE, 4, 8)


def encode_indices(idx, size, bits=None):
    """Inverse of decode_indices: the page bytes for a 128x128 index array. A compressed page
    (bits = 4 or 8) is packed again and padded to `size`; ValueError if it no longer fits."""
    idx = np.ascontiguousarray(idx, dtype=np.uint8)
    if is_compressed(size):
        flat = idx.reshape(-1)
        raw = ((flat[0::2] << 4) | flat[1::2]).astype(np.uint8).tobytes() if bits == 4 else flat.tobytes()
        packed = compress_page(raw, 64 if bits == 4 else 128)
        if len(packed) > size:
            raise ValueError("compressed page needs %d bytes, its slot has %d" % (len(packed), size))
        return packed + bytes(size - len(packed))
    if size == 8192:
        t = idx.reshape(PAGE // 8, 8, PAGE // 8, 8).swapaxes(1, 2).reshape(-1)
        return ((t[0::2] << 4) | t[1::2]).astype(np.uint8).tobytes()
    return idx.reshape(PAGE // 4, 4, PAGE // 8, 8).swapaxes(1, 2).reshape(-1).tobytes()


def page_colours(pal, index, size, n_used=0):
    """The colours a page is drawn with: 16 entries of palette number `index` (4-bit pages), or for an 8-bit page
    the 256 entries starting at 16 x `index` (the game loads the colour table from there; seen on scc_tops.arc
    y5_tic and gameplay.arc pages). Entries past the end of the table are transparent.
    `size` is the unpacked size (raw_size): 8192 for any 4-bit page."""
    if size == 8192:
        colours = pal[index * 16:index * 16 + 16]
        return colours if len(colours) == 16 else pal[:16]
    colours = pal[index * 16:index * 16 + 256]
    if len(colours) < 256:
        colours = np.concatenate([colours, np.zeros((256 - len(colours), 4), np.uint8)])
    return colours


def page_image(d, off, size, pal, index):
    idx = decode_indices(d, off, size)
    colours = page_colours(pal, index, raw_size(d, off, size))
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
    return d[:off] + encode_indices(new, size, page_bits(d, off, size)) + d[off + size:]


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
                index = use[n].most_common(1)[0][0] if use[n] else 0
                try:
                    images.append(page_image(d, off, size, pal, index))
                except ValueError:                  # a few 16,400-byte pages are in another format
                    continue
                rows.append((os.path.basename(path), b["name"], n, size, index, sum(use[n].values()),
                             len(images) - 1))
        if images:
            cols = 8
            sheet = Image.new("RGBA", (PAGE * cols, PAGE * ((len(images) + cols - 1) // cols)), (70, 70, 70, 255))
            for k, im in enumerate(images):
                sheet.alpha_composite(im, ((k % cols) * PAGE, (k // cols) * PAGE))
            sheet.convert("RGB").save(os.path.join(out_dir, os.path.basename(path)[:-4] + ".png"))
    with open(os.path.join(out_dir, "pages.tsv"), "w") as f:
        f.write("arc\tbank\tpage\tbytes\tpalette\tsprite parts\tposition on the sheet\n")
        for r in rows:
            f.write("%s\t%s\t%d\t%d\t%d\t%d\t%d\n" % r)
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
    if page_bits(d, off, size) != 4:
        sys.exit("only 4-bit pages can be imported")
    use = page_palette_use(b)[int(args[2])]
    index = int(args[4]) if len(args) > 4 else (use.most_common(1)[0][0] if use else 0)
    colours = page_colours(palette_colours(d, b["pal"]), index, 8192)
    try:
        new = import_page(d, off, size, Image.open(args[3]), colours)
    except ValueError as e:
        sys.exit(str(e))
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


def cmd_check(packed_arcs=()):
    """Decode and re-encode every 128x128 page of every .arc; also import each decoded image unchanged.
    Compressed pages are unpacked; those of the files named in `packed_arcs` are also packed again."""
    pages = same = rgba_same = dup = packed = unpacked = odd = again = fits = 0
    for path in sorted(glob.glob(os.path.join(S.DATA_FILES, "*.arc"))):
        with open(path, "rb") as f:
            d = f.read()
        out = bytearray(d)
        for b in banks(d, elf_symbols(d)):
            pal = palette_colours(d, b["pal"])
            use = page_palette_use(b)
            for n, (off, size) in enumerate(b["pages"]):
                if is_compressed(size):
                    packed += 1
                    try:
                        raw, width, used = decompress_page(d[off:off + size])
                    except ValueError:
                        odd += 1
                        continue
                    unpacked += size - 16 < used <= size
                    if os.path.basename(path) in packed_arcs:
                        new = compress_page(raw, width)
                        again += decompress_page(new + bytes(16))[0] == raw
                        fits += len(new) <= size
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
    print("%d compressed pages: %d unpack to exactly their size, %d are in another format" % (packed, unpacked, odd))
    if packed_arcs:
        print("packed again (%s): %d give the same picture, %d fit their slot" % (", ".join(packed_arcs), again, fits))


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
        cmd_check(a[1:])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
