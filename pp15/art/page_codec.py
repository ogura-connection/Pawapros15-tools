"""Decode and encode one texture page of an .arc file: raw tiled pages and the game's packed ("compressed") pages.

A page is a 128x128 picture of palette indices. The file stores it one of three ways: raw 4 bits per pixel (8,192 bytes,
8x8 pixel tiles), raw 8 bits per pixel (16,384 bytes, 8x4 tiles), or packed, whenever the size is anything else. A
packed page is stored row by row and shrinks runs of one colour into rectangles; the font glyphs of fonttex2.rel use the
same code (pp15/build/font.py). decode_indices and encode_indices convert between a page's bytes and a (128, 128) uint8
array; for a packed page the encoder searches for the smallest result and raises ValueError if it no longer fits the
slot the original occupied (an English page may not be larger than the Japanese one).

  decode_indices(d, off, size)           page bytes -> (128, 128) array of palette indices
  encode_indices(idx, size, bits)        the inverse; `bits` as returned by page_bits
  page_bits(d, off, size)                4 or 8 bits per pixel; negative for a padded raw page
  raw_size(d, off, size)                 8192 or 16384: the size once unpacked
  is_compressed(size), padded_raw(...)   how a page of a given size is stored
  decompress_page(data), compress_page(raw, width)   the packed format itself
"""
import heapq

import numpy as np

from pp15.art.gx_pixels import untile

PAGE = 128                     # side of every texture page, in pixels
RAW_SIZE_4BIT = 8192           # bytes of a raw 4-bit page (128 * 128 / 2)
RAW_SIZE_8BIT = 16384          # bytes of a raw 8-bit page
MAX_RECT = 19                  # the packer's rectangles are at most 19 x 19 cells

# ── Compressed pages ──────────────────────────────────────────────────────
# u16 little-endian header: low 13 bits = number of flag bytes, bit 14 = 4 bits per pixel (rows of
# 64 bytes, two pixels each), clear = 8 bits per pixel (rows of 128 bytes). Flag bytes follow, then the
# literal bytes; the symbol is padded to 16 bytes. Rows are plain raster rows, not GX tiles. Going
# through the page left to right, top to bottom, every byte not already covered takes one flag bit:
# 0 = one literal byte; 1 = a rectangle (width, height as 2 bits for 1..3, or 00 + 4 bits for 4..19)
# filled with one literal byte. The font glyphs of fonttex2.rel use the same code (pp15/build/font.py).

def is_compressed(size: int) -> bool:
    """True if a page of this many bytes is stored packed (anything but the two raw sizes)."""
    return size not in (RAW_SIZE_4BIT, RAW_SIZE_8BIT)


def padded_raw(d, off, size):
    """A raw page stored with 16 bytes of padding (8208 / 16400 bytes; pena_sub.arc g3_psp_0, vs_st.arc s5_k*): the
    same sizes also occur as compressed pages, so the content decides (it does not unpack)."""
    if size not in (8208, 16400):
        return False
    try:
        decompress_page(d[off:off + size])
        return False
    except Exception:
        return True


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
    """Append a rectangle side v (1..19) to the flag bits: 2 bits for 1..3, else 00 and 4 bits for v - 4."""
    bits += [v >> 1, v & 1] if v <= 3 else [0, 0] + [(v - 4) >> k & 1 for k in (3, 2, 1, 0)]


def _rectangles(g, width, tall, by_column):
    """Cover the page with one-colour rectangles of up to 19x19, largest area first (what the game's
    own packer does, to judge by its output). Returns {(y, x): (w, rows)} for rectangles of 2+ cells."""
    run = np.ones((PAGE, width), np.int32)                  # equal cells to the right, capped at 19
    for x in range(width - 2, -1, -1):
        run[:, x] = np.where(g[:, x] == g[:, x + 1], np.minimum(run[:, x + 1] + 1, MAX_RECT), 1)
    best, minrun, alive = run.copy(), run.copy(), np.ones((PAGE, width), bool)
    for r in range(2, MAX_RECT + 1):                                  # best area anchored at every cell
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
        v, w_ok, now = gl[y][x], MAX_RECT, (1, 1, 1)              # the best rectangle still free at this cell
        for r in range(1, MAX_RECT + 1):
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
    """4 or 8 bits per pixel; -4 / -8 for a padded raw page (encode_indices then writes it raw)."""
    if padded_raw(d, off, size):
        return -4 if size == 8208 else -8
    if is_compressed(size):
        return 4 if d[off + 1] & 0x40 else 8
    return 4 if size == RAW_SIZE_4BIT else 8


def raw_size(d, off, size):
    """Size of the page once unpacked: 8192 (4 bits per pixel) or 16384."""
    return RAW_SIZE_4BIT if abs(page_bits(d, off, size)) == 4 else RAW_SIZE_8BIT


def decode_indices(d, off, size):
    """Palette indices of a page as a 128x128 uint8 array (C4 tiles of 8x8, C8 tiles of 8x4, or a
    compressed page in raster order)."""
    if padded_raw(d, off, size):
        size -= 16
    elif is_compressed(size):
        raw, width, _ = decompress_page(d[off:off + size])
        raw = np.frombuffer(raw, dtype=np.uint8)
        return (np.stack([raw >> 4, raw & 15], -1) if width == 64 else raw).reshape(PAGE, PAGE)
    raw = np.frombuffer(d, dtype=np.uint8, count=size, offset=off)
    if size == RAW_SIZE_4BIT:
        return untile(np.stack([raw >> 4, raw & 15], -1).reshape(-1), PAGE, PAGE, 8, 8)
    return untile(raw, PAGE, PAGE, 4, 8)


def encode_indices(idx, size, bits=None):
    """Inverse of decode_indices: the page bytes for a 128x128 index array. A compressed page
    (bits = 4 or 8) is packed again and padded to `size`; ValueError if it no longer fits."""
    idx = np.ascontiguousarray(idx, dtype=np.uint8)
    if bits in (-4, -8):                                  # padded raw page: raw bytes + 16 bytes of padding
        return encode_indices(idx, size - 16) + bytes(16)
    if is_compressed(size):
        flat = idx.reshape(-1)
        raw = ((flat[0::2] << 4) | flat[1::2]).astype(np.uint8).tobytes() if bits == 4 else flat.tobytes()
        packed = compress_page(raw, 64 if bits == 4 else 128)
        if len(packed) > size:
            raise ValueError("compressed page needs %d bytes, its slot has %d" % (len(packed), size))
        return packed + bytes(size - len(packed))
    if size == RAW_SIZE_4BIT:
        t = idx.reshape(PAGE // 8, 8, PAGE // 8, 8).swapaxes(1, 2).reshape(-1)
        return ((t[0::2] << 4) | t[1::2]).astype(np.uint8).tobytes()
    return idx.reshape(PAGE // 4, 4, PAGE // 8, 8).swapaxes(1, 2).reshape(-1).tobytes()
