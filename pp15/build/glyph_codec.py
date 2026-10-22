"""Read and write the game's font glyphs: the compressed 22x28 pixel pictures of single characters.

What the thing is: the module `fonttex2.rel` (a REL file is a code-and-data module the game loads while running;
see docs/GLOSSARY.md) holds two fonts in its section 4: a small one and a large outlined one used in dialogue.
Each font is a table of compressed glyphs, one per character number. A glyph is 28 rows of 22 pixels, stored as
28 rows x 11 bytes (two 4-bit pixels per byte). It is compressed per byte column: for each byte a flag bit says
"literal byte" or "fill: repeat this byte over a rectangle of up to 19 columns x 19 rows". Stored as: one byte n,
n bytes of flag bits, then the literal bytes.

Font dataset layout: u16 0, u16 glyph count, u32 offset per glyph (from the end of the table), glyph data; all
little-endian (unlike the rest of the file, which is big-endian).

Public functions:
    compress(grid)            308 bytes of pixels -> compressed glyph
    decompress(data)          compressed glyph -> (308 bytes, number of bytes it used); mirrors the game's own code
    to_grid(rows)             28 rows of 22 shade values -> the 308 bytes `compress` takes
    font_glyphs(sec4, pos)    the compressed bytes of every glyph of the font at sec4+pos
    pack_font(glyphs, size)   glyph list -> a font dataset of exactly `size` bytes
    game_glyph(sec4, pos, index)  one glyph of the game's own font as 28 rows of 22 shade values
"""
import struct

CELL_W, CELL_H = 22, 28     # pixels of one glyph cell
ROW_BYTES = 11              # bytes per pixel row: two 4-bit pixels each
MAX_RUN = 19                # the longest fill the format can express, in rows and in columns
GLYPH_PADDING = 400         # upper bound of one glyph's size, used to read the last glyph of a font


def to_grid(rows: list[list[int]]) -> list[int]:
    """28 rows of 22 shade values (0..15) -> the 308 bytes the compressor takes (two pixels per byte)."""
    return [rows[y][2 * b] << 4 | rows[y][2 * b + 1] for y in range(CELL_H) for b in range(ROW_BYTES)]


def _put_run_length(bits: list[int], v: int) -> None:
    """Append a run length to the flag bits: 1..3 as two bits, 4..19 as 00 followed by four bits."""
    bits += [v >> 1, v & 1] if v <= 3 else [0, 0] + [(v - 4) >> k & 1 for k in (3, 2, 1, 0)]


def compress(grid: list[int]) -> bytes:
    """Compress one glyph: 308 bytes (28 rows x 11) -> flag-count byte, flag bytes, literal bytes."""
    bits, lits, left = [], [], [0] * ROW_BYTES      # left[x]: rows still covered by a fill started above
    for y in range(CELL_H):
        x = 0
        while x < ROW_BYTES:
            if left[x]:
                left[x] -= 1
                x += 1
                continue
            v = grid[y * ROW_BYTES + x]
            width = 1
            while x + width < ROW_BYTES and not left[x + width] and grid[y * ROW_BYTES + x + width] == v:
                width += 1
            # best rectangle of v starting here: try every width, take the largest area
            best = (1, 1)
            for w in range(1, width + 1):
                rows = 1
                while rows < MAX_RUN and y + rows < CELL_H and all(grid[(y + rows) * ROW_BYTES + x + k] == v for k in range(w)):
                    rows += 1
                if w * rows > best[0] * best[1]:
                    best = (w, rows)
            w, rows = best
            if w * rows >= 2:
                bits.append(1)
                _put_run_length(bits, w)
                _put_run_length(bits, rows)
                for k in range(w):
                    left[x + k] = rows
                left[x] -= 1
            else:
                bits.append(0)
            lits.append(v)
            x += 1
    bits += [0] * (-len(bits) % 8)
    flags = bytes(sum(b << (7 - k) for k, b in enumerate(bits[i:i + 8])) for i in range(0, len(bits), 8))
    assert len(flags) < 256
    return bytes([len(flags)]) + flags + bytes(lits)


def decompress(data: bytes) -> tuple[list[int], int]:
    """Inverse of `compress`: returns (308 bytes of pixels, number of bytes of `data` the glyph used).

    Mirrors the game's own decoder (main_prg.rel section 1 +0x078800), so a glyph that decodes here decodes in game.
    """
    nflags, pos, lit = data[0], 0, 1 + data[0]

    def bit() -> int:
        """The next flag bit."""
        nonlocal pos
        b = data[1 + pos // 8] >> (7 - pos % 8) & 1 if pos // 8 < nflags else 0
        pos += 1
        return b

    def run_length() -> int:
        """The next run length (1..19), the inverse of _put_run_length."""
        v = bit() * 2 + bit()
        return v if v else 4 + bit() * 8 + bit() * 4 + bit() * 2 + bit()

    grid, left, value = [], [0] * ROW_BYTES, [0] * ROW_BYTES
    for _ in range(CELL_H):
        for x in range(ROW_BYTES):
            if left[x]:
                left[x] -= 1
                grid.append(value[x])
            elif bit() == 0:
                grid.append(data[lit])
                lit += 1
            else:
                w, rows = run_length(), run_length()
                for k in range(w):
                    if x + k < ROW_BYTES:
                        left[x + k], value[x + k] = rows, data[lit]
                lit += 1
                left[x] -= 1
                grid.append(value[x])
    return grid, lit


def font_glyphs(sec4: bytes, pos: int) -> list[bytes]:
    """The compressed data of every glyph of the font that starts at `pos` in section 4 of fonttex2.rel."""
    count = struct.unpack_from("<H", sec4, pos + 2)[0]
    offsets = struct.unpack_from("<%dI" % count, sec4, pos + 4)
    base = pos + 4 + count * 4
    assert list(offsets) == sorted(offsets)
    last = base + offsets[-1]
    ends = list(offsets[1:]) + [offsets[-1] + decompress(sec4[last:last + GLYPH_PADDING])[1]]
    return [bytes(sec4[base + a:base + b]) for a, b in zip(offsets, ends)]


def pack_font(glyphs: list[bytes], size: int) -> bytes:
    """A glyph list -> a font dataset of exactly `size` bytes (unused space filled with 0xFF).

    Raises ValueError when the glyphs need more than `size` bytes.
    """
    table, data = [], bytearray()
    for g in glyphs:
        table.append(len(data))
        data += g
    out = struct.pack("<HH%dI" % len(glyphs), 0, len(glyphs), *table) + bytes(data)
    if len(out) > size:
        raise ValueError("font needs %d bytes, %d available" % (len(out), size))
    return out + b"\xff" * (size - len(out))


def game_glyph(sec4: bytes, pos: int, index: int) -> list[list[int]]:
    """One glyph of the game's own font as 28 rows of 22 shade values (0..15)."""
    grid, _ = decompress(font_glyphs(sec4, pos)[index])
    return [[(grid[y * ROW_BYTES + x // 2] >> 4) if x % 2 == 0 else (grid[y * ROW_BYTES + x // 2] & 15)
             for x in range(CELL_W)] for y in range(CELL_H)]
