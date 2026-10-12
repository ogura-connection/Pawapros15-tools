#!/usr/bin/env python3
"""
pair_font.py - two-letters-per-cell English font for Jikkyou Powerful Pro Yakyuu 15 (Wii)

The game draws text in fixed cells and its font has only full-width Latin letters, so one
letter per cell gives 18 letters per dialogue line and doubles the script size. This module
draws PAIRS of half-width letters into single glyph cells and stores them in kanji slots the
remaining Japanese text does not use. English then needs one text unit per two letters.

fonttex2.rel section 4 holds the fonts (same glyph numbering in both):
  +0x000000  small font: 16x17 pixels used of the 22x28 cell, shades 8 (ink) .. 15 (background)
  +0x05DF64  large outlined font (dialogue): 22x28, shades 1 (ink) .. 9 (outline) .. 15 (background)
Each is: u16 0, u16 count (LE), u32 offsets[count] (LE, from the end of the table), glyph data.
A glyph is 28 rows x 11 bytes (two 4-bit pixels per byte), compressed per column: a flag bit
says "literal byte" or "fill: this byte for the next F columns and R rows" (F, R = 1..19).
Stored as: u8 n, n bytes of flag bits, then the literal bytes.

  pair_font.py preview "Some text" [out.png]   render text as it will look, both fonts

rebuild_scripts.py calls this module during a build; there is nothing else to run by hand.
Needs Pillow and a monospaced TrueType font (FONT_FILE below, macOS Menlo by default).
"""
import os
import struct
import sys

from PIL import Image, ImageDraw, ImageFilter, ImageFont

FONT_FILE, FONT_INDEX = "/System/Library/Fonts/Menlo.ttc", 1      # Menlo Bold
CELL_W, CELL_H, ROW_BYTES = 22, 28, 11
SS = 8                                                           # supersampling factor
# (letter advance, baseline row, cap height in rows) per font
LARGE = {"adv": 11, "base": 22, "cap": 17.0, "ink_w": 9.4}
SMALL = {"adv": 8, "base": 14, "cap": 11.5, "ink_w": 7.0}
FONTS = (("small", 0x000000, SMALL), ("large", 0x05DF64, LARGE))
FONT_END = {0x000000: 0x05DF64, 0x05DF64: 0x117400}             # each font's space ends at the next one
KANJI_SLOTS = range(706, 3744)
_cache = {}


def _coverage(pair, m):
    """Ink coverage of a letter pair at SS times the cell size, as an 'L' image."""
    if "font" not in m:
        probe = ImageFont.truetype(FONT_FILE, 1000, index=FONT_INDEX)
        adv = probe.getlength("M") / 1000.0                          # advance in em
        cap = -probe.getbbox("H", anchor="ls")[1] / 1000.0           # cap height in em
        m["em"] = m["ink_w"] * SS / adv
        m["font"] = ImageFont.truetype(FONT_FILE, round(m["em"]), index=FONT_INDEX)
        m["stretch"] = m["cap"] * SS / (cap * m["em"])               # vertical stretch
    h = int(CELL_H * SS / m["stretch"]) + 1
    img = Image.new("L", (CELL_W * SS, h), 0)
    draw = ImageDraw.Draw(img)
    for k, ch in enumerate(pair):
        if ch != " ":
            x = k * m["adv"] * SS + (m["adv"] * SS - m["font"].getlength(ch)) / 2
            draw.text((x, m["base"] * SS / m["stretch"]), ch, font=m["font"], fill=255, anchor="ls")
    return img.resize((CELL_W * SS, CELL_H * SS), Image.LANCZOS)


def render_pair(pair, large):
    """A letter pair as 28 rows of 22 shade values (0..15)."""
    key = (pair, large)
    if key not in _cache:
        hi = _coverage(pair, LARGE if large else SMALL)
        cov = hi.resize((CELL_W, CELL_H), Image.BOX)
        if large:
            ring = hi.point(lambda v: 255 if v > 96 else 0).filter(ImageFilter.MaxFilter(2 * 13 + 1))
            ring = ring.filter(ImageFilter.GaussianBlur(3)).resize((CELL_W, CELL_H), Image.BOX)
            rows = [[max(1, min(15, round(15 - 6 * ring.getpixel((x, y)) / 255 - 8 * cov.getpixel((x, y)) / 255)))
                     for x in range(CELL_W)] for y in range(CELL_H)]
        else:
            rows = [[15 - round(7 * min(1.0, 1.3 * cov.getpixel((x, y)) / 255)) for x in range(CELL_W)]
                    for y in range(CELL_H)]
        _cache[key] = rows
    return _cache[key]


def to_grid(rows):
    """28x22 shades -> the 308 bytes the compressor takes."""
    return [rows[y][2 * b] << 4 | rows[y][2 * b + 1] for y in range(CELL_H) for b in range(ROW_BYTES)]


def split_pairs(text):
    """ASCII text -> letter pairs, the last one padded with a space."""
    return [(text[i:i + 2] + " ")[:2] for i in range(0, len(text), 2)]


# ── Glyph compression ─────────────────────────────────────────────────────

def _varlen(bits, v):
    """1..3 as two bits, 4..19 as 00 + four bits."""
    bits += [v >> 1, v & 1] if v <= 3 else [0, 0] + [(v - 4) >> k & 1 for k in (3, 2, 1, 0)]


def compress(grid):
    """308 bytes (28 rows x 11) -> compressed glyph."""
    bits, lits, left = [], [], [0] * ROW_BYTES
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
                while rows < 19 and y + rows < CELL_H and all(grid[(y + rows) * ROW_BYTES + x + k] == v for k in range(w)):
                    rows += 1
                if w * rows > best[0] * best[1]:
                    best = (w, rows)
            w, rows = best
            if w * rows >= 2:
                bits.append(1)
                _varlen(bits, w)
                _varlen(bits, rows)
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


def decompress(data):
    """Compressed glyph -> (308 bytes, number of bytes consumed). Mirrors main_prg.rel sec1+0x078800."""
    nflags, pos, lit = data[0], 0, 1 + data[0]

    def bit():
        nonlocal pos
        b = data[1 + pos // 8] >> (7 - pos % 8) & 1 if pos // 8 < nflags else 0
        pos += 1
        return b

    def varlen():
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
                w, rows = varlen(), varlen()
                for k in range(w):
                    if x + k < ROW_BYTES:
                        left[x + k], value[x + k] = rows, data[lit]
                lit += 1
                left[x] -= 1
                grid.append(value[x])
    return grid, lit


# ── The font inside fonttex2.rel ──────────────────────────────────────────

def font_glyphs(sec4, pos):
    """Compressed data of every glyph of the font at sec4+pos."""
    count = struct.unpack_from("<H", sec4, pos + 2)[0]
    offsets = struct.unpack_from("<%dI" % count, sec4, pos + 4)
    base = pos + 4 + count * 4
    assert list(offsets) == sorted(offsets)
    ends = list(offsets[1:]) + [offsets[-1] + decompress(sec4[base + offsets[-1]:base + offsets[-1] + 400])[1]]
    return [bytes(sec4[base + a:base + b]) for a, b in zip(offsets, ends)]


def pack_font(glyphs, size):
    """Glyph list -> font dataset of exactly `size` bytes."""
    table, data = [], bytearray()
    for g in glyphs:
        table.append(len(data))
        data += g
    out = struct.pack("<HH%dI" % len(glyphs), 0, len(glyphs), *table) + bytes(data)
    if len(out) > size:
        raise ValueError("font needs %d bytes, %d available" % (len(out), size))
    return out + b"\xff" * (size - len(out))


def build_font(rel_data, sec4_offset, slots):
    """fonttex2.rel with letter pairs drawn into glyph slots. slots = {glyph index: pair}"""
    out = bytearray(rel_data)
    for name, pos, _ in FONTS:
        sec4 = rel_data[sec4_offset:]
        glyphs = font_glyphs(sec4, pos)
        for index, pair in slots.items():
            glyphs[index] = compress(to_grid(render_pair(pair, name == "large")))
        size = FONT_END[pos] - pos
        try:
            new = pack_font(glyphs, size)
        except ValueError as e:
            raise ValueError("%s font: %s" % (name, e))
        out[sec4_offset + pos:sec4_offset + pos + size] = new
    return bytes(out)


def game_glyph(sec4, pos, index):
    grid, _ = decompress(font_glyphs(sec4, pos)[index])
    return [[(grid[y * ROW_BYTES + x // 2] >> 4) if x % 2 == 0 else (grid[y * ROW_BYTES + x // 2] & 15)
             for x in range(CELL_W)] for y in range(CELL_H)]


def cmd_preview(text, out):
    """Render text with the pair font next to a line of the game's own glyphs."""
    import scan_story as S
    from pawapuro15_text_tools import char_to_glyph
    rel = S.Rel(os.path.join(S.WORK_DIR, "orig", "fonttex2.rel") if os.path.isdir(os.path.join(S.WORK_DIR, "orig"))
                else os.path.join(S.DATA_FILES, "fonttex2.rel"))
    sec4 = rel.sec_data(4)
    sample = "今日はオレにとって記念すべき初出勤の日。"
    scale, lines = 3, []
    for name, pos, m in FONTS:
        large = name == "large"
        lines.append([game_glyph(sec4, pos, char_to_glyph(c)) for c in sample])
        for part in text.split("\n"):
            lines.append([render_pair(p, large) for p in split_pairs(part)])
    w = max(len(l) for l in lines) * CELL_W
    img = Image.new("L", (w, len(lines) * CELL_H), 255)
    for r, line in enumerate(lines):
        for c, rows in enumerate(line):
            for y in range(CELL_H):
                for x in range(CELL_W):
                    img.putpixel((c * CELL_W + x, r * CELL_H + y), rows[y][x] * 17)
    img.resize((w * scale, len(lines) * CELL_H * scale), Image.NEAREST).save(out)
    print("wrote", out)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "preview":
        cmd_preview(sys.argv[2].replace("\\n", "\n"), sys.argv[3] if len(sys.argv) > 3 else "_work/pair_preview.png")
    else:
        print(__doc__)
