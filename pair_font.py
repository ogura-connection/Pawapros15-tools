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
A glyph is 28 rows x 11 bytes (two 4-bit pixels per byte), compressed (see decompress_glyph.py).

  pair_font.py preview "Some text" [out.png]   render text as it will look, both fonts

rebuild_scripts.py calls this module during a build; there is nothing else to run by hand.
Needs Pillow and a monospaced TrueType font (FONT_FILE below, macOS Menlo by default).
"""
import os
import struct
import sys

from PIL import Image, ImageDraw, ImageFilter, ImageFont

from decompress_glyph import decompress_glyph

FONT_FILE, FONT_INDEX = "/System/Library/Fonts/Menlo.ttc", 1      # Menlo Bold
CELL_W, CELL_H, ROW_BYTES = 22, 28, 11
SS = 8                                                           # supersampling factor
# (letter advance, baseline row, cap height in rows) per font
LARGE = {"adv": 11, "base": 22, "cap": 17.0, "ink_w": 9.4}
SMALL = {"adv": 8, "base": 14, "cap": 11.5, "ink_w": 7.0}
FONTS = (("small", 0x000000, SMALL), ("large", 0x05DF64, LARGE))
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
            rows = [[15 - round(7 * cov.getpixel((x, y)) / 255) for x in range(CELL_W)] for y in range(CELL_H)]
        _cache[key] = rows
    return _cache[key]


def to_grid(rows):
    """28x22 shades -> the 308 bytes the compressor takes."""
    return [rows[y][2 * b] << 4 | rows[y][2 * b + 1] for y in range(CELL_H) for b in range(ROW_BYTES)]


def split_pairs(text):
    """ASCII text -> letter pairs, the last one padded with a space."""
    return [(text[i:i + 2] + " ")[:2] for i in range(0, len(text), 2)]


# ── Reading the game's font (previews, checks) ────────────────────────────

def font_table(sec4, pos):
    count = struct.unpack_from("<H", sec4, pos + 2)[0]
    return struct.unpack_from("<%dI" % count, sec4, pos + 4), pos + 4 + count * 4


def game_glyph(sec4, pos, index):
    offsets, base = font_table(sec4, pos)
    end = offsets[index + 1] if index + 1 < len(offsets) else offsets[index] + 400
    out, _ = decompress_glyph(sec4[base + offsets[index]:base + end])
    return [[(out[y * 16 + x // 2] >> 4) if x % 2 == 0 else (out[y * 16 + x // 2] & 15)
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
