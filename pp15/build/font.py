"""Draw English letter pairs in the game's font, and put them into the font file.

What it is for: the game draws text in fixed cells, and its font has only full-width Latin letters, so one letter
per cell would give 17 letters per dialogue line and double the script size. This module draws PAIRS of narrow
letters into single glyph cells and stores them in kanji slots the remaining Japanese text does not use, so English
needs one text unit per two letters. (See "Pair font" in docs/GLOSSARY.md.)

The font file is section 4 of fonttex2.rel. It holds two fonts with the same glyph numbering (the byte format is
described in glyph_codec.py):
    +0x000000  small font: 16x17 pixels used of the 22x28 cell, shades 8 (ink) .. 15 (background)
    +0x05DF64  large outlined font (dialogue): 22x28, shades 1 (ink) .. 9 (outline) .. 15 (background)

Public names:
    FONTS, FONT_END                 where the two fonts lie inside section 4
    NARROW, NARROW_CELLS            marker and length of the narrow pairs used by the match score display
    SINGLE, FULLWIDTH               one centred letter in place of the game's own full-width letter
    render_pair(pair, large)        a letter pair as 28 rows of 22 shade values
    pair_glyph(pair, large, cache)  the compressed glyph of a pair (cached on disk by the caller)
    build_font(rel_data, sec4_offset, slots, cache)   fonttex2.rel with the pairs drawn into their slots
    text_segments                   cut text into pairs (from pair_text.py), kept here because other modules ask for it
    main(argv)                      `pp15 font preview TEXT [OUT.png]`: draw text as the game will show it

`python3 -m pp15 build` uses this module; there is nothing else to run by hand. Needs Pillow and a monospaced
TrueType font (FONT_FILE below, macOS Menlo by default).
"""
import argparse
import json
import os

from PIL import Image, ImageDraw, ImageFilter, ImageFont

from pp15 import config
from pp15.build.glyph_codec import (CELL_H, CELL_W, compress, font_glyphs, game_glyph, pack_font, to_grid)
from pp15.build.pair_text import text_segments
from pp15.glyphs import char_to_glyph
from pp15.script import scan

FONT_FILE, FONT_INDEX = "/System/Library/Fonts/Menlo.ttc", 1      # Menlo Bold
SUPERSAMPLE = 8                                                   # letters are drawn 8 times larger, then shrunk
# Letter metrics per font: advance = pixels from one letter to the next, base = baseline row, cap = height of a
# capital in rows, ink_w = target width of a letter's ink in pixels.
LARGE = {"adv": 11, "base": 22, "cap": 17.0, "ink_w": 9.4}
SMALL = {"adv": 8, "base": 14, "cap": 11.5, "ink_w": 7.0}
# NARROW pairs: the match score bug draws the LARGE font at about 0.9 scale with a cell advance of only 17 screen
# pixels (the cell is 22 wide), so the next cell paints over the right ~3 columns of every cell: the second letter of
# "Ho" lost its right edge ("Hc"). Names that the score bug shows (the school and team names of sct_main.rel) use
# their own glyph slots, key NARROW + pair, with the two letters inside the first 17 columns.
NARROW = "\x02"
NARROW_CELLS = 4        # the score bug shows four cells of a name (8 letters)
NARROW_LARGE = {"adv": 8, "base": 22, "cap": 17.0, "ink_w": 7.2}
NARROW_SMALL = {"adv": 6.5, "base": 14, "cap": 11.5, "ink_w": 5.6}
# (name, offset in section 4, letter metrics). The large font is the one dialogue boxes use.
FONTS = (("small", 0x000000, SMALL), ("large", 0x05DF64, LARGE))
FONT_END = {0x000000: 0x05DF64, 0x05DF64: 0x117400}             # each font's space ends where the next one starts
# The game's own full-width Latin letters (name entry, names typed by the player, ＭＶＰ ...) are redrawn as one
# letter of this font, centred, so a typed name looks like the English around it. Key: SINGLE + the letter.
SINGLE = "\x01"
FULLWIDTH = {chr(0xFF21 + i): chr(0x41 + i) for i in range(26)} | {chr(0xFF41 + i): chr(0x61 + i) for i in range(26)}

# Outline of the large font: ink above this coverage (of 255) is grown by this many pixels, then blurred.
OUTLINE_THRESHOLD, OUTLINE_GROW, OUTLINE_BLUR = 96, 13, 3

_shade_cache = {}       # (pair, large) -> rows of shades
_face_cache = {}        # (advance, ink width) -> (font face, vertical stretch)


def _coverage(pair: str, metrics: dict) -> Image.Image:
    """Ink coverage of a letter pair at SUPERSAMPLE times the cell size, as a greyscale ('L') image."""
    key = (metrics["adv"], metrics["ink_w"])
    if key not in _face_cache:
        probe = ImageFont.truetype(FONT_FILE, 1000, index=FONT_INDEX)
        adv = probe.getlength("M") / 1000.0                          # advance in em
        cap = -probe.getbbox("H", anchor="ls")[1] / 1000.0           # cap height in em
        em = metrics["ink_w"] * SUPERSAMPLE / adv
        _face_cache[key] = (ImageFont.truetype(FONT_FILE, round(em), index=FONT_INDEX),
                            metrics["cap"] * SUPERSAMPLE / (cap * em))   # face, vertical stretch
    face, stretch = _face_cache[key]
    height = int(CELL_H * SUPERSAMPLE / stretch) + 1
    img = Image.new("L", (CELL_W * SUPERSAMPLE, height), 0)
    draw = ImageDraw.Draw(img)
    baseline = metrics["base"] * SUPERSAMPLE / stretch
    if pair.startswith(SINGLE):                                       # one letter, centred in the cell
        ch = pair[1]
        draw.text(((CELL_W * SUPERSAMPLE - face.getlength(ch)) / 2, baseline), ch, font=face, fill=255, anchor="ls")
        pair = ""
    for k, ch in enumerate(pair):
        if ch != " ":
            x = k * metrics["adv"] * SUPERSAMPLE + (metrics["adv"] * SUPERSAMPLE - face.getlength(ch)) / 2
            draw.text((x, baseline), ch, font=face, fill=255, anchor="ls")
    return img.resize((CELL_W * SUPERSAMPLE, CELL_H * SUPERSAMPLE), Image.LANCZOS)


def render_pair(pair: str, large: bool) -> list[list[int]]:
    """A letter pair as 28 rows of 22 shade values (0..15). `large` selects the dialogue font, else the small one."""
    key = (pair, large)
    if key not in _shade_cache:
        narrow = pair.startswith(NARROW)
        hi = _coverage(pair[1:] if narrow else pair,
                       (NARROW_LARGE if narrow else LARGE) if large else (NARROW_SMALL if narrow else SMALL))
        cov = hi.resize((CELL_W, CELL_H), Image.BOX)
        if large:
            ring = hi.point(lambda v: 255 if v > OUTLINE_THRESHOLD else 0).filter(ImageFilter.MaxFilter(2 * OUTLINE_GROW + 1))
            ring = ring.filter(ImageFilter.GaussianBlur(OUTLINE_BLUR)).resize((CELL_W, CELL_H), Image.BOX)
            rows = [[max(1, min(15, round(15 - 6 * ring.getpixel((x, y)) / 255 - 8 * cov.getpixel((x, y)) / 255)))
                     for x in range(CELL_W)] for y in range(CELL_H)]
        else:
            rows = [[15 - round(7 * min(1.0, 1.3 * cov.getpixel((x, y)) / 255)) for x in range(CELL_W)]
                    for y in range(CELL_H)]
        _shade_cache[key] = rows
    return _shade_cache[key]


def pair_glyph(pair: str, large: bool, cache: dict) -> bytes:
    """The compressed glyph of a letter pair. `cache` is a dict the caller keeps in _work/pair_glyphs.json."""
    metrics = (NARROW_LARGE if large else NARROW_SMALL) if pair.startswith(NARROW) else (LARGE if large else SMALL)
    key = "%s|%d|%s" % (FONT_FILE, FONT_INDEX, json.dumps([metrics, SUPERSAMPLE], sort_keys=True)) + "|" + pair
    if key not in cache:
        cache[key] = compress(to_grid(render_pair(pair, large))).hex()
    return bytes.fromhex(cache[key])


def build_font(rel_data: bytes, sec4_offset: int, slots: dict, cache: dict) -> bytes:
    """fonttex2.rel with letter pairs drawn into glyph slots. slots = {glyph index: pair}.

    Raises ValueError when a font no longer fits its space. The file keeps its size.
    """
    out = bytearray(rel_data)
    for name, pos, _ in FONTS:
        sec4 = rel_data[sec4_offset:]
        glyphs = font_glyphs(sec4, pos)
        for index, pair in slots.items():
            glyphs[index] = pair_glyph(pair, name == "large", cache)
        size = FONT_END[pos] - pos
        try:
            new = pack_font(glyphs, size)
        except ValueError as e:
            raise ValueError("%s font: %s" % (name, e))
        out[sec4_offset + pos:sec4_offset + pos + size] = new
    return bytes(out)


def preview(text: str, out: str) -> None:
    """Write a picture of `text` drawn with the pair font, under a line of the game's own glyphs, for both fonts."""
    rel = scan.Rel(os.path.join(config.ORIG_DIR, "fonttex2.rel") if os.path.isdir(config.ORIG_DIR)
                   else os.path.join(config.DATA_FILES, "fonttex2.rel"))
    sec4 = rel.sec_data(4)
    sample = "今日はオレにとって記念すべき初出勤の日。"      # a line of real Japanese text for comparison
    scale, lines = 3, []
    for name, pos, _ in FONTS:
        large = name == "large"
        lines.append([game_glyph(sec4, pos, char_to_glyph(c)) for c in sample])
        lines.append([])
        for kind, value in text_segments(text):
            if kind == "newline":
                lines.append([])
            else:
                lines[-1].append(render_pair(value, large) if kind == "pair"
                                 else game_glyph(sec4, pos, char_to_glyph(value)))
    width = max(len(line) for line in lines) * CELL_W
    img = Image.new("L", (width, len(lines) * CELL_H), 255)
    for r, line in enumerate(lines):
        for c, rows in enumerate(line):
            for y in range(CELL_H):
                for x in range(CELL_W):
                    img.putpixel((c * CELL_W + x, r * CELL_H + y), rows[y][x] * 17)
    img.resize((width * scale, len(lines) * CELL_H * scale), Image.NEAREST).save(out)
    print("wrote", out)


def main(argv: list[str] | None = None) -> None:
    """`pp15 font preview TEXT [OUT.png]`."""
    ap = argparse.ArgumentParser(prog="pp15 font", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("preview", help="draw TEXT as the game will show it, in both fonts")
    p.add_argument("text", help="the English text; a backslash-n is a line break")
    p.add_argument("out", nargs="?", default=os.path.join(config.WORK_DIR, "pair_preview.png"),
                   help="picture to write (default: _work/pair_preview.png)")
    args = ap.parse_args(argv)
    if args.cmd == "preview":
        preview(args.text.replace("\\n", "\n"), args.out)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
