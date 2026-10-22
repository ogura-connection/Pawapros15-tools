#!/usr/bin/env python3
"""
pair_font.py - two-letters-per-cell English font for Jikkyou Powerful Pro Yakyuu 15 (Wii)

The game draws text in fixed cells and its font has only full-width Latin letters, so one
letter per cell gives 17 letters per dialogue line and doubles the script size. This module
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
import collections
import json
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
# NARROW pairs: the match score bug draws the LARGE font at about 0.9 scale with a cell advance of only 17 screen
# pixels (the cell is 22 wide), so the next cell paints over the right ~3 columns of every cell: the second letter of
# "Ho" lost its right edge ("Hc"). Names that the score bug shows (the school and team names of sct_main.rel) use
# their own glyph slots, key NARROW + pair, with the two letters inside the first 17 columns.
NARROW = "\x02"
NARROW_LARGE = {"adv": 8, "base": 22, "cap": 17.0, "ink_w": 7.2}
NARROW_SMALL = {"adv": 6.5, "base": 14, "cap": 11.5, "ink_w": 5.6}
FONTS = (("small", 0x000000, SMALL), ("large", 0x05DF64, LARGE))
FONT_END = {0x000000: 0x05DF64, 0x05DF64: 0x117400}             # each font's space ends at the next one
KANJI_SLOTS = range(706, 3744)
# Glyph slots that hold a symbol the code draws by number, not text a scan can see: never given to a letter
# pair. 0xE77 (3703) is the arrow cursor of the My Life menus (ore_work.rel sec1+0x2DF4 and gdt_pn.rel
# sec1+0xC6E0 store it as the one-cell string "0xE77, 0xFFFF" and draw it); as a pair slot it showed "9"
# in front of the first menu line. No other code word loads a number in 0xE50..0xE9F as a glyph.
RESERVED_GLYPHS = frozenset({0xE77})
# The game's own full-width Latin letters (name entry, names typed by the player, ＭＶＰ ...) are redrawn as one
# letter of this font, centred, so a typed name looks like the English around it. Key: SINGLE + the letter.
SINGLE = "\x01"
FULLWIDTH = {chr(0xFF21 + i): chr(0x41 + i) for i in range(26)} | {chr(0xFF41 + i): chr(0x61 + i) for i in range(26)}
_cache, _faces = {}, {}


def _coverage(pair, m):
    """Ink coverage of a letter pair at SS times the cell size, as an 'L' image."""
    mkey = (m["adv"], m["ink_w"])
    if mkey not in _faces:
        probe = ImageFont.truetype(FONT_FILE, 1000, index=FONT_INDEX)
        adv = probe.getlength("M") / 1000.0                          # advance in em
        cap = -probe.getbbox("H", anchor="ls")[1] / 1000.0           # cap height in em
        em = m["ink_w"] * SS / adv
        _faces[mkey] = (ImageFont.truetype(FONT_FILE, round(em), index=FONT_INDEX),
                            m["cap"] * SS / (cap * em))              # face, vertical stretch
    face, stretch = _faces[mkey]
    h = int(CELL_H * SS / stretch) + 1
    img = Image.new("L", (CELL_W * SS, h), 0)
    draw = ImageDraw.Draw(img)
    if pair.startswith(SINGLE):                                       # one letter, centred in the cell
        ch = pair[1]
        draw.text(((CELL_W * SS - face.getlength(ch)) / 2, m["base"] * SS / stretch), ch, font=face, fill=255, anchor="ls")
        pair = ""
    for k, ch in enumerate(pair):
        if ch != " ":
            x = k * m["adv"] * SS + (m["adv"] * SS - face.getlength(ch)) / 2
            draw.text((x, m["base"] * SS / stretch), ch, font=face, fill=255, anchor="ls")
    return img.resize((CELL_W * SS, CELL_H * SS), Image.LANCZOS)


def render_pair(pair, large):
    """A letter pair as 28 rows of 22 shade values (0..15)."""
    key = (pair, large)
    if key not in _cache:
        narrow = pair.startswith(NARROW)
        hi = _coverage(pair[1:] if narrow else pair,
                       (NARROW_LARGE if narrow else LARGE) if large else (NARROW_SMALL if narrow else SMALL))
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


def segments(text):
    """Text -> ('pair', 'ab') | ('char', c) | ('newline', None). Pairing restarts on every line and
    after every non-ASCII character, so a pair never straddles them."""
    buf = ""
    for ch in text.replace("\\n", "\n") + "\n":
        if 0x20 <= ord(ch) <= 0x7E:
            buf += ch
            continue
        for pair in split_pairs(buf):
            yield "pair", pair
        buf = ""
        yield ("newline", None) if ch == "\n" else ("char", ch)


def text_segments(text):
    return list(segments(text))[:-1]          # without the newline added at the end


# ── Which glyph slots are free ────────────────────────────────────────────

def other_text_usage(mods, skip):
    """How often each glyph appears in text outside the Success scripts (heuristic scan of all
    modules for 16-bit glyph strings and 12-bit packed text). Cached in _work/glyph_usage2.json.
    A 16-bit string counts when it has kana in it, or when it is kanji only and ends with 0xFFFF
    (the short labels of the string tables: positions, school names, record titles)."""
    import scan_story as S
    path = os.path.join(S.WORK_DIR, "glyph_usage2.json")
    if os.path.exists(path):
        with open(path) as f:
            return collections.Counter({int(k): v for k, v in json.load(f).items()})
    print("Scanning all modules for text outside the scripts (once, about a minute)...")
    use = collections.Counter()
    for m in mods.values():
        if m.name in skip:
            continue
        for sec in m.sections:
            d = m.sec_data(sec["index"])
            if sec["exec"] or len(d) < 8:
                continue
            for _, units in S.find_packed_text(d):
                use.update(u for u in units if u <= S.MAX_GLYPH)
            run = []
            for v in struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2]) + (0,):
                if 0 < v <= S.MAX_GLYPH:
                    run.append(v)
                    continue
                if len(run) >= 3 and sum(282 <= u <= 450 for u in run) >= 2:
                    use.update(run)
                elif v == 0xFFFF and len(run) >= 2 and all(u >= 282 for u in run) and any(u >= 706 for u in run):
                    use.update(run)
                run = []
    with open(path, "w") as f:
        json.dump(use, f)
    return use


def _name_cells(rec):
    """Six cells of a player name: 0 = no name, 1 = a name, 2 = a name with kanji. A name is text
    glyphs with at most one blank cell inside (two kanji are spread out: 'te, blank, zuka') and
    blank cells behind."""
    n = len(rec)
    while n and rec[n - 1] == 0:
        n -= 1
    body = rec[:n]
    if not n or body.count(0) > 1 or any(v and v != 24 and not 282 <= v <= KANJI_SLOTS[-1] for v in body):
        return 0
    kanji = any(v >= KANJI_SLOTS[0] for v in body)
    return 2 if kanji and n - body.count(0) >= 2 and len(rec) - n >= 2 else 1


def name_usage(mods, skip):
    """The kanji of the name tables, which other_text_usage cannot see (no kana, and a blank cell in
    the middle of a two-kanji name). Cached in _work/name_kanji.json. Two layouts:
      - the surname list of main_prg.rel and scc_main.rel (1,856 names: team-mates, name entry):
        records of five 16-bit values, 0x1FFF, the announcer's call, three cells
      - player names in six cells, back to back or behind three other values (real players)"""
    import scan_story as S
    path = os.path.join(S.WORK_DIR, "name_kanji.json")
    if os.path.exists(path):
        with open(path) as f:
            return collections.Counter({int(k): v for k, v in json.load(f).items()})
    use = collections.Counter()
    for m in mods.values():
        if m.name in skip:
            continue
        for sec in m.sections:
            d = m.sec_data(sec["index"])
            if sec["exec"] or len(d) < 64:
                continue
            u = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
            i = 0
            while i + 5 <= len(u):
                j = i
                while j + 5 <= len(u) and u[j] == 0x1FFF and max(u[j + 2:j + 5]) <= KANJI_SLOTS[-1]:
                    j += 5
                if j - i >= 40:
                    for k in range(i, j, 5):
                        use.update(v for v in u[k + 2:k + 5] if v >= KANJI_SLOTS[0])
                i = max(j, i + 1)
            for stride, at in ((6, 0), (9, 3)):
                for phase in range(stride):
                    i = phase
                    while i + stride <= len(u):
                        j, good = i, 0
                        while j + stride <= len(u) and _name_cells(u[j + at:j + at + 6]):
                            good += _name_cells(u[j + at:j + at + 6]) == 2
                            j += stride
                        if j - i >= 6 * stride and good * 2 * stride >= j - i:
                            for k in range(i, j, stride):
                                use.update(v for v in u[k + at:k + at + 6] if v >= KANJI_SLOTS[0])
                        i = max(j, i + stride)
    with open(path, "w") as f:
        json.dump(use, f)
    return use


def allocate(pairs, usage, keep=()):
    """Give every letter pair a kanji slot: kanji no text uses first, then the least used, and the
    kanji in `keep` (the name tables) only when nothing else is left. Returns ({pair: glyph},
    number of slots taken from kanji that remaining text still uses, number taken from `keep`)."""
    free = sorted((g for g in KANJI_SLOTS if g not in RESERVED_GLYPHS), key=lambda g: (g in keep, usage.get(g, 0), -g))
    if len(pairs) > len(free):
        raise ValueError("%d different letter pairs, only %d glyph slots" % (len(pairs), len(free)))
    slots = dict(zip(sorted(pairs), free))
    return (slots, sum(1 for g in slots.values() if usage.get(g, 0) or g in keep),
            sum(1 for g in slots.values() if g in keep))


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


def pair_glyph(pair, large, cache):
    """Compressed glyph of a letter pair. cache: dict kept in _work/pair_glyphs.json by the caller."""
    m = (NARROW_LARGE if large else NARROW_SMALL) if pair.startswith(NARROW) else (LARGE if large else SMALL)
    key = "%s|%d|%s" % (FONT_FILE, FONT_INDEX, json.dumps([m, SS], sort_keys=True)) + "|" + pair
    if key not in cache:
        cache[key] = compress(to_grid(render_pair(pair, large))).hex()
    return bytes.fromhex(cache[key])


def build_font(rel_data, sec4_offset, slots, cache):
    """fonttex2.rel with letter pairs drawn into glyph slots. slots = {glyph index: pair}"""
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
        lines.append([])
        for kind, value in text_segments(text):
            if kind == "newline":
                lines.append([])
            else:
                lines[-1].append(render_pair(value, large) if kind == "pair"
                                 else game_glyph(sec4, pos, char_to_glyph(value)))
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
