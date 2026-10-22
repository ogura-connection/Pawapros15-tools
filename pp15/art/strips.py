"""Redraw names that the game cuts out of a text atlas, when the sprites doing the cutting live in another file.

Some Japanese names (team names, stadium names) are stored once in a large "atlas" picture and shown through small
sprites of a different .arc file. Both files must keep agreeing, so the English is drawn into each sprite's own picture
(its parts side by side, as the game assembles them) and written back into the page rectangles those parts read from.
Every other reader of the atlas then still finds each name where it was.

  paint_strips(entry, d, banks, pages, project)   draw one "strips" entry of a spec into the atlas pages
  strip_sprites(arc_name, prefix)                 the sprite tables opd_<prefix>_NN of another .arc
  write_sprite_parts(entries, d)                  new part lists for sprite tables ("sprite_parts" entries)
"""
import json
import os
import struct

import numpy as np

from pp15 import config
from pp15.art import textures
from pp15.art.textures import PAGE, bank_named, decode_indices, elf_symbols
from pp15.art.typeset import RENDER, typeset

SPRITE_HEADER_BYTES = 10      # a sprite table starts with 10 bytes (byte 0 = number of parts), then 10 bytes per part
PART_BYTES = 10
MAX_PAGE_NUMBER = 64          # sprite parts name their page in 6 bits
MIRROR_FLAGS = 0xC0           # top two bits of a part's page byte: mirrored / flagged


def strip_sprites(arc_name: str, prefix: str) -> dict:
    """{sprite id: [(page, palette, ox, oy, x0, y0, x1, y1)]} of the tables opd_<prefix>_NN of another .arc (its saved
    original if there is one): the sprites that cut names out of a text atlas (gameplay.arc h3_tnm_0 / y5_knm_0 /
    y4r_skn_0 draw the pages of dscn_str.arc). Parts a spec gives in its "sprite_parts" list replace the file's own."""
    path = os.path.join(textures.ORIG_ARC_DIR, arc_name)
    if not os.path.exists(path):
        path = os.path.join(config.DATA_FILES, arc_name)
    with open(path, "rb") as f:
        g = f.read()
    syms = elf_symbols(g)
    out = {}
    for k in sorted(n for n in syms if n.startswith("opd_" + prefix + "_")):
        off = syms[k][0]
        ps = []
        for i in range(g[off]):
            start = off + SPRITE_HEADER_BYTES + PART_BYTES * i
            q = g[start:start + PART_BYTES]
            if q[0] & MIRROR_FLAGS:
                raise ValueError("%s part %d is mirrored / flagged: not supported" % (k, i))
            oy, ox = struct.unpack(">hh", q[2:6])
            ps.append((q[0], q[1], ox, oy, q[7], q[6], q[9], q[8]))
        out[k[len(prefix) + 5:]] = ps
    over = os.path.join(config.SPECS_DIR, os.path.splitext(os.path.basename(arc_name))[0] + ".json")
    if os.path.exists(over):                        # parts that file's spec gives the tables ("sprite_parts")
        with open(over) as f:
            for e in json.load(f).get("sprite_parts", ()):
                if e["symbol"].startswith("opd_" + prefix + "_"):
                    out[e["symbol"][len(prefix) + 5:]] = [tuple(p) for p in e["parts"]]
    return out


def write_sprite_parts(entries: list, d: bytes) -> list:
    """[(file offset, bytes)] that give sprite tables new parts: [{"symbol": "opd_h3_tnm_0_11",
    "parts": [[page, palette, ox, oy, x0, y0, x1, y1], ...]}]. A table keeps its size: as many parts as it had."""
    syms = elf_symbols(d)
    out = []
    for e in entries:
        off = syms[e["symbol"]][0]
        if len(e["parts"]) != d[off]:
            raise ValueError("%s has %d parts, %d given" % (e["symbol"], d[off], len(e["parts"])))
        for i, (pg, pal, ox, oy, x0, y0, x1, y1) in enumerate(e["parts"]):
            if not (0 <= pg < MAX_PAGE_NUMBER and 0 <= x0 < x1 <= PAGE and 0 <= y0 < y1 <= PAGE):
                raise ValueError("%s part %d: bad rectangle" % (e["symbol"], i))
            out.append((off + SPRITE_HEADER_BYTES + PART_BYTES * i,
                        struct.pack(">BBhhBBBB", pg, pal, oy, ox, y0, x0, y1, x1)))
    return out


def _clear_pages(entry: dict, atlas_pages: list, d: bytes, bank: dict, pages: dict) -> None:
    """Apply the entry's "clear" setting: True empties every page of the set, a list of [page of the set, x0, y0, x1, y1]
    empties those rectangles."""
    clear = entry.get("clear")
    for i, k in enumerate(atlas_pages):
        rects = [(0, 0, PAGE, PAGE)] if clear is True else [r[1:] for r in clear or () if r[0] == i]
        for x0, y0, x1, y1 in rects:
            if (entry["bank"], k) not in pages:
                pages[(entry["bank"], k)] = decode_indices(d, *bank["pages"][k]).copy()
            pages[(entry["bank"], k)].reshape(PAGE, PAGE)[y0:y1, x0:x1] = 0


def _sprite_extent(parts: list) -> tuple:
    """(x_min, y_min, width, height) of the screen area a sprite's parts cover."""
    x_min = min(p[2] for p in parts)
    y_min = min(p[3] for p in parts)
    x_max = max(p[2] + p[6] - p[4] for p in parts)
    y_max = max(p[3] + p[7] - p[5] for p in parts)
    return x_min, y_min, x_max - x_min, y_max - y_min


def _draw_item(item: dict, entry: dict, parts: list, pages: dict, atlas_pages: list, painted: set, project) -> np.ndarray:
    """The picture of one item: its text styled and placed inside the sprite's area. A second word for a sprite is drawn
    over what the first one left there. Raises if the art is wider than the sprite or has ink where no part shows it."""
    label = "strip %s %s" % (entry["sprite_prefix"], item["sprite"])
    x_min, y_min, width, height = _sprite_extent(parts)
    shown = np.zeros((height, width), bool)
    for pg, pal, ox, oy, x0, y0, x1, y1 in parts:
        shown[oy - y_min:oy - y_min + y1 - y0, ox - x_min:ox - x_min + x1 - x0] = True
    ink, base = typeset(item["text"], item["font"], project)
    art, art_base = RENDER[item["style"]](ink, base)
    h, w = art.shape
    if w > width or h > height:
        raise ValueError("%s: %r is %dx%d, the sprite %dx%d" % (label, item["text"], w, h, width, height))
    x = item.get("dx", 0) if item.get("align") == "left" else (width - w) // 2 + item.get("dx", 0)
    y = item["baseline"] - art_base if "baseline" in item else (height - h) // 2 + item.get("dy", 0)
    if x < 0 or y < 0 or x + w > width or y + h > height:
        raise ValueError("%s: %r placed outside the sprite" % (label, item["text"]))
    canvas = np.zeros((height, width), np.uint8)
    if item["sprite"] in painted:                # a second word of the same sprite: drawn over the first
        for pg, pal, ox, oy, x0, y0, x1, y1 in parts:
            canvas[oy - y_min:oy - y_min + y1 - y0, ox - x_min:ox - x_min + x1 - x0] = \
                pages[(entry["bank"], atlas_pages[pg])][y0:y1, x0:x1]
    painted.add(item["sprite"])
    area = canvas[y:y + h, x:x + w]
    area[art > 0] = art[art > 0]
    if (canvas > 0)[~shown].any():
        raise ValueError("%s: %r has ink where no part shows it" % (label, item["text"]))
    return canvas


def _store_item(item: dict, entry: dict, parts: list, canvas: np.ndarray, d: bytes, bank: dict, pages: dict,
                atlas_pages: list, owner: dict) -> None:
    """Write the picture of an item back into the atlas page rectangles of its parts. Two sprites that share a rectangle
    must draw the same pixels there; `owner` remembers who wrote each pixel."""
    x_min, y_min, _, _ = _sprite_extent(parts)
    for pg, pal, ox, oy, x0, y0, x1, y1 in parts:
        key = (entry["bank"], atlas_pages[pg])
        if key not in pages:
            pages[key] = decode_indices(d, *bank["pages"][atlas_pages[pg]]).copy()
        new = canvas[oy - y_min:oy - y_min + y1 - y0, ox - x_min:ox - x_min + x1 - x0]
        for yy in range(y0, y1):
            for xx in range(x0, x1):
                v = new[yy - y0, xx - x0]
                o = owner.get((key, yy, xx))
                if o is not None and o[1] != v and o[0] != item["sprite"]:
                    raise ValueError("strip %s: sprites %s and %s share page %d (%d, %d) but differ there"
                                     % (entry["sprite_prefix"], o[0], item["sprite"], atlas_pages[pg], xx, yy))
                owner[(key, yy, xx)] = (item["sprite"], v)
        pages[key][y0:y1, x0:x1] = new


def paint_strips(entry: dict, d: bytes, banks: list, pages: dict, project=None) -> None:
    """A "strips" entry: names stored in a text atlas (pages of `bank` whose names start with `pages`, e.g.
    "tex_h3_tnm") and cut out by sprite tables of ANOTHER file ("sprites_arc", "sprite_prefix"). The sprites are left as
    they are: each item's English is drawn into the sprite's own picture (its parts side by side, as the game draws
    them) and written back into the page rectangles of its parts, so every reader of the atlas still finds each name
    where it was. {"bank", "pages", "sprites_arc", "sprite_prefix",
     "items": [{"sprite": "03", "text": "...", "font": "ttf:...", "style": "...", "align": "centre" | "left",
                "dx": 0, "dy": 0, "baseline": row}]}  (vertically centred on the strip, or its baseline on `baseline`;
    "left" starts at column `dx`). Several items may name one sprite (words placed one by one: the second is drawn
    over the first); names whose sprites share a rectangle (オール・セントラル / オール・パシフィック) must draw it alike.
    Raises when the art is wider than the sprite, when ink falls where no part shows it, or when two items write
    different pixels into a rectangle they share. "clear": true empties every page of the set first (names laid out
    anew with "sprite_parts"), or a list [[page of the set, x0, y0, x1, y1], ...] empties those rectangles.
    `pages` {(bank name, page number): index array} is edited in place."""
    bank = bank_named(banks, entry["bank"])
    atlas_pages = [k for k, n in enumerate(bank["page_names"]) if n.startswith(entry["pages"])]
    sprites = strip_sprites(entry["sprites_arc"], entry["sprite_prefix"])
    _clear_pages(entry, atlas_pages, d, bank, pages)
    owner, painted = {}, set()
    for item in entry["items"]:
        parts = sprites[item["sprite"]]
        canvas = _draw_item(item, entry, parts, pages, atlas_pages, painted, project)
        _store_item(item, entry, parts, canvas, d, bank, pages, atlas_pages, owner)
