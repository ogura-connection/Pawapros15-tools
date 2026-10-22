"""Read the untouched Japanese .arc files: the pages and sprites of the original art, for styles that copy or clean a piece of it.

Some styles in pp15/art/styles/ (eikan_school.py, logo_pictures.py) need to see what a sprite looked like before any
English was drawn, for example to wipe the Japanese lettering off a plate and keep the plate. These classes open the
saved original of an .arc (or the installed file if none was saved) and hand out its banks and sprites.

  Arc(name)                         one .arc file: Arc.bank(name) -> Bank, Arc.resolve(data, ref) -> bank dict
  Bank                              one sprite bank of an Arc: page(n), parts_of(sprite), index_image(sprite)

`ref` strings name a bank: "name" (the first bank of that name), "name#k" (the k-th bank of the file) or
"pages+sprites" (the pages of one bank with the sprite tables of another; see textures.bank_named).
"""
import os

import numpy as np

from pp15 import config
from pp15.art import textures

FLAG_MIRROR_X = 0x80      # sprite part flag: drawn mirrored left-right
FLAG_MIRROR_Y = 0x40      # sprite part flag: drawn mirrored top-bottom


class Arc:
    """One .arc file of the original game: its bytes, symbols and banks."""

    def __init__(self, name: str, share_pal=None):
        self.name = name
        src = os.path.join(textures.ORIG_ARC_DIR, name)
        if not os.path.exists(src):
            src = os.path.join(config.DATA_FILES, name)
        with open(src, "rb") as f:
            self.data = f.read()
        self.syms = textures.elf_symbols(self.data)
        self.banks = textures.banks(self.data, self.syms)
        self.share_pal = share_pal

    @property
    def D(self) -> bytes:
        """The file bytes; the name `D` is what pp15/art/styles/logo_pictures.py reads."""
        return self.data

    def bank(self, name: str) -> "Bank":
        """The first bank called `name`."""
        return Bank(self, next(b for b in self.banks if b["name"] == name))

    def resolve(self, data: bytes, ref: str) -> dict:
        """The bank dict of `ref` in a copy of the file's bytes (the original or the patched result): "name", "name#k",
        or "pages_ref+sprites_ref" (what Bank.key gives for a bank built with sprites=)."""
        banks = textures.banks(data, textures.elf_symbols(data))
        if "+" in ref:
            pages_ref, sprites_ref = ref.split("+")
            prefix = None
            if "@" in sprites_ref:
                sprites_ref, prefix = sprites_ref.split("@")
            sprites = textures.bank_named(banks, sprites_ref)["sprites"]
            if prefix:
                sprites = {n: ps for n, ps in sprites.items() if n.startswith("opd_" + prefix + "_")}
            return dict(textures.bank_named(banks, pages_ref), sprites=sprites)
        if "#" in ref:
            return textures.bank_named(banks, ref)
        same = [b for b in banks if b["name"] == ref]
        if len(same) > 1 and not same[0]["sprites"] and same[1]["sprites"]:
            return dict(same[0], sprites=same[1]["sprites"])
        return same[0]


class Bank:
    """A sprite bank of an Arc, with its pages decoded on demand."""

    def __init__(self, arc: Arc, bank: dict):
        self.arc, self.b, self.name = arc, bank, bank["name"]
        self._pages = {}

    def page(self, n: int) -> np.ndarray:
        """Page n as a (128, 128) array of palette indices."""
        if n not in self._pages:
            self._pages[n] = textures.decode_indices(self.arc.data, *self.b["pages"][n])
        return self._pages[n]

    def parts_of(self, sprite: str, pages=None, palettes=None) -> list:
        """The parts of the sprite whose symbol ends in _<sprite>, optionally only those on `pages` / in `palettes`."""
        ps = next(p for n, p in self.b["sprites"].items() if n.endswith("_" + sprite))
        return [p for p in ps if (pages is None or p.page in pages) and (palettes is None or p.palette in palettes)]

    def index_image(self, sprite: str, pages=None, palettes=None, pad: int = 8) -> tuple:
        """(array of palette indices of the sprite's parts, x0, y0) with `pad` clear rows / columns round it."""
        ps = self.parts_of(sprite, pages, palettes)
        x0 = min(p.x for p in ps) - pad
        y0 = min(p.y for p in ps) - pad
        x1 = max(p.x + p.x1 - p.x0 for p in ps) + pad
        y1 = max(p.y + p.y1 - p.y0 for p in ps) + pad
        img = np.zeros((y1 - y0, x1 - x0), int)
        for p in ps:
            t = self.page(p.page)[p.y0:p.y1, p.x0:p.x1]
            if p.flags & FLAG_MIRROR_X:
                t = t[:, ::-1]
            if p.flags & FLAG_MIRROR_Y:
                t = t[::-1]
            sl = img[p.y - y0:p.y - y0 + t.shape[0], p.x - x0:p.x - x0 + t.shape[1]]
            sl[t > 0] = t[t > 0]
        return img, x0, y0
