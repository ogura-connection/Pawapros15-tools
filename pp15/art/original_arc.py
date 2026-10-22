"""Read the untouched .arc files: the pages and sprites of the Japanese art, for styles that copy or clean a piece of it.

`Arc(name)` opens the saved original of an .arc (`textures.ORIG_ARC_DIR`, else the installed file in DATA/files).
`arc.bank(name)` gives a `Bank` (index pages and sprite parts); `arc.resolve(data, ref)` gives the bank dictionary a
reference like "name", "name#k" or "pages+sprites" stands for, in any copy of the file's bytes.

These are the few functions of the art-run scripts (gen_c_lib.py, kit.py in the scratch folder _work/ui_pages) that the
styles in pp15/art/styles call (eikan_school.py, logo_pictures.py), copied here so that the package needs nothing from _work.
"""
import os
import numpy as np

from pp15.art import textures as U
from pp15.script import scan as S


class Arc:
    def __init__(self, name, share_pal=None):
        self.name = name
        src = os.path.join(U.ORIG_ARC_DIR, name)
        if not os.path.exists(src):
            src = os.path.join(S.DATA_FILES, name)
        self.D = open(src, "rb").read()
        self.syms = U.elf_symbols(self.D)
        self.banks = U.banks(self.D, self.syms)
        self.share_pal = share_pal

    def bank(self, name):
        return Bank(self, next(b for b in self.banks if b["name"] == name))

    def resolve(self, data, ref):
        """The bank dict of `ref` in a copy of the file's bytes (the original or the patched result): "name", "name#k",
        or "pages_ref+sprites_ref" (what Bank.key gives for a bank built with sprites=)."""
        banks = U.banks(data, U.elf_symbols(data))
        if "+" in ref:
            p, s_ = ref.split("+")
            pre = None
            if "@" in s_:
                s_, pre = s_.split("@")
            sp = U.bank_named(banks, s_)["sprites"]
            if pre:
                sp = {n: ps for n, ps in sp.items() if n.startswith("opd_" + pre + "_")}
            return dict(U.bank_named(banks, p), sprites=sp)
        if "#" in ref:
            return U.bank_named(banks, ref)
        same = [b for b in banks if b["name"] == ref]
        if len(same) > 1 and not same[0]["sprites"] and same[1]["sprites"]:
            return dict(same[0], sprites=same[1]["sprites"])
        return same[0]


class Bank:
    def __init__(self, arc, bank):
        self.arc, self.b, self.name = arc, bank, bank["name"]
        self._pages = {}

    def page(self, n):
        if n not in self._pages:
            self._pages[n] = U.decode_indices(self.arc.D, *self.b["pages"][n])
        return self._pages[n]

    def parts_of(self, sprite, pages=None, palettes=None):
        ps = next(p for n, p in self.b["sprites"].items() if n.endswith("_" + sprite))
        return [p for p in ps if (pages is None or p.page in pages) and (palettes is None or p.palette in palettes)]

    def index_image(self, sprite, pages=None, palettes=None, pad=8):
        """(array of palette indices of the sprite's parts, x0, y0) with `pad` clear rows / columns round it."""
        ps = self.parts_of(sprite, pages, palettes)
        x0 = min(p.x for p in ps) - pad; y0 = min(p.y for p in ps) - pad
        x1 = max(p.x + p.x1 - p.x0 for p in ps) + pad; y1 = max(p.y + p.y1 - p.y0 for p in ps) + pad
        img = np.zeros((y1 - y0, x1 - x0), int)
        for p in ps:
            t = self.page(p.page)[p.y0:p.y1, p.x0:p.x1]
            if p.flags & 0x80: t = t[:, ::-1]
            if p.flags & 0x40: t = t[::-1]
            sl = img[p.y - y0:p.y - y0 + t.shape[0], p.x - x0:p.x - x0 + t.shape[1]]
            sl[t > 0] = t[t > 0]
        return img, x0, y0
