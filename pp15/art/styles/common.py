"""Drawing helpers shared by the other style modules (it defines no styles itself).

ringfill: letters filled from top to bottom with palette colours, inside solid one-pixel outlines and a drop shadow;
the recipe most screens use. flat: letters in a single colour ramp with no outline. win: keeps only a slice of the
columns of a word, so one word can be shared out over several sprite pieces that stand side by side.
_orig_page: an untouched picture from the original .arc file, for styles that copy a piece of the Japanese art.
"""
import os
import numpy as np
from pp15.script import scan as _S
from pp15.art import textures as _U


def _orig_page(arc, bank, page):
    """Index page of the untouched file (the saved original once pp15/art/labels.py has made one)."""
    path = os.path.join(_U.ORIG_ARC_DIR, arc)
    if not os.path.exists(path):
        path = os.path.join(_S.DATA_FILES, arc)
    d = open(path, "rb").read()
    b = next(x for x in _U.banks(d, _U.elf_symbols(d)) if x["name"] == bank)
    return _U.decode_indices(d, *b["pages"][page])


def ringfill(fill, rings, shadow=(), edge=3):
    """Letters filled top to foot from `fill` (a pixel of the soft edge below ink level `edge` takes the first ring's colour),
    inside solid one-pixel `rings` (innermost first, rounded corners from the second ring on) and a `shadow` (near to far)
    cast down and to the right of the last ring."""
    from pp15.art.typeset import grow, shift
    fill = list(fill)

    def style(ink, base):
        pad = len(rings) + len(shadow) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(shadow), 0, -1):
            out[shift(masks[-1], k, k) | shift(masks[-1], k, k - 1) | shift(masks[-1], k - 1, k)] = shadow[k - 1]
        for m, v in zip(masks[::-1], rings[::-1]):
            out[m] = v
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        row = np.broadcast_to(row, big.shape)
        out[letters] = np.where(big >= edge, row, rings[0])[letters]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


def flat(ramp, cut=1):
    """Letters only, no ring: ink level k (1..6) -> palette index ramp[k]; pixels below `cut` are clear."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        out = np.where(ink >= cut, ramp[ink], 0).astype(np.uint8)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut
