"""Two small operations on yes/no pixel masks that every lettering style is built from.

A mask is a 2-D numpy array of booleans, one entry per pixel of a piece of lettering (True = ink). Styles draw an
outline round a word by growing its mask, and a drop shadow by moving a grown copy of it down and to the right.

  grow(mask, n, diagonal, edge)   the mask made n pixels fatter
  shift(mask, dy, dx)             the mask moved by dy rows and dx columns

The function bodies, names and docstrings are deliberately unchanged from the time they lived in typeset.py:
tests/test_registry.py fingerprints every style by its byte code, so editing them (even a docstring) would flag
all 25,575 styles as changed.
"""
import numpy as np


def grow(mask: np.ndarray, n: int = 1, diagonal: bool = True, edge: bool = False) -> np.ndarray:
    """The mask grown by n pixels (8 directions, or 4 with diagonal=False)."""
    m = mask.copy()
    for _ in range(n):
        p = np.pad(m, 1, constant_values=edge)
        out = m.copy()
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if (dy or dx) and (diagonal or not (dy and dx)):
                    out |= p[1 + dy:1 + dy + m.shape[0], 1 + dx:1 + dx + m.shape[1]]
        m = out
    return m


def shift(mask: np.ndarray, dy: int, dx: int) -> np.ndarray:
    out = np.zeros_like(mask)
    h, w = mask.shape
    out[max(dy, 0):h + min(dy, 0), max(dx, 0):w + min(dx, 0)] = \
        mask[max(-dy, 0):h + min(-dy, 0), max(-dx, 0):w + min(-dx, 0)]
    return out
