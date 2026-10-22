"""Recipes that turn the ink of an English word into coloured pixels: outlines, shadows, plates and gradients.

A style is a function `style(ink, base) -> (pixels, base)`. `ink` is the array of ink levels 0..6 that a font produced
(see pp15/art/lettering_fonts.py) and `base` the row the letters stand on. The result is an array of palette indices of
the page the word will be drawn on (0 = clear), and the baseline row in it. Which indices mean what depends on the
palette of the Pawapuro 15 page, which is why each factory below takes the indices as arguments: a call such as
`banded([0, 9, 10, 11, 13, 14, 15], [7, 3])` makes the style "letters in that ramp of colours inside two outline rings".
The named styles built from these factories are listed in pp15/art/named_styles.py; screens of other modes define theirs
in pp15/art/styles/.

  style_command, style_stat           two fixed styles (the Success command words; the stat labels)
  outlined, shadowed, ringed, banded  letters with one or more outline rings, optionally with a shadow
  haloed, titled, badged, logo, called  letters filled with a vertical gradient on a white band with a glow or shadow
  boxed, plated, dropped, captioned   letters on a filled box, on a plate, with only a shadow, with a cast outline
  tight(style)                        the same style without the empty rows and columns round its art

Every factory keeps the argument names, the local variable names and the docstring text it had when it lived in
typeset.py: tests/test_registry.py fingerprints each style by its byte code, so any edit (even to a docstring) would
flag the 25,575 styles built from them as changed.
"""
from typing import Callable

import numpy as np

from pp15.art.pixel_ops import grow, shift


def style_command(ink: np.ndarray, base: int) -> tuple:
    """Palette indices (0 = clear) and baseline row of a command word: letters 9..13 (the page's
    white-to-violet ramp) on a white plate (8), green rim (4 inside, 5 outside), dark shadow (1)."""
    pad = 4
    h, w = ink.shape
    big = np.zeros((h + 2 * pad, w + 2 * pad), int)
    big[pad:pad + h, pad:pad + w] = ink
    letters = big >= 2
    plate = grow(grow(letters, 1, diagonal=False), 1)          # 2 pixels, corners rounded
    rim1 = grow(plate, 1, diagonal=False) & ~plate
    rim2 = grow(plate | rim1, 1) & ~plate & ~rim1
    shadow = (shift(plate, 1, 1) | shift(plate, 2, 2)) & (rim1 | rim2)
    out = np.zeros(big.shape, np.uint8)
    out[rim2] = 5
    out[rim1] = 4
    out[shadow] = 1
    out[plate] = 8
    ramp = np.array([8, 9, 10, 11, 12, 13, 13], np.uint8)
    out[big > 0] = np.maximum(ramp[big[big > 0]], out[big > 0])
    out[(big > 0) & ~plate & ~rim1 & ~rim2] = 0                 # faint ink outside everything
    return out, base + pad


def outlined(ramp: list, ring: int, corner: int) -> Callable:
    """A style: letters drawn with `ramp` (palette index for ink 0..6), a one-pixel outline `ring`
    on the four sides of every letter pixel and `corner` (0 = none) on the diagonals."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        side = grow(letters, 1, diagonal=False) & ~letters
        diag = grow(letters, 1) & ~letters & ~side
        out = np.zeros(big.shape, np.uint8)
        out[diag] = corner
        out[side] = ring
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def style_stat(ink: np.ndarray, base: int) -> tuple:
    """The stat labels (palette 58, blue to white): white letters shading to light blue at the foot,
    a blue ring (2) and a lighter outer ring (5), both solid."""
    pad = 2
    h, w = ink.shape
    big = np.zeros((h + 2 * pad, w + 2 * pad), int)
    big[pad:pad + h, pad:pad + w] = ink
    letters = big > 0
    ring1 = grow(letters, 1) & ~letters
    ring2 = grow(letters, 2) & ~letters & ~ring1
    out = np.zeros(big.shape, np.uint8)
    out[ring2] = 5
    out[ring1] = 2
    shade = np.rint(15 - 3 * np.arange(h) / max(h - 1, 1)).astype(np.uint8)
    out[pad:pad + h][letters[pad:pad + h]] = np.broadcast_to(shade[:, None], (h, w + 2 * pad))[letters[pad:pad + h]]
    return out, base + pad


def shadowed(ramp: list, ring: int, shadow: int, depth: int) -> Callable:
    """A style: letters drawn with `ramp`, a one-pixel outline `ring` all round, and a `shadow`
    `depth` pixels down and to the right."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        h, w = ink.shape
        big = np.zeros((h + 2 + depth, w + 2 + depth), int)
        big[1:1 + h, 1:1 + w] = ink
        letters = big > 0
        body = grow(letters, 1)
        cast = np.zeros_like(body)
        for k in range(1, depth + 1):
            cast |= shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
        out = np.zeros(big.shape, np.uint8)
        out[cast & ~body] = shadow
        out[body] = ring
        out[letters] = ramp[big[letters]]
        return out, base + 1
    return style


def ringed(ramp: list, rings: list) -> Callable:
    """A style: letters drawn with `ramp` inside solid one-pixel rings (first value innermost)."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = len(rings)
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        out = np.zeros(big.shape, np.uint8)
        for k in range(pad, 0, -1):
            out[grow(letters, k)] = rings[k - 1]
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def haloed(ramp: list, band: int, glow: list, width: int = 2, fill: list = None, light: int = None) -> Callable:
    """A style: letters drawn with `ramp` in a solid band `width` pixels wide, inside a one-pixel glow whose
    colour runs through `glow` from the top row to the bottom row; below and to the right the glow is
    two pixels (a soft shadow). The tab and field labels of the Data screen.
    With `fill` (palette indices from the top row of the letters to the bottom row) the letters are a
    vertical gradient instead, and their soft edge runs from the fill towards index `light` (the
    palette must be a ramp between the two)."""
    ramp, glow = np.array(ramp if ramp else [0], np.uint8), np.array(glow, np.uint8)

    def style(ink, base):
        pad = width + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        body = grow(grow(letters, width - 1), 1, diagonal=False) if width > 1 else grow(letters, 1)
        near = grow(body, 1, diagonal=False)
        far = near | shift(near, 1, 1)
        rows = np.nonzero(far.any(1))[0]
        frac = (np.arange(big.shape[0]) - rows.min()) / max(rows.max() - rows.min(), 1)
        shade = glow[np.rint(frac * (len(glow) - 1)).astype(int).clip(0, len(glow) - 1)]
        out = np.zeros(big.shape, np.uint8)
        out[far] = np.broadcast_to(shade[:, None], big.shape)[far]
        out[body] = band
        if fill:
            ys = np.nonzero(letters.any(1))[0]
            f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
            row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
            out[letters] = np.rint(row + (light - row) * (1 - big / 6.0))[letters].astype(np.uint8)
        else:
            out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def banded(ramp: list, rings: list, shadow: int = 0) -> Callable:
    """A style: letters drawn with `ramp` inside solid one-pixel rings (first value innermost, corners
    rounded from the second ring on), with a one-pixel `shadow` below and to the right of the last ring."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = len(rings) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        if shadow:
            out[shift(masks[-1], 1, 1)] = shadow
        for m, value in zip(masks[::-1], rings[::-1]):
            out[m] = value
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def titled(ramp: list, white: int, shadow: list, rim: list, plate: int = 3) -> Callable:
    """A style: the screen titles of the Data screen. Letters with a dark outline (`ramp`[0]) and a fill
    that goes from the brightest colour (`ramp`[-1]) at the top to the one before it at the foot, on a
    white plate `plate` pixels wide; the letters cast a grey shadow (`shadow`: near, far) on the plate, and
    the plate has a rim of two pixels (`rim`: inner, outer)."""
    def style(ink, base):
        pad = plate + 4
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        body = grow(letters, 1)                                  # letters and their outline
        board = grow(grow(body, plate - 1), 1, diagonal=False)
        out = np.zeros(big.shape, np.uint8)
        out[grow(board, 2, diagonal=False)] = rim[1]
        out[grow(board, 1, diagonal=False)] = rim[0]
        out[board] = white
        out[shift(body, 2, 2) & board] = shadow[1]
        out[shift(body, 1, 1) & board] = shadow[0]
        out[body] = ramp[0]
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        top = np.where(f < 0.55, len(ramp) - 1, len(ramp) - 2)[:, None]        # position on the ramp per row
        level = np.rint(top * big / 6.0).astype(int)
        out[letters] = np.array(ramp, np.uint8)[level][letters]
        return out, base + pad
    return style


def badged(fill: list, soft: list, outline: int, white: int, glow: list) -> Callable:
    """A style: the large names on the ratings page. Letters filled from `fill`[0] at the top to `fill`[-1]
    at the foot, with an outline two pixels wide (`soft` = the colours between outline and fill, for the
    soft edge of the letters), a white band two pixels wide and a `glow` (near, far) below and to the right."""
    def style(ink, base):
        pad = 6
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        dark = grow(grow(letters, 1), 1, diagonal=False)
        band = grow(grow(dark, 1), 1, diagonal=False)
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(glow), 0, -1):
            out[shift(band, k, k)] = glow[k - 1]
        out[band] = white
        out[dark] = outline
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        edge = np.array([outline] + list(soft) + [0], np.uint8)[np.rint(big * (len(soft) + 1) / 6.0).astype(int)]
        out[letters] = np.where(big >= 6, np.broadcast_to(row, big.shape), edge)[letters]
        return out, base + pad
    return style


def boxed(ramp: list, pad: tuple = (3, 4), size: tuple = (0, 0), rim: int = None) -> Callable:
    """A style: letters drawn with `ramp` on a filled box of colour `ramp`[0] with its four corner pixels
    cut off, `pad` (across, down) pixels larger than the letters and at least `size`; `rim` = the colour
    of a one-pixel edge round the box. The button hints."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        h, w = ink.shape
        bw, bh = max(w + 2 * pad[0], size[0]), max(base + 2 * pad[1], h + 2, size[1])
        x, y = (bw - w) // 2, (bh - base) // 2
        out = np.full((bh, bw), ramp[0], np.uint8)
        out[y:y + h, x:x + w] = ramp[ink]
        for cy, cx in ((0, 0), (0, -1), (-1, 0), (-1, -1)):
            out[cy, cx] = 0
        if rim is not None:
            out = np.pad(out, 1, constant_values=rim)
            for cy, cx in ((0, 0), (0, -1), (-1, 0), (-1, -1)):
                out[cy, cx] = 0
            y += 1
        return out, base + y
    return style


def dropped(ramp: list, shadow: list) -> Callable:
    """A style: letters drawn with `ramp` and nothing round them but a `shadow` (near to far, one pixel a
    colour) cast below and to the right."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        h, w = ink.shape
        depth = len(shadow)
        big = np.zeros((h + depth, w + depth), int)
        big[:h, :w] = ink
        letters = big > 0
        out = np.zeros(big.shape, np.uint8)
        for k in range(depth, 0, -1):
            out[shift(letters, k, k) | shift(letters, k, k - 1) | shift(letters, k - 1, k)] = shadow[k - 1]
        out[letters] = ramp[big[letters]]
        return out, base
    return style


def logo(fill: list, soft: list, outline: int, white: int, rim: int, shadow: list, band: int = 2,
         thick: int = 1) -> Callable:
    """A style: the shop titles. Letters filled from `fill`[0] at the top to `fill`[-1] at the foot (`soft` =
    the colours between outline and fill), an `outline` `thick` pixels wide, a white band `band` pixels wide
    with a one-pixel `rim`, and a `shadow` (near to far) cast below and to the right of the whole."""
    def style(ink, base):
        pad = band + 1 + thick + len(shadow)
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        dark = grow(letters, 1)
        for _ in range(thick - 1):
            dark = grow(dark, 1, diagonal=False)
        plate = grow(grow(dark, band - 1), 1, diagonal=False) if band > 1 else grow(dark, 1, diagonal=False)
        edge = grow(plate, 1, diagonal=False)
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(shadow), 0, -1):
            out[shift(edge, k, k) | shift(edge, k, k - 1) | shift(edge, k - 1, k)] = shadow[k - 1]
        out[edge] = rim
        out[plate] = white
        out[dark] = outline
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        low = np.array([outline] + list(soft) + [0], np.uint8)[np.rint(big * (len(soft) + 1) / 6.0).astype(int)]
        out[letters] = np.where(big >= 6, np.broadcast_to(row, big.shape), low)[letters]
        return out, base + pad
    return style


def called(fill: list, soft: list, outline: int, white: int, band: int, shadow: list, thick: int = 2, wide: int = 2,
           bandw: int = 3, drop: tuple = (1, 0)) -> Callable:
    """A style: the umpire's calls of a match (gameplay.arc h3_stf_0). Letters filled from `fill`[0] at the
    top to `fill`[-1] at the foot (`soft` = colours between outline and fill), an `outline` `thick` pixels
    wide, a `white` band `wide` pixels, a coloured `band` `bandw` pixels round everything, and a `shadow`
    (near to far) cast below it: each step moves drop[0] down and drop[1] right."""
    def style(ink, base):
        pad = thick + wide + bandw + len(shadow) * max(drop) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        dark = grow(letters, thick)
        plate = grow(dark, wide)
        outer = grow(plate, bandw)
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(shadow), 0, -1):
            out[shift(outer, k * drop[0], k * drop[1])] = shadow[k - 1]
        out[outer] = band
        out[plate] = white
        out[dark] = outline
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        low = np.array([outline] + list(soft) + [0], np.uint8)[np.rint(big * (len(soft) + 1) / 6.0).astype(int)]
        out[letters] = np.where(big >= 6, np.broadcast_to(row, big.shape), low)[letters]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


def tight(style: Callable) -> Callable:
    """The same style without the empty rows and columns round its art."""
    def trimmed(ink, base):
        out, b = style(ink, base)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], b - ys.min()
    return trimmed


def captioned(ramp: list, outline: int, soft: int, ring: int = 2, depth: int = 2) -> Callable:
    """A style: the scene captions. Letters drawn with `ramp` in a solid `outline` `ring` pixels wide that is
    also cast `depth` pixels down and to the right; `soft` colours the inner corners of the outer edge."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = ring + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad + depth, w + 2 * pad + depth), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        body = grow(letters, 1)
        for _ in range(ring - 1):
            body = grow(body, 1, diagonal=False)
        dark = body.copy()
        for k in range(1, depth + 1):
            dark |= shift(body, k, k)
        dark |= shift(dark, -1, 0) & shift(dark, 0, -1)          # close the steps the cast leaves
        near = sum(shift(dark, dy, dx).astype(int) for dy, dx in ((1, 0), (-1, 0), (0, 1), (0, -1)))
        out = np.zeros(big.shape, np.uint8)
        out[~dark & (near >= 2)] = soft
        out[dark] = outline
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


def plated(ramp: list, shadow: int, size: tuple) -> Callable:
    """A style: letters drawn with `ramp` on a filled rectangle `size` (w, h) of colour `ramp`[0], with a
    `shadow` one pixel down and to the right. Pieces of one plate that stand side by side."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        h, w = ink.shape
        bw, bh = max(size[0], w + 2), max(size[1], h + 2)
        big = np.zeros((bh, bw), int)
        x, y = (bw - w) // 2, max((bh - base) // 2, 0)           # capitals in the middle, whatever hangs below
        big[y:y + h, x:x + w] = ink
        out = np.full(big.shape, ramp[0], np.uint8)
        out[shift(big > 2, 1, 1)] = shadow
        out[big > 0] = ramp[big[big > 0]]
        return out, y + base
    return style
