"""Decode the two GameCube/Wii texture ingredients the art tools need: tiled index data and RGB5A3 colours.

The Wii stores a picture as small tiles (8x8 pixels at 4 bits, 8 wide by 4 high at 8 bits) in memory order, and colours as
16-bit RGB5A3 values (5-5-5 bits of red, green, blue when the top bit is set; otherwise 3 bits of alpha and 4-4-4 colour).
pp15/reference/mlb_assets.py already decodes both for the MLB discs; these two functions are the only place the art tools
reach into it. They call its underscore-named helpers `_blocks` and `_rgb5a3` because it offers no public name for them
(a note for whoever tidies mlb_assets: publish them and change the two lines here).

  untile(flat, height, width, tile_h, tile_w)   tiles in memory order -> (height, width) array
  rgb5a3_colours(values)                        array of big-endian 16-bit values -> (n, 4) uint8 RGBA
"""
import numpy as np

from pp15.reference import mlb_assets


def untile(flat: np.ndarray, height: int, width: int, tile_h: int, tile_w: int) -> np.ndarray:
    """A picture stored as tiles in reading order -> a (height, width) array."""
    return mlb_assets._blocks(flat, height, width, tile_h, tile_w)


def rgb5a3_colours(values: np.ndarray) -> np.ndarray:
    """RGB5A3 words (unsigned 16-bit) -> RGBA colours, shape (n, 4)."""
    return mlb_assets._rgb5a3(values)
