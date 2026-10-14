"""Label styles of the My Life screens (see ui_type.py: RENDER takes STYLES from every ui_styles_*.py)."""
import numpy as np

import ui_type
from ui_type import banded, ringed, outlined, shadowed, haloed, logo, captioned, dropped, boxed, plated

STYLES = {
    # the My Life menu tabs (orepena.arc, y3_menu, palette 4, a blue-to-white ramp): white letters, a solid dark blue
    # ring (6) and a solid lighter blue ring outside it (5), as round the Japanese letters
    "mltab": banded([0, 15, 15, 15, 15, 15, 15], [6, 5]),
}

# Small lettering is set with a font's own hinted pixel shapes (no grey edge pixels), which stay legible where
# an anti-aliased copy of the same letters runs together.  Fonts are named "pix:<face>:<size>:<fat>": the hinted
# face at that pixel size, <fat> = 1 draws every letter a second time one pixel to the right (a heavier stroke).
FACES = {"din": "DIN Condensed Bold.ttf", "narrow": "Arial Narrow Bold.ttf", "tahoma": "Tahoma Bold.ttf",
         "arial": "Arial Bold.ttf"}
_cache = {}


def pixel_ink(text, face, size, fat):
    """(ink, baseline row) of a word in hinted one-bit lettering; ink is 6 where the letters are."""
    from PIL import Image, ImageDraw, ImageFont
    key = (face, size)
    if key not in _cache:
        _cache[key] = ImageFont.truetype("/System/Library/Fonts/Supplemental/" + FACES[face], size)
        _cache[key].fontmode = "1"
    font = _cache[key]
    img = Image.new("L", (int(font.getlength(text)) + 12, size * 3), 0)
    draw = ImageDraw.Draw(img)
    for dx in range(fat + 1):
        draw.text((4 + dx, size * 2), text, fill=255, font=font, anchor="ls")
    a = np.asarray(img) > 0
    ys, xs = np.nonzero(a)
    return a[ys.min():ys.max() + 1, xs.min():xs.max() + 1].astype(int) * 6, size * 2 - ys.min()


class _Words(dict):
    """Every word is 'in' the font: it is drawn when asked for."""
    def __init__(self, face, size, fat):
        super().__init__()
        self.args = (face, size, fat)

    def __contains__(self, text):
        return True

    def __missing__(self, text):
        return pixel_ink(text, *self.args)


for _face in FACES:
    for _size in range(8, 17):
        for _fat in (0, 1):
            ui_type.FONTS["pix:%s:%d:%d" % (_face, _size, _fat)] = (
                lambda project, a=(_face, _size, _fat): {"words": _Words(*a), "glyphs": {}, "gap": 1, "space": 3})
