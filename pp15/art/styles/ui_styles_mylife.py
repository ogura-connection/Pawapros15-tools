"""Label styles of the My Life screens (see pp15/art/typeset.py: RENDER takes STYLES from every pp15/art/styles/ui_styles_*.py)."""
from pp15.art import typeset as ui_type
from pp15.art.typeset import banded, ringed, outlined, shadowed, haloed, logo, captioned, dropped, boxed, plated

# DIN Condensed Bold: tall narrow letters with strokes two pixels wide, like the Japanese lettering (font spec
# "ttf:din:<cap height>:0:1:0")
ui_type.TTF["din"] = ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0)

STYLES = {
    # the My Life menu tabs (orepena.arc, y3_menu, palette 4, a blue-to-white ramp): white letters whose soft edge runs
    # down to the blue of the outline, a solid dark blue ring (6) and a solid paler blue ring outside it (5), as round
    # the Japanese letters (whose outline is 6 / 7 with a lighter outer edge of 5)
    "mltab": banded([0, 8, 10, 12, 14, 15, 15], [6, 5]),
}
