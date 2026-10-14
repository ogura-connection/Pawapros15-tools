"""Label styles of the My Life screens (see ui_type.py: RENDER takes STYLES from every ui_styles_*.py)."""
from ui_type import banded, ringed, outlined, shadowed, haloed, logo, captioned, dropped, boxed, plated

STYLES = {
    # the My Life menu tabs (orepena.arc, y3_menu, palette 4, a blue-to-white ramp): white letters whose soft edge runs
    # down to the blue of the outline, a solid dark blue ring (6) and a solid lighter blue ring outside it (5)
    "mltab": banded([0, 8, 10, 12, 14, 15, 15], [6, 5]),
}
