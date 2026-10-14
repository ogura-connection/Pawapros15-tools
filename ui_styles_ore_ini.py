"""Label styles of ore_ini.arc (My Life title buttons, team choice, profile screens). See ui_type.py."""
import ui_type
from ui_type import banded, ringed, outlined, shadowed, haloed, logo, captioned, dropped, boxed, plated

STYLES = {
    # y3_myt: "Choose your ..." headings, palette 2 of the mye table: gold letters, blue outline, white band, pale shadow
    "mylhead": logo([11, 10, 9, 8, 7], [3], 1, 15, 14, [12], 2, 1),
}
