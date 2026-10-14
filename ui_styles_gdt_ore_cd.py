"""Label style for gdt_ore.arc bank y3_cd (My Life stat tickers). Loaded by ui_type.py.
The Japanese lettering is white (index 15 of the grey ramp) in a dark ring; palette 9 itself is black in the file (set at run time)."""
from ui_styles_orepena import solid
STYLES = {}
STYLES["gdo_cd"] = solid(15, [2, 1], cut=3)
