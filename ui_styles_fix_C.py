"""Styles of the review fixes, area C (Success): new names only (fxC_...)."""
from ui_styles_ore_ini import ringfill

STYLES = {}

# camp.arc g3_kya00 52: COM Level / Errors / Wind / Weather: yellow body, dark blue outline (as the Japanese and as COM Level)
STYLES["fxC_kya52"] = ringfill([10, 13, 13, 15, 15, 15], [12, 7], [])
# camp.arc g3_kya00 70 Normal: light gold body (ramp 5-11 of its palette), dark gold ring, white outline
STYLES["fxC_kya70_normal"] = ringfill([7, 8, 9, 10, 10, 11], [4, 1], [])
