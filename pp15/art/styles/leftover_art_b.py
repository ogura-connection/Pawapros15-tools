"""Styles for the art banks the earlier runs missed, group B (2026-10-22): Eikan Nine grade plates (sct_comd.arc), the
Success sound-effect words (scs_main.arc m3_gmoji), the Success club application form lying on the desk
(scs_make.arc y5_make_bg_opd) and the Eikan Nine story pictures (sct_main.arc n4_bg_*).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow. Colours are palette indices read from the Japanese lettering of the same sprite.

Used by: specs/sct_comd.json (group "lo_b gmp years").
"""
import numpy as np
from .common import ringfill, flat

STYLES = {}

# ---- sct_comd.arc tex_z4_gmp00 (opd_z4_gmp_0): 1年 2年 3年 on the blue / green / yellow plates. White letters (15) whose
# soft edge runs down the palette toward the dark plate colour (indices 14 .. 5); no outline.
STYLES["lo_b_grade"] = flat([0, 6, 9, 11, 13, 14, 15])
