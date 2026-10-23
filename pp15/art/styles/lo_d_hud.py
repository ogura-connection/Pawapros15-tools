"""Styles for the Success Mode HUD art missed by the earlier runs (2026-10-22): the yen sign after the money digits.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow. Colours are palette indices read from the Japanese lettering of the same sprite.

Used by: specs/scs_main.json (group "lo_d yen").
"""
from .common import ringfill

STYLES = {}

# scs_main.arc y5_np_0 sprite 4c (24x24, palette 47): the 円 that follows the money digits; read with style_reader.from_bank
STYLES['lo_d_yen'] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [8])
