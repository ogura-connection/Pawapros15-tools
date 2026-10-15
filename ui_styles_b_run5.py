"""Label styles of art run 5, agent B (pena_sub.arc: s3_opc_0, s3_pir00, s3_pih00). Loaded by ui_type.py.
Colours are read from the Japanese lettering; every style is crisp (solid rings, fill ramps only)."""
from ui_styles_ore_ini import ringfill

STYLES = {}

# s3_pih00: pitch names on the orange / cream plates (palette 125: white letters, dark brown ring, pale pink shadow)
STYLES["b5_pitch"] = ringfill([15, 15, 15, 15, 15, 15], [2, 1], [7, 8])
