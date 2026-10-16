"""Label styles of art run 9, agent D (names d9_*), read from the Japanese lettering by gen_d9_styles.add.
Keep importable at every moment."""
import ui_type
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat

STYLES = {}

# ---- main_prg
STYLES["d9_np_pos"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [8])
STYLES["d9_np_possm"] = ringfill([15] * 6, [8], [8])
STYLES["d9_np_hand"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [8, 4])
STYLES["d9_np_type"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [8])
# ---- order
STYLES["d9_od_name"] = ringfill([15, 15, 15, 15, 15, 15], [5, 5], [5])
