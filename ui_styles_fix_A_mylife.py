"""Label styles added by the fix_A_mylife art fix (names fxA_...). Loaded by ui_type.py."""
from ui_styles_ore_ini import ringfill

STYLES = {}
# koukai y3_koukai 96 (Press to OK): white letters, two navy rings as the Japanese
STYLES["fxA_koukai_96"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [])

# ore_ren g3_0ren practice names: blue letters, thick white ring, thin dark-blue edge (as the Japanese)
from ui_styles_ore_ren import solid as _solid
STYLES["fxA_ren"] = _solid(3, [15, 15, 7])
