"""Label styles of art run 9, agent A (leftover pages of scs_main / scs_data / scs_rens / scs_make). Read from the
Japanese lettering with style_reader; assembled from run9/A/styles_<stem>.txt by gen_r9a_lib.assemble(). Keep importable."""
import ui_type
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat

STYLES = {}

# styles_scs_main.txt
STYLES["a9_smi_8a"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
STYLES["a9_smi_8b"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
STYLES["a9_ai_0f"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_24"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_39"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_3a"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_3b"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
