"""Label styles of art run 9, agent A (leftover pages of scs_main / scs_data / scs_rens / scs_make). Read from the
Japanese lettering with style_reader; assembled from run9/A/styles_<stem>.txt by gen_r9a_lib.assemble(). Keep importable."""
import ui_type
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat
from ui_styles_c_run1 import win

STYLES = {}

# styles_scs_main.txt
STYLES["a9_smi_8a"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
STYLES["a9_smi_8b"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
STYLES["a9_ai_0f"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_24"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_39"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_3a"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_3b"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_smj_a"] = ringfill([1, 1, 1, 1, 1, 1], [8, 15, 15, 14])
STYLES["a9_smj_b"] = ringfill([1, 1, 1, 1, 1, 1], [15, 15, 15, 14])
STYLES["a9_smj_c"] = ringfill([1, 1, 1, 1, 1, 1], [14, 14, 14, 15])
STYLES["a9_smj_d"] = ringfill([1, 1, 1, 1, 1, 1], [9, 14, 14, 15])
# styles_scs_main_win.txt
STYLES["a9_smj_a~0_56"] = win(STYLES["a9_smj_a"], 0, 56)
STYLES["a9_smj_a~56_108"] = win(STYLES["a9_smj_a"], 56, 108)
STYLES["a9_smj_a~108_162"] = win(STYLES["a9_smj_a"], 108, 162)
STYLES["a9_smj_a~162_177"] = win(STYLES["a9_smj_a"], 162, 177)
STYLES["a9_smj_a~177_216"] = win(STYLES["a9_smj_a"], 177, 216)
STYLES["a9_smj_b~0_62"] = win(STYLES["a9_smj_b"], 0, 62)
STYLES["a9_smj_b~62_115"] = win(STYLES["a9_smj_b"], 62, 115)
STYLES["a9_smj_b~115_146"] = win(STYLES["a9_smj_b"], 115, 146)
STYLES["a9_smj_b~146_169"] = win(STYLES["a9_smj_b"], 146, 169)
STYLES["a9_smj_b~169_223"] = win(STYLES["a9_smj_b"], 169, 223)
STYLES["a9_smj_c~0_37"] = win(STYLES["a9_smj_c"], 0, 37)
STYLES["a9_smj_c~37_77"] = win(STYLES["a9_smj_c"], 37, 77)
STYLES["a9_smj_c~77_122"] = win(STYLES["a9_smj_c"], 77, 122)
STYLES["a9_smj_c~122_128"] = win(STYLES["a9_smj_c"], 122, 128)
STYLES["a9_smj_c~128_174"] = win(STYLES["a9_smj_c"], 128, 174)
STYLES["a9_smj_c~174_228"] = win(STYLES["a9_smj_c"], 174, 228)
STYLES["a9_smj_d~0_22"] = win(STYLES["a9_smj_d"], 0, 22)
STYLES["a9_smj_d~22_52"] = win(STYLES["a9_smj_d"], 22, 52)
STYLES["a9_smj_d~52_106"] = win(STYLES["a9_smj_d"], 52, 106)
