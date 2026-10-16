"""Label styles of art run 7, agent F (arr_sub.arc: s3_kh, s3_kkw, s3_ks, s3_kss, s3_t, s4r_sh00, z3_ait_0).
Read from the Japanese lettering by _work/ui_pages/run7/F/learn_styles.py; loaded by ui_type.py. Keep importable."""
import ui_type
from ui_styles_ore_ini import ringfill

STYLES = {}

STYLES["f7_t_blue"] = ui_type.logo(**{'fill': [6, 6, 13, 13, 11, 3], 'outline': 4, 'white': 14, 'rim': 13, 'shadow': [7, 7], 'soft': [], 'thick': 2, 'band': 2})
STYLES["f7_t_lineup"] = ui_type.logo(**{'fill': [8, 5, 14, 12, 12, 7], 'outline': 3, 'white': 15, 'rim': 9, 'shadow': [6, 8], 'soft': [], 'thick': 2, 'band': 2})
STYLES["f7_t_green"] = ui_type.logo(**{'fill': [9, 7, 13, 12, 11, 8], 'outline': 4, 'white': 14, 'rim': 7, 'shadow': [7, 7], 'soft': [], 'thick': 2, 'band': 2})
STYLES["f7_t_steal"] = ui_type.logo(**{'fill': [6, 7, 13, 12, 11, 9], 'outline': 4, 'white': 14, 'rim': 7, 'shadow': [7], 'soft': [], 'thick': 2, 'band': 2})
STYLES["f7_t_hit"] = ui_type.logo(**{'fill': [6, 9, 13, 13, 11, 7], 'outline': 4, 'white': 15, 'rim': 7, 'shadow': [7, 7], 'soft': [], 'thick': 2, 'band': 2})
STYLES["f7_t_red"] = ringfill([15, 1, 1, 1, 1, 15], [14], [7])
STYLES["f7_t_dblue"] = ringfill([15, 1, 1, 1, 1, 1], [14], [7])
STYLES["f7_t_dgreen"] = ringfill([15, 1, 1, 1, 1, 15], [12], [])
STYLES["f7_t_orange"] = ringfill([15, 1, 1, 1, 1, 1], [14], [7])
STYLES["f7_t_often"] = ringfill([15, 1, 1, 1, 1, 15], [14], [7])
STYLES["f7_t_normal"] = ringfill([15, 1, 1, 1, 1, 1], [14], [7])
STYLES["f7_t_rarely"] = ringfill([15, 15, 15, 1, 1, 15], [14], [7])
STYLES["f7_t_plat"] = ringfill([15, 1, 1, 1, 1, 1], [11], [7])
STYLES["f7_t_speed"] = ringfill([15, 1, 1, 1, 1, 1], [2], [7])

