"""Label styles of art run 1, agent C (vs.arc, sd_mode.arc, title.arc, dem_open.arc). Loaded by ui_type.py.
Written by _work/ui_pages/run1/C/build_styles.py: palette indices were read from the Japanese lettering of each palette
(see the comment on every style); edit that script, not this file."""
import numpy as np
import ui_type
from ui_type import grow, shift, logo, boxed
from ui_styles_ore_ini import ringfill

STYLES = {}
# s4_ts00 headings (palette 0): deep blue letters, white ring, blue ring, teal shadow
STYLES['c_vs_head'] = ringfill([6, 6, 6, 6, 6, 6, 8], [15, 9], [4, 1])
# s4_ts00 option values (palette 1): purple letters, white ring, blue shadow
STYLES['c_vs_opt'] = ringfill([9, 11, 11, 11, 11, 11, 11, 11], [4, 4], [15])
# s4_tsx00 title (256 colours): orange to pink letters, two white rings, blue rings, light blue and navy shadow
STYLES['c_vs_title'] = ringfill([0x82, 0x7c, 0x70, 0x6c, 0x5b, 0x57, 0x49, 0x45], [0xff, 0xff, 0x11, 0x11], [0x83, 0x01])
# s5_tm 15 / 17 Control Setup (palette 26): deep blue letters in a white ring
STYLES['c_vs_ctl'] = ringfill([15], [4, 4], [])
# s5_tm 3c Change Uniform (palette 34): yellow letters, dark blue rings
STYLES['c_vs_uni'] = ringfill([15], [4, 4, 2], [])
# s5_tm 20 Arrange (palette 8): white letters on the small dark blue plate
STYLES['c_vs_arr'] = boxed([1, 2, 4, 6, 9, 12, 14], pad=(4, 5), size=(54, 25), rim=15)
#  learned from vs.arc s5_tmz 00
STYLES['c_tmz_title'] = logo([184, 169, 149, 137, 101], [184, 184], 21, 255, 21, [21, 148, 148, 1], 3, 2)
#  learned from vs.arc s5_tmz 01
STYLES['c_tmz_title_s'] = logo([171, 157, 138, 126, 91], [171, 171], 21, 255, 221, [21, 144, 1, 1], 3, 2)
#  learned from vs.arc s5_tmz 02
STYLES['c_tmz_orange'] = logo([249, 247, 203, 194, 147], [249, 249], 2, 255, 240, [65, 47, 47, 47], 3, 2)
#  learned from vs.arc s5_tmz 03
STYLES['c_tmz_lime'] = logo([243, 241, 235, 226, 222], [243, 243], 3, 255, 120, [65, 47, 47, 47], 3, 2)
#  learned from vs.arc s5_tmz 04
STYLES['c_tmz_green'] = logo([244, 232, 188, 152, 122], [244, 244], 3, 255, 120, [65, 47, 47, 47], 3, 2)
#  learned from vs.arc s5_tmz 05
STYLES['c_tmz_sky'] = logo([202, 187, 184, 166, 141], [202, 202], 3, 255, 120, [52, 47, 47, 65], 3, 2)
#  learned from vs.arc s5_tmz 06
STYLES['c_tmz_lime2'] = logo([238, 234, 227, 221, 215], [238, 238], 3, 255, 124, [58, 50, 50, 69], 3, 2)
#  learned from vs.arc s5_tmz 07
STYLES['c_tmz_orange2'] = logo([246, 224, 194, 187, 143], [246, 246], 2, 255, 75, [58, 50, 50, 69], 3, 2)
#  learned from vs.arc s5_tmz 08
STYLES['c_tmz_orange3'] = logo([248, 250, 214, 192, 163, 155], [248, 248], 2, 255, 4, [23, 92, 92], 3, 2)
#  learned from vs.arc s5_tmz 09
STYLES['c_tmz_lime3'] = logo([243, 242, 237, 231, 224, 222], [243, 243], 3, 255, 4, [30, 92, 138], 3, 2)
#  learned from vs.arc s5_tmz 0a
STYLES['c_tmz_green3'] = logo([227, 244, 201, 190, 154, 148], [227, 227], 3, 255, 11, [92, 92, 92], 3, 2)
#  learned from vs.arc s5_tmz 0b
STYLES['c_tmz_sky3'] = logo([205, 205, 191, 172, 159, 152], [205, 205], 3, 255, 130, [30, 92, 92], 3, 2)
#  learned from vs.arc s5_tmz 0f
STYLES['c_tmz_pink'] = logo([247, 241, 227, 171, 135], [247, 247], 2, 255, 198, [98, 59, 59, 59], 3, 2)
#  learned from vs.arc s5w_trx 00
STYLES['c_trx_orange'] = logo([245, 228, 198, 172, 138, 94], [245, 245], 2, 255, 114, [72, 137, 137, 137], 3, 2)
#  learned from vs.arc s5w_trx 01
STYLES['c_trx_green'] = logo([236, 231, 224, 218, 208, 108], [236, 236], 3, 255, 114, [86, 116, 137, 137], 3, 2)
