"""Label styles of art run 1, agent C (vs.arc, sd_mode.arc, title.arc, dem_open.arc). Loaded by ui_type.py.
Written by _work/ui_pages/run1/C/build_styles.py: palette indices were read from the Japanese lettering of each palette
(see the comment on every style); edit that script, not this file."""
import numpy as np
import ui_type
from ui_type import grow, shift, logo, boxed
from ui_styles_ore_ini import ringfill

STYLES = {}


def banner(style, h, mx):
    """The word on a card piece: at least h rows high, mx clear columns each side. In these palettes index 0 is a colour
    (brown), so the clear pixels are part of the card."""
    def cut(ink, base):
        art, b = style(ink, base)
        H, W = art.shape
        oh = max(h, H)
        y = (oh - H) // 2
        out = np.zeros((oh, W + 2 * mx), np.uint8)
        out[y:y + H, mx:mx + W] = art
        return out, b + y
    return cut


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


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
# s5_tmz 0c VS: hollow letters, navy outline, cyan ring, grey shadow
STYLES['c_tmz_vs'] = ringfill([0], [2, 2, 2, 2, 0x8f, 0x8f], [0xb4, 0xb4, 0xb4])
#  learned from vs.arc s5_tmz 0d
STYLES['c_tmz_away'] = ringfill([248, 233, 228, 198, 182, 132, 124, 106], [2, 2, 2], [142, 142])
#  learned from vs.arc s5_tmz 0e
STYLES['c_tmz_home'] = ringfill([251, 240, 234, 217, 199, 185, 180, 166], [3, 3, 173], [142])
#  learned from vs.arc s5w_trx 00
STYLES['c_trx_orange'] = logo([245, 228, 198, 172, 138, 94], [245, 245], 2, 255, 114, [72, 137, 137, 137], 3, 2)
#  learned from vs.arc s5w_trx 01
STYLES['c_trx_green'] = logo([236, 231, 224, 218, 208, 108], [236, 236], 3, 255, 114, [86, 116, 137, 137], 3, 2)
# r3_sd 05 06 (palette 33): white to cyan letters, dark teal outline, green shadow
STYLES['c_sd_title'] = ringfill([15, 14, 14, 13, 13, 12, 12, 11], [4, 4], [3, 2, 1])
# r3_sd 07-0b, 54 (palette 32; the grey copies, palette 34, show the same art): mint letters, navy outline, blue shadow
STYLES['c_sd_head'] = ringfill([15, 15, 14, 13, 13, 12, 11, 11], [4, 4], [3, 2, 1])
# r3_sd 0d Stereo (palette 7): white to yellow letters, blue outline, white band, grey shadow
STYLES['c_sd_stereo'] = logo([12, 12, 9, 7, 6], [12, 12], 3, 12, 12, [1, 1, 1], 2, 2)
# r3_sd 0e Mono (palette 8): lilac to green
STYLES['c_sd_mono'] = logo([14, 10, 9, 8, 6], [14, 14], 3, 12, 12, [1, 1, 1], 2, 2)
# r3_sd 0f Recommended (palette 2): yellow to orange
STYLES['c_sd_rec'] = logo([9, 8, 7, 6, 6], [9, 9], 3, 12, 12, [1, 1, 1], 2, 2)
# r3_sd 10 Custom (palette 4): white to cyan
STYLES['c_sd_custom'] = logo([12, 11, 9, 8, 7], [12, 12], 3, 12, 12, [1, 1, 1], 2, 2)
# r3_sd 45 Surround (palette 9): pink
STYLES['c_sd_surround'] = logo([11, 9, 8, 7, 6], [11, 11], 3, 12, 12, [1, 1, 1], 2, 2)
# r3_sd 11 High (palette 6): orange to pink
STYLES['c_sd_high'] = logo([10, 9, 8, 7, 6], [10, 10], 3, 12, 12, [1], 1, 1)
# r3_sd 12 Mid (palette 7): yellow
STYLES['c_sd_mid'] = logo([11, 10, 9, 8, 7], [11, 11], 3, 12, 12, [1], 1, 1)
# r3_sd 13 Low (palette 8): green
STYLES['c_sd_low'] = logo([11, 10, 9, 8, 6], [11, 11], 3, 12, 12, [1], 1, 1)
# r3_sd 14 Off (palette 5): pink
STYLES['c_sd_off'] = logo([9, 8, 7, 6, 6], [9, 9], 3, 12, 12, [1], 1, 1)
# r3_sd 27 Sound banner lettering (palette 13): orange to pink letters, white ring, blue rings and shadow
STYLES['c_sd_banner'] = ringfill([12, 12, 12, 13, 14, 14, 15, 15], [8, 7, 1], [5, 4])
# h5_ti03_opd 01 Game Start (256 colours): white letters, thick green outline, dark green shadow
STYLES['c_title_start'] = ringfill([49], [123, 127, 127, 127, 127], [98, 98, 98])
# y4_vs00 / 10 / 20 / 71 (palette 2): red letters, two brown rings
STYLES['c_dem_red_raw'] = ringfill([14, 12, 14, 14, 10, 9, 9, 10], [1, 2, 2], [])
# the same on a 62 row brown card piece (two fit one page with the gap; the Japanese pieces are 64)
STYLES['c_dem_red_b'] = banner(STYLES['c_dem_red_raw'], 62, 6)
# y4_vs30 / 40 / 50 (palette 32): gold letters, black ring, white ring, grey edge
STYLES['c_dem_gold'] = ringfill([0x7a, 0xb8, 0xe0, 0xf8, 0xe9, 0xb8, 0x8a, 0x31], [255, 164, 164, 188], [])
STYLES['c_vs_ctl~0_32'] = win(STYLES['c_vs_ctl'], 0, 32)
STYLES['c_vs_ctl~32_64'] = win(STYLES['c_vs_ctl'], 32, 64)
STYLES['c_vs_ctl~64_4096'] = win(STYLES['c_vs_ctl'], 64, 4096)
STYLES['c_sd_head~0_60'] = win(STYLES['c_sd_head'], 0, 60)
STYLES['c_sd_head~60_4096'] = win(STYLES['c_sd_head'], 60, 4096)
STYLES['c_sd_title~0_128'] = win(STYLES['c_sd_title'], 0, 128)
STYLES['c_sd_title~128_4096'] = win(STYLES['c_sd_title'], 128, 4096)
STYLES['c_dem_red_b~0_32'] = win(STYLES['c_dem_red_b'], 0, 32)
STYLES['c_dem_red_b~0_64'] = win(STYLES['c_dem_red_b'], 0, 64)
STYLES['c_dem_red_b~0_96'] = win(STYLES['c_dem_red_b'], 0, 96)
STYLES['c_dem_red_b~0_128'] = win(STYLES['c_dem_red_b'], 0, 128)
STYLES['c_dem_red_b~0_160'] = win(STYLES['c_dem_red_b'], 0, 160)
STYLES['c_dem_red_b~0_192'] = win(STYLES['c_dem_red_b'], 0, 192)
STYLES['c_dem_red_b~0_224'] = win(STYLES['c_dem_red_b'], 0, 224)
STYLES['c_dem_red_b~0_256'] = win(STYLES['c_dem_red_b'], 0, 256)
STYLES['c_dem_red_b~0_288'] = win(STYLES['c_dem_red_b'], 0, 288)
STYLES['c_dem_red_b~0_320'] = win(STYLES['c_dem_red_b'], 0, 320)
STYLES['c_dem_red_b~0_4096'] = win(STYLES['c_dem_red_b'], 0, 4096)
STYLES['c_dem_red_b~32_64'] = win(STYLES['c_dem_red_b'], 32, 64)
STYLES['c_dem_red_b~32_96'] = win(STYLES['c_dem_red_b'], 32, 96)
STYLES['c_dem_red_b~32_128'] = win(STYLES['c_dem_red_b'], 32, 128)
STYLES['c_dem_red_b~32_160'] = win(STYLES['c_dem_red_b'], 32, 160)
STYLES['c_dem_red_b~32_192'] = win(STYLES['c_dem_red_b'], 32, 192)
STYLES['c_dem_red_b~32_224'] = win(STYLES['c_dem_red_b'], 32, 224)
STYLES['c_dem_red_b~32_256'] = win(STYLES['c_dem_red_b'], 32, 256)
STYLES['c_dem_red_b~32_288'] = win(STYLES['c_dem_red_b'], 32, 288)
STYLES['c_dem_red_b~32_320'] = win(STYLES['c_dem_red_b'], 32, 320)
STYLES['c_dem_red_b~32_4096'] = win(STYLES['c_dem_red_b'], 32, 4096)
STYLES['c_dem_red_b~64_96'] = win(STYLES['c_dem_red_b'], 64, 96)
STYLES['c_dem_red_b~64_128'] = win(STYLES['c_dem_red_b'], 64, 128)
STYLES['c_dem_red_b~64_160'] = win(STYLES['c_dem_red_b'], 64, 160)
STYLES['c_dem_red_b~64_192'] = win(STYLES['c_dem_red_b'], 64, 192)
STYLES['c_dem_red_b~64_224'] = win(STYLES['c_dem_red_b'], 64, 224)
STYLES['c_dem_red_b~64_256'] = win(STYLES['c_dem_red_b'], 64, 256)
STYLES['c_dem_red_b~64_288'] = win(STYLES['c_dem_red_b'], 64, 288)
STYLES['c_dem_red_b~64_320'] = win(STYLES['c_dem_red_b'], 64, 320)
STYLES['c_dem_red_b~64_4096'] = win(STYLES['c_dem_red_b'], 64, 4096)
STYLES['c_dem_red_b~96_128'] = win(STYLES['c_dem_red_b'], 96, 128)
STYLES['c_dem_red_b~96_160'] = win(STYLES['c_dem_red_b'], 96, 160)
STYLES['c_dem_red_b~96_192'] = win(STYLES['c_dem_red_b'], 96, 192)
STYLES['c_dem_red_b~96_224'] = win(STYLES['c_dem_red_b'], 96, 224)
STYLES['c_dem_red_b~96_256'] = win(STYLES['c_dem_red_b'], 96, 256)
STYLES['c_dem_red_b~96_288'] = win(STYLES['c_dem_red_b'], 96, 288)
STYLES['c_dem_red_b~96_320'] = win(STYLES['c_dem_red_b'], 96, 320)
STYLES['c_dem_red_b~96_4096'] = win(STYLES['c_dem_red_b'], 96, 4096)
STYLES['c_dem_red_b~128_160'] = win(STYLES['c_dem_red_b'], 128, 160)
STYLES['c_dem_red_b~128_192'] = win(STYLES['c_dem_red_b'], 128, 192)
STYLES['c_dem_red_b~128_224'] = win(STYLES['c_dem_red_b'], 128, 224)
STYLES['c_dem_red_b~128_256'] = win(STYLES['c_dem_red_b'], 128, 256)
STYLES['c_dem_red_b~128_288'] = win(STYLES['c_dem_red_b'], 128, 288)
STYLES['c_dem_red_b~128_320'] = win(STYLES['c_dem_red_b'], 128, 320)
STYLES['c_dem_red_b~128_4096'] = win(STYLES['c_dem_red_b'], 128, 4096)
STYLES['c_dem_red_b~160_192'] = win(STYLES['c_dem_red_b'], 160, 192)
STYLES['c_dem_red_b~160_224'] = win(STYLES['c_dem_red_b'], 160, 224)
STYLES['c_dem_red_b~160_256'] = win(STYLES['c_dem_red_b'], 160, 256)
STYLES['c_dem_red_b~160_288'] = win(STYLES['c_dem_red_b'], 160, 288)
STYLES['c_dem_red_b~160_320'] = win(STYLES['c_dem_red_b'], 160, 320)
STYLES['c_dem_red_b~160_4096'] = win(STYLES['c_dem_red_b'], 160, 4096)
STYLES['c_dem_red_b~192_224'] = win(STYLES['c_dem_red_b'], 192, 224)
STYLES['c_dem_red_b~192_256'] = win(STYLES['c_dem_red_b'], 192, 256)
STYLES['c_dem_red_b~192_288'] = win(STYLES['c_dem_red_b'], 192, 288)
STYLES['c_dem_red_b~192_320'] = win(STYLES['c_dem_red_b'], 192, 320)
STYLES['c_dem_red_b~192_4096'] = win(STYLES['c_dem_red_b'], 192, 4096)
STYLES['c_dem_red_b~224_256'] = win(STYLES['c_dem_red_b'], 224, 256)
STYLES['c_dem_red_b~224_288'] = win(STYLES['c_dem_red_b'], 224, 288)
STYLES['c_dem_red_b~224_320'] = win(STYLES['c_dem_red_b'], 224, 320)
STYLES['c_dem_red_b~224_4096'] = win(STYLES['c_dem_red_b'], 224, 4096)
STYLES['c_dem_red_b~256_288'] = win(STYLES['c_dem_red_b'], 256, 288)
STYLES['c_dem_red_b~256_320'] = win(STYLES['c_dem_red_b'], 256, 320)
STYLES['c_dem_red_b~256_4096'] = win(STYLES['c_dem_red_b'], 256, 4096)
STYLES['c_dem_red_b~288_320'] = win(STYLES['c_dem_red_b'], 288, 320)
STYLES['c_dem_red_b~288_4096'] = win(STYLES['c_dem_red_b'], 288, 4096)
STYLES['c_dem_red_b~320_4096'] = win(STYLES['c_dem_red_b'], 320, 4096)
STYLES['c_dem_gold~0_32'] = win(STYLES['c_dem_gold'], 0, 32)
STYLES['c_dem_gold~0_64'] = win(STYLES['c_dem_gold'], 0, 64)
STYLES['c_dem_gold~0_96'] = win(STYLES['c_dem_gold'], 0, 96)
STYLES['c_dem_gold~0_128'] = win(STYLES['c_dem_gold'], 0, 128)
STYLES['c_dem_gold~0_160'] = win(STYLES['c_dem_gold'], 0, 160)
STYLES['c_dem_gold~0_192'] = win(STYLES['c_dem_gold'], 0, 192)
STYLES['c_dem_gold~0_224'] = win(STYLES['c_dem_gold'], 0, 224)
STYLES['c_dem_gold~0_256'] = win(STYLES['c_dem_gold'], 0, 256)
STYLES['c_dem_gold~0_288'] = win(STYLES['c_dem_gold'], 0, 288)
STYLES['c_dem_gold~0_320'] = win(STYLES['c_dem_gold'], 0, 320)
STYLES['c_dem_gold~0_4096'] = win(STYLES['c_dem_gold'], 0, 4096)
STYLES['c_dem_gold~32_64'] = win(STYLES['c_dem_gold'], 32, 64)
STYLES['c_dem_gold~32_96'] = win(STYLES['c_dem_gold'], 32, 96)
STYLES['c_dem_gold~32_128'] = win(STYLES['c_dem_gold'], 32, 128)
STYLES['c_dem_gold~32_160'] = win(STYLES['c_dem_gold'], 32, 160)
STYLES['c_dem_gold~32_192'] = win(STYLES['c_dem_gold'], 32, 192)
STYLES['c_dem_gold~32_224'] = win(STYLES['c_dem_gold'], 32, 224)
STYLES['c_dem_gold~32_256'] = win(STYLES['c_dem_gold'], 32, 256)
STYLES['c_dem_gold~32_288'] = win(STYLES['c_dem_gold'], 32, 288)
STYLES['c_dem_gold~32_320'] = win(STYLES['c_dem_gold'], 32, 320)
STYLES['c_dem_gold~32_4096'] = win(STYLES['c_dem_gold'], 32, 4096)
STYLES['c_dem_gold~64_96'] = win(STYLES['c_dem_gold'], 64, 96)
STYLES['c_dem_gold~64_128'] = win(STYLES['c_dem_gold'], 64, 128)
STYLES['c_dem_gold~64_160'] = win(STYLES['c_dem_gold'], 64, 160)
STYLES['c_dem_gold~64_192'] = win(STYLES['c_dem_gold'], 64, 192)
STYLES['c_dem_gold~64_224'] = win(STYLES['c_dem_gold'], 64, 224)
STYLES['c_dem_gold~64_256'] = win(STYLES['c_dem_gold'], 64, 256)
STYLES['c_dem_gold~64_288'] = win(STYLES['c_dem_gold'], 64, 288)
STYLES['c_dem_gold~64_320'] = win(STYLES['c_dem_gold'], 64, 320)
STYLES['c_dem_gold~64_4096'] = win(STYLES['c_dem_gold'], 64, 4096)
STYLES['c_dem_gold~96_128'] = win(STYLES['c_dem_gold'], 96, 128)
STYLES['c_dem_gold~96_160'] = win(STYLES['c_dem_gold'], 96, 160)
STYLES['c_dem_gold~96_192'] = win(STYLES['c_dem_gold'], 96, 192)
STYLES['c_dem_gold~96_224'] = win(STYLES['c_dem_gold'], 96, 224)
STYLES['c_dem_gold~96_256'] = win(STYLES['c_dem_gold'], 96, 256)
STYLES['c_dem_gold~96_288'] = win(STYLES['c_dem_gold'], 96, 288)
STYLES['c_dem_gold~96_320'] = win(STYLES['c_dem_gold'], 96, 320)
STYLES['c_dem_gold~96_4096'] = win(STYLES['c_dem_gold'], 96, 4096)
STYLES['c_dem_gold~128_160'] = win(STYLES['c_dem_gold'], 128, 160)
STYLES['c_dem_gold~128_192'] = win(STYLES['c_dem_gold'], 128, 192)
STYLES['c_dem_gold~128_224'] = win(STYLES['c_dem_gold'], 128, 224)
STYLES['c_dem_gold~128_256'] = win(STYLES['c_dem_gold'], 128, 256)
STYLES['c_dem_gold~128_288'] = win(STYLES['c_dem_gold'], 128, 288)
STYLES['c_dem_gold~128_320'] = win(STYLES['c_dem_gold'], 128, 320)
STYLES['c_dem_gold~128_4096'] = win(STYLES['c_dem_gold'], 128, 4096)
STYLES['c_dem_gold~160_192'] = win(STYLES['c_dem_gold'], 160, 192)
STYLES['c_dem_gold~160_224'] = win(STYLES['c_dem_gold'], 160, 224)
STYLES['c_dem_gold~160_256'] = win(STYLES['c_dem_gold'], 160, 256)
STYLES['c_dem_gold~160_288'] = win(STYLES['c_dem_gold'], 160, 288)
STYLES['c_dem_gold~160_320'] = win(STYLES['c_dem_gold'], 160, 320)
STYLES['c_dem_gold~160_4096'] = win(STYLES['c_dem_gold'], 160, 4096)
STYLES['c_dem_gold~192_224'] = win(STYLES['c_dem_gold'], 192, 224)
STYLES['c_dem_gold~192_256'] = win(STYLES['c_dem_gold'], 192, 256)
STYLES['c_dem_gold~192_288'] = win(STYLES['c_dem_gold'], 192, 288)
STYLES['c_dem_gold~192_320'] = win(STYLES['c_dem_gold'], 192, 320)
STYLES['c_dem_gold~192_4096'] = win(STYLES['c_dem_gold'], 192, 4096)
STYLES['c_dem_gold~224_256'] = win(STYLES['c_dem_gold'], 224, 256)
STYLES['c_dem_gold~224_288'] = win(STYLES['c_dem_gold'], 224, 288)
STYLES['c_dem_gold~224_320'] = win(STYLES['c_dem_gold'], 224, 320)
STYLES['c_dem_gold~224_4096'] = win(STYLES['c_dem_gold'], 224, 4096)
STYLES['c_dem_gold~256_288'] = win(STYLES['c_dem_gold'], 256, 288)
STYLES['c_dem_gold~256_320'] = win(STYLES['c_dem_gold'], 256, 320)
STYLES['c_dem_gold~256_4096'] = win(STYLES['c_dem_gold'], 256, 4096)
STYLES['c_dem_gold~288_320'] = win(STYLES['c_dem_gold'], 288, 320)
STYLES['c_dem_gold~288_4096'] = win(STYLES['c_dem_gold'], 288, 4096)
STYLES['c_dem_gold~320_4096'] = win(STYLES['c_dem_gold'], 320, 4096)
