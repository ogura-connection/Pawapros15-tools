"""Styles for the match screens: the umpire's calls, pause menu, pitch chart, player panels, scoreboard, substitution, lineup and batting-order screens, and the team and stadium names of the match intro.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): gameplay, main_prg, order, shift_ed, vs_st, time, dscn_str.
"""
import numpy as np
from pp15.art.typeset import banded, called, tight, grow, shift, outlined, logo
from pp15.art import typeset as ui_type
from .common import ringfill

STYLES = {}


# ---- time.arc, gameplay.arc, main_prg.arc: umpire's calls, pause menu, pitch chart, player panel, substitution screen ----

def turned(style):
    """A style turned a quarter clockwise: vertical lettering that reads from top to bottom."""
    def t(ink, base):
        art, _ = style(ink, base)
        return np.ascontiguousarray(np.rot90(art, -1)), 0
    return t


STYLES.update({
    # the umpire's calls of a match (gameplay.arc h3_stf_0), one per palette of the bank
    "call0": called([15, 14, 13, 12, 11], [3, 7], 1, 10, 2, [6, 6, 6, 6]),      # blue: Play Ball, Time, Ball
    "call1": called([15, 14, 13, 12], [2, 3], 1, 11, 4, [6, 7, 7, 7]),          # yellow on olive: Strike, Foul
    "call2": called([9, 10, 11, 13], [6, 7], 5, 14, 1, [4, 4, 4, 4]),           # green: Walk, Safe, Hit ...
    "call3": called([9, 10, 11, 12, 13], [2, 3], 1, 15, 4, [6, 7, 7, 7]),       # pink: Out, Change, Game Set
    "call5": called([6, 7, 8, 9], [2, 4], 1, 10, 15, [13, 12, 12, 12]),         # yellow on pink: home runs
    # the pause menu of a match (gameplay.arc h3_tim_0, palettes 6..11 share one layout)
    "pausemenu": called([15, 14, 13, 12, 11], [8, 9, 10], 6, 6, 4, [6, 2], thick=1, wide=0, bandw=1),
    # pitch names of the match's pitch chart (main_prg.arc g3_np2, palette 14): white in a solid blue ring
    "pitchchart": tight(banded([0, 1, 1, 7, 7, 7, 7], [1])),
    # the player panel of a match (main_prg.arc g3_np, palette 13): navy in a white ring, a teal shadow
    "panel": tight(banded([0, 5, 6, 7, 8, 8, 8], [4, 4], 12)),
    # the substitution screen of a match (time.arc g3_tim)
    "subhead": tight(banded([0, 7, 6, 5, 3, 2, 1], [8, 8])),                 # column headers: navy in a white ring
    "subtab": tight(banded([0, 5, 4, 3, 2, 1, 1], [15, 13])),                # Batter / Bench: white in navy, italic
    "submenu": called([15, 15], [9, 11, 13], 8, 8, 4, [3, 2], thick=1, wide=0, bandw=1),   # palettes 55..60
    # words on the stripes of time.arc g3_tim (pals 20, 21): white, dark ring, light cyan shadow
    "tim_stripe": tight(banded([0, 5, 7, 8, 8, 8, 8], [1], 13)),
    # 今日の成績 on the bar of the score screen (pal 13): white, navy ring, blue shadow
    "tim_bar": tight(banded([0, 6, 4, 1, 1, 1, 1], [15], 12)),
    # 今日の成績 between « » (pal 8): deep blue letters in a white halo of two pixels, a blue shadow
    "tim_halo": tight(banded([0, 5, 3, 1, 1, 1, 1], [8, 8], 15)),
    # 攻撃中 standing between two red bars (pal 9): red letters in a white halo, blue shadow, turned
    "tim_vert": turned(tight(banded([0, 5, 3, 1, 1, 1, 1], [8, 8], 15))),
})


# ---- dscn_str.arc, gameplay.arc: the team / stadium name atlas of the match intro ------------------------------------

# dscn_str names (palette 4 of gameplay pal_y5_knm_0): white letters (15), navy ring (4), navy shadow cast down-right
STYLES["mi_name"] = ringfill([0xf], [4], [4, 4])
# h3_dem_0 スターティングオーダー / オーダー (palette 4): yellow shading to orange (13, 14, 15), blue ring (1) (the thin white
# rim of the Japanese is left out: qa RING wants the dark outside), blue shadow (2)
STYLES["mi_head"] = ringfill([0xd, 0xd, 0xe, 0xe, 0xf], [1, 1], [2, 2])
# h3_dem_0 打率 / 本塁打 (palette 3): white letters on a navy band (4), a blue shadow (6); kept 14 rows high so it clears the 16-row cells (qa CLIP)
STYLES["mi_col"] = ringfill([0xf], [4, 4], [6])


# ---- gameplay.arc bank h3_ap_ps2: score bug, batter / pitcher panels, swing tags -------------------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))

STYLES.update({
    # panel words 率 本 打点 試合 勝 敗 防: white letters, soft edge down to the dark ring, two solid rings
    "psp_panel": tight(banded([0, 5, 7, 9, 11, 13, 15], [1, 3])),
    # swing tags 強振 プッシュ バント 内前 外後 ...: the same white letters in a navy ring and an outer ring of the plate colour
    "psp_tag": tight(banded([0, 6, 8, 10, 12, 13, 15], [4, 1])),
    # 球 (pitch counts) on pages 2: letters 15 with a light ring 3 and an outer ring 5
    "psp_ball": tight(banded([0, 13, 13, 14, 14, 15, 15], [3, 5])),
    # bank h3_sc_ps2 (same runtime palettes): AT-BAT in the lettering colour 8 of 打席目 with its dark edge 3
    "sc_atbat": tight(banded([0, 0, 8, 8, 8, 8, 8], [3])),
    # SIGN on the サイン plate: letters 2 shading out through 3..8 into the plate, no ring
    "sc_sign": tight(banded([0, 0, 3, 2, 2, 2, 2], [])),
})


# ---- main_prg.arc bank h3_ulk_0: inning, home-run number, distance, replay banners -----------------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def banner(fill, inner, ext=(), outer=(), cut=3):
    def style(ink, base):
        pad = len(inner) + len(ext) + len(outer) + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big >= cut
        out = np.zeros(big.shape, np.uint8)
        masks = []
        m = letters
        for k in range(len(inner)):
            m = grow(m, 1, diagonal=(k == 0))
            masks.append(m)
        body = masks[-1] if masks else letters
        sil = body.copy()
        steps = []
        for k in range(1, len(ext) + 1):
            s = shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
            steps.append(s)
            sil |= s
        rings = []
        m = sil
        for k in range(len(outer)):
            m = grow(m, 1, diagonal=False)
            rings.append(m)
        for mk, v in zip(rings[::-1], list(outer)[::-1]):
            out[mk] = v
        for s, v in zip(steps[::-1], list(ext)[::-1]):
            out[s] = v
        for mk, v in zip(masks[::-1], list(inner)[::-1]):
            out[mk] = v
        ys = np.nonzero(letters.any(1))[0]
        y0, y1 = ys.min(), ys.max() + 1
        for y in range(y0, y1):
            row = letters[y]
            out[y][row] = fill[min(len(fill) - 1, (y - y0) * len(fill) // (y1 - y0))]
        yy = np.nonzero(out.any(1))[0]
        xx = np.nonzero(out.any(0))[0]
        r0, r1, c0, c1 = yy.min(), yy.max() + 1, xx.min(), xx.max() + 1
        return out[r0:r1, c0:c1], base + pad - r0
    return style


STYLES.update({
    # inning, home-run number, distance (pal 14): white, blue ring, deep blue shadow, as the digits beside them
    "ulk_inn": banner([15], [6], [5, 2]),
    # the big home-run number plate (pal 160): white, blue ring, bright blue extrusion
    "ulk_hr": banner([15], [6], [4, 4, 4, 4]),
    # Replay of the bar (pal 38): yellow-to-orange, dark olive ring, teal shadow
    "ulk_a": banner([14, 14, 13, 12, 11, 11], [4, 4], [2, 1]),
    # the replay tags (pal 125): yellow, brown rings, dark brown extrusion
    "ulk_b": banner([15, 15, 14, 13], [5, 6], [6, 6]),
    # the replay banners (pal 158): gold, navy outline and extrusion, white ring
    "ulk_c": banner([15, 14, 13, 12], [8, 8], [8, 8, 8], [7, 7]),
    # position plates of main_prg.arc g3_pur (pals 0..4): white letters, a dark ring and a mid ring of the plate colour
    "pur_pos": ui_type.tight(ui_type.banded([0, 1, 14, 13, 12, 11, 11], [1, 3, 6])),
    # あき of the same bank (pal 21, a ramp from white 15 down to dark rose 8): white letters, dark rose ring
    "pur_empty": ui_type.tight(ui_type.banded([0, 9, 11, 13, 14, 15, 15], [8, 5])),
})


# ---- gameplay.arc: defensive shift panel, record banners, team names, position tags ----------------------------------

# h3_aps_0: Def. Shift title (palette 14): orange letters in two black rings
STYLES["d_aps_title"] = ringfill([0xf], [1, 1])
# Outfield / Infield (palettes 50, 51): lavender letters, a blue-lavender ring, black shadow
STYLES["d_aps_side"] = ringfill([0xf], [6], [3])
# the rows of shift choices and the Bunt Shift line (palette 52): navy letters in light rings
STYLES["d_aps_row"] = ringfill([4], [0xe, 0xa])
STYLES["d_aps_row1"] = ringfill([4], [0xe])
# h3_lo_0: the record banner (palette 23): white letters shading to cream, blue ring, dark brown outer ring
STYLES["d_lo_banner"] = ringfill([0xf, 0xe, 0xd, 0xc], [8, 8, 1])
# hit-direction tags (palettes 39, 40): orange letters, green ring, dark green outer ring
STYLES["d_lo_tag"] = ringfill([0xf], [4, 1])
# h3_mrg_0 team names (palette 0): white letters, navy ring (one ring: the page has room for 19 names of 20 pixels only)
STYLES["d_mrg_name"] = ringfill([0xf], [1])
# y5_tnp_1 titles: Turning Point (palette 4, cyan on navy), Defense Point (palette 6, mint on deep green),
# Attack Point (palette 5, pink on maroon); each has a three-pixel dark outline and a white outer ring
STYLES["d_tnp_turn"] = ringfill([4, 4, 3, 3, 2, 2], [0xf, 0xf, 0xf, 5, 5, 6])
STYLES["d_tnp_def"] = ringfill([4, 5, 5, 8, 8, 8], [0xf, 0xf, 0xf, 3, 3, 2])
STYLES["d_tnp_atk"] = ringfill([4, 5, 6, 7, 8, 8], [0xf, 0xf, 0xf, 2, 2, 1])
# y4_kkg_0 position names (palette 2): black italic letters with a thin white edge
STYLES["d_kkg"] = ringfill([0xf], [1])
# y4_dem_1 title 守備交代 (palette 4): orange letters, dark ring, brown shadow
STYLES["d_dem_title"] = ringfill([0xf, 0xf, 0xe, 0xd], [4, 1], [8])
# h3_dem_2 headings (palettes 2, 3: one red ramp each): red-orange letters, dark brown ring, black-green outer ring, brown shadow
STYLES["d_dem_head"] = ringfill([0xf, 0xf, 0xe, 0xd], [4, 2], [7])


def platefill(fill, rings, shadow, w, h):
    """ringfill lettering centred on a w x h plate (the plate is palette index 0, opaque in these palettes)."""
    inner = ringfill(fill, rings, shadow)

    def style(ink, base):
        a, b = inner(ink, base)
        ah, aw = a.shape
        if aw > w or ah > h:
            raise ValueError("lettering %dx%d does not fit a plate %dx%d" % (aw, ah, w, h))
        out = np.zeros((h, w), np.uint8)
        x, y = (w - aw) // 2, (h - ah) // 2
        out[y:y + ah, x:x + aw] = a
        return out, b + y
    return style


# h3_rt_0 (g3_hk) score-challenge labels (palette 13): light tan letters, brown ring, on the orange plate (index 0);
# Bonus (palette 15): white letters, grey ring, on the cream plate
for _w in range(16, 97):
    STYLES["d_rt_%d" % _w] = platefill([0xf, 0xe, 0xd], [6], [], _w, 24)
    STYLES["d_oma_%d" % _w] = platefill([0xf, 0xf, 0xf, 0xe], [2], [1], _w, 24)
STYLES["d_rt_measure"] = ringfill([0xf, 0xe, 0xd], [6])      # width probe for the plate styles
STYLES["d_oma_measure"] = ringfill([0xf, 0xf, 0xf, 0xe], [2], [1])

# h3_nxt_ps2: ticker headings (palette 69): cream letters, navy ring; silver titles and rankings (72); league names (73-75); tags (95, 76)
STYLES["d_nxt_head"] = ringfill([8, 8, 0xd, 0xd], [0xf, 0xf], [4])
STYLES["d_nxt_top"] = ringfill([0xb, 0xc, 0xd, 0xd], [1, 1, 0xa, 9], [2])
STYLES["d_nxt_rank"] = ringfill([0xb, 0xc, 0xd, 0xd], [1, 1, 0xa, 9], [2])
STYLES["d_nxt_ce"] = ringfill([0xe, 0xd, 0xc, 0xb], [4, 1], [1])
STYLES["d_nxt_pa"] = ringfill([0xf, 0xe, 0xd, 0xc], [6, 4, 1], [2])
STYLES["d_nxt_le"] = ringfill([0xf, 0xe, 0xc, 0xa], [4, 1], [2])
STYLES["d_nxt_cl"] = ringfill([0xf, 0xf, 0xe, 0xc], [4])
STYLES["d_nxt_ch"] = ringfill([0xf, 0xf, 0xe, 0xd], [8])

# h3_her_0: banners (palette 23): mint letters, bright green ring, dark green outer ring; highlights (14): green letters, blue ring;
# Today's Highlights in red (65): red letters, dark ring, white edge
STYLES["d_her_big"] = ringfill([0xc, 0xc, 0xd, 0xe, 0xf], [1, 1, 8, 5])
STYLES["d_her_hl"] = ringfill([0xf, 0xf, 0xe, 0xd], [4, 1])
STYLES["d_her_red"] = ringfill([9, 8, 8, 7], [4, 1, 0xf])
# h3_rs_0: defence practice (palettes 11, 26, 27): white letters in blue rings
STYLES["d_rs_btn"] = ringfill([0xf], [5])
STYLES["d_rs_head"] = ringfill([0xf, 0xf, 0xe, 0xd], [7, 7], [6])
STYLES["d_rs_sub"] = ringfill([5, 5, 6, 7], [2, 1])


# ---- order.arc, vs_st.arc --------------------------------------------------------------------------------------------

def cast(mask, shadow):
    """The shadow of `mask`: colour shadow[k-1] at k steps down and to the right (near to far), only outside the mask."""
    out = np.zeros(mask.shape, np.uint8)
    for k in range(len(shadow), 0, -1):
        out[shift(mask, k, k) | shift(mask, k, k - 1) | shift(mask, k - 1, k)] = shadow[k - 1]
    return out


def trimmed(out, base):
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


def bandtext(ramp, rings, shadow=()):
    """Coloured letters (ramp[ink], ink 0..6) directly inside solid one-pixel rings (innermost first; the first ring
    keeps square corners, the others are rounded) and a cast shadow (near to far)."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = len(rings) + len(shadow) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = cast(masks[-1], shadow)
        for m, v in zip(masks[::-1], rings[::-1]):
            out[m] = v
        out[letters] = ramp[big[letters]]
        return trimmed(out, base + pad)
    return style


def onoval(oval, rim, ring, shadow, ramp, height=13, margin=6, ends=(4, 2, 1)):
    """White letters on a dark oval (a stadium shape `height` rows high, the ends cut in by `ends` pixels on the first
    rows, `margin` pixels longer than the word each side) with a lighter `rim` row round it, a one-pixel `ring` round
    the letters (the colour of the oval: letters that stand out of it keep an edge) and the shadow of what hangs out
    of it. The word headings of the bars in g3_od: the oval replaces the dark middle of the bar, which the heading's
    part used to carry."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pd = margin + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * 4 + 4, w + 2 * pd), int)
        big[4:4 + h, pd:pd + w] = ink
        L = big > 0
        B = grow(L, 1)
        cy = 4 + base // 2
        top = cy - height // 2
        ov = np.zeros(L.shape, bool)
        for y in range(top, top + height):
            d = min(y - top, top + height - 1 - y)
            inset = ends[d] if d < len(ends) else 0
            ov[y, pd - margin + inset:pd + w + margin - inset] = True
        rimm = grow(ov, 1, diagonal=False) & ~ov
        out = cast(B, shadow)
        out[(out > 0) & ov] = 0
        out[rimm] = rim
        out[ov] = oval
        out[B & ~ov] = ring
        out[L] = ramp[big[L]]
        return trimmed(out, base + 4)
    return style


# g3_od buttons (palettes 16-23): letters in the colour of the palette (8 .. e, e the light edge), a white ring, a
# blue ring, a light blue shadow
STYLES["f_btn"] = bandtext([0, 12, 10, 9, 8, 8, 8], [15, 7], [4, 3])
# g3_od bars (palettes 32-36): white letters on the dark oval (1) with a lighter rim (4); a light blue shadow (13, 12)
STYLES["f_bar"] = onoval(1, 4, 1, [13, 12], [0, 9, 9, 8, 8, 8, 8])

# g3_od tabs (palette 9, the 控え / 2軍 tabs of the bench panel): navy letters, white ring, blue shadow
STYLES["f_tab"] = bandtext([0, 5, 3, 2, 1, 1, 1], [8, 9], [14, 13])


# thin lettering (the Japanese is one or two pixels thick): regular weight faces
ui_type.TTF["f_arial"] = ("/System/Library/Fonts/Supplemental/Arial.ttf", 0)
ui_type.TTF["f_arialn"] = ("/System/Library/Fonts/Supplemental/Arial Narrow.ttf", 0)


def thin(ramp):
    """Letters only, ramp[ink] (ink 0..6), no ring and no shadow."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        out = np.zeros(ink.shape, np.uint8)
        out[ink > 0] = ramp[ink[ink > 0]]
        return trimmed(out, base)
    return style


# g3_od, light to dark ramps of one colour in the palette (index 1 lightest .. 15 darkest)
STYLES["f_thin"] = thin([0, 4, 7, 9, 12, 14, 15])
STYLES["f_thin_blue"] = thin([0, 4, 6, 9, 11, 13, 14])         # palette 100 (no index 15): ramp 1 .. 14

# the tags Type A / Type B / Rookie / Normal (palettes 43-46): coloured letters (1 darkest .. 12 light edge), a white ring
STYLES["f_tag"] = bandtext([0, 12, 9, 5, 3, 1, 1], [15, 15], [])
# Ready / Resting (palettes 49, 50: 13 = light .. 15 = dark of the blue / red of the 可 / 不可), white ring (12), blue glow
STYLES["f_rdy"] = bandtext([0, 13, 14, 15, 15, 15, 15], [12, 12], [7, 6])
# days (palette 48): dark green letters, white ring (15), blue shadow
STYLES["f_days"] = bandtext([0, 13, 9, 5, 3, 1, 1], [15, 15], [8])


def titlebar(letter, ring, fill, outline, thick=2, margin=7, rows=8, over=1):
    """White letters in a thick dark ring standing on a cyan pill (outline `outline` `thick` pixels, `rows` rows of `fill`).
    The letters' baseline lies `over` rows below the top of the pill's fill. The title bar of the lineup screen."""
    letter = np.array(letter, np.uint8)

    def style(ink, base):
        pd = margin + 4
        h, w = ink.shape
        H = h + 2 * 4 + rows + thick * 2
        big = np.zeros((H, w + 2 * pd), int)
        big[4:4 + h, pd:pd + w] = ink
        L = big > 0
        ringm = grow(grow(L, 1), 1, diagonal=False)
        fill_top = 4 + base - over                     # first row of the pill's fill
        top = fill_top - thick
        bot = fill_top + rows + thick
        bar = np.zeros(L.shape, bool)
        for y in range(top, bot):
            d = min(y - top, bot - 1 - y)
            inset = (4, 2, 1, 0)[d] if d < 4 else 0
            bar[y, pd - margin + inset:pd + w + margin - inset] = True
        inner = np.zeros(L.shape, bool)
        for y in range(fill_top, fill_top + rows):
            d = min(y - fill_top, fill_top + rows - 1 - y)
            inset = (3, 1, 0)[d] if d < 3 else 0
            inner[y, pd - margin + thick + inset:pd + w + margin - thick - inset] = True
        out = np.zeros(L.shape, np.uint8)
        out[bar] = outline
        out[inner] = fill
        out[ringm] = ring
        out[L] = letter[big[L]]
        return trimmed(out, base + 4)
    return style


# the title bar Starting Lineup (palette 12): white letters, blue ring (1), cyan bar (15)
STYLES["f_title"] = titlebar([0, 11, 12, 12, 12, 12, 12], 1, 15, 1)


# ---- vs_st.arc (stadium select) -----------------------------------------------------------------------------------------

# s5_tk, the short names on the stadium tiles (palette 7): navy letters, a white ring, a pale teal glow
STYLES["f_name"] = ringfill([6], [15, 15, 3, 4])
STYLES["f_name2"] = ringfill([6], [15, 3, 4])
STYLES["f_name3"] = ringfill([6], [15, 15, 3])
STYLES["f_name5"] = ringfill([6], [15, 15])
# s5_tk, ランダムで球場が決まります (palette 9): gold letters shading to orange, a navy ring, a muted violet edge
STYLES["f_help"] = ringfill([15, 15, 14, 14, 13, 13, 12, 12, 11, 11], [4, 4, 6], [7, 3])
# s5_tk, the ground types (palettes 21, 22, 24): green / yellow / orange letters, a blue-violet ring, a lilac glow
STYLES["f_turf"] = ringfill([15, 15, 14, 14, 13, 13, 12], [8, 7, 5], [5])
STYLES["f_grass"] = ringfill([15, 15, 14, 14, 13, 13, 12], [5, 8, 4], [4])
STYLES["f_dirt"] = ringfill([15, 15, 14, 14, 13, 13, 12], [8, 7, 5], [5])
# s5_tkz, the full names (8-bit pages, palette 16 = entries 256-511): letters shading from yellow (231) to orange (162), a dark
# teal ring (1), a light blue ring (193), a white band, a pink ring (135, 98) and a dark cast shadow
GOLD = [231, 229, 227, 223, 222, 219, 217, 212, 210, 208, 205, 202, 198, 194, 192, 190, 187, 181, 179, 175, 173, 171, 165, 164, 162]
STYLES["f_stad"] = ringfill(GOLD, [1, 193, 255, 255, 255, 135, 98], [35, 3, 3])
STYLES["f_stad2"] = ringfill(GOLD, [1, 193, 255, 255, 135, 98], [35, 3])


# ---- scorebook tags, team initials, plates, shift editor (main_prg.arc, shift_ed.arc) --------------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


# ---- the scorebook tag font: pp15/art/typeset.py's pixel tag font (capitals 11 high, two-pixel stems, every B with its bar) plus the
# 1, 3 and Q it lacks and narrower w and g, so that K-Swing fits one line ----
ETAG_EXTRA = {
    "1": ["..##", ".###", "####", "..##", "..##", "..##", "..##", "..##", "..##", "..##", "..##"],
    "3": ["+####+", "######", "##..##", "....##", "..###+", "..###+", "....##", "##..##", "##..##", "######", "+####+"],
    "Q": ["+####+.", "######.", "##..##.", "##..##.", "##..##.", "##..##.", "##..##.", "##.+##.", "######.", "+####+.", "....###"],
    "w": ["##.#.#", "##.#.#", "##.#.#", "##.#.#", "##.#.#", "######", "######", "+#+.+#"],
    "g": ["+###+", "##.##", "##.##", "##.##", "+####", "...##", "...##", "...##", "...##", "##.##", "+###+"],
}


def etag_font(project=None):
    if "etag" not in ui_type._fonts:
        level = {".": 0, "+": 3, "#": 6}
        rows = dict(ui_type.TAG_GLYPHS)
        rows.update(ETAG_EXTRA)
        ui_type._fonts["etag"] = {"words": {}, "space": 5, "gap": 1, "glyphs": {
            ch: (np.array([[level[c] for c in row] for row in r]), ui_type.TAG_DROP.get(ch, 0))
            for ch, r in rows.items()}}
    return ui_type._fonts["etag"]


ui_type.FONTS["etag"] = etag_font


def crisp(style, thr=3):
    """The style applied to ink cut at `thr`: every letter pixel full ink, no half tones."""
    def s(ink, base):
        return style(np.where(ink >= thr, 6, 0), base)
    return s


def scm_style(ink, base):
    """Team initials of the scoreboard (g3_scm, palette 0): white letters whose lower edge turns grey, a dark green
    outline that is cast two pixels down and to the right, a green fringe on that shadow."""
    pad = 4
    ink = np.where(ink >= 3, 6, 0)
    h, w = ink.shape
    big = np.zeros((h + 2 * pad, w + 2 * pad), int)
    big[pad:pad + h, pad:pad + w] = ink
    letters = big > 0
    ring = grow(letters, 1)
    body = ring | ui_type.shift(ring, 1, 1) | ui_type.shift(ring, 2, 2) | ui_type.shift(ring, 1, 2) | ui_type.shift(ring, 2, 1)
    fringe = (ui_type.shift(body, 1, 0) | ui_type.shift(body, 0, 1) | ui_type.shift(body, 1, 1)) & ~body
    out = np.zeros(big.shape, np.uint8)
    out[fringe] = 6
    out[body] = 7
    out[letters] = 15
    low = letters & ~ui_type.shift(letters, -1, 0)                  # no letter pixel below: the foot of a stroke
    out[low] = 11
    low2 = letters & ~ui_type.shift(letters, -2, 0) & ~low
    out[low2] = 13
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()


# ---- plates whose lettering is part of the picture: the plate is cleaned and the English drawn over it ----
_plates = {}


def _orig_sprite(bank, sid):
    """Palette indices (h, w) of a sprite as the game composes it, from the untouched original file."""
    key = (bank, sid)
    if key not in _plates:
        import os
        from pp15.art import textures as U
        path = os.path.join(U.ORIG_ARC_DIR, "main_prg.arc")
        d = open(path if os.path.exists(path) else os.path.join(U.S.DATA_FILES, "main_prg.arc"), "rb").read()
        b = next(x for x in U.banks(d, U.elf_symbols(d)) if x["name"] == bank)
        ps = next(v for n, v in b["sprites"].items() if n.endswith("_" + sid))
        w = max(p.x + p.x1 - p.x0 for p in ps)
        h = max(p.y + p.y1 - p.y0 for p in ps)
        im = np.zeros((h, w), np.uint8)
        for p in ps:
            idx = U.decode_indices(d, *b["pages"][p.page])[p.y0:p.y1, p.x0:p.x1]
            im[p.y:p.y + idx.shape[0], p.x:p.x + idx.shape[1]] = idx
        _plates[key] = im
    return _plates[key].copy()


def inpaint(im, mask):
    """Pixels of `mask` take the colour of the nearest pixel outside it (rows and columns, nearest first)."""
    out = im.copy()
    ys, xs = np.nonzero(~mask & (im > 0))
    pts = np.stack([ys, xs], 1)
    for y, x in zip(*np.nonzero(mask)):
        d2 = ((pts - (y, x)) ** 2).sum(1)
        out[y, x] = im[tuple(pts[d2.argmin()])]
    return out


def plated_text(bank, sid, clean, ramp, rings, centre, sharp=False):
    """A style that returns the whole plate: its original art, `clean`ed of the Japanese, with the ink drawn over
    it (letters shaded with `ramp`, ink 0..6, solid `rings`; `sharp` = no half tones), centred on `centre` (x, y)."""
    inner = banded(ramp, rings)

    def style(ink, base):
        orig = _orig_sprite(bank, sid)
        plate = clean(orig.copy())
        art, _ = tight(inner)(np.where(ink >= 3, 6, 0) if sharp else ink, base)
        cx, cy = centre
        h, w = art.shape
        x0, y0 = cx - w // 2, cy - h // 2
        area = plate[y0:y0 + h, x0:x0 + w]
        assert area.shape == art.shape, (sid, art.shape, plate.shape)
        area[art > 0] = art[art > 0]
        return plate, 0
    return style


def clean_box(*boxes, fill):
    def clean(im):
        for x0, y0, x1, y1 in boxes:
            im[y0:y1, x0:x1] = fill
        return im
    return clean


def clean_all(fill):
    def clean(im):
        im[im > 0] = fill
        return im
    return clean


def clean_inpaint(letters, box=None):
    def clean(im):
        mask = np.isin(im, letters)
        if box:
            keep = np.zeros_like(mask)
            x0, y0, x1, y1 = box
            keep[y0:y1, x0:x1] = True
            mask &= keep
        return inpaint(im, mask)
    return clean


def _orig_rect(arc, bank, page, rect):
    """Palette indices of a rectangle of a page, from the untouched original file (or the installed one)."""
    import os
    from pp15.art import textures as U
    key = (arc, bank, page)
    if key not in _plates:
        path = os.path.join(U.ORIG_ARC_DIR, arc)
        d = open(path if os.path.exists(path) else os.path.join(U.S.DATA_FILES, arc), "rb").read()
        b = next(x for x in U.banks(d, U.elf_symbols(d)) if x["name"] == bank)
        _plates[key] = U.decode_indices(d, *b["pages"][page]).copy()
    x0, y0, x1, y1 = rect
    return _plates[key][y0:y1, x0:x1].copy()


def gem_text(page, rect, glyph, box, well, centre):
    """The batter mark on the jewels of the shift editor: the original face with the glyph's box (x0, y0, x1, y1)
    filled with the well colour `well`, and the new letter in white with a black shadow below and to the right."""
    def style(ink, base):
        im = _orig_rect("shift_ed.arc", "r4_syu", page, rect)
        out = im.copy()
        x0, y0, x1, y1 = box
        out[y0:y1, x0:x1] = well                                    # the glyph and its halo: the well's own dark
        letters = np.where(ink >= 3, 1, 0).astype(bool)
        h, w = letters.shape
        art = np.zeros((h + 2, w + 2), np.uint8)
        shadow = ui_type.shift(np.pad(letters, ((0, 2), (0, 2))), 1, 1) | ui_type.shift(np.pad(letters, ((0, 2), (0, 2))), 1, 0) \
            | ui_type.shift(np.pad(letters, ((0, 2), (0, 2))), 0, 1)
        art[shadow] = 15
        art[:h, :w][letters] = 11
        cx, cy = centre
        ah, aw = art.shape
        area = out[cy - ah // 2:cy - ah // 2 + ah, cx - aw // 2:cx - aw // 2 + aw]
        area[art > 0] = art[art > 0]
        ys, xs = np.nonzero(im)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], 0
    return style


_WHITE = [0, 15, 15, 15, 15, 15, 15]
STYLES.update({
    # the shift editor (shift_ed.arc r4_syu): screen title, orange to pink letters in a white band with a blue rim and shadow
    "e_sh_title": crisp(logo([12, 12, 13, 13, 14, 14, 15, 15], [10], 9, 9, 3, [2, 1, 1], 3, 1)),
    # the headings (palettes 27 yellow, 28 green, 29 cream share their indices): letters shading down in three steps,
    # navy outline, a one-pixel teal edge with a darker teal shadow below
    "e_sh_head": crisp(called([12, 12, 12, 13, 13, 13, 14, 14, 14], [7, 6], 5, 5, 4, [3, 2], thick=2, wide=0, bandw=1, drop=(1, 0))),
    # Show Infield / Show Outfield (palette 24): dark blue letters, a white band, a teal edge
    "e_sh_show": crisp(tight(banded(_WHITE, [5, 5, 3]))),
    # column heads of the two gauges (palettes 98 and 99): dark blue letters in white, a dark edge
    "e_sh_h98": crisp(tight(banded(_WHITE, [9, 9, 3]))),
    "e_sh_h99": crisp(tight(banded([0, 5, 5, 5, 5, 5, 5], [13, 13, 4]))),
    # the small plates (palettes 81, 82, 83): white letters, a dark blue ring
    "e_sh_plate": crisp(tight(banded(_WHITE, [4]))),
    # the buttons (palettes 21, 22, 23): coloured letters, a white band two pixels wide, blue and light blue edges
    "e_sh_btn": crisp(tight(banded(_WHITE, [8, 8, 3, 5]))),
    # Starter Avg. (palette 102): white letters, a navy band, a teal edge
    "e_sh_avg": crisp(tight(banded(_WHITE, [8, 8, 6]))),
    "e_scm": scm_style,
    # team-type plates of r4_12h, as the Japanese lettering: white bold italic letters in a thick dark ring in the
    # plate's colour (palettes 32, 34, 37 share their indices: 1 dark)
    "e_plate2": crisp(tight(banded([0, 11, 11, 11, 11, 11, 11], [1, 1]))),
    # side marks on the digit font (g3_suuzi page 1): white letters, a black two-pixel outline
    "e_suuzi": crisp(banded([0, 1, 1, 1, 1, 1, 1], [15, 15])),
    # Mii choice plates (r4w_mi): green letters in a white halo; the game draws the same art again as a light blue silhouette
    "e_mi": tight(banded([0, 8, 6, 4, 3, 2, 2], [15, 15])),
    # 残り時間 (s4_clo00): blue letters shading to pale at the edge, a one-pixel white halo
    "e_clo": tight(banded([0, 10, 7, 5, 3, 1, 1], [15])),
    "e_pl_bb": plated_text("r4_12h", "bb", clean_box((4, 7, 31, 25), fill=15), [0, 8, 5, 3, 2, 1, 1], [], (17, 16)),      # League (palette 84)
    "e_pl_e1": plated_text("r4_12h", "e1", clean_box((14, 12, 39, 39), fill=10), [0, 15, 15, 15, 15, 15, 15], [1, 3], (26, 25), True),
    "e_pl_e2": plated_text("r4_12h", "e2", clean_box((9, 8, 26, 26), fill=10), [0, 15, 15, 15, 15, 15, 15], [1, 3], (17, 17), True),
    "e_pl_e3": plated_text("r4_12h", "e3", clean_all(7), [0, 1, 1, 1, 1, 1, 1], [15, 11], (13, 16), True),
    "e_sh_gem": gem_text(13, (0, 104, 24, 128), [10, 11, 12, 13, 14, 15], (4, 6, 22, 22), 1, (13, 14)),
    "e_pl_bc": plated_text("r4_12h", "bc", clean_box((4, 7, 31, 24), (4, 24, 32, 25), (7, 25, 32, 28), fill=15), [0, 9, 6, 4, 2, 1, 1], [], (17, 16)),       # All-Time (palette 85)
    # team-type plates of r4_12h (palettes 32, 34, 37 share their indices): white letters, a dark ring, a lighter ring
    "e_plate": crisp(tight(banded([0, 11, 11, 11, 11, 11, 11], [1, 3]))),
    # Baseball School & Practice (g3_rt): yellow shading to orange in a brown outline, a white band, blue rim and glow
    "e_rt_title": crisp(logo([12, 12, 14, 14, 13, 13], [1], 3, 15, 4, [6, 8], 2, 2)),
    # the two tabs (palette 2): the same in orange
    "e_rt_tab": crisp(logo([14, 14, 13, 12, 12], [1], 3, 15, 4, [6, 8], 2, 2)),
    # scorebook tags (g3_nk, g3_tij): white letters, navy ring, a blue outer ring (palettes 7-10 share indices 3..f)
    "e_tag": crisp(tight(banded([0, 15, 15, 15, 15, 15, 15], [4])), 4),
})
