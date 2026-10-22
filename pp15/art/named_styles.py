"""The named styles of the lettering tool: a name such as "plate" or "title22" -> the style function that draws it.

Each entry says how one kind of English label is drawn on its Pawapuro 15 page: the colours are indices into that page's
palette (named in the comment above the entry, e.g. "palette 8 of g3_tn00 in are_abi.arc"), so the numbers only make
sense with the page in view. The factories (banded, logo, haloed, ...) are in pp15/art/lettering_styles.py. A spec
(specs/*.json) picks a style by name for a label; typeset.RENDER holds this table plus the ones from pp15/art/styles/.

BASE_STYLES is the table; it is copied into typeset.RENDER.
"""
from pp15.art.lettering_styles import (badged, banded, boxed, captioned, dropped, haloed, logo, outlined, plated,
                                       ringed, shadowed, style_command, style_stat, titled)

BASE_STYLES = {
    "command": style_command,
    # the ability plates (palette 8 of g3_tn00 in are_abi.arc): white letters, dark blue outline, a paler ring
    "plate": banded([0, 9, 10, 11, 13, 14, 15], [7, 3]),
    # the names on the ratings page (palettes 147-150 of y5_mh): Kantoku, Scout, Teammates, Bucho
    "rater147": badged([8, 9, 10], [2, 3, 5, 6, 7], 1, 11, [12, 14, 13]),
    "rater148": badged([12, 13, 14, 15], [2, 3, 4, 5], 1, 11, [8, 7, 6]),
    "rater149": badged([11, 12, 13, 14, 15], [8, 9, 10], 7, 1, [2, 3, 4]),
    "rater150": badged([14, 13, 12, 8, 7, 6, 5], [2, 3, 4], 1, 15, [13, 10, 11]),
    # the screen titles (palettes 22-28 of z3_dts; every palette has its own order of colours)
    "title22": titled([1, 2, 3, 4, 5, 6, 7], 10, [8, 9], [13, 15], 2),
    "title23": titled([1, 2, 3, 4, 5, 6, 7], 15, [8, 9], [12, 10], 2),
    "title24": titled([1, 2, 3, 4, 5, 6, 8, 7], 13, [15, 14], [12, 10], 2),
    "title25": titled([1, 2, 3, 4, 5, 6, 7, 8], 9, [12, 11], [13, 15], 2),
    "title26": titled([1, 2, 3, 6, 4, 5], 12, [8, 15], [11, 9], 2),
    "title27": titled([1, 2, 3, 4, 5, 6, 7], 15, [8, 11], [12, 9], 2),
    "title28": titled([1, 2, 3, 4, 5, 6, 7, 8], 11, [13, 12], [14, 15], 2),
    # Data screen (scs_data.arc, scs_sys.arc). White letters, dark outline, a shadow one step lighter: the
    # ability tabs (palettes 56-59 of z3_dt), handedness and form names (72), trait plates (104, 105)
    "data": banded([0, 6, 8, 10, 12, 14, 15], [4, 3], 2),
    # dark letters in a white band with a pink glow: B/T, Form, Growth (palette 64 of z3_dt)
    "datafield": haloed([0, 7, 6, 5, 3, 2, 1], 8, [9, 8, 8, 8, 10, 11, 12, 13, 14, 15]),
    # dark letters in a white band with a blue glow: the screen buttons (palettes 32-36 of z3_dts)
    "databutton": haloed([0, 7, 6, 5, 3, 2, 1], 8, [10, 10, 11, 11, 12, 12, 13, 14, 15]),
    # letters shading from light at the top to dark at the foot, white band, pale blue glow: the stat names and
    # tags of the team-mate list (palettes 116-125 of z3_dtn), the equipment headers (82 of z3_dt)
    "datastat": haloed(None, 8, [8, 9, 10, 11, 12, 13, 14, 15], fill=[5, 4, 4, 3, 3, 2, 2, 1, 1], light=8),
    "datastat1": haloed(None, 8, [8, 9, 10, 11, 12, 13, 14, 15], 1, fill=[3, 3, 2, 2, 1, 1], light=8),
    # blue letters in a white band, pale blue glow: the lists of the equipment page (palette 82 of z3_dt)
    "datahead": haloed([0, 7, 6, 5, 4, 3, 2], 8, [8, 9, 10, 11, 12, 13, 14, 15]),
    # white letters in one dark ring: a trait name that lies across the two colours of its plate
    "dataflat": banded([0, 6, 8, 10, 12, 14, 15], [4, 4]),
    # dark blue at the top to light blue at the foot, white band: 装備中アイテム (palette 80 of z3_dt)
    "dataequip": haloed(None, 15, [15, 15, 15, 14, 13, 12, 11, 10], fill=[1, 2, 3, 4, 5, 6, 7], light=15),
    # the rank plate of scenario 1 (y5_siba_1): 平社員 grey with a white outline (palette 19), 係長 dark with a white
    # outline (20), 課長 orange in white and blue (21); 役職 white with a dark outline (20)
    "rank0": ringed([0, 12, 11, 9, 7, 5, 4], [15, 15]),
    "rank1": ringed([0, 12, 10, 8, 5, 3, 1], [15, 15]),
    "rank2": ringed([0, 13, 15, 6, 5, 4, 3], [11, 2, 1]),
    "ranktag": outlined([0, 8, 10, 12, 13, 14, 15], 2, 3),
    # navy letters, white outline, light blue shadow: the pitch names (palette 32 of z3_nph_scs)
    "pitch": shadowed([0, 7, 6, 4, 3, 2, 1], 8, 14, 2),
    # white letters, navy outline and shadow: 年目 / 月 / 週 of the date (palette 22 of y5_ten)
    "calendar": shadowed([0, 9, 11, 13, 14, 15, 15], 3, 4, 1),
    # yellow letters, purple outline: the 天気 tag (palette 56 of y5_np)
    "weather": outlined([0, 9, 10, 11, 12, 14, 15], 7, 5),
    # white letters in a red glow: 熱血発動中 (palette 47 of y5_npm)
    "glow": ringed([0, 9, 11, 12, 13, 14, 15], [4, 2]),
    # white letters, black outline: the button hints (palette 60 of y5_npm, a grey ramp)
    "hint": outlined([0, 8, 10, 12, 13, 14, 15], 1, 2),
    # plain black letters, no outline (palette 82 of z3_smr, light grey to black)
    "plain": outlined([0, 3, 6, 9, 11, 13, 15], 0, 0),
    # the shop (scs_item.arc, z3_shp): tab names, dark blue shading to light at the foot, in a white band with a
    # lilac glow (palette 24); 所持金 (72); the Cancel button (53, drawn again as a shadow with 50 / 51);
    # the 購入 / 所持 tags, white with a dark outline (60, 61); the − hint, white on a black box (44);
    # the screen title, pink in a blue outline on a white band with a dark shadow (54, 55)
    "shoptab": haloed(None, 8, [9, 10, 11, 12, 13, 14, 15], fill=[1, 1, 2, 3, 3, 4, 4, 5, 5], light=8),
    "shopmoney": haloed([0, 7, 6, 4, 3, 2, 1], 8, [13, 12, 12, 11, 11, 10, 12, 14]),
    "shopcancel": haloed([0, 12, 11, 7, 5, 3, 1], 14, [8, 10, 9, 9, 9, 9, 8], 1),
    "shoptag": outlined([0, 9, 10, 12, 13, 14, 15], 8, 8),
    "shophint": boxed([1, 4, 7, 9, 11, 13, 15], (3, 4), (31, 21)),
    "shoptitle": logo([12, 12, 13, 13, 15, 15, 14], [14], 2, 10, 8, [1, 1]),
    # 売り切れ！: green letters, lighter at the top, in a dark outline on a white band, lilac shadow (palette 63)
    "shopsold": logo([7, 7, 7, 6, 6, 6, 5, 5, 4, 3], [2, 3], 1, 15, 13, [8, 9]),
    # the gear names on the item icons (m4_item1, palette 13, a grey ramp): white, black outline, grey shadow
    "gear": shadowed([0, 4, 7, 10, 12, 14, 15], 1, 9, 1),
    # the settings list of the System screen (scs_sys.arc, pages z3_sys): row names, yellow shading from orange,
    # in a violet outline with a paler edge (palette 161); values, dark at the top to light at the foot, white
    # band, blue shadow (162-170, one colour each); 難度, yellow-green on a blue box (160)
    "sysheader": haloed(None, 9, [12, 11, 11, 10, 10, 10, 10, 11, 12, 13], fill=[3, 3, 3, 2, 2, 2, 1, 1, 1], light=9),
    "sysvalue": haloed(None, 8, [8, 8, 8, 9, 10, 12, 14, 15, 15, 15], fill=[1, 1, 1, 2, 2, 3, 3, 3, 4, 4, 5], light=8),
    "sysbox": boxed([9, 8, 7, 6, 5, 3, 2], (3, 4), (0, 0), 11),
    # the item list (scs_main.arc, z3_itw): tab names, blue shading to pale at the foot, white band (palettes 50, 51)
    "itemtab": haloed(None, 15, [14, 14, 14, 14, 13, 12, 10, 9, 8, 7, 7, 7],
                      fill=[1, 1, 2, 2, 3, 3, 4, 5, 5, 6, 6, 7, 8], light=15),
    # scene captions of scs_main.arc (r3_ai, palette 160): white letters, navy outline and cast shadow
    "caption": captioned([15, 15, 14, 12, 11, 10, 8], 15, 13),
    # position words of the main screen (y5_np_0 pages 3 and 7, palettes 32-35): white in a double ring
    "position": banded([3, 5, 7, 9, 11, 13, 15], [3, 3], 2),
    # the before / after panel of the Equip page (scs_data.arc z3_ikp_0): stat names in palette 2,
    # Before / After in palettes 14 and 15 (green and yellow letters on a white band)
    "equipstat": banded([4, 6, 8, 10, 12, 14, 15], [4, 3]),
    "equipbefore": logo([15, 15, 14, 14, 13, 13, 12, 12, 11], [9, 10], 8, 1, 2, [4, 5]),
    # league plates of the standings (scs_data.arc z4_dtj_0, palettes 90-92): white on the plate colour
    "league44": plated([8, 8, 10, 10, 13, 15, 15], 6, (44, 20)),
    "league36": plated([8, 8, 10, 10, 13, 15, 15], 6, (36, 20)),
    # team names of the standings (palette 87, black on the board): two grey levels only, as the Japanese has,
    # so that the compressed pages stay inside their slots
    "team": outlined([0, 0, 4, 7, 15, 15, 15], 0, 0),
    "month": logo([15], [15], 15, 8, 7, [4, 1], 3),     # navy on a white band, blue cast: the month banner
    "stat": style_stat,
    # white letters, dark blue outline: the 体力 / 熱血 tags (palette 58, a blue-to-white ramp)
    "tag": outlined([0, 5, 7, 10, 12, 14, 15], 1, 3),
    # dark blue letters, white outline: 所持金 (palette 19, dark blue to white)
    "money": outlined([0, 12, 10, 8, 5, 3, 2], 15, 15),
    # blue letters, white outline: やる気 (palette 50; the game draws a shadow copy with palette 30)
    "motivation": outlined([0, 12, 10, 8, 5, 2, 1], 15, 15),
    # the Success start screen (scs_titl.arc, y5_scs_tit_0). The three buttons: yellow letters in a thick brown
    # outline (palette 17), pink in dark magenta (18), light green in dark green (19), each on a white band
    # with a pale rim and a blue shadow
    "titlestart": logo([6], [2, 3, 4, 5], 1, 13, 11, [9, 8], 2, 2),
    "titleview": logo([12, 12, 12, 13, 14, 15], [4, 5, 6], 3, 10, 8, [2, 1], 2, 2),
    "titlelink": logo([6, 6, 6, 6, 5, 5], [2, 3, 4], 1, 14, 12, [9, 8], 2, 2),
    # New Game / Continue / the lists: white letters in a blue outline that is cast down and to the right (22)
    "titleitem": captioned([4, 10, 11, 12, 13, 14, 15], 5, 3),
    # the counts line: white letters in a navy ring (26)
    "titlecount": banded([0, 5, 7, 9, 11, 13, 15], [1]),
    # Cleared / Turned Pro: navy letters on a white band with a grey shadow (45)
    "titleclear": banded([0, 12, 10, 9, 1, 2, 3], [15, 15], 5),
    # the overwrite warning (r4_sta): red lines (palette 27) and black lines (28), each a ramp to white, in a
    # white band; the heading, yellow in a thick blue outline on white (25; palette 26 draws it again in one
    # colour as its shadow)
    "warnline": banded([0, 12, 9, 7, 4, 2, 1], [15, 15, 15]),
    "warnhead": logo([10, 10, 11, 11, 12, 12], [15, 14, 9], 1, 7, 7, [], 2, 2),
    # Cleared on the album page: green letters on a white band inside blue rings (1); the movie button: white
    # letters in thick navy (2)
    "albumclear": banded([0, 9, 8, 6, 4, 2, 1], [10, 10, 12, 14, 15]),
    "albummovie": banded([0, 6, 8, 10, 12, 14, 15], [3, 3, 3]),
    # the scenario's team name on the start screen (y5_sge_0, palette 4): white letters in two blue rings
    "titleteam": banded([0, 10, 11, 12, 13, 14, 15], [4, 5]),
    # the profile screens (scs_make.arc, y5_cmk_0): headings, cream shading from orange in a thick blue outline
    # with a lilac rim (palette 30); the lists, dark grey letters with a pale shadow (26)
    "makehead": logo([9, 9, 10, 11, 12], [5], 1, 1, 14, [], 1, 2),
    "makeitem": dropped([0, 11, 11, 13, 13, 15, 15], [7, 5]),
    # the view hint of the form screens: lilac letters on a white band with a pale shadow (16)
    "makehint": banded([0, 13, 5, 3, 2, 1, 1], [15, 15], 7),
    # the difficulty screen (y5_nan_0): Normal, green fading to white at the foot in a dark green outline on a
    # white band (palette 24); Rookie, the same in orange (23, another order of colours). Palette 31 draws
    # each again in black as its shadow.
    "nannormal": logo([10, 9, 8, 7, 6, 5, 4], [13, 11], 15, 3, 2, [], 2, 2),
    "nanrookie": logo([9, 11, 12, 13, 14, 15, 4], [6, 8], 5, 4, 2, [], 2, 2),
    # name entry (namein.arc, s3_nam): headings, yellow in a thick blue outline on a white band with a lilac
    # shadow (palette 14); the button words, dark letters on a white band in blue rings (25, 26, 28)
    "namehead": logo([13, 13, 11, 11, 10, 10], [8], 3, 15, 14, [7, 6], 2, 2),
    "namebutton": banded([0, 10, 11, 12, 13, 14, 15], [9, 9, 7, 5]),
}
