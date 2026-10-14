"""Label styles of the match HUD (gameplay.arc bank h3_ap_ps2: score bug, batter / pitcher panels, swing tags).
Loaded by ui_type.py like every ui_styles_*.py. Spec: _work/ui_pages/gen_match_more_gameplay.py.

The pages of this bank are 4-bit with a team-colour palette chosen by the game at run time; every variant is a
ramp, so only the roles of the indices matter: on the panel words (pages 3, 4) white fill = 15 with an inner
ring 1 and an outer ring 3; on the swing tags (pages 0 to 2) fill = 15 shading down to 4, rings 4 and 1."""
import ui_type
from ui_type import banded, tight

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))

STYLES = {
    # panel words 率 本 打点 試合 勝 敗 防: white letters, soft edge down to the dark ring, two solid rings
    "psp_panel": tight(banded([0, 5, 7, 9, 11, 13, 15], [1, 3])),
    # swing tags 強振 プッシュ バント 内前 外後 ...: the same white letters in a navy ring and an outer ring of the plate colour
    "psp_tag": tight(banded([0, 6, 8, 10, 12, 13, 15], [4, 1])),
    # 球 (pitch counts) on pages 2: letters 15 with a light ring 3 and an outer ring 5
    "psp_ball": tight(banded([0, 13, 13, 14, 14, 15, 15], [3, 5])),
    # bank h3_sc_ps2 (same runtime palettes): AT-BAT in the lettering colour 8 of 打席目 with its dark edge 3
    "sc_atbat": tight(banded([0, 6, 7, 8, 8, 8, 8], [3])),
    # SIGN on the サイン plate: letters 2 shading out through 3..8 into the plate, no ring
    "sc_sign": tight(banded([0, 7, 5, 4, 3, 2, 2], [])),
}
