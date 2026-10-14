"""Label styles of the match screens: umpire's calls, pause menu, pitch chart, player panel, substitution screen
(see ui_type.py: RENDER takes STYLES from every ui_styles_*.py). Specs: ui_specs/gameplay.json, main_prg.json,
time.json, written by _work/ui_pages/gen_match_spec.py."""
import numpy as np
from ui_type import banded, called, tight


def turned(style):
    """A style turned a quarter clockwise: vertical lettering that reads from top to bottom."""
    def t(ink, base):
        art, _ = style(ink, base)
        return np.ascontiguousarray(np.rot90(art, -1)), 0
    return t


STYLES = {
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
}
