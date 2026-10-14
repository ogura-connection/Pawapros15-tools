"""Label styles and a bank fix for gdt_ore.arc (My Life match overlays: h3_apm_0, y3_ss, y4_ind_0). Loaded by ui_type.py.

gdt_ore.arc merges sprite sets into one bank: h3_apm_0 holds the pages of h3_apm (0-3) and y3_sb (4, 5); y3_ss holds y3_ss
(0, 1), y3_cd (2-4) and g3_mib (5-10). The sprites of the later sets count their pages from 0 again. banks() is wrapped
here for this one file (recognised by its symbols) so that every set is a bank of its own with its own pages."""
import re
import numpy as np
import ui_type
import ui_textures as _U
from ui_type import grow, shift

_orig_banks = _U.banks


def _split(d, syms):
    out = []
    for b in _orig_banks(d, syms):
        if b["pal"] is not None and "tex_y3_sb00" in syms and "tex_h3_apm00" in syms and b["name"] == "h3_apm_0":
            sets = {"h3_apm_0": "opd_h3_apm_0_", "y3_sb": "opd_y3_sb_"}
        elif b["pal"] is not None and "tex_y3_cd00" in syms and b["name"] == "y3_ss":
            sets = {"y3_ss": "opd_y3_ss_", "y3_cd": "opd_y3_cd_", "g3_mib": "opd_g3_mib_"}
        else:
            out.append(b)
            continue
        pages = list(zip(b["page_names"], b["pages"]))
        for nm, pre in sets.items():
            tex = {"h3_apm_0": "tex_h3_apm", "y3_sb": "tex_y3_sb", "y3_ss": "tex_y3_ss", "y3_cd": "tex_y3_cd", "g3_mib": "tex_g3_mib"}[nm]
            mine = [(pn, pg) for pn, pg in pages if pn.startswith(tex)]
            nb = dict(b)
            nb.update({"name": nm, "pages": [pg for _, pg in mine], "page_names": [pn for pn, _ in mine],
                       "sprites": {n: ps for n, ps in b["sprites"].items() if n.startswith(pre)}})
            out.append(nb)
    return out


_U.banks = _split

STYLES = {}
