"""Label styles of orepena.arc, third set: b5_m00, b5_mm, g3_rire, y3_file, y3_hist, y3_jim0, y3_jim1, y3_m256,
z3_nph_ore_0_opd, z3_ut_hen (command items, jobs, growth chart, file select, history, chapter cards, pitch names, stat arrows).
Loaded by pp15/art/typeset.py. Styles are the gsolid() ones of pp15/art/styles/ui_styles_orepena2, definitions in specs/orepena3_styles.json
(written by _work/ui_pages/gen_orepena_rest2.py); DIN fonts "dc29g2b10" .. "dc48g2b20" for the chapter cards."""
import json, os
from pp15 import config
from pp15.art import typeset as ui_type
from . import ui_styles_orepena as _O
from . import ui_styles_orepena2 as _O2

for _cap in range(29, 49):
    for _b in (10, 20):
        ui_type.FONTS["dc%dg2b%d" % (_cap, _b)] = _O._din_font(_cap, 2, _b / 100.0)


def _load():
    path = os.path.join(config.SPECS_DIR, "orepena3_styles.json")
    out = {}
    if os.path.exists(path):
        for name, v in json.load(open(path)).items():
            out[name] = _O2.plate2(v) if v.get("kind") == "plate2" else _O2.gsolid(v["fills"], v["rings"], v.get("shadow", 0), v.get("cut", 2))
    return out


STYLES = _load()
