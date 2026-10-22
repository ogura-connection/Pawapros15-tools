"""One-off: rewrite the old style-module names (ui_styles_<run>_run<N>, ui_styles_voice, ...) in the scratch scripts of _work.

    python3 docs/one_off_rewrite_work_imports.py DIR [--write]      DIR = e.g. _work/ui_pages ; without --write it only counts

The old names are mapped to the new modules of pp15/art/styles/ (table in docs/styles_map.md). Names that moved into
common.py (ringfill, _orig_page, flat, win) are redirected there. Files under folders that start with "orig" are skipped.
Delete this file after the swap.
"""
import json
import os
import re
import sys

MAP = json.loads('{ "a_run1": "controller", "a_run2": "success_start_end", "a_run3": "logo_front_panel", "a_run4": "eikan_menus", "a_run5": "pennant", "a_run6": "pennant", "a_run7": "arrange_sub", "a_run8": "records_room", "a_run9": "success_main", "b_run1": "settings", "b_run2": "success_scenarios", "b_run3": "success_scenarios", "b_run4": "eikan_menus", "b_run5": "pennant_sub", "b_run6": "pennant", "b_run7": "arrange", "b_run8": "records_room", "b_run9": "logo_pictures", "c_run1": "main_menu", "c_run2": "success_main", "c_run3": "success_main", "c_run4": "eikan_school", "c_run5": "pennant_sub", "c_run6": "pennant_start", "c_run7": "arrange", "c_run8": "records_room_extra", "c_run9": "champion", "cheer_menu": "settings", "d_run1": "match", "d_run2": "success_start_end", "d_run4": "eikan_main", "d_run5": "pennant_sub", "d_run6": "pennant", "d_run7": "arrange", "d_run8": "game_results", "d_run9": "settings", "e_run1": "match", "e_run10": "champion", "e_run2": "success_main", "e_run4": "eikan_main", "e_run5": "pennant_sub", "e_run6": "pennant_start", "e_run7": "arrange_edit", "e_run8": "camp_remopawa", "ek_strip": "eikan_menus", "f_run1": "match", "f_run10": "success_main", "f_run2": "success_main", "f_run7": "arrange_edit", "f_run7b": "arrange_edit", "f_run7c": "arrange_edit", "f_run8": "contract_talks", "fix_A_mylife": "late_fixes", "fix_A_mylife_orepena": "my_life_screens", "fix_B_pennant": "pennant_sub", "fix_C": "camp_remopawa", "fix_D_eikan": "eikan_menus", "fix_E_other": "late_fixes", "fix_left": "late_fixes", "g_run10": "eikan_menus", "gdt_ore": "my_life_match", "gdt_ore_cd": "my_life_match", "h_run10": "champion", "l_run11": "logo_title_screens", "match": "match", "match_intro": "match", "match_ps2": "match", "match_ulk": "match", "myend": "my_life_report", "mylife": "my_life_screens", "ore_fa": "my_life_practice", "ore_i_co": "my_life_practice", "ore_ini": "my_life_screens", "ore_ini_card": "my_life_screens", "ore_ini_card2": "my_life_chapters", "ore_myk": "my_life_chapters", "ore_ren": "my_life_practice", "ore_sub": "my_life_practice", "ore_sub2": "my_life_practice", "ore_sub3": "my_life_practice", "orepena": "my_life_screens", "orepena2": "my_life_report", "orepena3": "my_life_chapters", "p_run11": "logo_pictures", "q_run11": "champion", "sip_comm": "eikan_main", "voice": "settings", "vs_flame": "success_versus", "zz_reader2": "late_fixes", "zzz_camp": "camp_remopawa", "zzzz_leftd": "eikan_main"}')
COMMON = {"ore_ini": ("ringfill", "_orig_page"), "voice": ("flat",), "c_run1": ("win",)}


def target(old, line):
    if old in COMMON and any(re.search(r"\b%s\b" % n, line) for n in COMMON[old]):
        return "common"
    return MAP.get(old, old)


def rewrite_line(line):
    if "ui_styles_" not in line:
        return line
    # bare "import ui_styles_x [as y]"
    m = re.match(r"^(\s*)import (ui_styles_(\w+?))(?: as (\w+))?\s*$", line.rstrip("\n"))
    if m and m.group(3) in MAP:
        new = target(m.group(3), line)
        return "%sfrom pp15.art.styles import %s as %s\n" % (m.group(1), new, m.group(4) or new)
    # "from ui_styles_x import ..." without the package
    line = re.sub(r"\bfrom ui_styles_(\w+?) import", lambda k: "from pp15.art.styles.%s import" % target(k.group(1), line), line)
    names = sorted(MAP, key=len, reverse=True) + ["ore_ini"]
    def sub(k):
        old = k.group(1)
        return target(old, line) if old in MAP else k.group(0)
    return re.sub(r"ui_styles_(%s)\b" % "|".join(re.escape(n) for n in sorted(MAP, key=len, reverse=True)), sub, line)


def main(argv):
    root, write = argv[0], "--write" in argv
    changed = lines = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if not d.startswith("orig") and d != "__pycache__"]
        for f in fn:
            if not f.endswith((".py", ".sh", ".txt", ".md")):
                continue
            p = os.path.join(dp, f)
            try:
                src = open(p, encoding="utf-8").read()
            except UnicodeDecodeError:
                continue
            if "ui_styles_" not in src:
                continue
            out = "".join(rewrite_line(l) for l in src.splitlines(True))
            n = sum(1 for a, b in zip(src.splitlines(), out.splitlines()) if a != b)
            if n:
                changed += 1
                lines += n
                if write:
                    open(p, "w", encoding="utf-8").write(out)
    print("%d files, %d lines %s" % (changed, lines, "rewritten" if write else "would change"))


if __name__ == "__main__":
    main(sys.argv[1:])
