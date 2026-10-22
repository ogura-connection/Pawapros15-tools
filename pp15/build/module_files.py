"""Find, load and install the game's REL modules.

What it is for: the build never reads the game files it is about to overwrite. On the first run it copies every
.rel module (and the memory plan) from DATA/files to _work/orig/; from then on that folder is the untouched
original. Built files are written to _work/build/, checked there, and only then copied to DATA/files.

Public functions:
    ensure_orig()          save the original files on first use
    load_dir(*dirs)        parse every module of some folders: {module id: scan.Rel}
    load_scripts(mods, remaps)   parse the four Success Mode script modules
    install(changed)       DATA/files = originals + the built files named in `changed`
"""
import filecmp
import os
import shutil

from pp15 import config
from pp15.build.dol_block import DOL, DOL_BUILT
from pp15.build.memory_plan import PLAN_FILE
from pp15.script import scan
from pp15.text import strings

ORIG_DIR = config.ORIG_DIR
BUILD_DIR = config.BUILD_DIR


def ensure_orig() -> None:
    """Copy the .rel modules and the memory plan from DATA/files to _work/orig/ unless already there.

    The first run must be on unpatched files: whatever is in DATA/files then becomes "the original".
    """
    if not os.path.isdir(ORIG_DIR):
        os.makedirs(ORIG_DIR)
        print("Saving the original files to %s" % ORIG_DIR)
    for fn in sorted(os.listdir(config.DATA_FILES)):
        if (fn.endswith(".rel") or fn == PLAN_FILE) and not os.path.exists(os.path.join(ORIG_DIR, fn)):
            shutil.copy2(os.path.join(config.DATA_FILES, fn), os.path.join(ORIG_DIR, fn))


def load_dir(*dirs: str) -> dict:
    """Load every module of the given folders, later folders overriding earlier ones. Returns {module id: Rel}."""
    paths = {}
    for d in dirs:
        for fn in os.listdir(d):
            if fn.endswith(".rel"):
                paths[fn] = os.path.join(d, fn)
    mods = {}
    for fn in sorted(paths):
        rel = scan.Rel(paths[fn])
        mods[rel.mod_id] = rel
    return mods


def load_scripts(mods: dict, remaps: dict | None = None) -> list:
    """Parse the four Success Mode script modules (scan.SCRIPT_FILES) into scan.Script objects.

    `remaps`: pass the remaps of a rebuilt set of files, whose label tables have moved.
    """
    by_name = {m.name: m for m in mods.values()}
    main = by_name["scs_main.rel"]
    move = (remaps or {}).get((main.mod_id, main.script_section()), lambda off: off)
    tables = tuple(move(off) for off in scan.LABEL_TABLES)
    return [scan.Script(by_name[fn], mods, tables) for fn in scan.SCRIPT_FILES]


def install(changed: list[str]) -> None:
    """Make DATA/files = the originals plus the built files named in `changed`; main.dol goes to DATA/sys."""
    n = 0
    for fn in sorted(os.listdir(ORIG_DIR)):
        src = os.path.join(BUILD_DIR if fn in changed else ORIG_DIR, fn)
        dst = os.path.join(config.DATA_FILES, fn)
        if not filecmp.cmp(src, dst, shallow=False):
            shutil.copy2(src, dst)
            n += 1
    print("Installed: %d file(s) written to DATA/files (%d differ from the originals)."
          % (n, len([fn for fn in changed if fn != DOL])))
    if os.path.exists(strings.DOL_ORIG):         # main.dol: DATA/sys = the built one or the original
        src = DOL_BUILT if DOL in changed else strings.DOL_ORIG
        if not os.path.exists(strings.DOL_SOURCE) or not filecmp.cmp(src, strings.DOL_SOURCE, shallow=False):
            shutil.copy2(src, strings.DOL_SOURCE)
            print("Installed: %s written to DATA/sys (%s)." % (DOL, "translated dialogs" if DOL in changed else "the original"))
