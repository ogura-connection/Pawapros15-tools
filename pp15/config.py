"""Where every file and folder of the project lives; the other modules import their paths from here.

The game data (extracted disc files, working copies) is not in git; the folders below say where the tools look for it.
This module only builds path strings (nothing is read or created), plus `use_scratch()` for the few places that still
import a helper script from `_work/`.

Folder layout (the workspace is ~/Projects/Pawapuro; see its README.md):

    <workspace>/roms/  reference/  tools/      shared by every game: discs, MLB reference discs, helper binaries (wit)
    <workspace>/pp15/                          everything about Pawapuro 15 ("the game folder")
        pp15-tools/                            this repository: code, translation, specs, tests (the only thing in git)
        data/DATA, data/_work                  extracted game files and working files (private, never in git)
        emulator/  release/  probes/  docs/    test Dolphin, finished patch, investigations, notes

Defaults follow that layout; environment variables override them:

    PP15_ROOT   the repository folder (default: the parent of this package)
    PP15_DATA   the folder that holds DATA/ and _work/   (default: <game folder>/data)
    PP15_EMU    the Dolphin test folder (save states, the OCR helper)   (default: <game folder>/emulator)
    PP15_KIT    the translation-kit folder, the target of `export-tm` / `export-labels`   (default: ~/Projects/translation-kit,
                the folder beside the workspace)
    PP15_MLB    the folder that holds the extracted MLB reference discs   (default: <workspace>/reference)
"""
import os
import sys

ROOT = os.environ.get("PP15_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GAME_DIR = os.path.dirname(ROOT)                      # the Pawapuro 15 folder: repository, data, emulator, release
WORKSPACE = os.path.dirname(GAME_DIR)                 # the Pawapuro workspace: roms, reference discs, tools, one folder per game
DATA_ROOT = os.environ.get("PP15_DATA") or os.path.join(GAME_DIR, "data")

# Game data: extracted from the disc, never committed (outside the repository)
DATA = os.path.join(DATA_ROOT, "DATA")
DATA_FILES = os.path.join(DATA, "files")
DATA_SYS = os.path.join(DATA, "sys")
DOL_SOURCE = os.path.join(DATA_SYS, "main.dol")

# Working files (game data too, git-ignored)
WORK_DIR = os.path.join(DATA_ROOT, "_work")
ORIG_DIR = os.path.join(WORK_DIR, "orig")             # untouched .rel files (and moduleID2addr.o)
ORIG_ARC_DIR = os.path.join(WORK_DIR, "orig_arc")     # untouched .arc files; not _work/orig: the build installs that whole folder
ORIG_SYS_DIR = os.path.join(WORK_DIR, "orig_sys")     # untouched main.dol
BUILD_DIR = os.path.join(WORK_DIR, "build")
UI_PAGES_DIR = os.path.join(WORK_DIR, "ui_pages")     # pictures and arrays prepared for the lettering work; the art styles read them (game data, git-ignored)

# What is in git
TRANSLATION_DIR = os.path.join(ROOT, "translation")
SPECS_DIR = os.path.join(ROOT, "specs")
TESTS_DIR = os.path.join(ROOT, "tests")

# Things outside the repository
KIT_DIR = os.environ.get("PP15_KIT") or os.path.normpath(os.path.join(WORKSPACE, "..", "translation-kit"))
KIT_TM_DIR = os.path.join(KIT_DIR, "pawapuro15-wii", "tm")
KIT_LABELS_DIR = os.path.join(KIT_DIR, "pawapuro15-wii", "labels")
EMU_DIR = os.environ.get("PP15_EMU") or os.path.join(GAME_DIR, "emulator")
OCR = os.path.join(EMU_DIR, "ocr", "ocr")
MLB_DIR = os.environ.get("PP15_MLB") or os.path.join(WORKSPACE, "reference")
MLB_PROJECT_BIN = os.path.join(MLB_DIR, "MLB2008", "DATA", "files", "project.bin")
WIT_FALLBACK = os.path.join(WORKSPACE, "tools", "wit", "wit-v3.05a-r8638-mac", "bin", "wit")


def use_scratch(*subfolders: str) -> str:
    """Make a folder under _work importable, e.g. use_scratch("ui_pages", "tools").

    Only a few helper scripts that live in the git-ignored _work folder (the romaji converter used by `pp15 names
    export`, the sprite composer used by `pp15 export-labels`) need this; nothing else may import code from _work.

    Arguments: the folder names below _work. Returns the folder path; it is appended to sys.path once."""
    path = os.path.join(WORK_DIR, *subfolders)
    if path not in sys.path:
        sys.path.append(path)
    return path
