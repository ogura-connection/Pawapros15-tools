"""Where everything lives. This is the only module that knows paths; every other module imports them from here.

Everything is relative to the repository (the folder that holds the `pp15` package) unless an environment variable says
otherwise:

    PP15_ROOT   the repository folder (default: the parent of this package)
    PP15_KIT    the translation-kit folder, the target of `export-tm` / `export-labels`
                (default: translation-kit next to the folder that holds the repository's parent)
    PP15_EMU    the Dolphin test folder (save states, the OCR helper)   (default: dolphin-test beside the repository)
    PP15_MLB    the folder that holds the extracted MLB reference discs (MLB2008/DATA/files/project.bin, ...)
                (default: the folder beside the repository)

The game data (DATA/, _work/) is not in git; see README.md.
"""
import os
import sys

ROOT = os.environ.get("PP15_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECTS = os.path.dirname(ROOT)                      # the folder around the repository (the other projects live here)

# Game data: extracted from the disc, never committed
DATA = os.path.join(ROOT, "DATA")
DATA_FILES = os.path.join(DATA, "files")
DATA_SYS = os.path.join(DATA, "sys")
DOL_SOURCE = os.path.join(DATA_SYS, "main.dol")

# Working files (game data too, git-ignored)
WORK_DIR = os.path.join(ROOT, "_work")
ORIG_DIR = os.path.join(WORK_DIR, "orig")             # untouched .rel files (and moduleID2addr.o)
ORIG_ARC_DIR = os.path.join(WORK_DIR, "orig_arc")     # untouched .arc files; not _work/orig: the build installs that whole folder
ORIG_SYS_DIR = os.path.join(WORK_DIR, "orig_sys")     # untouched main.dol
BUILD_DIR = os.path.join(WORK_DIR, "build")
UI_PAGES_DIR = os.path.join(WORK_DIR, "ui_pages")     # scratch scripts of the art runs (historical, not maintained)

# What is in git
TRANSLATION_DIR = os.path.join(ROOT, "translation")
SPECS_DIR = os.path.join(ROOT, "specs")
TESTS_DIR = os.path.join(ROOT, "tests")

# Things outside the repository
KIT_DIR = os.environ.get("PP15_KIT") or os.path.normpath(os.path.join(PROJECTS, "..", "translation-kit"))
KIT_TM_DIR = os.path.join(KIT_DIR, "pawapuro15-wii", "tm")
KIT_LABELS_DIR = os.path.join(KIT_DIR, "pawapuro15-wii", "labels")
EMU_DIR = os.environ.get("PP15_EMU") or os.path.join(PROJECTS, "dolphin-test")
OCR = os.path.join(EMU_DIR, "ocr", "ocr")
MLB_DIR = os.environ.get("PP15_MLB") or PROJECTS
MLB_PROJECT_BIN = os.path.join(MLB_DIR, "MLB2008", "DATA", "files", "project.bin")
WIT_FALLBACK = os.path.join(PROJECTS, "tools_dl", "wit", "wit-v3.05a-r8638-mac", "bin", "wit")


def use_scratch(*subfolders):
    """Make a folder under _work importable (use_scratch("ui_pages", "tools")). Only a few historical art styles and the
    name-table export need this (they import helper scripts that live in _work); nothing else may reach into _work
    for code."""
    path = os.path.join(WORK_DIR, *subfolders)
    if path not in sys.path:
        sys.path.append(path)
    return path
