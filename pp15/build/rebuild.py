"""`pp15 build`: put the English text into the game's files, check the result, and install it.

What it does, in plain words: the game stores its text inside its program modules (.rel files), so changing the
length of a line moves everything behind it. The build writes each module out again with the English, moves every
pointer that pointed into the moved data, rebuilds the font so that two English letters fit in one text cell,
updates the memory plan, re-reads the built files to check them against the originals, and only then copies them
into DATA/files and DATA/sys. See docs/ARCHITECTURE.md for where this fits and docs/GLOSSARY.md for the words.

Commands (also `python3 -m pp15 COMMAND`):
    build [TRANSLATION.json] [--pad FILE=BYTES]   apply the translation and install the result
    build-check                                   round-trip test, no files are changed (roundtrip_check.py)
    build-restore                                 put the original files back

Translation file: a JSON list of entries in the format of _work/story_text.json (`pp15 scan extract --dump`) with an
added "en" field; see translation_file.py. The other texts (menus, messages, names, system dialogs) are read from
_work/strings.json, _work/messages.json and translation/names/ by their own modules.

Original .rel files and moduleID2addr.o are kept in _work/orig/ (copied from DATA/files on first use, so the first
run must be on unpatched files). Built files are checked in _work/build/ before they are installed to DATA/files.
Both folders are game data: git-ignored, never commit them.

The work is split by job; each module starts with what it does:
    pipeline.py          the order of the stages            translation_file.py   read the dialogue translation
    script_stage.py      lay the scripts out again          script_emit.py        Success Mode and block scripts
    ore_script.py        the My Life script and its annex   name_stage.py         append the name tables
    name_patches.py      write names into modules           ui_write.py           menus, messages, pitch names
    module_stage.py      assemble every module              relocations.py        pointer tables of a module
    memory_plan.py       moduleID2addr.o                    dol_block.py          system dialogs in main.dol
    font_assign.py       pick a font slot per letter pair   font.py, font_usage.py, glyph_codec.py, pair_text.py
    verify.py            re-read and compare                module_files.py       load and install modules
"""
import argparse
import os
import sys

from pp15 import config
from pp15.build import pipeline, roundtrip_check
from pp15.build.module_files import ensure_orig, install, load_dir, load_scripts
from pp15.build.translation_file import load_translation
from pp15.script import scan
from pp15.text import messages, strings

# Other modules import these names from here (names/kyu.py, names/schools.py, disc/ram_scan.py); they are defined in
# the modules named on the right and kept importable from this path.
from pp15.build.module_files import ORIG_DIR                       # noqa: F401
from pp15.build.memory_plan import PLAN_FILE, plan_tables          # noqa: F401
from pp15.build.relocations import parse_imports                   # noqa: F401


def cmd_build(args: argparse.Namespace) -> None:
    """Build from the translation file named in `args.json` and install the result."""
    orig = load_dir(ORIG_DIR)
    scripts = load_scripts(orig) + scan.load_block_scripts(orig)
    texts = load_translation(args.json, scripts)
    pad = {}
    for item in args.pad or []:
        name, size = item.split("=")
        pad[name] = int(size, 0)
    install(pipeline.build(texts, pad, strings.load_for_build(), strings.load_dol_for_build(),
                           messages.load_for_build()))


def cmd_restore(args: argparse.Namespace) -> None:
    """Put the original files back into DATA/files and DATA/sys."""
    install([])


def cmd_check(args: argparse.Namespace) -> None:
    """Round-trip test of the build; changes no file."""
    roundtrip_check.run_check()


def main(argv: list[str] | None = None) -> None:
    """The command line of `pp15 build`, `pp15 build-check` and `pp15 build-restore` (see the module docstring)."""
    ap = argparse.ArgumentParser(prog="pp15", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("check", help="round-trip test, no files are changed").set_defaults(func=cmd_check)
    p = sub.add_parser("build", help="apply a translation file and install the result")
    p.add_argument("json", nargs="?", default=os.path.join(config.WORK_DIR, "translation.json"),
                   help="translation file (default: _work/translation.json, written by `pp15 merge-script`)")
    p.add_argument("--pad", action="append", metavar="FILE=BYTES",
                   help="test only: add empty space to a script module, e.g. scs_main.rel=0x80000")
    p.set_defaults(func=cmd_build)
    sub.add_parser("restore", help="put the original files back").set_defaults(func=cmd_restore)
    args = ap.parse_args(argv)
    if not args.cmd:
        return ap.print_help()
    if not os.path.isdir(config.DATA_FILES):
        sys.exit("Game files not found at %s" % config.DATA_FILES)
    ensure_orig()
    args.func(args)


if __name__ == "__main__":
    main()
