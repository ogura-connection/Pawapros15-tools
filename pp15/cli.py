"""The `pp15` command: one entry point for every tool of the repository.

    python3 -m pp15 COMMAND [ARGUMENTS]        (or `pp15 COMMAND` after `pip install -e .`)
    python3 -m pp15 --help                     the list of commands
    python3 -m pp15 COMMAND --help             what one command does

How it works: COMMANDS is the list of commands (name, module that does the work, arguments put in front of the user's,
one-line summary, usage line). This file only looks the command up and hands the rest of the command line to the
`main(argv)` of that module, so every command keeps the arguments it always had. A command whose module parses its
arguments with argparse answers `--help` itself (those names are in NATIVE_HELP); for the others this file prints the
summary and the module's docstring.

Public functions: overview (the text of `pp15 --help`), command_help, main.
"""
import importlib
import importlib.util
import os
import sys
from types import ModuleType
from typing import List, Optional

from pp15 import config

# name, module, arguments put in front of the user's, summary, usage line (after the command name)
COMMANDS = [
    ("Build", None, None, None, None),
    ("build", "pp15.build.rebuild", ["build"],
     "rebuild every module from translation/ and install it to DATA/files and DATA/sys",
     "[TRANSLATION.json] [--pad FILE=BYTES]"),
    ("build-check", "pp15.build.rebuild", ["check"],
     "round-trip test of the build: parse and re-encode every module, change no file", ""),
    ("build-restore", "pp15.build.rebuild", ["restore"],
     "put the original game files back into DATA/files and DATA/sys", ""),
    ("golden", "golden", [],
     "record or check the SHA-1 of every installed game file against the released build",
     "record | check"),

    ("Dialogue, strings, names", None, None, None, None),
    ("script", "pp15.script.translate", [],
     "scenes of the Success Mode scripts: export, show, apply, check, set, merge, status",
     "export | show FILE A [B] | apply FILE [SCENE] | check FILE | set FILE OFFSET TEXT | merge | status"),
    ("merge-script", "pp15.script.translate", ["merge"],
     "translation/*.tsv -> _work/translation.json, with every check of the build", ""),
    ("strings", "pp15.text.strings", [],
     "fixed-slot UI strings (menus, system text): export, set, check, apply, merge, status",
     "export [FILE ...] | set | check FILE | apply FILE | merge | status"),
    ("merge-strings", "pp15.text.strings", ["merge"],
     "translation/strings/*.tsv -> _work/strings.json, with every check of the build", ""),
    ("messages", "pp15.text.messages", [],
     "in-game messages (Pennant news and similar): export, set, check, apply, merge, status",
     "export [FILE ...] | set | check FILE | apply FILE | merge | status"),
    ("merge-messages", "pp15.text.messages", ["merge"],
     "translation/messages/*.tsv -> _work/messages.json, with checks", ""),
    ("names", "pp15.names.commands", [],
     "player names: export / check the surname table and the in-place name tables",
     "export | export-given | export-draft | export-holders | export-foreign | check"),
    ("kyu-names", "pp15.names.kyu", [],
     "pitch names: list the Japanese and English, or check what fits",
     "list | check"),
    ("scan", "pp15.script.scan", [],
     "static analysis of the story scripts: extract, xref, entropy, scan",
     "extract [--dump] | xref | entropy | scan"),

    ("Art", None, None, None, None),
    ("apply-art", "pp15.art.labels", ["apply"],
     "write the English lettering of a spec (specs/*.json) into DATA/files/<arc>, the original kept first",
     "SPEC.json"),
    ("check-art", "pp15.art.textures", ["check"],
     "check the sprite pages of the .arc files: decode, re-encode, packed pages",
     "[ARC ...]"),
    ("restore-art", "pp15.art.labels", ["restore"],
     "put the saved original of one .arc back", "ARC"),
    ("art", "pp15.art.labels", [],
     "MLB label tools: boxes, preview, apply, restore", "boxes PACK TEX [MIN] | preview SPEC OUT.png | apply SPEC | restore ARC"),
    ("textures", "pp15.art.textures", [],
     "sprite pages of the .arc files: export, parts, page, import, check",
     "export [OUT_DIR] | parts ARC | page ... | import ... | check [ARC ...]"),
    ("sheet", "pp15.art.sheet", [],
     "preview of a spec's pictures painted over several pages", "preview SPEC.json OUT.png [PAGES ...]"),
    ("font", "pp15.build.font", [],
     "the pair font: preview a string as the game draws it", "preview TEXT [OUT.png]"),

    ("Disc and release", None, None, None, None),
    ("release", "pp15.disc.xdelta", [],
     "write the English disc (Nintendo's layout kept) and an xdelta patch against the original ISO",
     "ORIGINAL.iso OUT.iso [PATCH.xdelta]"),
    ("extract-iso", "pp15.disc.extract", [],
     "extract one file from an encrypted Wii ISO", "ISO FILENAME [OUTPUT]"),
    ("extract-text", "pp15.disc.extract_text", [],
     "extract every readable text of the script modules to DATA/extracted_text_full.json", "[--data-dir DIR]"),
    ("ram-scan", "pp15.disc.ram_scan", [],
     "loaded modules and memory use of a Dolphin save state; writes _work/ram/", "STATE"),
    ("glyphs", "pp15.glyph_cli", [],
     "glyph table and font tools: extract-text, dump-font, char-table, decode-bytes, info",
     "extract-text | dump-font | char-table | decode-bytes HEX ... | info"),

    ("Translation kit and MLB reference", None, None, None, None),
    ("export-tm", "pp15.kit.export_tm", [],
     "translation memory (Japanese/English pairs) for the translation kit",
     "[OUT_DIR]   default %s" % config.KIT_TM_DIR),
    ("export-labels", "pp15.kit.export_labels", [],
     "every English label as a picture next to its Japanese one, with an index, for the kit",
     "[OUT_DIR] [SPEC.json ...]   default %s" % config.KIT_LABELS_DIR),
    ("mlb-assets", "pp15.reference.mlb_assets", [],
     "read the MLB Power Pros discs: list, sheet, text, textures", "list PROJECT.BIN | sheet ... | text DISC OUT | textures DISC OUT"),
    ("mlb-labels", "pp15.reference.mlb_labels", [],
     "index of the English lettering of the MLB discs (needs the OCR helper)", "PROJECT.BIN TEXTURES.TSV OUT_DIR [GAME]"),
]
BY_NAME = {c[0]: c for c in COMMANDS if c[1]}
# Commands whose module has an argparse parser: `pp15 COMMAND --help` goes to the module
NATIVE_HELP = {"build", "build-check", "build-restore", "scan", "glyphs",
               "names", "kyu-names", "release", "extract-iso", "extract-text", "ram-scan",
               "export-tm", "export-labels", "mlb-assets", "mlb-labels"}


def _load(module: str) -> ModuleType:
    """Import the module that does the work of a command (`golden` is tests/golden.py, outside the package)."""
    if module == "golden":                                   # tests/golden.py is not part of the package
        spec = importlib.util.spec_from_file_location("golden", os.path.join(config.TESTS_DIR, "golden.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    return importlib.import_module(module)


def overview() -> str:
    """The text of `pp15 --help`: every command with its summary, grouped by the section headers of COMMANDS."""
    lines = ["usage: pp15 COMMAND [ARGUMENTS]    (python3 -m pp15 ...; `pp15 COMMAND --help` for one command)", ""]
    for name, module, _, summary, _ in COMMANDS:
        if module is None:
            lines += ["", name + ":"]
        else:
            lines.append("  %-14s %s" % (name, summary))
    lines += ["", "Paths come from pp15/config.py; PP15_ROOT, PP15_KIT, PP15_EMU and PP15_MLB override them."]
    return "\n".join(lines)


def command_help(name: str) -> None:
    """Print the usage line, the summary and the module docstring of a command whose module has no argparse help."""
    _, module, prefix, summary, usage = BY_NAME[name]
    print("usage: pp15 %s %s\n\n%s\n" % (name, usage, summary))
    try:
        doc = (_load(module).__doc__ or "").strip()
    except ModuleNotFoundError as e:                       # an optional package is not installed
        doc = "(the details need the Python package %r: see pyproject.toml)" % e.name
    if doc:
        print(doc)


def main(argv: Optional[List[str]] = None) -> int:
    """Run `pp15 COMMAND ...`. Returns the exit code: 0 after help or a finished command, 2 for an unknown command;
    otherwise whatever the command's own main returns. `argv` defaults to sys.argv[1:]."""
    a = sys.argv[1:] if argv is None else list(argv)
    if not a or a[0] in ("-h", "--help", "help"):
        print(overview())
        return 0
    name, rest = a[0], a[1:]
    if name not in BY_NAME:
        print("pp15: unknown command %r\n" % name, file=sys.stderr)
        print(overview(), file=sys.stderr)
        return 2
    _, module, prefix, _, _ = BY_NAME[name]
    if ("-h" in rest or "--help" in rest) and name not in NATIVE_HELP:
        command_help(name)
        return 0
    return _load(module).main(prefix + rest)


if __name__ == "__main__":
    sys.exit(main())
