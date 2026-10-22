"""Fixed-slot UI strings: the menu and system text that is not in the story scripts. The `pp15 strings` command.

  pp15 strings export [FILE ...]   Japanese strings to _work/strings/<file>.txt, with line layout
  pp15 strings check FILE          validate "ID<tab>English" lines from stdin, write nothing
  pp15 strings apply FILE          the same check, then store the lines (nothing if one fails)
  pp15 strings set FILE ID TEXT    the English of one string ("" removes it)
  pp15 strings merge               translation/strings/*.tsv -> _work/strings.json, with checks
  pp15 strings status              translated / total per file

FILE is a module (scs_data.rel) or main.dol. ID is section:offset as in the export.

Besides the story dialogue, the game's modules hold plain tables of text in slots of fixed size. The English goes into
the same slot, two letters per cell (the "pair font", docs/GLOSSARY.md), so nothing moves and no file grows.
`python3 -m pp15 build` reads _work/strings.json and writes the strings into the built modules.

A string is identified by file, section and section offset; translation/strings/<file>.tsv (in git) holds section,
offset, a hash of the original and the English, no Japanese. The Japanese lists stay in _work/ (git-ignored).

Where the parts are:
  slot_finder.py     how strings are found in a module (what counts as a string, help texts, coloured text)
  line_layout.py     how the width of a line in a multi-line box is worked out (write | for a new line in the English)
  movable_blocks.py  lists the build lays out again (the schedule), so entries may be longer than their Japanese
  dol_dialogs.py     the blue system dialogs of main.dol
  string_rules.py    the rules an English string must meet (used by check, merge and the build)
  string_tables.py   the hand-found exceptions;  colour_text.py  {6:coloured} runs;  string_tsv.py  the files

Public functions used by other tools: strings_of, load_mods, load_for_build, load_dol_for_build, judge, japanese_lines
(and the names imported below, which the build uses).
"""
import argparse
import collections
import json
import os
import sys
from typing import List, Optional, Tuple

from pp15 import config
# Names the build and other tools read from this module (`from pp15.text import strings`): the imports below are that
# public interface.
from pp15.text.colour_text import colour_runs, letters, plain  # noqa: F401
from pp15.text.dol_dialogs import dol_cells, dol_data, dol_fit, dol_need, dol_segments, dol_strings  # noqa: F401
from pp15.text.line_layout import japanese_lines, line_caps
from pp15.text.movable_blocks import block_fit, block_layout, block_of  # noqa: F401
from pp15.text.slot_finder import find, load_mods, strings_of
from pp15.text.string_rules import check_rows, judge, read_pairs
from pp15.text.string_tables import (BLOCKS, DOL, DOL_ADDRESS, DOL_BLOCK, DOL_CTRL, DOL_GLYPH, DOL_ORIG, DOL_OVER,  # noqa: F401
                                     DOL_SOURCE, DOL_STRINGS, HELP_FILES, HELP_NL, WIDE_SLOTS)
from pp15.text.string_tsv import TSV_DIR, load_tsv, save_tsv, text_hash

LIST_DIR = os.path.join(config.WORK_DIR, "strings")        # the Japanese lists for the translator
OUT_JSON = os.path.join(config.WORK_DIR, "strings.json")   # the checked English, read by the build

# Header of an exported list file; the %s are filled from HEADER_REL / HEADER_DOL.
HEADER = """# %s: one string per line, columns separated by tabs
# 1 ID        section:offset. Lines for check/apply are ID<tab>English.
# 2 cells     %s. One cell holds two letters, or one Japanese character.
# 3 capacity  %s
# 4 Japanese  %s
# 5 English   so far%s
"""
HEADER_REL = ("size of the slot",
              "letters each line holds, for example 44|38: two lines, 44 and 38 letters. A ? behind it: the line"
              "\n#             width is a guess (see ui_strings.py), check such a string in the game.",
              "with | where the game breaks the line (line padding removed)",
              "; | starts a new line, a line may be shorter and lines may be left out")
HEADER_DOL = ("length of the Japanese, each {} included",
              "soft/hard letters: beyond soft (3 cells over the Japanese) check warns, beyond hard it fails."
              "\n#             \"N fixed\": the string cannot move, N letters is all it holds. A {} is not counted,"
              "\n#             and letter pairs start again behind a {} (an odd run of letters wastes half a cell)."
              "\n#             The strings between two fixed ones share their space (the # lines): what one line"
              "\n#             grows, others must give back. check tells when it does not fit.",
              "one line of a blue system dialog. {} is a control code of the Yes/No rows: keep every {}.",
              "; always one line, no |")


# ── check / apply / set ───────────────────────────────────────────────────

def cmd_check(name: str, pairs: List[Tuple[str, str]], store: bool = False) -> None:
    """Check "ID, English" pairs for module `name`; print the problems and exit 1 on any. With store=True and no
    problem, write them to the translation file."""
    found, good, problems, warnings = check_rows(name, pairs)
    for line in problems + warnings:
        print(line)
    note = ", %d warnings" % len(warnings) if warnings else ""
    if problems:
        print("%s: %d problems in %d lines%s%s" % (name, len(problems), len(pairs), note,
                                               ", nothing stored" if store else ""))
        sys.exit(1)
    if store:
        rows = load_tsv(name)
        for key, en in good.items():
            rows[key] = (text_hash(found[key]["text"]), en)
        save_tsv(name, rows)
        print("%s: %d lines stored%s, %d of %d strings translated" % (name, len(pairs), note, len(rows), len(found)))
    else:
        print("%s: %d lines, no problems%s" % (name, len(pairs), note))


def cmd_set(name: str, where: str, en: str) -> None:
    """Store the English of one string, or remove it when `en` is empty."""
    if en:
        return cmd_check(name, [(where, en)], store=True)
    rows = load_tsv(name)
    sec, off = (int(x) for x in where.split(":"))
    if rows.pop((sec, off), None) is None:
        sys.exit("%s %s: not translated" % (name, where))
    if name == DOL:                         # the Japanese comes back: does the block still hold it?
        problems = dol_fit(dol_strings(), {key: en for key, (_, en) in rows.items()})
        if problems:
            sys.exit("\n".join(problems + ["%s %s: not removed, the Japanese line needs that room" % (name, where)]))
    save_tsv(name, rows)
    print("%s %s removed" % (name, where))


# ── export, merge, status ─────────────────────────────────────────────────

def capacity(s: dict, longest: int = 0) -> str:
    """The "capacity" column of an exported list: letters per line, or the limits of a movable or main.dol string."""
    if s.get("block"):
        return "%d movable" % (s["block"]["max"] * 2)
    if "fixed" not in s:
        return "|".join(str(c * 2) for c in line_caps(s)) + "?" * s["uncertain"]
    if s["fixed"]:
        return "%d fixed" % ((s["cells"] - s["ctrl"]) * 2)
    return "%d/%d" % ((min(s["cells"] + DOL_OVER, longest) - s["ctrl"]) * 2, (longest - s["ctrl"]) * 2)


def _export_one(name: str, found: List[dict], path: str) -> None:
    """Write the list file of one module (or main.dol)."""
    done = load_tsv(name)
    longest = max(s["cells"] for s in found) if name == DOL else 0
    with open(path, "w", encoding="utf-8") as f:
        f.write(HEADER % ((name,) + (HEADER_DOL if name == DOL else HEADER_REL)))
        notes = {}
        if name == DOL:                 # the space each run of movable strings shares
            need = dol_need({key: en for key, (_, en) in done.items()})
            for run, room in dol_segments(found, need):
                used = sum(need(s) for s in run)
                notes[run[0]["offset"]] = ("# the %d strings from here to the next fixed string share %d units "
                                           "(cells + 1 per string); in use now: %d\n" % (len(run), room, used))
        for s in found:
            f.write(notes.get(s["offset"], ""))
            f.write("%d:%d\t%d\t%s\t%s\t%s\n" % (s["section"], s["offset"], s["cells"], capacity(s, longest),
                                                 japanese_lines(s), done.get((s["section"], s["offset"]), ("", ""))[1]))
    if name == DOL:
        print("%-14s %5d strings, %d fixed, longest line %d cells" % (name, len(found), sum(s["fixed"] for s in found), longest))
        return
    lines = collections.Counter(len(line_caps(s)) for s in found)
    widths = collections.Counter(s["width"] for s in found if s["width"])
    unsure = ["%d:%d" % (s["section"], s["offset"]) for s in found if s["uncertain"]]
    print("%-14s %5d strings; lines %s; line widths %s; %d uncertain%s"
          % (name, len(found), ", ".join("%d: %d" % kv for kv in sorted(lines.items())),
             ", ".join("%d cells: %d" % kv for kv in sorted(widths.items())) or "-",
             len(unsure), (": " + " ".join(unsure)) if unsure else ""))


def cmd_export(names: List[str]) -> None:
    """Write the Japanese lists to _work/strings/<file>.txt for the given modules (all of them, and main.dol, when
    none are named)."""
    if not names:
        names = sorted(m.name for m in load_mods().values()) + [DOL]
    os.makedirs(LIST_DIR, exist_ok=True)
    total = 0
    for name in names:
        found = strings_of(name)
        path = os.path.join(LIST_DIR, name + ".txt")
        if not found:
            if os.path.exists(path):
                os.remove(path)
            continue
        _export_one(name, found, path)
        total += len(found)
    print("%d strings -> %s" % (total, LIST_DIR))


def _merge_modules(names: List[str]) -> List[dict]:
    """Check every module's translation file and return its entries for strings.json."""
    entries = []
    for name in names:
        if name == DOL:
            continue
        found = {(s["section"], s["offset"]): s for s in strings_of(name)}
        for (sec, off), (h, en) in sorted(load_tsv(name).items()):
            s = found.get((sec, off))
            if s is None or text_hash(s["text"]) != h:
                sys.exit("%s %d:%d: the original string changed or is gone" % (name, sec, off))
            errors, _, en = judge(s, en)
            if errors:
                sys.exit("%s %d:%d: %s" % (name, sec, off, "; ".join(errors)))
            entries.append({"file": name, "section": sec, "offset": off, "cells": s["cells"], "en": en})
        problems = block_fit(name, found.values(), {key: en for key, (_, en) in load_tsv(name).items()})
        if problems:
            sys.exit("\n".join("%s %s" % (name, line) for line in problems))
    return entries


def _merge_dol() -> List[dict]:
    """Check the main.dol translation and return an entry for each of its 264 strings (the build lays the whole block
    out again)."""
    entries = []
    strs, rows = dol_strings(), load_tsv(DOL)
    found = {(0, s["offset"]): s for s in strs}
    longest = max(s["cells"] for s in strs)
    for key, (h, en) in sorted(rows.items()):
        s = found.get(key)
        if s is None or text_hash(s["text"]) != h:
            sys.exit("%s %d:%d: the original string changed or is gone" % ((DOL,) + key))
        errors, warnings, _ = judge(s, en, longest)
        if errors:
            sys.exit("%s %d:%d: %s" % (DOL, key[0], key[1], "; ".join(errors)))
        for w in warnings:
            print("%s %d:%d: warning: %s" % (DOL, key[0], key[1], w))
    problems = dol_fit(strs, {key: en for key, (_, en) in rows.items()})
    if problems:
        sys.exit("\n".join(problems))
    for s in strs:
        entries.append({"file": DOL, "section": 0, "offset": s["offset"], "cells": s["cells"],
                        "en": rows.get((0, s["offset"]), (None, None))[1], "fixed": s["fixed"]})
    print("%s: %d of %d strings translated" % (DOL, len(rows), len(strs)))
    return entries


def cmd_merge() -> None:
    """Check all translation files and write _work/strings.json for the build; exits on the first problem."""
    names = []
    if os.path.isdir(TSV_DIR):
        names = sorted(fn[:-4] for fn in os.listdir(TSV_DIR) if fn.endswith(".tsv"))
    entries = _merge_modules(names)
    count = len(entries)
    if DOL in names or os.path.exists(DOL_ORIG) or os.path.exists(DOL_SOURCE):
        entries += _merge_dol()
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    print("%d strings -> %s" % (count, OUT_JSON))


def cmd_status() -> None:
    """Print translated / total strings per translation file."""
    if os.path.isdir(TSV_DIR):
        for fn in sorted(os.listdir(TSV_DIR)):
            if fn.endswith(".tsv"):
                print("%-14s %5d / %d" % (fn[:-4], len(load_tsv(fn[:-4])), len(strings_of(fn[:-4]))))


# ── What the build reads ──────────────────────────────────────────────────

def load_for_build() -> dict:
    """{module name: {(section, offset): (cells, english)}} from _work/strings.json, for the build.
    Modules only: the main.dol entries come from load_dol_for_build()."""
    out = collections.defaultdict(dict)
    if os.path.exists(OUT_JSON):
        with open(OUT_JSON, encoding="utf-8") as f:
            for e in json.load(f):
                if e["file"] != DOL:
                    out[e["file"]][(e["section"], e["offset"])] = (e["cells"], e["en"])
    return out


def load_dol_for_build() -> List[dict]:
    """The main.dol entries of _work/strings.json, all 264 strings of the block in file order:
    [{"offset": file offset, "cells": units of the Japanese without its 0xFFFF, "en": English or
    None (keep the Japanese), "fixed": must stay at its offset}]. In "en", {} stands for one
    0x1FFD unit and the letter pairs start again behind it (dol_cells counts the units); every
    other unit is 0x1000 | glyph number. Empty when merge found no main.dol."""
    if not os.path.exists(OUT_JSON):
        return []
    with open(OUT_JSON, encoding="utf-8") as f:
        return [{k: e[k] for k in ("offset", "cells", "en", "fixed")} for e in json.load(f) if e["file"] == DOL]


# ── Command line ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """The argparse parser, one sub-command per step."""
    ap = argparse.ArgumentParser(prog="pp15 strings", description=__doc__.split("\n\n")[0],
                                 epilog="FILE is a module (scs_data.rel) or main.dol; ID is section:offset as in the export.")
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")
    p = sub.add_parser("export", help="Japanese strings to _work/strings/<file>.txt, with line layout")
    p.add_argument("files", metavar="FILE", nargs="*", help="modules to export (default: all, and main.dol)")
    p = sub.add_parser("check", help='validate "ID<tab>English" lines from stdin, write nothing')
    p.add_argument("file", metavar="FILE")
    p = sub.add_parser("apply", help="the same check, then store the lines (nothing if one fails)")
    p.add_argument("file", metavar="FILE")
    p = sub.add_parser("set", help='the English of one string ("" removes it)')
    p.add_argument("file", metavar="FILE")
    p.add_argument("id", metavar="ID", help="section:offset")
    p.add_argument("text", metavar="TEXT")
    sub.add_parser("merge", help="translation/strings/*.tsv -> _work/strings.json, with checks")
    sub.add_parser("status", help="translated / total per file")
    return ap


def main(argv: Optional[List[str]] = None) -> None:
    """Entry point of `pp15 strings`; prints the help when no command is given."""
    ap = build_parser()
    args = ap.parse_args(sys.argv[1:] if argv is None else list(argv))
    if args.cmd == "export":
        cmd_export(args.files)
    elif args.cmd == "set":
        cmd_set(args.file, args.id, args.text)
    elif args.cmd == "check":
        cmd_check(args.file, read_pairs())
    elif args.cmd == "apply":
        cmd_check(args.file, read_pairs(), store=True)
    elif args.cmd == "merge":
        cmd_merge()
    elif args.cmd == "status":
        cmd_status()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
