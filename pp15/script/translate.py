"""The story-dialogue translation workflow: scenes out for the translator, English in, a checked file for the build.

Run as `python3 -m pp15 script COMMAND` (`pp15 merge-script` for merge):

  pp15 script export               write the scenes of every script file to _work/scenes/<file>/sNNNN.txt
  pp15 script show FILE A [B]      print scenes A..B for translating (speaker, layout, Japanese)
  pp15 script apply FILE [SCENE]   read English from stdin, one line per text run of the scene, in order;
                                   without SCENE the input holds several scenes, each after a line @sNNNN
  pp15 script check FILE           the same input as apply: report wrong line counts and the warnings of merge
                                   for these scenes, store nothing (exit 1 on an error)
  pp15 script set FILE OFFSET TEXT replace the English of one run
  pp15 script merge                translation/*.tsv -> _work/translation.json, and check every line
  pp15 script status               translated / total runs per file

Vocabulary: a "text run" is one piece of dialogue shown at one time (one on-screen line or box). A "scene" is the text
between two script entry points (a label after a return or jump), the natural unit to translate in one go. A "window
type" says which kind of text box the run appears in (30 is the ordinary dialogue box, 26 a menu).

The English lives in translation/<file>.tsv (in git): section offset, a 4-digit hash of the original run, the English.
It holds no Japanese text. The hash catches a run that moved or changed. The scene files hold the Japanese and stay in
_work/ (git-ignored).

Scene file columns: section offset, window type, speaker (from the portrait in that window's slot, a hint only), layout
mark, text. Layout marks:
  B first run of a box        L new line        W new line after a button wait
  + same line as the run before (after a colour change or an inserted name)
Lines starting with # are notes: {name} = inserted name, colour N = text colour from here on.
In "apply" input, write \\n for a line break inside a run, a single - for an empty run, and \\_ for a space where an
editor would strip it (the end of a line, a run that is only a space).

Public functions: scenes(script), find_script(name), all_scripts(), check_scene(...), load_tsv/save_tsv, main(argv).
"""
import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

from pp15 import config
from pp15.script import block_scripts
from pp15.script.block_scripts import BLOCK_SCRIPTS, ORE_BLOCK_END, ORE_ELSE, ORE_IF, ORE_WINDOW
from pp15.script.packed_text import decode_units
from pp15.script.rel import load_all_rels
from pp15.script.scripts import (OP_GOTO, OP_NEWLINE, OP_NEWLINE_WAIT, OP_RETURN, OP_WAIT, SCRIPT_FILES,
                                 Script)
from pp15.text.tsv_store import read_rows, text_hash, write_rows

TSV_DIR = config.TRANSLATION_DIR
SCENE_DIR = os.path.join(config.WORK_DIR, "scenes")
OUT_JSON = os.path.join(config.WORK_DIR, "translation.json")

LINE_LETTERS = 34       # letters a dialogue line holds (17 cells of two letters) in Success Mode
BOX_LINES = 3           # lines a dialogue box shows
NAME_OPS = set(range(0x4B, 0x50)) | {0xA5, 0xA6, 0xA7, 0xDA}      # opcodes that insert a player name or number
OP_COLOUR = 0x73                                                   # change the text colour from here on
PORTRAIT_SLOT = {0x7A: 2, 0x7B: 3, 0x7C: 4, 0x7D: 5}     # opcode that sets a portrait -> window type it speaks in
MENU_WINDOW = 26        # window type of menu text: it must keep its line breaks
BUBBLE_WINDOW = 30      # window type of the ordinary dialogue box (the box does not restart for the same speaker)
WIDE_WINDOWS = {31: 60}                                    # glossary pop-ups: a wider box, letters per line
ORE_CALL = 0x32         # My Life: call another routine
ORE_WINDOW_BASE = 100   # My Life: window type = 100 + the number its window instruction (0018) gives
NAME_LETTERS = 12       # room an inserted name takes: up to 6 full-width cells = 12 letters
# Portrait id ranges (id // 16) seen in Success scenario 1, for the speaker column of the scene files.
SPEAKERS = [(0x00, 0x03, "player"), (0x04, 0x05, "Yabe"), (0x2B, 0x37, "extra"), (0x4D, 0x4E, "Momoko"),
            (0x56, 0x56, "Kageyama"), (0x5E, 0x5F, "Tamano"), (0x60, 0x60, "Yajima"),
            (0x61, 0x61, "Todoroki"), (0x62, 0x62, "Maruo"), (0x65, 0x66, "Kagurazaka")]
TSV_HEADER = "# section_offset\thash of the original run\tEnglish (see tl.py)\n"


# ── Reading the scripts ───────────────────────────────────────────────────

def speaker(face: Optional[int]) -> str:
    """Name for a portrait id, "-" for none, or its hex value when it is not in SPEAKERS."""
    if face is None:
        return "-"
    return next((name for lo, hi, name in SPEAKERS if lo <= face >> 4 <= hi), "%X" % face)


def all_scripts() -> list:
    """The Success Mode scripts and the scripts of the other modes (Eikan Nine, match lines, My Life), parsed."""
    mods = load_all_rels()
    by_name = {m.name: m for m in mods.values()}
    return [Script(by_name[fn], mods) for fn in SCRIPT_FILES] + block_scripts.load_block_scripts(mods)


def find_script(name: str):
    """The parsed script of module file `name` (for example "scs_sce1.rel")."""
    if name in BLOCK_SCRIPTS:
        return block_scripts.load_block_scripts()[list(BLOCK_SCRIPTS).index(name)]
    mods = load_all_rels()
    return Script(next(m for m in mods.values() if m.name == name), mods)


def line_letters(sc) -> int:
    """Letters a line of this script's boxes holds."""
    return 2 * sc.spec["line"] if hasattr(sc, "spec") else LINE_LETTERS


def scenes(sc) -> List[List[dict]]:
    """The scenes of a parsed script: [[row, ...], ...] with row = dict(off, window, face, mark, text) for a text run
    or dict(note=...) for something the translator should know (an inserted name, a colour change, an if/else).

    `off` is the section offset of the run, `face` the portrait speaking, `mark` the layout mark (see the module
    docstring). A scene ends at a return or goto; the next label starts a new one."""
    block = hasattr(sc, "spec")             # another engine: no portrait or colour opcodes known
    ore = block and sc.spec.get("engine") == "ore"      # My Life: whole-halfword opcodes, windows set by 0018
    name_ops = sc.name_ops if block else NAME_OPS
    ends = sc.ends if block else (OP_RETURN, OP_GOTO)
    out, cur = [], []
    face, mark, ended, ore_window = {}, "B", True, ORE_WINDOW_BASE
    ore_labels = sc.label_table() if ore else None
    for i in sorted(k for k, v in sc.kind.items() if v == "op"):
        op = sc.op(i) if block else sc.hw[i] & 0xFF
        if i in sc.labels and ended:
            if any("off" in r for r in cur):
                out.append(cur)
            cur, mark, face, ore_window = [], "B", {}, ORE_WINDOW_BASE
        ended = False
        if i in sc.texts:
            window, units, _ = sc.texts[i]
            cur.append({"off": i * 2, "window": ore_window if ore else window,
                        "face": None if block else face.get(window, 0), "mark": mark,
                        "text": decode_units(units)})
            mark = "+"
        elif op in name_ops:
            cur.append({"note": "{name}"})
        elif ore:
            if op in sc.spec["marks"]:
                mark = sc.spec["marks"][op]
            elif op == ORE_WINDOW:
                ore_window, mark = ORE_WINDOW_BASE + sc.hw[i + 1], "B"
            elif op == ORE_CALL:
                said = sc.routine_text(ore_labels[sc.hw[i + 1]])
                if said:
                    cur.append({"note": "{sub} " + (said if len(said) <= 30 else said[:30] + "...")})
            elif op in ORE_IF:
                cur.append({"note": "if"})
            elif op == ORE_ELSE:
                cur.append({"note": "else"})
            elif op == ORE_BLOCK_END:
                cur.append({"note": "end"})
            elif op in ends:
                ended = True
        elif block:
            if op in (OP_NEWLINE, OP_NEWLINE_WAIT, OP_WAIT):
                mark = {OP_NEWLINE: "L", OP_NEWLINE_WAIT: "W", OP_WAIT: "B"}[op]
            elif op in ends:
                ended = True
        elif op == OP_COLOUR:
            cur.append({"note": "colour %d" % (sc.hw[i] >> 8)})
        elif op in PORTRAIT_SLOT:
            face[PORTRAIT_SLOT[op]] = sc.hw[i + 1]
        elif op == OP_NEWLINE:
            mark = "L"
        elif op == OP_NEWLINE_WAIT:
            mark = "W"
        elif op == OP_WAIT:
            mark = "B"
        elif op in (OP_RETURN, OP_GOTO):
            ended = True
    if any("off" in r for r in cur):
        out.append(cur)
    return out


# ── The translation files ─────────────────────────────────────────────────

def load_tsv(name: str) -> Dict[int, Tuple[str, str]]:
    """{section offset: (hash of the original, English)} of translation/<name>.tsv; \\n in the file is a line break."""
    rows = read_rows(os.path.join(TSV_DIR, name + ".tsv"), 3)
    return {int(off): (h, en.replace("\\n", "\n")) for off, h, en in rows}


def save_tsv(name: str, rows: Dict[int, Tuple[str, str]]) -> None:
    """Write translation/<name>.tsv, sorted by offset, line breaks written as \\n."""
    write_rows(os.path.join(TSV_DIR, name + ".tsv"), TSV_HEADER,
               ((off, rows[off][0], rows[off][1].replace("\n", "\\n")) for off in sorted(rows)))


# ── Commands ──────────────────────────────────────────────────────────────

def cmd_export(args: argparse.Namespace) -> None:
    """Write each script's scenes as text files under _work/scenes/<module>/, plus an index.txt per module."""
    for sc in all_scripts():
        folder = os.path.join(SCENE_DIR, sc.rel.name)
        os.makedirs(folder, exist_ok=True)
        done = load_tsv(sc.rel.name)
        index = []
        for n, rows in enumerate(scenes(sc)):
            runs = [r for r in rows if "off" in r and r["text"]]
            with open(os.path.join(folder, "s%04d.txt" % n), "w", encoding="utf-8") as f:
                for r in rows:
                    if "note" in r:
                        f.write("# %s\n" % r["note"])
                    else:
                        f.write("%d\t%d\t%s\t%s\t%s\n" % (r["off"], r["window"], speaker(r["face"]), r["mark"],
                                                          r["text"].replace("\n", "\\n")))
            index.append("s%04d\t%d runs\t%d done\t0x%X" % (n, len(runs),
                                                           sum(1 for r in runs if r["off"] in done),
                                                           rows[0].get("off", 0) if "off" in rows[0]
                                                           else next(r["off"] for r in rows if "off" in r)))
        with open(os.path.join(folder, "index.txt"), "w") as f:
            f.write("\n".join(index) + "\n")
        print("%s: %d scenes -> %s" % (sc.rel.name, len(index), folder))


def cmd_show(args: argparse.Namespace) -> None:
    """Print scenes args.first..args.last of module args.file for the translator."""
    sc = find_script(args.file)
    all_scenes = scenes(sc)
    for n in range(int(args.first.lstrip("s")), int(args.last.lstrip("s")) + 1):
        print("@s%04d" % n)
        for r in all_scenes[n]:
            if "note" in r:
                print("# " + r["note"])
            else:
                print("%d %s %s | %s" % (r["window"], speaker(r["face"]), r["mark"],
                                         r["text"].replace("\n", "\\n") or "(empty)"))


def read_input(scene: Optional[str] = None) -> List[Tuple[int, List[str]]]:
    """The English typed on standard input: [(scene number, [line, ...]), ...].

    Lines after a `@sNNNN` marker belong to that scene; without markers all lines belong to `scene`. Blank lines are
    skipped, `\\_` becomes a space (so a trailing space survives editors that strip it)."""
    batches, cur = [], None
    for l in sys.stdin:
        l = l.rstrip("\n")
        blank = not l.strip(" \t\r")
        l = l.replace("\\_", " ")
        if l.startswith("@s"):
            cur = (int(l[2:]), [])
            batches.append(cur)
        elif not blank:                              # a line of full-width spaces is text
            if cur is None:
                if scene is None:
                    sys.exit("input must start with @sNNNN")
                cur = (int(scene.lstrip("s")), [])
                batches.append(cur)
            cur[1].append(l)
    return batches


def cmd_apply(args: argparse.Namespace) -> None:
    """Store the English read from stdin for the scenes it names (nothing is stored when one scene is wrong)."""
    name = args.file
    sc = find_script(name)
    all_scenes = scenes(sc)
    batches = read_input(args.scene)
    rows = load_tsv(name)
    for n, lines in batches:
        runs = [r for r in all_scenes[n] if "off" in r]
        if len(lines) != len(runs):
            sys.exit("scene s%04d has %d runs, got %d lines (nothing stored)" % (n, len(runs), len(lines)))
        for r, en in zip(runs, lines):
            if not r["text"]:
                if en != "-":
                    sys.exit("s%04d +%d is an empty run, expected -" % (n, r["off"]))
                continue
            rows[r["off"]] = (text_hash(r["text"]), "" if en == "-" else en.replace("\\n", "\n"))
    save_tsv(name, rows)
    print("%s: %d scene(s), %d runs stored" % (name, len(batches), sum(len(l) for _, l in batches)))


def cmd_check(args: argparse.Namespace) -> None:
    """Dry run of apply: print errors (line counts, empty runs, stray characters) and the merge warnings; store
    nothing; exit 1 when there is an error."""
    sc = find_script(args.file)
    all_scenes = scenes(sc)
    rows, errors, warnings, stored = load_tsv(args.file), [], [], 0
    for n, lines in read_input():
        if not 0 <= n < len(all_scenes):
            errors.append("s%04d: no such scene" % n)
            continue
        runs = [r for r in all_scenes[n] if "off" in r]
        if len(lines) != len(runs):
            errors.append("s%04d has %d runs, got %d lines" % (n, len(runs), len(lines)))
            continue
        for k, (r, en) in enumerate(zip(runs, lines), 1):
            if not r["text"]:
                if en != "-":
                    errors.append("s%04d line %d is an empty run, expected -" % (n, k))
                continue
            en = "" if en == "-" else en.replace("\\n", "\n")
            stray = sorted(set(c for c in en if ord(c) >= 128 and c not in r["text"]))
            if stray:
                errors.append("s%04d line %d: not ASCII and not in the original: %s" % (n, k, " ".join(stray)))
            if en.count("\n") != r["text"].count("\\n") and r["window"] == MENU_WINDOW:
                errors.append("s%04d line %d: a menu run must keep its %d line breaks (\\n)"
                              % (n, k, r["text"].count("\\n")))
            rows[r["off"]] = (text_hash(r["text"]), en)
            stored += 1
        offs = {r["off"]: k for k, r in enumerate(runs, 1)}
        for w in check_scene("s%04d" % n, all_scenes[n], rows, line_letters(sc)):
            head, _, rest = w.partition(":")
            off = head.split("+")[-1] if "+" in head else ""
            warnings.append("s%04d line %s:%s" % (n, offs.get(int(off), "?"), rest) if off.isdigit() else w)
    for w in warnings:
        print("warning:", w)
    for e in errors:
        print("ERROR:", e)
    print("%d runs checked, %d errors, %d warnings" % (stored, len(errors), len(warnings)))
    sys.exit(1 if errors else 0)


def cmd_set(args: argparse.Namespace) -> None:
    """Replace the English of one already translated run (the hash of the original stays)."""
    rows = load_tsv(args.file)
    rows[int(args.offset)] = (rows[int(args.offset)][0], args.text.replace("\\n", "\n"))
    save_tsv(args.file, rows)


# ── Checks: does the English fit the box? ─────────────────────────────────

def letters(text: str) -> int:
    """Width in letters: a Japanese character fills a whole cell, two letters."""
    return sum(1 if ord(c) < 128 else 2 for c in text)


def odd_tail(text: str) -> bool:
    """True if the letters after the last Japanese character do not fill their last cell.

    The game draws two letters per cell, so a run that ends in an odd number of letters leaves half a cell empty,
    which shows as a gap when another run continues on the same line."""
    n = 0
    for c in reversed(text):
        if ord(c) >= 128:
            break
        n += 1
    return n % 2 == 1


def check_scene(name: str, rows: List[dict], done: Dict[int, Tuple[str, str]], per_line: int = LINE_LETTERS) -> List[str]:
    """Warnings for one scene: lines that are too long, too many lines in a box, odd-length runs before a run that
    continues the same line, and a scene that is only partly translated.

    rows = the scene from scenes(); done = {offset: (hash, English)}; per_line = letters a line holds."""
    warn, line, pending, box, box_orig, bubble = [], 0, None, 0, 0, None
    runs = [r for r in rows if "off" in r]
    some = sum(1 for r in runs if r["off"] in done)
    missing = [r["off"] for r in runs if r["text"] and r["off"] not in done]
    if some and missing:
        warn.append("%s: scene partly translated, missing +%s" % (name, ", +".join(map(str, missing[:5]))))
    frames, closed = [], None       # My Life: the runs between "if" and "end" are alternatives, one is shown
    for r in rows:
        if "note" in r:
            note = r["note"]
            if note == "{name}":
                line += NAME_LETTERS
            if note in ("if", "else"):
                if closed is not None:                      # the next of a row of alternatives: same start
                    frames.append(closed)
                    line = closed[0]
                else:
                    frames.append([line, line])             # [line before the block, widest way through it]
            elif note == "end" and frames:
                closed = frames.pop()
                closed[1] = max(closed[1], line)
                line, pending = closed[1], None
                continue
            closed = None
            continue
        closed = None
        if r["mark"] == "B" or (r["window"] != BUBBLE_WINDOW and r["window"] != bubble):
            box = box_orig = 0                              # a new box, or another speaker's bubble
        if r["window"] != BUBBLE_WINDOW:
            bubble = r["window"]
        if r["mark"] != "+":
            line = 0
            box, box_orig = box + 1, box_orig + 1
        if r["off"] not in done:
            pending = None
            continue
        en = done[r["off"]][1]
        limit = WIDE_WINDOWS.get(r["window"], per_line)
        if (r["mark"] == "+" and pending is not None and odd_tail(pending[1]) and en
                and r["window"] not in WIDE_WINDOWS):
            warn.append("%s +%d: odd number of letters before a same-line run: %r" % (name, *pending))
        box, box_orig = box + en.count("\n"), box_orig + r["text"].count("\\n")
        if box > max(BOX_LINES, box_orig) and r["window"] not in WIDE_WINDOWS and r["window"] != MENU_WINDOW:
            warn.append("%s +%d: box has %d lines (original %d)" % (name, r["off"], box, box_orig))
        for k, part in enumerate(en.split("\n")):
            line = letters(part) + (line if k == 0 else 0)
            if line > limit:
                warn.append("%s +%d: line is %d letters (max %d): %r" % (name, r["off"], line, limit, part))
        pending = (r["off"], en.split("\n")[-1])
    return warn


def cmd_merge(args: argparse.Namespace) -> None:
    """Check every stored translation against the scripts and write _work/translation.json for the build."""
    entries, warnings = [], []
    for sc in all_scripts():
        done = load_tsv(sc.rel.name)
        if not done:
            continue
        seen = set()
        for rows in scenes(sc):
            for r in rows:
                if "off" in r and r["off"] in done:
                    h, en = done[r["off"]]
                    if h != text_hash(r["text"]):
                        sys.exit("%s +%d: the original run changed (hash %s)" % (sc.rel.name, r["off"], h))
                    seen.add(r["off"])
                    entries.append({"file": sc.rel.name, "section_offset": r["off"],
                                    "window": r["window"], "text": r["text"], "en": en})
            warnings += check_scene(sc.rel.name, rows, done, line_letters(sc))
        if set(done) - seen:
            sys.exit("%s: no text run at +%s" % (sc.rel.name, sorted(set(done) - seen)[:5]))
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    for w in warnings:
        print("warning:", w)
    print("%d runs -> %s, %d warnings" % (len(entries), OUT_JSON, len(warnings)))


def cmd_status(args: argparse.Namespace) -> None:
    """Print translated / total text runs per script module."""
    for sc in all_scripts():
        done = load_tsv(sc.rel.name)
        runs = [r for rows in scenes(sc) for r in rows if "off" in r and r["text"]]
        print("%-13s %5d / %5d runs" % (sc.rel.name, sum(1 for r in runs if r["off"] in done), len(runs)))


# ── Command line ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """The argparse parser, one sub-command per workflow step."""
    ap = argparse.ArgumentParser(prog="pp15 script", description=__doc__.split("\n\n")[0],
                                 epilog="Details: the module docstring of pp15/script/translate.py.")
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")
    p = sub.add_parser("export", help="write every script's scenes to _work/scenes/<file>/sNNNN.txt")
    p.set_defaults(func=cmd_export)
    p = sub.add_parser("show", help="print scenes A..B of a module for translating")
    p.add_argument("file", metavar="FILE", help="module, e.g. scs_sce1.rel")
    p.add_argument("first", metavar="A", help="first scene (number or sNNNN)")
    p.add_argument("last", metavar="B", nargs="?", help="last scene (default: A)")
    p.set_defaults(func=lambda a: cmd_show(_with_default_last(a)))
    p = sub.add_parser("apply", help="store English from stdin, one line per text run (nothing stored on an error)")
    p.add_argument("file", metavar="FILE")
    p.add_argument("scene", metavar="SCENE", nargs="?",
                   help="the scene the lines belong to; without it the input names scenes with @sNNNN lines")
    p.set_defaults(func=cmd_apply)
    p = sub.add_parser("check", help="dry run of apply: report errors and warnings, store nothing")
    p.add_argument("file", metavar="FILE")
    p.set_defaults(func=cmd_check)
    p = sub.add_parser("set", help="replace the English of one run")
    p.add_argument("file", metavar="FILE")
    p.add_argument("offset", metavar="OFFSET", help="section offset of the run")
    p.add_argument("text", metavar="TEXT", help="the English (\\n for a line break)")
    p.set_defaults(func=cmd_set)
    p = sub.add_parser("merge", help="translation/*.tsv -> _work/translation.json, with every check")
    p.set_defaults(func=cmd_merge)
    p = sub.add_parser("status", help="translated / total runs per file")
    p.set_defaults(func=cmd_status)
    return ap


def _with_default_last(args: argparse.Namespace) -> argparse.Namespace:
    """`show FILE A` means scene A alone."""
    if args.last is None:
        args.last = args.first
    return args


def main(argv: Optional[List[str]] = None) -> None:
    """Entry point of `pp15 script`; prints the help when no command is given."""
    ap = build_parser()
    args = ap.parse_args(sys.argv[1:] if argv is None else list(argv))
    if not args.cmd:
        ap.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
