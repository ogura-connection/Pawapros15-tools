#!/usr/bin/env python3
"""Translation workflow: scenes out, English in, translation.json for the build.

  tl.py export              write the scenes of every script file to _work/scenes/<file>/sNNN.txt
  tl.py show FILE A [B]     print scenes A..B for translating (speaker, layout, Japanese)
  tl.py apply FILE [SCENE]  read English from stdin, one line per text run of the scene, in order;
                            without SCENE the input holds several scenes, each after a line @sNNNN
  tl.py check FILE          the same input as apply: report wrong line counts and the warnings of merge
                            for these scenes, store nothing (exit 1 on an error)
  tl.py set FILE OFFSET TEXT  replace the English of one run
  tl.py merge               translation/*.tsv -> _work/translation.json, and check every line
  tl.py status              translated / total runs per file

The English lives in translation/<file>.tsv (in git): section offset, a 4-digit hash of the
original run, the English. No Japanese text. The hash catches a run that moved or changed.
Scene files hold the Japanese and stay in _work/ (git-ignored).

A scene is the text between two script entry points (a label after a return or jump). Scene file
columns: section offset, window type, speaker (from the portrait in that window's slot, a hint
only), layout mark, text.
Layout marks:  B first run of a box   L new line   W new line after a button wait
               + same line as the run before (after a colour change or an inserted name)
Lines starting with # are notes: {name} = inserted name, colour N = text colour from here on.
In "apply" input, write \\n for a line break inside a run, a single - for an empty run, and \\_ for
a space where an editor would strip it (the end of a line, a run that is only a space).
"""
import collections
import glob
import hashlib
import json
import os
import sys

import scan_story as S

HERE = os.path.dirname(os.path.abspath(__file__))
TSV_DIR = os.path.join(HERE, "translation")
SCENE_DIR = os.path.join(S.WORK_DIR, "scenes")
OUT_JSON = os.path.join(S.WORK_DIR, "translation.json")
LINE_LETTERS = 34
NAME_OPS = set(range(0x4B, 0x50)) | {0xA5, 0xA6, 0xA7, 0xDA}
OP_COLOUR = 0x73
PORTRAIT_SLOT = {0x7A: 2, 0x7B: 3, 0x7C: 4, 0x7D: 5}     # opcode -> window type it speaks in
WIDE_WINDOWS = {31: 60}                                    # glossary pop-ups: a wider box
BOX_LINES = 3
ORE_CALL = 0x32
ORE_WINDOW_BASE = 100                                      # My Life: window = 100 + the number its 0018 gives
# Portrait id ranges seen in scenario 1 (id // 16), for the speaker column of the scene files.
SPEAKERS = [(0x00, 0x03, "player"), (0x04, 0x05, "Yabe"), (0x2B, 0x37, "extra"), (0x4D, 0x4E, "Momoko"),
            (0x56, 0x56, "Kageyama"), (0x5E, 0x5F, "Tamano"), (0x60, 0x60, "Yajima"),
            (0x61, 0x61, "Todoroki"), (0x62, 0x62, "Maruo"), (0x65, 0x66, "Kagurazaka")]


def text_hash(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:4]


def speaker(face):
    if face is None:
        return "-"
    return next((name for lo, hi, name in SPEAKERS if lo <= face >> 4 <= hi), "%X" % face)


def all_scripts():
    """The Success Mode scripts and the scripts of the other modes (Eikan Nine)."""
    mods = S.load_all_rels()
    by_name = {m.name: m for m in mods.values()}
    return [S.Script(by_name[fn], mods) for fn in S.SCRIPT_FILES] + S.load_block_scripts(mods)


def find_script(name):
    if name in S.BLOCK_SCRIPTS:
        return S.load_block_scripts()[list(S.BLOCK_SCRIPTS).index(name)]
    mods = S.load_all_rels()
    return S.Script(next(m for m in mods.values() if m.name == name), mods)


def line_letters(sc):
    """Letters a line of this script's boxes holds."""
    return 2 * sc.spec["line"] if hasattr(sc, "spec") else LINE_LETTERS


def scenes(sc):
    """[[row, ...], ...]; row = dict(off, window, face, mark, text) or dict(note=...)."""
    block = hasattr(sc, "spec")             # another engine: no portrait or colour opcodes known
    ore = block and sc.spec.get("engine") == "ore"      # My Life: whole-halfword opcodes, windows set by 0018
    name_ops = sc.name_ops if block else NAME_OPS
    ends = sc.ends if block else (S.OP_RETURN, S.OP_GOTO)
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
                        "text": S.decode_units(units)})
            mark = "+"
        elif op in name_ops:
            cur.append({"note": "{name}"})
        elif ore:
            if op in sc.spec["marks"]:
                mark = sc.spec["marks"][op]
            elif op == S.ORE_WINDOW:
                ore_window, mark = ORE_WINDOW_BASE + sc.hw[i + 1], "B"
            elif op == ORE_CALL:
                said = sc.routine_text(ore_labels[sc.hw[i + 1]])
                if said:
                    cur.append({"note": "{sub} " + (said if len(said) <= 30 else said[:30] + "...")})
            elif op in S.ORE_IF:
                cur.append({"note": "if"})
            elif op == S.ORE_ELSE:
                cur.append({"note": "else"})
            elif op == S.ORE_BLOCK_END:
                cur.append({"note": "end"})
            elif op in ends:
                ended = True
        elif block:
            if op in (S.OP_NEWLINE, S.OP_NEWLINE_WAIT, S.OP_WAIT):
                mark = {S.OP_NEWLINE: "L", S.OP_NEWLINE_WAIT: "W", S.OP_WAIT: "B"}[op]
            elif op in ends:
                ended = True
        elif op == OP_COLOUR:
            cur.append({"note": "colour %d" % (sc.hw[i] >> 8)})
        elif op in PORTRAIT_SLOT:
            face[PORTRAIT_SLOT[op]] = sc.hw[i + 1]
        elif op == S.OP_NEWLINE:
            mark = "L"
        elif op == S.OP_NEWLINE_WAIT:
            mark = "W"
        elif op == S.OP_WAIT:
            mark = "B"
        elif op in (S.OP_RETURN, S.OP_GOTO):
            ended = True
    if any("off" in r for r in cur):
        out.append(cur)
    return out


def load_tsv(name):
    """{section offset: (hash, english)}"""
    rows = {}
    path = os.path.join(TSV_DIR, name + ".tsv")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    off, h, en = line.rstrip("\n").split("\t", 2)
                    rows[int(off)] = (h, en.replace("\\n", "\n"))
    return rows


def save_tsv(name, rows):
    os.makedirs(TSV_DIR, exist_ok=True)
    with open(os.path.join(TSV_DIR, name + ".tsv"), "w", encoding="utf-8") as f:
        f.write("# section_offset\thash of the original run\tEnglish (see tl.py)\n")
        for off in sorted(rows):
            f.write("%d\t%s\t%s\n" % (off, rows[off][0], rows[off][1].replace("\n", "\\n")))


def cmd_export():
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


def cmd_show(name, first, last):
    sc = find_script(name)
    all_scenes = scenes(sc)
    for n in range(int(first.lstrip("s")), int(last.lstrip("s")) + 1):
        print("@s%04d" % n)
        for r in all_scenes[n]:
            if "note" in r:
                print("# " + r["note"])
            else:
                print("%d %s %s | %s" % (r["window"], speaker(r["face"]), r["mark"],
                                         r["text"].replace("\n", "\\n") or "(empty)"))


def read_input(scene=None):
    """[(scene number, [line, ...]), ...] from stdin."""
    batches, cur = [], None
    for l in sys.stdin:
        l = l.rstrip("\n")
        blank = not l.strip(" \t\r")
        l = l.replace("\\_", " ")                    # \_ is a space (safe at the end of a line)
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


def cmd_apply(name, scene=None):
    sc = find_script(name)
    all_scenes = scenes(sc)
    batches = read_input(scene)
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


def cmd_check(name):
    """Dry run of apply: errors (line counts, empty runs, stray characters) and the merge warnings."""
    sc = find_script(name)
    all_scenes = scenes(sc)
    rows, errors, warnings, stored = load_tsv(name), [], [], 0
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
            if en.count("\n") != r["text"].count("\\n") and r["window"] == 26:
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


def letters(text):
    """Width in letters: a Japanese character fills a whole cell, two letters."""
    return sum(1 if ord(c) < 128 else 2 for c in text)


def odd_tail(text):
    """True if the letters after the last Japanese character do not fill their last cell."""
    n = 0
    for c in reversed(text):
        if ord(c) >= 128:
            break
        n += 1
    return n % 2 == 1


def check_scene(name, rows, done, per_line=LINE_LETTERS):
    """Warnings for one scene: long lines, too many lines, odd-length runs before a same-line run, gaps."""
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
                line += 12                                  # an inserted name: up to 6 full cells
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
        if r["mark"] == "B" or (r["window"] != 30 and r["window"] != bubble):
            box = box_orig = 0                              # a new box, or another speaker's bubble
        if r["window"] != 30:
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
        if box > max(BOX_LINES, box_orig) and r["window"] not in WIDE_WINDOWS and r["window"] != 26:
            warn.append("%s +%d: box has %d lines (original %d)" % (name, r["off"], box, box_orig))
        for k, part in enumerate(en.split("\n")):
            line = letters(part) + (line if k == 0 else 0)
            if line > limit:
                warn.append("%s +%d: line is %d letters (max %d): %r" % (name, r["off"], line, limit, part))
        pending = (r["off"], en.split("\n")[-1])
    return warn


def cmd_merge():
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


def cmd_status():
    for sc in all_scripts():
        done = load_tsv(sc.rel.name)
        runs = [r for rows in scenes(sc) for r in rows if "off" in r and r["text"]]
        print("%-13s %5d / %5d runs" % (sc.rel.name, sum(1 for r in runs if r["off"] in done), len(runs)))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "export":
        cmd_export()
    elif cmd == "show" and len(sys.argv) in (4, 5):
        cmd_show(sys.argv[2], sys.argv[3], sys.argv[-1])
    elif cmd == "apply" and len(sys.argv) in (3, 4):
        cmd_apply(*sys.argv[2:])
    elif cmd == "check" and len(sys.argv) == 3:
        cmd_check(sys.argv[2])
    elif cmd == "set" and len(sys.argv) == 5:
        rows = load_tsv(sys.argv[2])
        rows[int(sys.argv[3])] = (rows[int(sys.argv[3])][0], sys.argv[4].replace("\\n", "\n"))
        save_tsv(sys.argv[2], rows)
    elif cmd == "merge":
        cmd_merge()
    elif cmd == "status":
        cmd_status()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
