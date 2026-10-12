#!/usr/bin/env python3
"""Translation workflow: scenes out, English in, translation.json for the build.

  tl.py export              write the scenes of every script file to _work/scenes/<file>/sNNN.txt
  tl.py apply FILE SCENE    read English from stdin, one line per text run of that scene, in order
  tl.py merge               translation/*.tsv -> _work/translation.json, and check every line
  tl.py status              translated / total runs per file

The English lives in translation/<file>.tsv (in git): section offset, a 4-digit hash of the
original run, the English. No Japanese text. The hash catches a run that moved or changed.
Scene files hold the Japanese and stay in _work/ (git-ignored).

A scene is the text between two script entry points (a label after a return or jump). Scene file
columns: section offset, window type, portrait id of the speaker's slot, layout mark, text.
Layout marks:  B first run of a box   L new line   W new line after a button wait
               + same line as the run before (after a colour change or an inserted name)
Lines starting with # are notes: {name} = inserted name, colour N = text colour from here on.
In "apply" input, write \\n for a line break inside a run and a single - for an empty run.
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
UNCHECKED_WINDOWS = {26, 31}                               # menus and glossary pop-ups: own layout


def text_hash(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:4]


def scenes(sc):
    """[[row, ...], ...]; row = dict(off, window, face, mark, text) or dict(note=...)."""
    out, cur = [], []
    face, mark, ended = {}, "B", True
    for i in sorted(k for k, v in sc.kind.items() if v == "op"):
        op = sc.hw[i] & 0xFF
        if i in sc.labels and ended:
            if any("off" in r for r in cur):
                out.append(cur)
            cur, mark, face = [], "B", {}
        ended = False
        if i in sc.texts:
            window, units, _ = sc.texts[i]
            cur.append({"off": i * 2, "window": window, "face": face.get(window, 0), "mark": mark,
                        "text": S.decode_units(units)})
            mark = "+"
        elif op in NAME_OPS:
            cur.append({"note": "{name}"})
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
    for sc in S.load_scripts():
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
                        f.write("%d\t%d\t%X\t%s\t%s\n" % (r["off"], r["window"], r["face"], r["mark"],
                                                          r["text"].replace("\n", "\\n")))
            index.append("s%04d\t%d runs\t%d done\t0x%X" % (n, len(runs),
                                                           sum(1 for r in runs if r["off"] in done),
                                                           rows[0].get("off", 0) if "off" in rows[0]
                                                           else next(r["off"] for r in rows if "off" in r)))
        with open(os.path.join(folder, "index.txt"), "w") as f:
            f.write("\n".join(index) + "\n")
        print("%s: %d scenes -> %s" % (sc.rel.name, len(index), folder))


def cmd_apply(name, scene):
    sc = next(s for s in S.load_scripts() if s.rel.name == name)
    runs = [r for r in scenes(sc)[int(scene.lstrip("s"))] if "off" in r]
    lines = [l.rstrip("\n") for l in sys.stdin if l.strip()]
    if len(lines) != len(runs):
        sys.exit("scene %s has %d runs, got %d lines" % (scene, len(runs), len(lines)))
    rows = load_tsv(name)
    for r, en in zip(runs, lines):
        if not r["text"]:
            if en != "-":
                sys.exit("+%d is an empty run, expected -" % r["off"])
            continue
        rows[r["off"]] = (text_hash(r["text"]), "" if en == "-" else en.replace("\\n", "\n"))
    save_tsv(name, rows)
    print("%s %s: %d runs stored" % (name, scene, len(runs)))


def check_scene(name, rows, done):
    """Warnings for one scene: long lines, odd-length runs before a same-line run, gaps."""
    warn, line, pending = [], 0, None
    runs = [r for r in rows if "off" in r]
    some = sum(1 for r in runs if r["off"] in done)
    missing = [r["off"] for r in runs if r["text"] and r["off"] not in done]
    if some and missing:
        warn.append("%s: scene partly translated, missing +%s" % (name, ", +".join(map(str, missing[:5]))))
    for r in rows:
        if "note" in r:
            if r["note"] == "{name}":
                line += 12                                  # an inserted name: up to 6 full cells
            continue
        if r["off"] not in done or r["window"] in UNCHECKED_WINDOWS:
            line, pending = 0, None
            continue
        en = done[r["off"]][1]
        if r["mark"] != "+":
            line = 0
        elif pending is not None and len(pending[1]) % 2:
            warn.append("%s +%d: odd number of letters before a same-line run: %r" % (name, *pending))
        for k, part in enumerate(en.split("\n")):
            line = len(part) + (line if k == 0 else 0)
            if line > LINE_LETTERS:
                warn.append("%s +%d: line is %d letters (max %d): %r" % (name, r["off"], line,
                                                                         LINE_LETTERS, part))
        pending = (r["off"], en.split("\n")[-1])
    return warn


def cmd_merge():
    entries, warnings = [], []
    for sc in S.load_scripts():
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
            warnings += check_scene(sc.rel.name, rows, done)
        if set(done) - seen:
            sys.exit("%s: no text run at +%s" % (sc.rel.name, sorted(set(done) - seen)[:5]))
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    for w in warnings:
        print("warning:", w)
    print("%d runs -> %s, %d warnings" % (len(entries), OUT_JSON, len(warnings)))


def cmd_status():
    for sc in S.load_scripts():
        done = load_tsv(sc.rel.name)
        runs = [r for rows in scenes(sc) for r in rows if "off" in r and r["text"]]
        print("%-13s %5d / %5d runs" % (sc.rel.name, sum(1 for r in runs if r["off"] in done), len(runs)))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "export":
        cmd_export()
    elif cmd == "apply" and len(sys.argv) == 4:
        cmd_apply(sys.argv[2], sys.argv[3])
    elif cmd == "merge":
        cmd_merge()
    elif cmd == "status":
        cmd_status()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
