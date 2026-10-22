"""Translation memory: every translated piece of the game as a Japanese / English pair, for reuse in other games.

  pp15 export-tm [OUT_DIR]     default <translation-kit>/pawapuro15-wii/tm, config.KIT_TM_DIR (outside this repository)

Writes tm.tsv (one pair per row: kind, file, id, scene, speaker, Japanese, English) and counts.txt.
kind = script (story text, one run each, in scene order), string (fixed-slot menu and system text, main.dol dialogs included), message
(Pennant news). The Japanese comes from the scene and message exports in _work/ (`pp15 script export`, `pp15 messages
export`) and, for strings, from the modules themselves (pp15/text/strings.py), the English from translation/; a pair is kept only when the hash in the TSV matches the
Japanese, so a stale export never pairs the wrong lines. Japanese layout marks are kept as written there
(| = line break of a slot, {n} {p} {66} = codes of a message, \\n inside a run). The output holds game text:
it stays out of this repository (the auto-sync would publish it).
"""
import glob
import hashlib
import os
import sys

from pp15 import config

WORK = config.WORK_DIR
TR = config.TRANSLATION_DIR


def h4(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:4]


def tsv(path, keys):
    """{key: (hash, English)} of a translation TSV with `keys` leading key columns."""
    out = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.strip() and not line.startswith("#"):
                p = line.rstrip("\n").split("\t", keys + 1)
                out[tuple(p[:keys])] = (p[keys], p[keys + 1] if len(p) > keys + 1 else "")
    return out


def clean(s):
    return s.replace("\t", " ").replace("\r", " ").replace("\n", "\\n")


def scripts():
    for folder in sorted(glob.glob(os.path.join(WORK, "scenes", "*"))):
        name = os.path.basename(folder)
        en = tsv(os.path.join(TR, name + ".tsv"), 1)
        for path in sorted(glob.glob(os.path.join(folder, "s*.txt"))):
            scene = os.path.basename(path)[:-4]
            for line in open(path, encoding="utf-8"):
                if line.startswith("#") or not line.strip():
                    continue
                p = line.rstrip("\n").split("\t")
                if len(p) < 5:
                    continue
                off, _, who, _, ja = p[:5]
                got = en.get((off,))
                if got and got[0] == h4(ja) and got[1]:
                    yield "script", name, off, scene, who, ja, got[1]


def strings():
    """Fixed-slot strings, read from the modules by pp15/text/strings.py (the hash is over the unpadded text)."""
    from pp15.text import strings as U
    mods = U.load_mods()
    names = sorted(os.path.basename(p)[:-4] for p in glob.glob(os.path.join(TR, "strings", "*.tsv")))
    for name in names:
        en = tsv(os.path.join(TR, "strings", name + ".tsv"), 2)
        for st in U.strings_of(name, None if name == U.DOL else mods):
            got = en.get((str(st["section"]), str(st["offset"])))
            if got and got[1]:
                yield (("string" if got[0] == h4(st["text"]) else "string?"), name,
                       "%d:%d" % (st["section"], st["offset"]), "", "", U.japanese_lines(st), got[1])


def messages():
    for path in sorted(glob.glob(os.path.join(WORK, "messages", "*.txt"))):
        name = os.path.basename(path)[:-4]
        en = tsv(os.path.join(TR, "messages", name + ".tsv"), 2)
        for line in open(path, encoding="utf-8"):
            if line.startswith("#"):
                continue
            p = line.rstrip("\n").split("\t")
            if len(p) < 3 or ":" not in p[0]:
                continue
            sec, off = p[0].split(":")
            got = en.get((sec, off))
            if got and got[1]:
                yield ("message" if got[0] == h4(p[2]) else "message?"), name, p[0], "", "", p[2], got[1]


def main(argv=None):
    a = sys.argv[1:] if argv is None else list(argv)
    out = a[0] if a else config.KIT_TM_DIR
    os.makedirs(out, exist_ok=True)
    counts = {}
    with open(os.path.join(out, "tm.tsv"), "w", encoding="utf-8") as f:
        f.write("kind\tfile\tid\tscene\tspeaker\tjapanese\tenglish\n")
        for gen in (scripts, strings, messages):
            for row in gen():
                f.write("\t".join(clean(str(x)) for x in row) + "\n")
                counts[(row[0], row[1])] = counts.get((row[0], row[1]), 0) + 1
    with open(os.path.join(out, "counts.txt"), "w") as f:
        f.write("pairs by kind and file (kind with ? = hash did not match the export: check before trusting)\n")
        for (k, n), c in sorted(counts.items()):
            f.write("%-9s %-16s %6d\n" % (k, n, c))
    print(open(os.path.join(out, "counts.txt")).read())
    print("total", sum(counts.values()), "->", os.path.join(out, "tm.tsv"))


if __name__ == "__main__":
    main()
