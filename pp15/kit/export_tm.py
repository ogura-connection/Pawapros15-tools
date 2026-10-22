"""Translation memory: every translated piece of the game as a Japanese / English pair, for reuse in other games.

    pp15 export-tm [OUT_DIR]     default <translation-kit>/pawapuro15-wii/tm, config.KIT_TM_DIR (outside this repository)

What it is for: later games of the same series reuse much of this text, so the finished pairs are collected in one
table that a translator (or a tool) can search. Writes OUT_DIR/tm.tsv (one pair per row: kind, file, id, scene,
speaker, Japanese, English) and OUT_DIR/counts.txt (pairs by kind and file).

kind = script (story text, one run each, in scene order), string (fixed-slot menu and system text, main.dol dialogs
included), message (Pennant news). A kind ending in ? means the hash in the translation file no longer matches the
Japanese: the export is stale, check before trusting the pair.

Where the text comes from: the Japanese of scripts and messages from the exports in _work/ (`pp15 script export`,
`pp15 messages export`), of strings from the modules themselves (pp15/text/strings.py); the English from translation/.
A pair is kept only when the hash in the TSV matches the Japanese, so a stale export never pairs the wrong lines. Japanese
layout marks are kept as written there (| = line break of a slot, {n} {p} {66} = codes of a message, \\n inside a run).
The output holds game text: it stays out of this repository (the auto-sync would publish it).

Public functions: hash4, read_translation_tsv, flatten, script_pairs, string_pairs, message_pairs, main.
"""
import argparse
import glob
import hashlib
import os
import sys
from typing import Dict, Iterator, List, Optional, Tuple

from pp15 import config
from pp15.text import strings

WORK = config.WORK_DIR
TRANSLATION = config.TRANSLATION_DIR
Pair = Tuple[str, str, str, str, str, str, str]       # kind, file, id, scene, speaker, Japanese, English


def hash4(text: str) -> str:
    """The first four hex digits of the SHA-1 of the text: the check value stored next to each translation."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:4]


def read_translation_tsv(path: str, key_columns: int) -> Dict[tuple, Tuple[str, str]]:
    """Read a translation TSV whose first `key_columns` columns identify a line, followed by the hash of the Japanese
    and the English. Returns {key tuple: (hash, English)}; empty if the file does not exist."""
    out = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.strip() and not line.startswith("#"):
                parts = line.rstrip("\n").split("\t", key_columns + 1)
                out[tuple(parts[:key_columns])] = (parts[key_columns], parts[key_columns + 1] if len(parts) > key_columns + 1 else "")
    return out


def flatten(text: str) -> str:
    """Make a text fit in one TSV cell: tabs and carriage returns become spaces, line breaks become the two characters \\n."""
    return text.replace("\t", " ").replace("\r", " ").replace("\n", "\\n")


def script_pairs() -> Iterator[Pair]:
    """Story text: a pair for each line of every scene export in _work/scenes/<group>/s*.txt that has English."""
    for folder in sorted(glob.glob(os.path.join(WORK, "scenes", "*"))):
        group = os.path.basename(folder)
        english = read_translation_tsv(os.path.join(TRANSLATION, group + ".tsv"), 1)
        for path in sorted(glob.glob(os.path.join(folder, "s*.txt"))):
            scene = os.path.basename(path)[:-4]
            for line in open(path, encoding="utf-8"):
                if line.startswith("#") or not line.strip():
                    continue
                columns = line.rstrip("\n").split("\t")
                if len(columns) < 5:
                    continue
                offset, _, speaker, _, japanese = columns[:5]
                found = english.get((offset,))
                if found and found[0] == hash4(japanese) and found[1]:
                    yield "script", group, offset, scene, speaker, japanese, found[1]


def string_pairs() -> Iterator[Pair]:
    """Fixed-slot strings, read from the modules by pp15/text/strings.py (the hash is over the unpadded text)."""
    modules = strings.load_mods()
    names = sorted(os.path.basename(p)[:-4] for p in glob.glob(os.path.join(TRANSLATION, "strings", "*.tsv")))
    for name in names:
        english = read_translation_tsv(os.path.join(TRANSLATION, "strings", name + ".tsv"), 2)
        for string in strings.strings_of(name, None if name == strings.DOL else modules):
            found = english.get((str(string["section"]), str(string["offset"])))
            if found and found[1]:
                yield (("string" if found[0] == hash4(string["text"]) else "string?"), name,
                       "%d:%d" % (string["section"], string["offset"]), "", "", strings.japanese_lines(string), found[1])


def message_pairs() -> Iterator[Pair]:
    """In-game messages (Pennant news and similar) from _work/messages/*.txt that have English."""
    for path in sorted(glob.glob(os.path.join(WORK, "messages", "*.txt"))):
        name = os.path.basename(path)[:-4]
        english = read_translation_tsv(os.path.join(TRANSLATION, "messages", name + ".tsv"), 2)
        for line in open(path, encoding="utf-8"):
            if line.startswith("#"):
                continue
            columns = line.rstrip("\n").split("\t")
            if len(columns) < 3 or ":" not in columns[0]:
                continue
            section, offset = columns[0].split(":")
            found = english.get((section, offset))
            if found and found[1]:
                yield ("message" if found[0] == hash4(columns[2]) else "message?"), name, columns[0], "", "", columns[2], found[1]


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 export-tm [OUT_DIR]`. `argv` defaults to sys.argv[1:]."""
    parser = argparse.ArgumentParser(prog="pp15 export-tm", description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("out_dir", metavar="OUT_DIR", nargs="?", default=config.KIT_TM_DIR,
                        help="where to write tm.tsv and counts.txt (default: %s)" % config.KIT_TM_DIR)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    out = args.out_dir
    os.makedirs(out, exist_ok=True)
    counts = {}
    with open(os.path.join(out, "tm.tsv"), "w", encoding="utf-8") as f:
        f.write("kind\tfile\tid\tscene\tspeaker\tjapanese\tenglish\n")
        for generator in (script_pairs, string_pairs, message_pairs):
            for row in generator():
                f.write("\t".join(flatten(str(x)) for x in row) + "\n")
                counts[(row[0], row[1])] = counts.get((row[0], row[1]), 0) + 1
    with open(os.path.join(out, "counts.txt"), "w") as f:
        f.write("pairs by kind and file (kind with ? = hash did not match the export: check before trusting)\n")
        for (kind, name), count in sorted(counts.items()):
            f.write("%-9s %-16s %6d\n" % (kind, name, count))
    print(open(os.path.join(out, "counts.txt")).read())
    print("total", sum(counts.values()), "->", os.path.join(out, "tm.tsv"))


if __name__ == "__main__":
    main()
