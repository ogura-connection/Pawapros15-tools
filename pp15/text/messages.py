"""In-game messages that are small scripts, not fixed slots (the news of Pennant mode). The `pp15 messages` command.

  pp15 messages export [FILE ...]   messages to _work/messages/<file>.txt
  pp15 messages check FILE          validate "ID<tab>English" lines from stdin, write nothing
  pp15 messages apply FILE          the same check, then store the lines (nothing if one fails)
  pp15 messages set FILE ID TEXT    the English of one message ("" removes it)
  pp15 messages merge               translation/messages/*.tsv -> _work/messages.json, with checks
  pp15 messages status              translated / total per file

A message is a run of pieces. A piece is: control codes, the unit 0, text, 0xFFFF. The codes seen: 1 new line, 7 new
page (the reader presses a button), 0x60 to 0x9F an inserted value (club, player name, number: which one shows from the
Japanese behind it), and 0xF (pena_sub.rel) or 8 (pn_fa.rel) after the last piece: the end. Only the start of a message
has a pointer (two tables of relocations in pena_sub.rel, docs/GLOSSARY.md "Relocation"), so the game reads a message
piece after piece and the pieces of one message can be of any length, as long as the message still ends before the next
pointer target.

A message is written as one line: the text of its pieces with a tag for the codes in front of each piece:
  {n} new line, {p} new page, {66} the insert 0x66, {+} a piece with no code, {*6} the colour of the text after it.
The English has the same tags in the same order; what stands between them is free. Two letters take one cell and the
letter pairs start again in every piece, so a piece with an odd number of letters wastes half a cell. ID is
section:offset of the pointer target. REGIONS lists where messages are; a span between two pointer targets that does
not parse as pieces is left alone.

Public names: messages_of(name), judge(msg, en), encode(msg, texts, encode_text), load_for_build(), REGIONS, main(argv).
"""
import argparse
import collections
import json
import os
import re
import struct
import sys
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from pp15 import config
from pp15.glyphs import MAX_GLYPH, char_to_glyph, glyph_to_char
from pp15.text.colour_text import COLOUR_SHIFT, letters
from pp15.text.slot_finder import load_mods
from pp15.text.string_rules import read_pairs
from pp15.text.tsv_store import read_rows, text_hash, write_rows

TSV_DIR = os.path.join(config.TRANSLATION_DIR, "messages")
LIST_DIR = os.path.join(config.WORK_DIR, "messages")
OUT_JSON = os.path.join(config.WORK_DIR, "messages.json")
TSV_HEADER = "# section\toffset\thash of the original message\tEnglish (see ui_messages.py)\n"
END = 0xFFFF
# file -> [(section, first offset, end offset)] where the messages are
REGIONS = {"pena_sub.rel": [(5, 110900, 130016)], "pn_fa.rel": [(5, 6584, 6976)]}
CODES = {1: "n", 7: "p"}    # control codes with a tag of their own: new line, new page
STOP = (0xF, 8)             # ends a message; kept where it is, never written by a translator
INSERT_FIRST, INSERT_END = 0x60, 0xA0       # codes 0x60..0x9F insert a value (club, player name, number)
CLUB_LAST = 0x6B            # inserts up to this code are clubs/names (wide), above it numbers (narrow)
INSERT_NAME_LETTERS, INSERT_NUMBER_LETTERS = 8, 4       # screen width of an inserted name/club, of a number
TAG = re.compile(r"\{([0-9a-f]{2}|[np+]|\*[0-9a-f])\}")
LINE = 40                   # letters of a line of the news box (the longest Japanese lines), see width()

Piece = Tuple[tuple, tuple, int]    # (control codes in front, glyph numbers of the text, colour)


# ── Reading messages from a module ────────────────────────────────────────

def is_code(u: int) -> bool:
    """True when unit u is a control code of a message (new line/page, stop code, or an insert)."""
    return u in CODES or u in STOP or INSERT_FIRST <= u < INSERT_END


def anchors(rel, mods: dict, sec: int) -> List[int]:
    """Sorted section offsets in section `sec` of module `rel` that any module points at (message starts)."""
    out = set()
    for m in mods.values():
        for _, _, _, tm, ts, addend in m.relocs():
            if tm == rel.mod_id and ts == sec:
                out.add(addend)
    return sorted(out)


def parse(units: Sequence[int]):
    """([(codes, text units, colour)], trailer, kind) or None when the span is not a message.

    kind "end": every piece is closed by 0xFFFF and the trailer holds the stop code. kind "stop": one piece closed by
    the stop code itself ("0 name F"). colour = the top four bits of the units of a piece (0x6000 and 0x2000 mark the
    lines about the number of fans)."""
    pieces, i, n = [], 0, len(units)
    while i < n:
        j = i
        while j < n and units[j] and is_code(units[j]):
            j += 1
        if j == n:
            break                           # codes and nothing behind them: the end of the message
        if units[j] != 0:
            return None
        try:
            k = units.index(END, j + 1)
        except ValueError:
            break
        text = units[j + 1:k]
        colour = {u >> COLOUR_SHIFT for u in text}
        if len(colour) > 1 or any(u & 0xFFF > MAX_GLYPH for u in text):
            return None
        pieces.append((tuple(units[i:j]), tuple(u & 0xFFF for u in text), colour.pop() if text else 0))
        i = k + 1
    trailer = list(units[i:])
    while trailer and trailer[-1] == 0:
        trailer.pop()
    if not pieces:                          # "0 name F": a short text with the stop code behind it
        j = 0
        while j < len(trailer) and trailer[j] and is_code(trailer[j]) and trailer[j] not in STOP:
            j += 1
        text = trailer[j + 1:-1]
        if j + 2 < len(trailer) and trailer[j] == 0 and trailer[-1] in STOP and all(u <= MAX_GLYPH for u in text):
            return [(tuple(trailer[:j]), tuple(text), 0)], (trailer[-1],), "stop"
        return None
    if any(not is_code(u) for u in trailer):
        return None
    return pieces, tuple(trailer), "end"


def tags(k: int, codes: Sequence[int], colour: int) -> List[str]:
    """The tags in front of the text of piece k: its codes, its colour, or {+} for a later piece with neither."""
    out = ["{%s}" % CODES.get(c, "%02x" % c) for c in codes] + (["{*%x}" % colour] if colour else [])
    return out or (["{+}"] if k else [])


def form(pieces: Sequence[Piece], text_of: Callable[[Sequence[int]], str]) -> str:
    """The one-line form of a message: for each piece its tags and then text_of(its units)."""
    return "".join("".join(tags(k, codes, colour)) + text_of(units) for k, (codes, units, colour) in enumerate(pieces))


def japanese(units: Sequence[int]) -> str:
    """The characters of glyph numbers (? for a glyph with no character)."""
    return "".join(glyph_to_char(u) or "?" for u in units)


_messages_cache: Dict[str, List[dict]] = {}


def messages_of(name: str, mods: Optional[dict] = None) -> List[dict]:
    """The messages of module `name`: [{"section", "offset", "cells" (of the span), "pieces", "trailer", "kind",
    "ja" (the one-line Japanese form)}]. Read once and cached."""
    if name in _messages_cache:
        return _messages_cache[name]
    mods = mods or load_mods()
    rel = next((m for m in mods.values() if m.name == name), None)
    if rel is None:
        sys.exit("%s: no such module" % name)
    out = []
    for sec, lo, hi in REGIONS.get(name, ()):
        d = rel.sec_data(sec)
        marks = [a for a in anchors(rel, mods, sec) if lo <= a < hi] + [hi]
        for a, b in zip(marks, marks[1:]):
            units = list(struct.unpack(">%dH" % ((b - a) // 2), d[a:b]))
            got = parse(units)
            if got is None or not any(t for _, t, _ in got[0]):
                continue
            pieces, trailer, kind = got
            out.append({"section": sec, "offset": a, "cells": len(units), "pieces": pieces, "trailer": trailer,
                        "kind": kind, "ja": form(pieces, japanese)})
    _messages_cache[name] = out
    return out


# ── Rules ─────────────────────────────────────────────────────────────────

def room(msg: dict) -> int:
    """Cells the text of all pieces may take together."""
    fixed = sum(len(c) + 2 for c, _, _ in msg["pieces"]) + len(msg["trailer"])
    if msg["kind"] == "stop":
        fixed -= 1                          # no 0xFFFF: the stop code closes the text
    return msg["cells"] - fixed


def width(line: str) -> int:
    """Letters a line takes on screen: its text, 8 for an inserted name or club, 4 for a number."""
    n = len(TAG.sub("", line))
    for m in TAG.finditer(line):
        if len(m.group(1)) == 2 and m.group(1)[0] != "*":
            n += INSERT_NAME_LETTERS if INSERT_FIRST <= int(m.group(1), 16) <= CLUB_LAST else INSERT_NUMBER_LETTERS
    return n


def judge(msg: dict, en: str) -> Tuple[List[str], List[str]]:
    """Check the English `en` of a message: (errors, [text of each piece]).

    The tags must be the Japanese's tags in the same order, only drawable characters, the pieces must fit the message's
    span, and no line may be wider than the news box."""
    if not en.strip():
        return ["empty English"], []
    plain = TAG.sub("", en)
    bad = sorted({c for c in plain if not 0x20 <= ord(c) <= 0x7E and char_to_glyph(c) is None})
    if bad or "\\n" in en or "|" in en:
        return ["cannot be drawn: %s" % " ".join(["%r" % c for c in bad] + ["\\n"] * ("\\n" in en) + ["|"] * ("|" in en))], []
    if "{" in plain or "}" in plain:
        return ["a { or } that is not a tag"], []
    toks = re.findall(r"\{[^{}]*\}|[^{}]+", en)
    want = [x for k, (c, _, col) in enumerate(msg["pieces"]) for x in tags(k, c, col)]
    if [x for x in toks if x.startswith("{")] != want:
        return ["tags differ: the Japanese has %s, the English %s"
                % (" ".join(want) or "none", " ".join(x for x in toks if x.startswith("{")) or "none")], []
    texts, i = [], 0
    for k, (codes, _, colour) in enumerate(msg["pieces"]):
        mine = tags(k, codes, colour)
        if toks[i:i + len(mine)] != mine:   # text where the tags of one piece must stand together
            return ["no text may stand in front of %s here (%s)"
                    % (mine[-1], "the message starts with it" if i == 0 and len(mine) == 1 else
                       "%s belong together" % " ".join(mine))], []
        i += len(mine)
        if i < len(toks) and not toks[i].startswith("{"):
            texts.append(toks[i])
            i += 1
        else:
            texts.append("")
    errors = []
    need = sum(letters(x) for x in texts)
    if need > room(msg):
        errors.append("%d letters too long: the pieces take %d cells, the message holds %d"
                      % ((need - room(msg)) * 2, need, room(msg)))
    for line in re.split(r"\{[np]\}", en):
        if width(line) > LINE:
            errors.append("a line is %d letters too wide (%d of %d, a name or club counts 8, a number 4): %r"
                          % (width(line) - LINE, width(line), LINE, line))
    return errors, texts


def encode(msg: dict, texts: Sequence[str], encode_text: Callable[[str], Sequence[int]]) -> List[int]:
    """The units of the whole span of a message with English text.

    encode_text(text) -> glyph units (the build's pair-font encoder); texts = the English of each piece. The span is
    padded with zeros to its original length; raises ValueError when it does not fit."""
    out = []
    for (codes, _, colour), text in zip(msg["pieces"], texts):
        units = [u | colour << COLOUR_SHIFT for u in encode_text(text)] if text else []
        out += list(codes) + [0] + units + ([END] if msg["kind"] == "end" else [])
    out += list(msg["trailer"])
    if len(out) > msg["cells"]:
        raise ValueError("message %d:%d does not fit" % (msg["section"], msg["offset"]))
    return out + [0] * (msg["cells"] - len(out))


# ── Translation files ─────────────────────────────────────────────────────

def load_tsv(name: str) -> Dict[Tuple[int, int], Tuple[str, str]]:
    """{(section, offset): (hash of the original message, English)} for module `name`."""
    rows = read_rows(os.path.join(TSV_DIR, name + ".tsv"), 4)
    return {(int(sec), int(off)): (h, en) for sec, off, h, en in rows}


def save_tsv(name: str, rows: Dict[Tuple[int, int], Tuple[str, str]]) -> None:
    """Write translation/messages/<name>.tsv sorted by section and offset."""
    write_rows(os.path.join(TSV_DIR, name + ".tsv"), TSV_HEADER, (key + rows[key] for key in sorted(rows)))


# ── Commands ──────────────────────────────────────────────────────────────

def check_rows(name: str, pairs: List[Tuple[str, str]]):
    """Check "ID, English" pairs. Returns (found, good, problems): found = {(section, offset): message}, good =
    {(section, offset): English} for rows without errors, problems = lines "ID: text"."""
    found = {(m["section"], m["offset"]): m for m in messages_of(name)}
    good, seen, problems = {}, set(), []
    for where, en in pairs:
        try:
            key = tuple(int(x) for x in where.split(":"))
        except ValueError:
            key = None
        if key not in found:
            problems.append("%s: unknown ID" % where)
        elif key in seen:
            problems.append("%s: duplicate ID" % where)
        else:
            seen.add(key)
            errors, _ = judge(found[key], en)
            problems += ["%s: %s" % (where, e) for e in errors]
            if not errors:
                good[key] = en
    return found, good, problems


def cmd_check(name: str, pairs: List[Tuple[str, str]], store: bool = False) -> None:
    """Check pairs for module `name`; print problems and exit 1 on any. With store=True and no problem, save them."""
    found, good, problems = check_rows(name, pairs)
    for line in problems:
        print(line)
    if problems:
        print("%s: %d problems in %d lines%s" % (name, len(problems), len(pairs), ", nothing stored" if store else ""))
        sys.exit(1)
    if store:
        rows = load_tsv(name)
        for key, en in good.items():
            rows[key] = (text_hash(found[key]["ja"]), en)
        save_tsv(name, rows)
        print("%s: %d lines stored, %d of %d messages translated" % (name, len(pairs), len(rows), len(found)))
    else:
        print("%s: %d lines, no problems" % (name, len(pairs)))


def cmd_set(name: str, where: str, en: str) -> None:
    """Store the English of one message, or remove it when `en` is empty."""
    if en:
        return cmd_check(name, [(where, en)], store=True)
    rows = load_tsv(name)
    if rows.pop(tuple(int(x) for x in where.split(":")), None) is None:
        sys.exit("%s %s: not translated" % (name, where))
    save_tsv(name, rows)
    print("%s %s removed" % (name, where))


def cmd_export(names: List[str]) -> None:
    """Write the Japanese message lists to _work/messages/<file>.txt (all files when none are named)."""
    os.makedirs(LIST_DIR, exist_ok=True)
    for name in names or sorted(REGIONS):
        found, done = messages_of(name), load_tsv(name)
        with open(os.path.join(LIST_DIR, name + ".txt"), "w", encoding="utf-8") as f:
            f.write("# %s: one message per line: ID, cells its text may take (2 letters each), Japanese, English so far\n" % name)
            for m in found:
                f.write("%d:%d\t%d\t%s\t%s\n" % (m["section"], m["offset"], room(m), m["ja"],
                                                 done.get((m["section"], m["offset"]), ("", ""))[1]))
        print("%-14s %4d messages, %d pieces, %d cells of text" % (name, len(found), sum(len(m["pieces"]) for m in found),
                                                               sum(len(t) for m in found for _, t, _ in m["pieces"])))


def cmd_merge() -> None:
    """Check all translation files and write _work/messages.json for the build; exits on the first problem."""
    entries = []
    names = sorted(fn[:-4] for fn in os.listdir(TSV_DIR) if fn.endswith(".tsv")) if os.path.isdir(TSV_DIR) else []
    for name in names:
        found = {(m["section"], m["offset"]): m for m in messages_of(name)}
        for key, (h, en) in sorted(load_tsv(name).items()):
            m = found.get(key)
            if m is None or text_hash(m["ja"]) != h:
                sys.exit("%s %d:%d: the original message changed or is gone" % ((name,) + key))
            errors, texts = judge(m, en)
            if errors:
                sys.exit("%s %d:%d: %s" % (name, key[0], key[1], "; ".join(errors)))
            entries.append({"file": name, "section": key[0], "offset": key[1], "texts": texts})
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    print("%d messages -> %s" % (len(entries), OUT_JSON))


def cmd_status() -> None:
    """Print translated / total messages per file."""
    for name in sorted(REGIONS):
        print("%-14s %5d / %d" % (name, len(load_tsv(name)), len(messages_of(name))))


def load_for_build() -> dict:
    """{module name: {(section, offset): (message, [text of each piece])}} from _work/messages.json, for the build."""
    out = collections.defaultdict(dict)
    if os.path.exists(OUT_JSON):
        with open(OUT_JSON, encoding="utf-8") as f:
            for e in json.load(f):
                found = {(m["section"], m["offset"]): m for m in messages_of(e["file"])}
                out[e["file"]][(e["section"], e["offset"])] = (found[(e["section"], e["offset"])], e["texts"])
    return out


# ── Command line ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """The argparse parser, one sub-command per step."""
    ap = argparse.ArgumentParser(prog="pp15 messages", description=__doc__.split("\n\n")[0],
                                 epilog="FILE is a module (pena_sub.rel, pn_fa.rel); ID is section:offset as in the export.")
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")
    p = sub.add_parser("export", help="messages to _work/messages/<file>.txt")
    p.add_argument("files", metavar="FILE", nargs="*", help="modules to export (default: all)")
    p = sub.add_parser("check", help='validate "ID<tab>English" lines from stdin, write nothing')
    p.add_argument("file", metavar="FILE")
    p = sub.add_parser("apply", help="the same check, then store the lines (nothing if one fails)")
    p.add_argument("file", metavar="FILE")
    p = sub.add_parser("set", help='the English of one message ("" removes it)')
    p.add_argument("file", metavar="FILE")
    p.add_argument("id", metavar="ID", help="section:offset")
    p.add_argument("text", metavar="TEXT")
    sub.add_parser("merge", help="translation/messages/*.tsv -> _work/messages.json, with checks")
    sub.add_parser("status", help="translated / total per file")
    return ap


def main(argv: Optional[List[str]] = None) -> None:
    """Entry point of `pp15 messages`; prints the help when no command is given."""
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
