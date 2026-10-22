"""Message scripts: UI text that is a small script, not a fixed slot (the news of Pennant).

  pp15 messages export [FILE ...]   messages to _work/messages/<file>.txt
  pp15 messages check FILE          validate "ID<tab>English" lines from stdin, write nothing
  pp15 messages apply FILE          the same check, then store the lines (nothing if one fails)
  pp15 messages set FILE ID TEXT    the English of one message ("" removes it)
  pp15 messages merge               translation/messages/*.tsv -> _work/messages.json, with checks
  pp15 messages status              translated / total per file

A message is a run of pieces. A piece is: control codes, the unit 0, text, 0xFFFF. The codes seen:
1 new line, 7 new page (the reader presses a button), 0x60 to 0x9F an inserted value (club, player
name, number: which one shows from the Japanese behind it), and 0xF (pena_sub.rel) or 8 (pn_fa.rel)
after the last piece: the end. Only the start of a message has a pointer (two tables of
R_PPC_ADDR32 in pena_sub.rel), so the game reads a message piece after piece and the pieces of one
message can be of any length, as long as the message still ends before the next pointer target.

A message is written as one line: the text of its pieces with a tag for the codes in front of each
piece: {n} new line, {p} new page, {66} the insert 0x66, {+} a piece with no code. The English has
the same tags in the same order; what stands between them is free. Two letters take one cell and
the letter pairs start again in every piece, so a piece with an odd number of letters wastes half a
cell. {*6} in front of a text is its colour and stays, like the other tags. ID is section:offset of the pointer target. REGIONS lists where messages are; a span between
two pointer targets that does not parse as pieces is left alone.
"""
import collections
import json
import os
import re
import struct
import sys

from pp15 import config
from pp15.glyphs import char_to_glyph, glyph_to_char
from pp15.script import scan as S
from pp15.text import strings as U

TSV_DIR = os.path.join(config.TRANSLATION_DIR, "messages")
LIST_DIR = os.path.join(config.WORK_DIR, "messages")
OUT_JSON = os.path.join(config.WORK_DIR, "messages.json")
END = 0xFFFF
# file -> [(section, first offset, end offset)]
REGIONS = {"pena_sub.rel": [(5, 110900, 130016)], "pn_fa.rel": [(5, 6584, 6976)]}
CODES = {1: "n", 7: "p"}
STOP = (0xF, 8)             # ends a message; kept where it is, never written by a translator
TAG = re.compile(r"\{([0-9a-f]{2}|[np+]|\*[0-9a-f])\}")
LINE = 40                   # letters of a line of the news box (the longest Japanese lines), see width()


def is_code(u):
    return u in CODES or u in STOP or 0x60 <= u < 0xA0


def anchors(rel, mods, sec):
    out = set()
    for m in mods.values():
        for _, _, _, tm, ts, addend in m.relocs():
            if tm == rel.mod_id and ts == sec:
                out.add(addend)
    return sorted(out)


def parse(units):
    """([(codes, text units, colour)], trailer, kind) or None when the span is not a message.
    kind "end": every piece is closed by 0xFFFF and the trailer holds the stop code. kind "stop":
    one piece closed by the stop code itself ("0 name F"). colour = the top four bits of the units
    of a piece (0x6000 and 0x2000 mark the lines about the number of fans)."""
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
        colour = {u >> 12 for u in text}
        if len(colour) > 1 or any(u & 0xFFF > S.MAX_GLYPH for u in text):
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
        if j + 2 < len(trailer) and trailer[j] == 0 and trailer[-1] in STOP and all(u <= S.MAX_GLYPH for u in text):
            return [(tuple(trailer[:j]), tuple(text), 0)], (trailer[-1],), "stop"
        return None
    if any(not is_code(u) for u in trailer):
        return None
    return pieces, tuple(trailer), "end"


def tags(k, codes, colour):
    """The tags in front of the text of piece k."""
    out = ["{%s}" % CODES.get(c, "%02x" % c) for c in codes] + (["{*%x}" % colour] if colour else [])
    return out or (["{+}"] if k else [])


def form(pieces, text_of):
    return "".join("".join(tags(k, codes, colour)) + text_of(units) for k, (codes, units, colour) in enumerate(pieces))


def japanese(units):
    return "".join(glyph_to_char(u) or "?" for u in units)


_cache = {}


def messages_of(name, mods=None):
    """[{"section", "offset", "cells" (of the span), "pieces", "trailer", "kind", "ja"}]"""
    if name in _cache:
        return _cache[name]
    mods = mods or U.load_mods()
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
    _cache[name] = out
    return out


def room(msg):
    """Cells the text of all pieces may take together."""
    fixed = sum(len(c) + 2 for c, _, _ in msg["pieces"]) + len(msg["trailer"])
    if msg["kind"] == "stop":
        fixed -= 1                          # no 0xFFFF: the stop code closes the text
    return msg["cells"] - fixed


def width(line):
    """Letters a line takes on screen: its text, 8 for an inserted name or club, 4 for a number."""
    n = len(TAG.sub("", line))
    for m in TAG.finditer(line):
        if len(m.group(1)) == 2 and m.group(1)[0] != "*":
            n += 8 if 0x60 <= int(m.group(1), 16) <= 0x6B else 4
    return n


def judge(msg, en):
    """(errors, [text of each piece])"""
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
    need = sum(U.letters(x) for x in texts)
    if need > room(msg):
        errors.append("%d letters too long: the pieces take %d cells, the message holds %d"
                      % ((need - room(msg)) * 2, need, room(msg)))
    for line in re.split(r"\{[np]\}", en):
        if width(line) > LINE:
            errors.append("a line is %d letters too wide (%d of %d, a name or club counts 8, a number 4): %r"
                          % (width(line) - LINE, width(line), LINE, line))
    return errors, texts


def encode(msg, texts, encode_text):
    """The units of the whole span with English text. encode_text(text) -> glyph units."""
    out = []
    for (codes, _, colour), text in zip(msg["pieces"], texts):
        units = [u | colour << 12 for u in encode_text(text)] if text else []
        out += list(codes) + [0] + units + ([END] if msg["kind"] == "end" else [])
    out += list(msg["trailer"])
    if len(out) > msg["cells"]:
        raise ValueError("message %d:%d does not fit" % (msg["section"], msg["offset"]))
    return out + [0] * (msg["cells"] - len(out))


def load_tsv(name):
    rows = {}
    path = os.path.join(TSV_DIR, name + ".tsv")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    sec, off, h, en = line.rstrip("\n").split("\t", 3)
                    rows[(int(sec), int(off))] = (h, en)
    return rows


def save_tsv(name, rows):
    os.makedirs(TSV_DIR, exist_ok=True)
    with open(os.path.join(TSV_DIR, name + ".tsv"), "w", encoding="utf-8") as f:
        f.write("# section\toffset\thash of the original message\tEnglish (see ui_messages.py)\n")
        for key in sorted(rows):
            f.write("%d\t%d\t%s\t%s\n" % (key + rows[key]))


def check_rows(name, pairs):
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


def cmd_check(name, pairs, store=False):
    found, good, problems = check_rows(name, pairs)
    for line in problems:
        print(line)
    if problems:
        print("%s: %d problems in %d lines%s" % (name, len(problems), len(pairs), ", nothing stored" if store else ""))
        sys.exit(1)
    if store:
        rows = load_tsv(name)
        for key, en in good.items():
            rows[key] = (U.text_hash(found[key]["ja"]), en)
        save_tsv(name, rows)
        print("%s: %d lines stored, %d of %d messages translated" % (name, len(pairs), len(rows), len(found)))
    else:
        print("%s: %d lines, no problems" % (name, len(pairs)))


def cmd_set(name, where, en):
    if en:
        return cmd_check(name, [(where, en)], store=True)
    rows = load_tsv(name)
    if rows.pop(tuple(int(x) for x in where.split(":")), None) is None:
        sys.exit("%s %s: not translated" % (name, where))
    save_tsv(name, rows)
    print("%s %s removed" % (name, where))


def cmd_export(names):
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


def cmd_merge():
    entries = []
    names = sorted(fn[:-4] for fn in os.listdir(TSV_DIR) if fn.endswith(".tsv")) if os.path.isdir(TSV_DIR) else []
    for name in names:
        found = {(m["section"], m["offset"]): m for m in messages_of(name)}
        for key, (h, en) in sorted(load_tsv(name).items()):
            m = found.get(key)
            if m is None or U.text_hash(m["ja"]) != h:
                sys.exit("%s %d:%d: the original message changed or is gone" % ((name,) + key))
            errors, texts = judge(m, en)
            if errors:
                sys.exit("%s %d:%d: %s" % (name, key[0], key[1], "; ".join(errors)))
            entries.append({"file": name, "section": key[0], "offset": key[1], "texts": texts})
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    print("%d messages -> %s" % (len(entries), OUT_JSON))


def load_for_build():
    """{module name: {(section, offset): (message, [text of each piece])}} from _work/messages.json."""
    out = collections.defaultdict(dict)
    if os.path.exists(OUT_JSON):
        with open(OUT_JSON, encoding="utf-8") as f:
            for e in json.load(f):
                found = {(m["section"], m["offset"]): m for m in messages_of(e["file"])}
                out[e["file"]][(e["section"], e["offset"])] = (found[(e["section"], e["offset"])], e["texts"])
    return out


def main(argv=None):
    a = sys.argv[1:] if argv is None else list(argv)
    if a[:1] == ["export"]:
        cmd_export(a[1:])
    elif a[:1] == ["set"] and len(a) == 4:
        cmd_set(a[1], a[2], a[3])
    elif a[:1] in (["check"], ["apply"]) and len(a) == 2:
        cmd_check(a[1], U.read_pairs(), store=a[0] == "apply")
    elif a[:1] == ["merge"]:
        cmd_merge()
    elif a[:1] == ["status"]:
        for name in sorted(REGIONS):
            print("%-14s %5d / %d" % (name, len(load_tsv(name)), len(messages_of(name))))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
