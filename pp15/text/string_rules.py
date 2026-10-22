"""The rules an English string must meet to fit its slot, and the check of a list of "ID<tab>English" lines.

`judge` is the single place where the rules live; `check`, `apply`, `merge` and the build all call it so that they
agree. The rules differ by kind of string:
  * slot string        lines (written `|`) must fit the cells of each line of the slot (line_layout.py);
  * main.dol dialog    one line, same number of `{}`, within the limits of dol_dialogs.py;
  * movable block      one line no wider than the column (movable_blocks.py);
  * help text          explicit line breaks, no line more than 4 cells wider than the longest Japanese line.
Every character must be ASCII or a character the font has (docs/GLOSSARY.md, "Glyph").

Public names: judge(s, en, longest), check_rows(name, pairs), read_pairs(), too_long, pad_line.
"""
import re
import sys
from typing import Callable, List, Tuple

from pp15.glyphs import char_to_glyph
from pp15.text.colour_text import colour_runs, letters
from pp15.text.dol_dialogs import dol_cells, dol_fit
from pp15.text.line_layout import line_caps
from pp15.text.movable_blocks import block_fit
from pp15.text.slot_finder import strings_of
from pp15.text.string_tables import BLOCKS, DOL, DOL_OVER
from pp15.text.string_tsv import load_tsv

ASCII_PRINTABLE = "".join(map(chr, range(0x20, 0x7F)))
HELP_EXTRA_CELLS = 4        # a help line may be this much wider than the longest Japanese line


def too_long(line: str, cap: int, count: Callable[[str], int] = letters) -> int:
    """How many letters a line is over its capacity of `cap` cells (0 = it fits)."""
    if line.isascii() and "{" not in line:
        return max(0, len(line) - cap * 2)
    return max(0, (count(line) - cap) * 2)


def pad_line(line: str, width: int) -> str:
    """A line filled up with spaces to `width` cells (the game wraps by position, so every line but the last must be
    padded)."""
    last = colour_runs(line)[-1][1]                     # the letter pairs start again in every coloured run
    tail = len(last) - len(last.rstrip(ASCII_PRINTABLE))
    line += " " * (tail % 2)
    return line + "  " * (width - letters(line))


def _judge_dol(s: dict, en: str, lines: List[str], longest: int) -> Tuple[List[str], List[str], str]:
    errors, warnings = [], []
    if len(lines) > 1:
        errors.append("%d lines, a dialog string is one line" % len(lines))
    if en.count("{}") != s["ctrl"]:
        errors.append("%d {} in the English, %d in the Japanese" % (en.count("{}"), s["ctrl"]))
    cells = dol_cells(en)
    if s["fixed"] and cells > s["cells"]:
        errors.append("%d letters too long: this string cannot move and holds %d cells (%d letters)"
                      % (too_long(en, s["cells"], dol_cells), s["cells"], (s["cells"] - s["ctrl"]) * 2))
    elif cells > longest:
        errors.append("%d letters too long: a line holds at most %d cells (%d letters), the longest "
                      "Japanese line" % (too_long(en, longest, dol_cells), longest, (longest - s["ctrl"]) * 2))
    elif cells > s["cells"] + DOL_OVER:
        warnings.append("%d cells, the Japanese has %d: the dialog box may be too narrow"
                        % (cells, s["cells"]))
    return errors, warnings, en


def _judge_block(s: dict, en: str, lines: List[str]) -> Tuple[List[str], List[str], str]:
    errors = []
    if len(lines) > 1:
        errors.append("%d lines, an entry of this list is one line" % len(lines))
    elif letters(en) > s["block"]["max"]:
        errors.append("%d letters too long: an entry holds at most %d cells (%d letters)"
                      % (too_long(en, s["block"]["max"]), s["block"]["max"], s["block"]["max"] * 2))
    return errors, [], en


def _judge_help(s: dict, en: str, lines: List[str]) -> Tuple[List[str], List[str], str]:
    errors = []
    jl = [re.sub(r"\{\d+:|\}", "", line) for line in s["text"].split("|")]
    width = max(len(line) for line in jl)            # the longest Japanese line, in cells
    if len(lines) > len(jl):
        errors.append("%d lines, the Japanese has %d" % (len(lines), len(jl)))
    need = len(lines) - 1
    for k, line in enumerate(lines):
        n = sum(-(-len(part) // 2) for _, part in colour_runs(line))
        need += n
        if n > width + HELP_EXTRA_CELLS:
            errors.append("line %d is %d cells, the longest Japanese line is %d" % (k + 1, n, width))
    if need > s["cells"]:
        errors.append("%d cells, the slot holds %d" % (need, s["cells"]))
    return errors, [], "\n".join(lines)


def judge(s: dict, en: str, longest: int = 0) -> Tuple[List[str], List[str], str]:
    """Check the English `en` for string `s` (a dict of strings_of()).

    longest = for main.dol, the longest Japanese line of the block. Returns (errors, warnings, the English as the
    build takes it): for a multi-line slot string the lines are padded to the line width."""
    warnings: List[str] = []
    if not en.strip():
        return ["empty English"], warnings, en
    bad = sorted({c for c in en if not 0x20 <= ord(c) <= 0x7E and char_to_glyph(c) is None})
    if bad or "\\n" in en:
        errors = ["the font cannot draw %s" % " ".join(["%r" % c for c in bad] + ["\\n"] * ("\\n" in en))]
        return errors, warnings, en
    lines = en.split("|")
    if "fixed" in s:                                    # main.dol: one line, no slot
        return _judge_dol(s, en, lines, longest)
    if s.get("block"):                                  # a string the build moves: one line, no slot
        return _judge_block(s, en, lines)
    if s.get("help"):                                   # explicit line breaks (HELP_NL) in a slot of s["cells"] units
        return _judge_help(s, en, lines)
    errors = []
    caps = line_caps(s)
    if len(lines) > len(caps):
        errors.append("%d lines, the slot has %d (%s letters)"
                      % (len(lines), len(caps), "|".join(str(c * 2) for c in caps)))
        return errors, warnings, en
    for k, (line, cap) in enumerate(zip(lines, caps)):
        if too_long(line, cap):
            errors.append("line %d is %d letters too long (%d, it holds %d): %r"
                          % (k + 1, too_long(line, cap), len(line), cap * 2, line))
    if errors:
        return errors, warnings, en
    return errors, warnings, "".join(pad_line(line, s["width"]) for line in lines[:-1]) + lines[-1]


def check_rows(name: str, pairs: List[Tuple[str, str]]):
    """Check "ID, English" pairs for module `name`.

    Returns (found, good, problems, warnings): found = {(section, offset): string} of the module, good = {(section,
    offset): English} of the rows without errors, problems and warnings = lists of "ID: text". For main.dol and
    for modules with movable blocks it also checks that the whole block still holds everything."""
    strs = strings_of(name)
    found = {(s["section"], s["offset"]): s for s in strs}
    longest = max(s["cells"] for s in strs) if name == DOL else 0
    good, seen, problems, warnings = {}, set(), [], []
    for where, en in pairs:
        try:
            sec, off = (int(x) for x in where.split(":"))
        except ValueError:
            problems.append("%s: not an ID (section:offset)" % where)
            continue
        s = found.get((sec, off))
        if s is None:
            problems.append("%s: unknown ID" % where)
        elif (sec, off) in seen:
            problems.append("%s: duplicate ID" % where)
        else:
            seen.add((sec, off))
            errors, warns, _ = judge(s, en, longest)
            problems += ["%s: %s" % (where, e) for e in errors]
            warnings += ["%s: warning: %s" % (where, w) for w in warns]
            if not errors:
                good[(sec, off)] = en
    if name == DOL:                         # does the block still hold everything?
        english = {key: en for key, (_, en) in load_tsv(name).items()}
        english.update(good)
        problems += dol_fit(strs, english)
    elif name in BLOCKS:
        english = {key: en for key, (_, en) in load_tsv(name).items()}
        english.update(good)
        problems += block_fit(name, strs, english)
    return found, good, problems, warnings


def read_pairs() -> List[Tuple[str, str]]:
    """The "ID<tab>English" lines on standard input as (ID, English); a line without a tab is an ID with no English.
    Blank lines and lines starting with # are skipped."""
    pairs = []
    for line in sys.stdin:
        line = line.rstrip("\n")
        if line.strip() and not line.startswith("#"):
            pairs.append(tuple(line.split("\t", 1)) if "\t" in line else (line.strip(), ""))
    return pairs
