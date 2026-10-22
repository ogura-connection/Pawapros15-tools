"""Find and decode the Success Mode story dialogue: the `pp15 scan` command (static analysis only, nothing is changed).

The story dialogue of Success Mode (the mode where you build a player through a story, see docs/GLOSSARY.md) is stored
inline in the script sections of scs_main.rel and scs_sce1/2/3.rel (Jikkyou Powerful Pro Yakyuu 15, Wii, RP5JA4, Rev 1).
An instruction whose low byte is 0x00 switches the game's script interpreter into text mode; the text that follows is
a stream of 12-bit glyph numbers (3 nibbles each), ended by 0xFFF and padded with 0xF nibbles to the next 16-bit
word. FINDINGS.md has the full write-up.

Commands (python3 -m pp15 scan COMMAND):
  extract   parse the scripts, count lines, verify byte-exact re-encoding (--dump writes all text to _work/)
  xref      show the machine-code evidence for the format (needs: pip install capstone)
  entropy   entropy map of the script modules and of the other game files
  scan      look for other packed-text stores and for compressed data

The file formats themselves are read by the modules next to this one:
  rel.py (REL modules), packed_text.py (12-bit text), scripts.py (Success Mode script), block_scripts.py (Eikan Nine,
  match lines, My Life), disassembly.py (`xref`), survey.py (`entropy`, `scan`).
Other tools import the reader names through this module (`from pp15.script import scan`): the lines below that import
them are that public interface, so they stay here.

Full text dumps are written only to _work/ (git-ignored). Never commit them.
"""
import argparse
import collections
import json
import os
import sys
from typing import Dict, List, Optional

from pp15 import config
from pp15.disc.extract_text import is_quality_text
from pp15.script.block_scripts import (BLOCK_SCRIPTS, BlockScript, ORE_ANNEX_MAGIC, ORE_ANNEX_MODULE, ORE_BLOCK,  # noqa: F401
                                       ORE_BLOCK_END, ORE_ELSE, ORE_IF, ORE_WINDOW, OreScript, load_block_scripts)
from pp15.script.disassembly import print_xref
from pp15.script.packed_text import (MAX_GLYPH, TEXT_END, TEXT_NEWLINE, decode_units, pack_text,  # noqa: F401
                                     unpack_text, units_valid)
from pp15.script.rel import R_END, R_NOP, R_SECTION, RELOC_NAMES, Rel, load_all_rels  # noqa: F401
from pp15.script.scripts import (LABEL_TABLES, OP_GOTO, OP_IF, OP_LEN, OP_NEWLINE, OP_NEWLINE_WAIT,  # noqa: F401
                                 OP_RETURN, OP_SKIPLIST, OP_TEXT, OP_WAIT, SCRIPT_FILES, Script,
                                 instruction_length, load_scripts)
from pp15.script.survey import find_packed_text, print_entropy_report, print_scan_report  # noqa: F401

# Paths, re-exported because many tools write `scan.WORK_DIR` / `scan.DATA_FILES`.
DATA_FILES = config.DATA_FILES
WORK_DIR = config.WORK_DIR

SAMPLE_MIN_UNITS, SAMPLE_MAX_UNITS = 6, 16     # a "sample line" is a short, clean-looking text run


def page_numbers(sc: Script) -> Dict[int, int]:
    """{halfword index of a text run: page number}, counting in address order; a page ends at each wait-for-button
    instruction."""
    page_of, page = {}, 0
    for i in sorted(k for k, v in sc.kind.items() if v == "op"):
        if i in sc.texts:
            page_of[i] = page
        elif sc.hw[i] & 0xFF in (OP_WAIT, OP_NEWLINE_WAIT):
            page += 1
    return page_of


def survey_script(sc: Script, want_dump: bool, samples: list, dump: list) -> dict:
    """Count the text runs of one parsed script; append sample lines to `samples` and, when want_dump, every run to
    `dump`. Returns the counts: runs, empty, glyphs, round trips that matched, invalid runs, control-unit Counter."""
    stats = {"runs": 0, "empty": 0, "glyphs": 0, "rt_ok": 0, "invalid": 0, "controls": collections.Counter()}
    page_of = page_numbers(sc)
    for i in sorted(sc.texts):
        window, units, j = sc.texts[i]
        stats["runs"] += 1
        if not units:
            stats["empty"] += 1
        stats["glyphs"] += sum(1 for u in units if u <= MAX_GLYPH)
        for u in units:
            if u > MAX_GLYPH:
                stats["controls"][u] += 1
        if list(sc.hw[i + 1:j]) == pack_text(units):
            stats["rt_ok"] += 1
        if not units_valid(units):
            stats["invalid"] += 1
            continue
        text = decode_units(units)
        if want_dump:
            dump.append({"file": sc.rel.name, "section": sc.sec, "file_offset": sc.offset_of(i),
                         "section_offset": i * 2, "page": page_of[i], "window": window,
                         "bytes": (j - i - 1) * 2,
                         "glyphs": len(units), "text": text})
        if SAMPLE_MIN_UNITS <= len(units) <= SAMPLE_MAX_UNITS and TEXT_NEWLINE not in units and is_quality_text(text):
            samples.append((sc.rel.name, sc.offset_of(i), text))
    return stats


def cmd_extract(args: argparse.Namespace) -> None:
    """Parse the four Success Mode scripts and print a table: labels, text runs, glyphs, pages, coverage and how many
    runs re-encode byte for byte."""
    scripts = load_scripts()
    tot = collections.Counter()
    samples, dump, spans = [], [], []
    print("%-13s %7s %7s %7s %8s %8s %9s %9s" % ("file", "labels", "runs", "empty", "glyphs",
                                                  "pages", "coverage", "roundtrip"))
    for sc in scripts:
        st = survey_script(sc, args.dump, samples, dump)
        runs, empty, glyphs, rt_ok = st["runs"], st["empty"], st["glyphs"], st["rt_ok"]
        pages = sc.op_count[OP_WAIT] + sc.op_count[OP_NEWLINE_WAIT]
        lo, hi = min(sc.kind), max(sc.kind) + 1
        cov = 100.0 * len(sc.kind) / (hi - lo)
        spans.append((sc.rel.name, sc.sec, sc.offset_of(lo), sc.offset_of(hi), lo * 2, hi * 2))
        print("%-13s %7d %7d %7d %8d %8d %8.1f%% %5d/%d" % (sc.rel.name, len(sc.labels), runs, empty,
                                                             glyphs, pages, cov, rt_ok, runs))
        if st["controls"]:
            print("    non-glyph units: " + ", ".join("0x%03X x%d" % kv for kv in st["controls"].most_common(8)))
        if st["invalid"] or sc.errors:
            print("    invalid runs: %d  parse notes: %s" % (st["invalid"], dict(sc.errors)))
        tot.update(runs=runs, empty=empty, glyphs=glyphs, pages=pages, rt=rt_ok)
    print("%-13s %7s %7d %7d %8d %8d %9s %5d/%d" % ("TOTAL", "", tot["runs"], tot["empty"], tot["glyphs"],
                                                    tot["pages"], "", tot["rt"], tot["runs"]))
    print("\nruns = text runs (one on-screen line each), pages = wait-for-button commands (0x49/0x4A)")
    print("labels = distinct script entry points, coverage = share of the script region reached\n")
    print("Script regions:")
    for name, sec, f0, f1, s0, s1 in spans:
        print("  %-13s sec%d+0x%06X..0x%06X  (file 0x%06X..0x%06X, %d KB)" % (name, sec, s0, s1, f0, f1, (s1 - s0) // 1024))

    if args.samples and samples:
        step = max(1, len(samples) // args.samples)
        print("\nSample lines (file, file offset, text):")
        for name, off, text in samples[step // 2::step][:args.samples]:
            print("  %-13s 0x%06X  %s" % (name, off, text))

    if args.dump:
        os.makedirs(WORK_DIR, exist_ok=True)
        path = os.path.join(WORK_DIR, "story_text.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(dump, f, ensure_ascii=False, indent=1)
        print("\nWrote %d runs to %s (git-ignored; do not commit)" % (len(dump), path))


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser: one sub-command per analysis."""
    ap = argparse.ArgumentParser(prog="pp15 scan", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("extract", help="parse scripts, count lines, verify re-encoding")
    p.add_argument("--samples", type=int, default=8, help="sample lines to print (default 8)")
    p.add_argument("--dump", action="store_true", help="write all text to _work/story_text.json")
    p.set_defaults(func=cmd_extract)
    p = sub.add_parser("xref", help="code evidence (needs capstone)")
    p.set_defaults(func=lambda args: print_xref())
    p = sub.add_parser("entropy", help="entropy map")
    p.add_argument("--top", type=int, default=5, help="high-entropy files to list per type")
    p.set_defaults(func=lambda args: print_entropy_report(args.top))
    p = sub.add_parser("scan", help="search all files for packed text and compressed data")
    p.add_argument("--all", action="store_true", help="include the sound/ directory (slow)")
    p.set_defaults(func=lambda args: print_scan_report(args.all))
    return ap


def main(argv: Optional[List[str]] = None) -> None:
    """Entry point of `pp15 scan`; needs the extracted game files in DATA/files."""
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return
    if not os.path.isdir(DATA_FILES):
        sys.exit("Game files not found at %s" % DATA_FILES)
    args.func(args)


if __name__ == "__main__":
    main()
