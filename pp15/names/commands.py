"""The `pp15 names` command: write the name files from the game, or check the English names against the game's limits.

    pp15 names export          write translation/names/surnames.tsv (keeps English already there)
    pp15 names check           lengths, short forms and the patch sites of the original modules (changes nothing)
    pp15 names export-given | export-draft | export-holders | export-foreign
                               write translation/names/in_place/<module>.tsv (see pp15/names/export_tsv.py: they
                               overwrite the checked-in files, look at `git diff` afterwards)

Public function: main(argv).
"""
import argparse
import os
import sys
from typing import List, Optional

from pp15 import config
from pp15.names import export_tsv, table
from pp15.script import scan


def check_names() -> None:
    """Print how many surnames are too long or not plain ASCII, how many need a short form in main_prg.rel, and how
    many words are patched in each module that reads the list. Changes no file."""
    names = table.load_tsv()
    bad = [(i, english) for i, (_, english) in names.items() if not table.letters_ok(english)]
    too_long_for_short = [english for _, english in names.values() if len(english) > 2 * table.SHORT_CELLS]
    stay_kanji = [english for english in too_long_for_short if table.short_form(english) is None]
    print("%d names, %d too long or not plain ASCII: %s" % (len(names), len(bad), bad[:20]))
    print("main_prg.rel (8 letters): %d use a short form, %d stay kanji: %s"
          % (len(too_long_for_short) - len(stay_kanji), len(stay_kanji), stay_kanji))
    host = scan.Rel(os.path.join(config.ORIG_DIR, table.HOST))
    for filename in table.READERS:
        rel = scan.Rel(os.path.join(config.ORIG_DIR, filename))
        print("  %-13s %d words patched" % (filename, len(table.code_patches(rel, host.mod_id))))


def build_parser() -> argparse.ArgumentParser:
    """The argument parser: one sub-command per action."""
    parser = argparse.ArgumentParser(prog="pp15 names", description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    for name, function, text in (
            ("export", export_tsv.export_surnames,
             "write translation/names/surnames.tsv from _work/surnames.json (English already there is kept)"),
            ("check", check_names,
             "check name lengths, short forms and the patch sites of the original modules; changes no file"),
            ("export-given", export_tsv.export_given_names,
             "write in_place/main_prg.rel.tsv: the 200 given names (overwrites the checked-in file)"),
            ("export-draft", export_tsv.export_draft_prospects,
             "write in_place/draft.rel.tsv: the 2,000 draft prospects (overwrites the checked-in file)"),
            ("export-holders", export_tsv.export_record_holders,
             "write in_place/pn_ore_i.rel.tsv: the record holders (overwrites the checked-in file)"),
            ("export-foreign", export_tsv.export_foreign_players,
             "write in_place/pennant.rel.tsv and scc_main.rel.tsv: the foreign players (overwrites the checked-in files)")):
        sub.add_parser(name, help=text, description=text).set_defaults(function=function)
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 names COMMAND`. `argv` defaults to sys.argv[1:]."""
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    args.function()


if __name__ == "__main__":
    main()
