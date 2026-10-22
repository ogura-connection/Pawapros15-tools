"""Pitch names shown during a match: the name under the pitcher after a pitch ("ストレート 146 km/h") and on the pitch
selector (SLIDER, CURVE, FORK ...).

  pp15 kyu-names list    the 26 names: number, Japanese, English
  pp15 kyu-names check   does the English fit the block of the game file?

How the game stores them: they are not normal text. gameplay.rel section 5 offset 0x29CD4 holds 26 names, one byte
per letter, each closed by 0x7D, reached through a table of 26 pointers at section 5 offset 0x29DA8 (the pitch type is
the index; the code reads the table at section 1 offset 0x176A6). A byte is an index into a table of sprite pointers
that the game fills at run time (at 0x80A5CDB8 in a match): the sprites of gameplay.arc bank h3_kyu_0, the font of the
original-pitch names. The letters of that font, in byte order, are CODES: katakana, the long-vowel bar, digits,
capital A-Z and six kanji. There is no lower case and no punctuation: the English is written in capitals, "-" is drawn
with the long-vowel bar. The game draws MAX_LETTERS letters at most (9 sprite slots, 12 pixels apart: "DROP CURVE"
showed as "DROP CURV"), and a space leaves a gap wider than a letter.

The English is in translation/pitch_names.tsv (number, tab, English). The build lays the 26 names out again in their
212 bytes (a name that is the end of another shares its bytes: SLIDER in HARD SLIDER) and rewrites the 26 pointer
offsets of the table, as pp15/text/strings.py BLOCKS does for 16-bit strings.

Public functions: encode, decode (name <-> font codes), load_tsv, originals, layout (the new block), main.
"""
import argparse
import os
import sys
from typing import Dict, List, Optional, Tuple

from pp15 import config
from pp15.script import scan
from pp15.text import strings

TSV = os.path.join(config.TRANSLATION_DIR, "pitch_names.tsv")
END = 0x7D                      # closes a name in the game's block
MAX_LETTERS = 9                 # the match screen has nine letter slots
R_ADDR32 = 1                    # relocation type "write the 32-bit address of the target" (see docs/GLOSSARY.md)
CODES = (" ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾタダチヂッツヅテデトドナニヌネノハバパヒビピフブプヘベペホボポ"
         "マミムメモャヤュユョヨラリルレロワヲンヴー0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ号超真改魔球")   # letter of each font code
# Where the names are: module -> section, first byte of the names, end of the names, the pointer table, how many names
BLOCKS = {"gameplay.rel": {"section": 5, "start": 0x29CD4, "end": 0x29DA8, "table": 0x29DA8, "count": 26}}


def encode(text: str) -> bytes:
    """English -> font codes, without the end mark. Raises ValueError for a name longer than MAX_LETTERS or with a
    character the pitch-name font does not have (it has A-Z, 0-9, space and "-")."""
    out = []
    if len(text) > MAX_LETTERS:
        raise ValueError("%r: the game draws %d letters at most" % (text, MAX_LETTERS))
    for ch in text.upper().replace("-", "ー"):
        if ch not in CODES:
            raise ValueError("%r: the pitch-name font has no %r (A-Z, 0-9, space and - only)" % (text, ch))
        out.append(CODES.index(ch))
    return bytes(out)


def decode(data: bytes) -> str:
    """Font codes -> text; a code outside the font is written as {XX}."""
    return "".join(CODES[b] if b < len(CODES) else "{%02X}" % b for b in data)


def table(rel, blk: dict) -> Dict[int, int]:
    """The pointer table of the block: {position of a pointer in its section: offset it points at}, in table order.
    `rel` is the original module (a scan.Rel). Exits with a message if the table is not what is expected."""
    sec = blk["section"]
    pointers = {pos: addend for s, pos, typ, mod, tsec, addend in rel.relocs()
                if s == sec and blk["table"] <= pos < blk["table"] + 4 * blk["count"]
                and (typ, mod, tsec) == (R_ADDR32, rel.mod_id, sec)}
    if len(pointers) != blk["count"] or not all(blk["start"] <= a < blk["end"] for a in pointers.values()):
        sys.exit("%s: the pitch-name table at sec%d+0x%X is not as expected" % (rel.name, sec, blk["table"]))
    return dict(sorted(pointers.items()))


def originals(rel, blk: dict) -> List[bytes]:
    """The Japanese names of the block in table order, as font-code bytes (without the end mark)."""
    data = rel.sec_data(blk["section"])
    return [data[a:data.index(END, a)] for a in table(rel, blk).values()]


def load_tsv() -> Dict[int, str]:
    """Read translation/pitch_names.tsv. Returns {number: English}; empty if the file does not exist."""
    out = {}
    if os.path.exists(TSV):
        with open(TSV, encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    number, english = line.rstrip("\n").split("\t")
                    out[int(number)] = english
    return out


def layout(rel, blk: dict, english: Dict[int, str]) -> Tuple[bytes, Dict[int, int], Dict[int, bytes]]:
    """Lay the 26 names out again in the block (names that end alike share bytes).

    Arguments: the original module `rel`, its entry of BLOCKS, `english` from load_tsv() (a number without English
    keeps its Japanese name). Returns (the bytes of the block, {pointer position: new pointer offset}, {new offset:
    the bytes it must read}). Raises ValueError if the names need more bytes than the block has."""
    pointers = table(rel, blk)
    sequences = [encode(english[i]) if english.get(i) else old for i, old in enumerate(originals(rel, blk))]
    starts, used = strings.block_layout([tuple(s) for s in sequences])
    room = blk["end"] - blk["start"]
    if used > room:
        raise ValueError("%s: the pitch names need %d bytes, the block has %d" % (rel.name, used, room))
    block = bytearray(room)
    for a, s in zip(starts, sequences):
        block[a:a + len(s) + 1] = s + bytes([END])
    addends = {pos: blk["start"] + a for pos, a in zip(pointers, starts)}
    return bytes(block), addends, {blk["start"] + a: s for a, s in zip(starts, sequences)}


def load_module(name: str):
    """The original (untouched) game module `name` from _work/orig, as a scan.Rel."""
    return scan.Rel(os.path.join(config.ORIG_DIR, name))


def list_names() -> None:
    """Print number, Japanese and English of every pitch name (English blank if not translated yet)."""
    english = load_tsv()
    for name, blk in BLOCKS.items():
        for i, old in enumerate(originals(load_module(name), blk)):
            print("%2d\t%s\t%s" % (i, decode(old), english.get(i, "")))


def check_names() -> None:
    """Print how many names have English and how many bytes of the block they use. Raises if they do not fit."""
    english = load_tsv()
    for name, blk in BLOCKS.items():
        rel = load_module(name)
        layout(rel, blk, english)                       # raises ValueError if the names do not fit
        used = strings.block_layout([tuple(encode(english[i]) if english.get(i) else o)
                                     for i, o in enumerate(originals(rel, blk))])[1]
        print("%s: %d of %d names in English, %d of %d bytes used"
              % (name, len(english), blk["count"], used, blk["end"] - blk["start"]))


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 kyu-names list|check`. `argv` defaults to sys.argv[1:]; with no command the help is printed."""
    parser = argparse.ArgumentParser(prog="pp15 kyu-names", description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.add_parser("list", help="the names: number, Japanese, English").set_defaults(function=list_names)
    sub.add_parser("check", help="does the English fit the block?").set_defaults(function=check_names)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.command is None:
        parser.print_help()
        return
    args.function()


if __name__ == "__main__":
    main()
