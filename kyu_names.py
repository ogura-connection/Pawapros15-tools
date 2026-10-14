#!/usr/bin/env python3
"""Pitch names of a match: the name under the pitcher after a pitch ("ストレート 146 km/h") and on the pitch
selector.

  kyu_names.py list      the names: number, Japanese, English
  kyu_names.py check     does the English fit the block

They are not glyph strings. gameplay.rel sec5+0x29CD4 holds 26 names, one byte per letter, each closed by
0x7D, reached through a table of 26 R_PPC_ADDR32 at sec5+0x29DA8 (the pitch type is the index; the code
reads the table at sec1+0x176A6). A byte is an index into a table of sprite pointers that the game
fills at run time (at 0x80A5CDB8 in a match): the sprites of gameplay.arc bank h3_kyu_0, the font of
the original-pitch names. Its letters, in byte order, are CODES: katakana, the long-vowel bar, digits,
capital A-Z and six kanji. There is no lower case and no punctuation: the English is written in capitals,
"-" is drawn with the long-vowel bar. The game draws MAX_LETTERS letters at most (9 sprite slots, 12 pixels
apart: "DROP CURVE" showed as "DROP CURV"), and a space leaves a gap wider than a letter.

The English is in translation/pitch_names.tsv (number, tab, English). The build lays the 26 names out
again in their 212 bytes (a name that is the end of another shares its bytes: SLIDER in HARD SLIDER) and
rewrites the 26 addends of the table, as ui_strings.BLOCKS does for 16-bit strings.
"""
import os
import struct
import sys

import ui_strings

HERE = os.path.dirname(os.path.abspath(__file__))
TSV = os.path.join(HERE, "translation", "pitch_names.tsv")
END = 0x7D
MAX_LETTERS = 9
CODES = (" ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾタダチヂッツヅテデトドナニヌネノハバパヒビピフブプヘベペホボポ"
         "マミムメモャヤュユョヨラリルレロワヲンヴー0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ号超真改魔球")
BLOCKS = {"gameplay.rel": {"section": 5, "start": 0x29CD4, "end": 0x29DA8, "table": 0x29DA8, "count": 26}}


def encode(text):
    """English -> bytes (without the end mark)."""
    out = []
    if len(text) > MAX_LETTERS:
        raise ValueError("%r: the game draws %d letters at most" % (text, MAX_LETTERS))
    for ch in text.upper().replace("-", "ー"):
        if ch not in CODES:
            raise ValueError("%r: the pitch-name font has no %r (A-Z, 0-9, space and - only)" % (text, ch))
        out.append(CODES.index(ch))
    return bytes(out)


def decode(data):
    return "".join(CODES[b] if b < len(CODES) else "{%02X}" % b for b in data)


def table(m, blk):
    """{position of a pointer in its section: addend}, in table order."""
    sec = blk["section"]
    t = {pos: addend for s, pos, typ, mod, tsec, addend in m.relocs()
         if s == sec and blk["table"] <= pos < blk["table"] + 4 * blk["count"] and (typ, mod, tsec) == (1, m.mod_id, sec)}
    if len(t) != blk["count"] or not all(blk["start"] <= a < blk["end"] for a in t.values()):
        sys.exit("%s: the pitch-name table at sec%d+0x%X is not as expected" % (m.name, sec, blk["table"]))
    return dict(sorted(t.items()))


def originals(m, blk):
    """The Japanese names in table order, as bytes."""
    d = m.sec_data(blk["section"])
    return [d[a:d.index(END, a)] for a in table(m, blk).values()]


def load_tsv():
    """{number: English}"""
    out = {}
    if os.path.exists(TSV):
        with open(TSV, encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    n, en = line.rstrip("\n").split("\t")
                    out[int(n)] = en
    return out


def layout(m, blk, english):
    """(the bytes of the block, {pointer position: new addend}, {new addend: the bytes it must read})."""
    t = table(m, blk)
    seqs = [encode(english[i]) if english.get(i) else old for i, old in enumerate(originals(m, blk))]
    starts, used = ui_strings.block_layout([tuple(s) for s in seqs])
    room = blk["end"] - blk["start"]
    if used > room:
        raise ValueError("%s: the pitch names need %d bytes, the block has %d" % (m.name, used, room))
    out = bytearray(room)
    for a, s in zip(starts, seqs):
        out[a:a + len(s) + 1] = s + bytes([END])
    addends = {pos: blk["start"] + a for pos, a in zip(t, starts)}
    return bytes(out), addends, {blk["start"] + a: s for a, s in zip(starts, seqs)}


def load_module(name):
    import rebuild_scripts as R
    return next(m for m in R.load_dir(R.ORIG_DIR).values() if m.name == name)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    english = load_tsv()
    for name, blk in BLOCKS.items():
        m = load_module(name)
        if cmd == "list":
            for i, old in enumerate(originals(m, blk)):
                print("%2d\t%s\t%s" % (i, decode(old), english.get(i, "")))
        elif cmd == "check":
            data, addends, reads = layout(m, blk, english)
            used = ui_strings.block_layout([tuple(encode(english[i]) if english.get(i) else o)
                                            for i, o in enumerate(originals(m, blk))])[1]
            print("%s: %d of %d names in English, %d of %d bytes used"
                  % (name, len(english), blk["count"], used, blk["end"] - blk["start"]))
        else:
            print(__doc__)
            return


if __name__ == "__main__":
    main()
