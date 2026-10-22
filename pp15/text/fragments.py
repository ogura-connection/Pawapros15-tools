"""Fragments: pieces of Japanese text that no string slot covers, written over in place.

What it is for: the string finder (slot_finder.py) only sees runs of plain glyphs closed by 0xFFFF. Some text is laid
out differently: help pages cut into many short pieces, a coloured label inside the same string as a sentence, lines
closed by 0x1FFF or by a blank cell. Untranslated, such text now draws letter pairs where its kanji were, because the
pair font took those kanji slots. A fragment names one such piece by its place in the original module; the build
writes the English into exactly the cells the Japanese took, pads it with glyph 0 and keeps the colour of the original
units (the top four bits), so nothing around it moves.

Translation files: translation/fragments/<module>.tsv, one line per fragment:
    section, offset (bytes in the section), cells, colour (0 = none), hash of the original Japanese, English
The hash is checked against the original module, so a fragment can never land on other bytes.

Public names: TSV_DIR, japanese(units), load_for_build(orig), save(name, rows).
"""
import os
import struct
from typing import Dict, Iterable, Sequence, Tuple

from pp15 import config
from pp15.glyphs import glyph_to_char
from pp15.text.tsv_store import read_rows, text_hash, write_rows

TSV_DIR = os.path.join(config.TRANSLATION_DIR, "fragments")
TSV_HEADER = "# section\toffset\tcells\tcolour\thash of the original Japanese\tEnglish (see pp15/text/fragments.py)\n"
GLYPH_BITS = 0xFFF          # a unit's low 12 bits are the glyph number, the top four bits its colour
COLOUR_SHIFT = 12


def japanese(units: Sequence[int]) -> str:
    """The characters of the units, colour bits ignored (glyph 0, the padding, reads as a full-width space)."""
    return "".join(glyph_to_char(u & GLYPH_BITS) or "?" for u in units)


def load_for_build(orig: dict) -> Dict[str, Dict[Tuple[int, int], Tuple[int, int, str]]]:
    """{module name: {(section, offset): (cells, colour, English)}} from translation/fragments/*.tsv.

    `orig` = the original modules ({id: Rel}). Raises ValueError when a fragment's original units do not match its
    hash or the English is empty."""
    out: Dict[str, Dict[Tuple[int, int], Tuple[int, int, str]]] = {}
    if not os.path.isdir(TSV_DIR):
        return out
    modules = {m.name: m for m in orig.values()}
    for filename in sorted(os.listdir(TSV_DIR)):
        if not filename.endswith(".tsv"):
            continue
        name = filename[:-4]
        if name not in modules:
            raise ValueError("%s: no module %s" % (filename, name))
        data = modules[name].sec_data
        for sec, off, cells, colour, digest, english in read_rows(os.path.join(TSV_DIR, filename), 6):
            sec, off, cells, colour = int(sec), int(off), int(cells), int(colour)
            units = struct.unpack(">%dH" % cells, data(sec)[off:off + 2 * cells])
            if text_hash(japanese(units)) != digest:
                raise ValueError("%s %d:%d: the original is not the Japanese this fragment was made for" % (name, sec, off))
            if not english.strip():
                raise ValueError("%s %d:%d: empty English" % (name, sec, off))
            out.setdefault(name, {})[(sec, off)] = (cells, colour, english)
    return out


def save(name: str, rows: Iterable[Sequence]) -> None:
    """Write translation/fragments/<name>.tsv from rows (section, offset, cells, colour, hash, English)."""
    write_rows(os.path.join(TSV_DIR, name + ".tsv"), TSV_HEADER, sorted(rows, key=lambda r: (int(r[0]), int(r[1]))))
