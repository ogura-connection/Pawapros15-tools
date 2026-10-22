"""The translation files of the fixed-slot strings: translation/strings/<module>.tsv.

One line per translated string: section, offset, a fingerprint of the Japanese, the English (see tsv_store.py for the
shared format). The English may use `|` for a line break and `{c:text}` for a coloured run.

Public names: TSV_DIR, load_tsv(name), save_tsv(name, rows), text_hash.
"""
import os
from typing import Dict, Tuple

from pp15 import config
from pp15.text.tsv_store import read_rows, text_hash, write_rows  # noqa: F401  (text_hash is part of this module's interface)

TSV_DIR = os.path.join(config.TRANSLATION_DIR, "strings")
TSV_HEADER = "# section\toffset\thash of the original string\tEnglish (see ui_strings.py)\n"


def load_tsv(name: str) -> Dict[Tuple[int, int], Tuple[str, str]]:
    """{(section, offset): (hash of the original, English)} for module `name`; empty when it has no file yet."""
    rows = read_rows(os.path.join(TSV_DIR, name + ".tsv"), 4)
    return {(int(sec), int(off)): (h, en) for sec, off, h, en in rows}


def save_tsv(name: str, rows: Dict[Tuple[int, int], Tuple[str, str]]) -> None:
    """Write translation/strings/<name>.tsv, sorted by section and offset."""
    write_rows(os.path.join(TSV_DIR, name + ".tsv"), TSV_HEADER, (key + rows[key] for key in sorted(rows)))
