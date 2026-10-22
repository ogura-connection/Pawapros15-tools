"""Reading and writing the translation files (`translation/**/*.tsv`), shared by the story, string and message tools.

A translation file is plain text with one entry per line and columns separated by tabs: where the original text is
(section/offset), a 4-character fingerprint of the original, and the English. It holds no Japanese, so it can be kept in
the public repository; the fingerprint is how the build notices that an original text moved or changed. Lines that
start with `#` (the header) and blank lines are ignored.

Public names: text_hash(text), read_rows(path, columns), write_rows(path, header, rows).
"""
import hashlib
import os
from typing import Iterable, List, Sequence

HASH_LENGTH = 4         # hex digits of the SHA-1 kept as the fingerprint of an original text


def text_hash(text: str) -> str:
    """The 4-hex-digit fingerprint of an original (Japanese) text: the start of its SHA-1."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:HASH_LENGTH]


def read_rows(path: str, columns: int) -> List[List[str]]:
    """The entries of a translation file as lists of `columns` strings (the last column keeps any tabs).
    Returns [] when the file does not exist."""
    rows: List[List[str]] = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    rows.append(line.rstrip("\n").split("\t", columns - 1))
    return rows


def write_rows(path: str, header: str, lines: Iterable[Sequence]) -> None:
    """Write a translation file: the one-line header (a `#` comment naming the columns) and then one tab-separated
    line per entry. Creates the folder when needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        for columns in lines:
            f.write("\t".join(str(c) for c in columns) + "\n")
