"""Cut English text into the two-letter units that the game's text cells hold.

Why this exists: the game draws one text cell per character, and a cell is as wide as a Japanese character. To fit
English, this project draws two narrow letters into every cell (see "Pair font" in docs/GLOSSARY.md). Before any
text can be encoded or counted it must be cut into those pairs, and that cutting has to be the same everywhere
(the build, the length checks, the font allocation), so it lives here, in a module with no other dependencies.

Public functions:
    split_pairs(text)    ASCII text -> list of two-letter strings (the last one padded with a space)
    segments(text)       text -> iterator of ("pair", "ab") | ("char", "c") | ("newline", None)
    text_segments(text)  the same as a list, without the newline that `segments` adds at the end
"""
from typing import Iterator

FIRST_ASCII, LAST_ASCII = 0x20, 0x7E     # the printable ASCII range: space .. tilde. Only these are paired.


def split_pairs(text: str) -> list[str]:
    """ASCII text -> letter pairs, the last one padded with a space ("abc" -> ["ab", "c "])."""
    return [(text[i:i + 2] + " ")[:2] for i in range(0, len(text), 2)]


def segments(text: str) -> Iterator[tuple[str, str | None]]:
    """Cut text into ("pair", "ab"), ("char", c) and ("newline", None) pieces.

    Pairing restarts on every line and after every non-ASCII character (a Japanese character or a symbol keeps a
    cell of its own), so a pair never straddles them. A literal backslash-n in the text counts as a line break.
    A final ("newline", None) is always produced because the text is closed with a newline; use `text_segments`
    to leave it out.
    """
    buf = ""
    for ch in text.replace("\\n", "\n") + "\n":
        if FIRST_ASCII <= ord(ch) <= LAST_ASCII:
            buf += ch
            continue
        for pair in split_pairs(buf):
            yield "pair", pair
        buf = ""
        yield ("newline", None) if ch == "\n" else ("char", ch)


def text_segments(text: str) -> list[tuple[str, str | None]]:
    """`segments(text)` as a list, without the newline that `segments` adds at the end."""
    return list(segments(text))[:-1]
