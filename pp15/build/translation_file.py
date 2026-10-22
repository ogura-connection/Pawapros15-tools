"""Read the translation file of the Success Mode style scripts and check it against the originals.

What it is for: the dialogue is exported to a JSON file (`python3 -m pp15 scan extract --dump` writes
_work/story_text.json; `pp15 merge-script` writes _work/translation.json from translation/*.tsv). Each entry names
one run of text in one script module and carries its English:

    {"file": "scs_sce1.rel", "section_offset": 25148, "text": "<original>", "en": "New text"}

"file" + "section_offset" identify the run; "text" (optional) is compared with the original so a stale file is
caught; "en" is the replacement, with \\n for a line break. Entries without "en" are ignored.

Public functions:
    load_translation(path, scripts)   -> {module name: {halfword index: English text}}
"""
import collections
import json
import sys

from pp15.build.pair_text import text_segments
from pp15.script import scan

LINE_CELLS = 17        # width of the dialogue box (window type 29) in glyph cells
POPUP_WINDOW, POPUP_CELLS = 31, 30   # glossary pop-ups (window type 31): the original lines run to about 31 cells


def load_translation(path: str, scripts: list) -> dict:
    """Read a translation file and return {module name: {halfword index of the text run: English text}}.

    Stops the build (sys.exit) when an entry does not point at a text run, or when its "text" is not the original.
    Prints a warning for every line wider than its box holds (the build still goes on).
    """
    by_name = {sc.rel.name: sc for sc in scripts}
    texts = collections.defaultdict(dict)
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)
    for e in entries:
        if e.get("en") is None:
            continue
        sc = by_name.get(e["file"])
        i = e["section_offset"] // 2
        if sc is None or e["section_offset"] % 2 or i not in sc.texts:
            sys.exit("%s +0x%X: not a text run" % (e["file"], e["section_offset"]))
        old = scan.decode_units(sc.texts[i][1])
        if "text" in e and e["text"] != old:
            sys.exit("%s +0x%X: original text is %r, the translation file says %r"
                     % (e["file"], e["section_offset"], old, e["text"]))
        texts[e["file"]][i] = e["en"]
        cells, line = 0, 0
        for kind, _ in text_segments(e["en"]):
            line = 0 if kind == "newline" else line + 1
            cells = max(cells, line)
        limit = sc.spec["line"] if hasattr(sc, "spec") else POPUP_CELLS if sc.texts[i][0] == POPUP_WINDOW else LINE_CELLS
        if cells > limit:
            print("warning: %s +0x%X is %d cells wide, the line holds %d (%d letters): %r"
                  % (e["file"], e["section_offset"], cells, limit, limit * 2, e["en"]))
    return texts
