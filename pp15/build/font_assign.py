"""Choose which letter pairs the translation needs, give each a font slot, and draw them into fonttex2.rel.

What it is for: English is stored two letters per text cell (see "Pair font" in docs/GLOSSARY.md). Before any text
can be encoded the build must know every pair that occurs anywhere in the translation (dialogue, menus, messages,
names, system dialogs), and which kanji cell of the font each pair will replace. The cells chosen are the ones the
remaining Japanese text uses least.

Public functions:
    assign_pairs(...)   {letter pair: glyph number} for everything the translation uses
    build_font_file(orig, slots)   the new fonttex2.rel with the pairs drawn in (the file keeps its size)
"""
import collections
import json
import os

from pp15 import config
from pp15.build import font, font_usage
from pp15.build.glyph_codec import font_glyphs
from pp15.build.pair_text import text_segments
from pp15.build.text_encode import BLANK_PAIR
from pp15.glyphs import char_to_glyph
from pp15.script import scan
from pp15.text import strings

PAIR_CACHE = "pair_glyphs.json"      # in _work: the compressed glyph of every pair drawn so far (drawing is slow)
# Modules whose text is not Success Mode dialogue and must not count as "Japanese text that stays":
# namein.rel is the name-entry kanji picker; it lists every kanji once and is not text, and fonttex2.rel is the font.
NOT_TEXT_MODULES = {"fonttex2.rel", "namein.rel"}
UNIT_GLYPH_MASK = 0xFFF      # a text unit's low 12 bits are the glyph number; the top bits hold a colour or a flag


def _count_text(text: str, pairs: set, usage: collections.Counter) -> None:
    """Add the letter pairs of an English text to `pairs`, and the Japanese characters in it to `usage`."""
    for kind, value in text_segments(text):
        if kind == "pair" and value != BLANK_PAIR:
            pairs.add(value)
        elif kind == "char":
            usage[char_to_glyph(value)] += 1


def _count_narrow_names(names: list, pairs: set) -> None:
    """Score-display names use their own narrow pairs for the first cells (font.NARROW)."""
    for en in names:
        n = 0
        for kind, value in text_segments(en):
            if kind == "pair":
                n += 1
                if value != BLANK_PAIR:
                    pairs.add((font.NARROW if n <= font.NARROW_CELLS else "") + value)


def _count_translation(scripts, texts, ui_texts, dol, message_texts, names, pairs, usage) -> None:
    """Fill `pairs` with every letter pair the translation uses and `usage` with the glyphs of Japanese text
    that will stay (untranslated strings and runs), so that those glyph slots are not taken."""
    for en in names:                            # one name per field: pairs from its first letter
        _count_text(en, pairs, usage)
    for messages in message_texts.values():     # message scripts: the pairs start again in every piece
        for _, pieces in messages.values():
            for en in pieces:
                _count_text(en, pairs, usage)
    for string, en in dol or []:
        if en is None:              # stays Japanese: its glyphs are in use (units are 0x1000 | glyph)
            usage.update(u & UNIT_GLYPH_MASK for u in string["units"] if u != strings.DOL_CTRL and u & UNIT_GLYPH_MASK)
            continue
        for part in en.split("{}"):
            _count_text(part, pairs, usage)
    for slots_of_module in ui_texts.values():
        for _, en in slots_of_module.values():
            for _, part in strings.colour_runs(en):
                _count_text(part, pairs, usage)
    for script in scripts:          # the string tables of the script modules that stay Japanese
        if hasattr(script, "spec"):     # a block script's module is counted with the other modules, below
            continue
        idx = sorted(script.kind)
        done = ui_texts.get(script.rel.name, {})
        for st in strings.find(script.rel, (script.sec, idx[0] * 2, (idx[-1] + 1) * 2)):
            if (st["section"], st["offset"]) not in done:
                usage.update(u & UNIT_GLYPH_MASK if u > scan.MAX_GLYPH else u for u in st["units"] if u & UNIT_GLYPH_MASK)
    for script in scripts:
        new = texts.get(script.rel.name, {})
        for i, (_, units, _) in script.texts.items():
            if i not in new:
                if not hasattr(script, "spec"):
                    usage.update(units)
                continue
            _count_text(new[i], pairs, usage)


def assign_pairs(scripts: list, texts: dict, orig: dict, ui_texts: dict | None = None, dol: list | None = None,
                 message_texts: dict | None = None, names=(), narrow=()) -> dict:
    """Choose a glyph slot for every letter pair in the translation. Returns {pair: glyph number}.

    scripts = the parsed scripts (Success Mode and the others); texts = {module name: {halfword index: English}};
    orig = all original modules; ui_texts, message_texts = the English of the fixed-slot strings and of the message
    scripts; dol = `dol_block.load_dol()`: the dialog strings of main.dol with their English; names = names in
    English (surnames, players, My Life names); narrow = school names for the score display.
    Prints a line saying how many slots were used and whether any name kanji were lost.
    """
    pairs, usage = set(), collections.Counter()
    _count_narrow_names(narrow, pairs)
    _count_translation(scripts, texts, ui_texts or {}, dol, message_texts or {}, names, pairs, usage)
    if not pairs:
        return {}
    usage.update(font_usage.other_text_usage(orig, set(scan.SCRIPT_FILES) | NOT_TEXT_MODULES))
    name_kanji = font_usage.name_usage(orig, NOT_TEXT_MODULES)       # team-mates, real players
    slots, taken, lost = font_usage.allocate(pairs, usage, name_kanji)
    print("Font: %d letter pairs in %d kanji slots (%d slots left)%s%s"
          % (len(slots), len(slots), len(font_usage.KANJI_SLOTS) - len(slots),
             "" if not taken else "; %d of them are kanji that Japanese text elsewhere still uses" % taken,
             "; all %d kanji of the name tables are kept" % len(name_kanji) if not lost else
             "; %d of the %d kanji of the name tables are LOST" % (lost, len(name_kanji))))
    return slots


def build_font_file(orig: dict, slots: dict) -> bytes:
    """fonttex2.rel with the pair glyphs drawn into their slots (the file keeps its size).

    Draws each pair once and keeps the result in _work/pair_glyphs.json. Also draws the full-width letters as one
    centred letter. Reads the new fonts back and asserts every slot holds its pair and no other glyph changed.
    """
    rel = next(m for m in orig.values() if m.name == "fonttex2.rel")
    cache_path, cache = os.path.join(config.WORK_DIR, PAIR_CACHE), {}
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            cache = json.load(f)
    known = len(cache)
    slots = dict(slots)
    for fullwidth, letter in font.FULLWIDTH.items():             # full-width letters: one letter of the pair font
        slots[font.SINGLE + letter] = char_to_glyph(fullwidth)
    image = font.build_font(rel.data, rel.sections[4]["offset"], {g: p for p, g in slots.items()}, cache)
    if len(cache) != known:
        with open(cache_path, "w") as f:
            json.dump(cache, f)
    sec4 = image[rel.sections[4]["offset"]:]
    for name, pos, _ in font.FONTS:                       # read it back
        old = font_glyphs(rel.sec_data(4), pos)
        new = font_glyphs(sec4, pos)
        for pair, g in slots.items():
            assert new[g] == font.pair_glyph(pair, name == "large", cache), pair
        assert all(a == b for g, (a, b) in enumerate(zip(old, new)) if g not in set(slots.values())), name
    assert len(image) == len(rel.data)
    return image
