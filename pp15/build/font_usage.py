"""Decide which font slots may be given to English letter pairs.

Why this exists: English is drawn two letters per text cell, and every letter pair needs a cell of its own in the
font. The game has 3,038 kanji cells (glyph numbers 706..3743); the translation takes the ones the remaining
Japanese text uses least. This module counts how much each kanji is still used and hands out the slots.
(See "Pair font" and "Kanji cell" in docs/GLOSSARY.md.)

Public names:
    KANJI_SLOTS            the glyph numbers that may be re-drawn as letter pairs
    RESERVED_GLYPHS        glyph numbers that must never be re-drawn
    other_text_usage(modules, skip)   how often each glyph appears in text outside the Success Mode scripts
    name_usage(modules, skip)         how often each kanji appears in the player-name tables
    allocate(pairs, usage, keep)      pair -> glyph number, using the least-used kanji first
"""
import collections
import json
import os
import struct
from typing import Collection

from pp15 import config
from pp15.script import scan

KANJI_SLOTS = range(706, 3744)
# Glyph slots that hold a symbol the code draws by number, not text a scan can see: never given to a letter
# pair. 0xE77 (3703) is the arrow cursor of the My Life menus (ore_work.rel sec1+0x2DF4 and gdt_pn.rel
# sec1+0xC6E0 store it as the one-cell string "0xE77, 0xFFFF" and draw it); as a pair slot it showed "9"
# in front of the first menu line. No other code word loads a number in 0xE50..0xE9F as a glyph.
RESERVED_GLYPHS = frozenset({0xE77})

KANA_FIRST, KANA_LAST = 282, 450     # glyph numbers of the hiragana and katakana
ITERATION_MARK = 24                  # the glyph 々, which appears in names next to kanji
END_OF_TEXT = 0xFFFF                 # closes a 16-bit text string
SURNAME_MARKER = 0x1FFF              # first value of a record of the surname list
SURNAME_RECORD = 5                   # values per surname record: marker, call id, three cells
MIN_SURNAME_RECORDS = 40             # a run of fewer records is not the surname list
NAME_CELLS = 6                       # cells of a player name
MIN_NAMES_IN_TABLE = 6               # a run of fewer player names is not a name table

USAGE_CACHE = "glyph_usage2.json"    # in _work: the scan takes about a minute, so the result is kept
NAME_USAGE_CACHE = "name_kanji.json"


def _load_counter(path: str) -> collections.Counter | None:
    """The glyph counts saved at `path`, or None when there is no such file."""
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return collections.Counter({int(k): v for k, v in json.load(f).items()})


def other_text_usage(modules: dict, skip: set) -> collections.Counter:
    """How often each glyph appears in text outside the Success Mode scripts.

    A heuristic scan of every module for 16-bit glyph strings and for 12-bit packed text. A 16-bit string counts when
    it has kana in it, or when it is kanji only and ends with 0xFFFF (the short labels of the string tables:
    positions, school names, record titles). `modules` = {module id: scan.Rel}; `skip` = module names not to scan.
    The result is cached in _work/glyph_usage2.json (delete it to scan again).
    """
    path = os.path.join(config.WORK_DIR, USAGE_CACHE)
    cached = _load_counter(path)
    if cached is not None:
        return cached
    print("Scanning all modules for text outside the scripts (once, about a minute)...")
    use = collections.Counter()
    for module in modules.values():
        if module.name in skip:
            continue
        for sec in module.sections:
            data = module.sec_data(sec["index"])
            if sec["exec"] or len(data) < 8:
                continue
            for _, units in scan.find_packed_text(data):
                use.update(u for u in units if u <= scan.MAX_GLYPH)
            run = []
            for v in struct.unpack(">%dH" % (len(data) // 2), data[:len(data) // 2 * 2]) + (0,):
                if 0 < v <= scan.MAX_GLYPH:
                    run.append(v)
                    continue
                if len(run) >= 3 and sum(KANA_FIRST <= u <= KANA_LAST for u in run) >= 2:
                    use.update(run)
                elif v == END_OF_TEXT and len(run) >= 2 and all(u >= KANA_FIRST for u in run) \
                        and any(u >= KANJI_SLOTS[0] for u in run):
                    use.update(run)
                run = []
    with open(path, "w") as f:
        json.dump(use, f)
    return use


def _name_cells(record: tuple) -> int:
    """Classify six cells as a player name: 0 = no name, 1 = a name, 2 = a name with kanji.

    A name is text glyphs with at most one blank cell inside (two kanji are spread out: "te, blank, zuka") and blank
    cells behind it.
    """
    n = len(record)
    while n and record[n - 1] == 0:
        n -= 1
    body = record[:n]
    if not n or body.count(0) > 1 or any(
            v and v != ITERATION_MARK and not KANA_FIRST <= v <= KANJI_SLOTS[-1] for v in body):
        return 0
    kanji = any(v >= KANJI_SLOTS[0] for v in body)
    return 2 if kanji and n - body.count(0) >= 2 and len(record) - n >= 2 else 1


def _count_surname_list(units: tuple, use: collections.Counter) -> None:
    """Count the kanji of the surname list: records of five 16-bit values (0x1FFF, the announcer's call, three cells)."""
    i = 0
    while i + SURNAME_RECORD <= len(units):
        j = i
        while j + SURNAME_RECORD <= len(units) and units[j] == SURNAME_MARKER \
                and max(units[j + 2:j + SURNAME_RECORD]) <= KANJI_SLOTS[-1]:
            j += SURNAME_RECORD
        if j - i >= MIN_SURNAME_RECORDS:
            for k in range(i, j, SURNAME_RECORD):
                use.update(v for v in units[k + 2:k + SURNAME_RECORD] if v >= KANJI_SLOTS[0])
        i = max(j, i + 1)


def _count_player_names(units: tuple, use: collections.Counter) -> None:
    """Count the kanji of player names: six cells, back to back (stride 6) or behind three other values (stride 9)."""
    for stride, at in ((NAME_CELLS, 0), (NAME_CELLS + 3, 3)):
        for phase in range(stride):
            i = phase
            while i + stride <= len(units):
                j, good = i, 0
                while j + stride <= len(units) and _name_cells(units[j + at:j + at + NAME_CELLS]):
                    good += _name_cells(units[j + at:j + at + NAME_CELLS]) == 2
                    j += stride
                if j - i >= MIN_NAMES_IN_TABLE * stride and good * 2 * stride >= j - i:
                    for k in range(i, j, stride):
                        use.update(v for v in units[k + at:k + at + NAME_CELLS] if v >= KANJI_SLOTS[0])
                i = max(j, i + stride)


def name_usage(modules: dict, skip: set) -> collections.Counter:
    """The kanji of the name tables, which `other_text_usage` cannot see.

    They have no kana, and a two-kanji name has a blank cell in the middle. Two layouts are recognised: the surname
    list of main_prg.rel and scc_main.rel (1,856 names: team-mates, name entry), and player names in six cells.
    The result is cached in _work/name_kanji.json.
    """
    path = os.path.join(config.WORK_DIR, NAME_USAGE_CACHE)
    cached = _load_counter(path)
    if cached is not None:
        return cached
    use = collections.Counter()
    for module in modules.values():
        if module.name in skip:
            continue
        for sec in module.sections:
            data = module.sec_data(sec["index"])
            if sec["exec"] or len(data) < 64:
                continue
            units = struct.unpack(">%dH" % (len(data) // 2), data[:len(data) // 2 * 2])
            _count_surname_list(units, use)
            _count_player_names(units, use)
    with open(path, "w") as f:
        json.dump(use, f)
    return use


def allocate(pairs: Collection[str], usage: dict, keep: Collection[int] = (),
             pinned: dict | None = None) -> tuple[dict, int, int]:
    """Give every letter pair a kanji slot.

    Kanji no text uses come first, then the least used; the kanji in `keep` (the name tables) are taken only when
    nothing else is left. `pinned` = {pair: glyph number} of a released font: those pairs keep their slots (even if
    no text uses them any more) and only new pairs get free slots, because saves store generated names as glyph
    numbers and a moved pair would garble them. Returns ({pair: glyph number}, number of slots taken from kanji that
    remaining text still uses, number taken from `keep`). Raises ValueError when there are more pairs than slots.
    """
    pinned = dict(pinned or {})
    free = sorted((g for g in KANJI_SLOTS if g not in RESERVED_GLYPHS and g not in set(pinned.values())),
                  key=lambda g: (g in keep, usage.get(g, 0), -g))
    new = sorted(p for p in pairs if p not in pinned)
    if len(new) > len(free):
        raise ValueError("%d different letter pairs, only %d glyph slots" % (len(pinned) + len(new), len(pinned) + len(free)))
    slots = pinned | dict(zip(new, free))
    return (slots, sum(1 for g in slots.values() if usage.get(g, 0) or g in keep),
            sum(1 for g in slots.values() if g in keep))
