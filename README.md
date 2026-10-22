# Pawapuro 15 — English patch toolkit

Tools for translating **Jikkyou Powerful Pro Yakyuu 15** (Wii, RP5JA4, Rev 1) into English, and the research
behind them. The repository holds code, the English (keyed by file and offset, no Japanese), the label specs
and the notes. It does **not** hold the game, extracted game files or Japanese game text: those stay in
`DATA/` and `_work/`, which git ignores. (`translation_high_quality.json` from the first approach is the one
exception still in the tree.)

Where things stand, what is next and how a session works: `../HANDOFF.md` (outside the repository).
How each store of text was found and how the tools work: `FINDINGS.md`. Voices, terms and wording:
`TRANSLATION_STYLE.md`. Low-level reference (encoding, font, VM): `TECHNICAL_GUIDE.md`.

## Repository map

```
Pawapros15-tools/
  README.md  FINDINGS.md  TECHNICAL_GUIDE.md  TRANSLATION_STYLE.md   what the project knows (read in this order)
  pyproject.toml   the `pp15` package and its command (`pip install -e .`, or run `python3 -m pp15` from this folder)
  pp15/            the code
    config.py        every path (repository, DATA, _work, translation, specs, the translation kit, the MLB discs); env overrides
    cli.py           the `pp15` command: a thin dispatcher to the tools below (`python3 -m pp15 --help`)
    glyphs.py        glyph table, text encoding and decoding, REL parsing (glyph_cli.py: its own commands)
    script/          scan.py (formats of the story scripts), translate.py (export / apply / merge of the scenes)
    text/            strings.py (fixed-slot UI strings), messages.py (Pennant news)
    names/           table.py (surnames and in-place name tables), schools.py, kyu.py (pitch names)
    build/           rebuild.py (English + font + names -> DATA/files and DATA/sys), font.py (the pair font)
    art/             textures.py (sprite pages), labels.py (specs -> .arc), typeset.py (typeface recipes), sheet.py;
                     styles/ the 91 ui_styles_*.py files, every one imported by typeset.py (file names unchanged for now)
    disc/            extract.py (Wii ISO to files), xdelta.py (release disc + patch), ram_scan.py, extract_text.py
    reference/       mlb_assets.py, mlb_labels.py (the MLB Power Pros discs as a reference)
    kit/             export_tm.py, export_labels.py (results for ~/Projects/translation-kit)
  specs/           one JSON per .arc: every sprite label (rect, wording, style); applied by `pp15 apply-art`
  translation/     the English: script TSVs (<file>.rel.tsv), strings/, messages/, names/ (in_place/ = names written over the original)
  tests/           golden.py (SHA-1 of every installed file against the release), test_imports.py, test_roundtrip.py, run_all.sh
  docs/            PIPELINE.md and TECHNIQUES.md (the method, game independent), refactor_notes.md, a title picture
  legacy/          the first approach and the abandoned Python patcher (apply_patch / make_patch): kept for reference, nothing imports them
  DATA/  _work/    game data and scratch (git-ignored, never committed)
```

Needs Python 3.10 or newer, numpy and Pillow (`pip install -e .`); `capstone` only for `pp15 scan xref`, `pycryptodome` only
for `pp15 extract-iso`. Paths default to this folder and its neighbours; set `PP15_ROOT`, `PP15_KIT`, `PP15_EMU`, `PP15_MLB`
to move them (see `pp15/config.py`).

Build in one go: `python3 -m pp15 merge-strings; python3 -m pp15 merge-script; python3 -m pp15 build` (idempotent; prints "Verified" lines),
then art with `python3 -m pp15 apply-art specs/<arc>.json`, then `python3 -m pp15 check-art`, then `python3 -m pp15 release ORIGINAL.iso ../release/PP15_English_final.iso ../release/PP15_English.xdelta`.
`python3 -m pp15 --help` lists every command; `python3 -m pp15 COMMAND --help` explains one.
Tests: `tests/run_all.sh` (imports, `build-check`, then the golden check: the build must reproduce the released files byte for byte).
The style modules are many (91) because every art run added its own; they import each other as `pp15.art.styles.*`.

## The four stores of text, and their tools

| Store | What | Tool | English in |
|---|---|---|---|
| Script text | Story and event dialogue: 12-bit packed glyph runs inside scripts (Success, Eikan Nine, My Life) | `pp15/script/scan.py` (formats), `pp15 script` (export / apply / merge) | `translation/<file>.tsv` |
| Fixed-slot strings | Menus, help, item and ability texts, system dialogs (`main.dol`) | `pp15 strings` | `translation/strings/<file>.tsv` |
| Message scripts | Pennant news: text pieces with codes for new line, page, inserted names | `pp15 messages` | `translation/messages/<file>.tsv` |
| Sprite lettering | Words drawn in the `.arc` sprite sheets (and `.rom` menu art) | `pp15 textures` (pages), `pp15 apply-art` (`pp15/art/labels.py` + `typeset.py`: typeset, repack) | `specs/<arc>.json` |

`pp15 build` turns `_work/translation.json` and `_work/strings.json` into the built modules, builds
the pair font (`pp15/build/font.py`: two Latin letters per kanji cell), checks every file and installs it into
`DATA/files`. `pp15 apply-art` writes a spec into its `.arc`. Originals are kept in `_work/orig*`.

## Other tools

| Command | Purpose |
|---|---|
| `pp15 extract-iso` | Wii disc to files (partition, title key, AES clusters, FST) |
| `pp15 extract-text`, `pp15 glyphs` | Glyph table, text decoding, shared helpers |
| `pp15 ram-scan` | Loaded modules and memory map from a Dolphin save state |
| `pp15 mlb-assets` | Read MLB Power Pros / MLB 2008 discs (project.bin, .pack textures, English strings) |
| `pp15 mlb-labels` | Index of MLB's English lettering: every label cut out and read by text recognition |
| `pp15 export-tm` | Translation memory: every Japanese / English pair, for reuse in later games |
| `pp15 export-labels` | Our English sprite lettering as pictures (Japanese and English side by side) |
| `pp15 release` | The English disc with Nintendo's layout kept, and an xdelta patch against the original ISO |
| `legacy/` | The first approach (in-place inserter, ASCII font patch, dialogue logger): superseded, kept for reference |

The emulator test harness (`harness.py`, `autoplay.py`, text recognition of frames in `ocr/`) lives beside the
repository in `../dolphin-test/`. The bulk-translation pipeline (batches, briefs, checkers, collect scripts)
lives in `_work/tl_bulk/` because its batches hold game text.

## Reuse for other games

Reusable material that holds game data (translation memory, MLB English art and text, our label art, the
briefs) is collected outside this repository in `~/Projects/translation-kit/` (see its README). What carries
over to other Power Pro titles: the glyph encoding, the font compression, the script VM family, the sprite
bank format, the pair-font trick, and the whole translation memory. What carries over to unrelated games:
the method (find each store of text, prove which copy the screen draws, translate in checked batches, read
the result back from the emulator as text), the harness and the text-recognition reading.

## MLB Power Pros as a reference

MLB Power Pros (2007) and MLB Power Pros 2008 are 2K Sports' English versions of the same engine. Their English
strings and UI textures are the source of the stat labels, command words and much of the wording here; they
merge all modules into one `ovl_main.rel` and pack the art into `.pack` files inside `project.bin`.

MIT License (the code). The game and its text belong to Konami.
