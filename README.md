# Pawapuro 15 — English patch toolkit

Tools for translating **Jikkyou Powerful Pro Yakyuu 15** (Wii, RP5JA4, Rev 1) into English, and the research
behind them. The repository holds code, the English (keyed by file and offset, no Japanese), the label specs
and the notes. It does **not** hold the game, extracted game files or Japanese game text: those stay in
`DATA/` and `_work/`, which git ignores. (`translation_high_quality.json` from the first approach is the one
exception still in the tree.)

Where things stand, what is next and how a session works: `../HANDOFF.md` (outside the repository).
How each store of text was found and how the tools work: `FINDINGS.md`. Voices, terms and wording:
`TRANSLATION_STYLE.md`. Low-level reference (encoding, font, VM): `TECHNICAL_GUIDE.md`.

## The four stores of text, and their tools

| Store | What | Tool | English in |
|---|---|---|---|
| Script text | Story and event dialogue: 12-bit packed glyph runs inside scripts (Success, Eikan Nine, My Life) | `scan_story.py` (formats), `tl.py` (export / apply / merge) | `translation/<file>.tsv` |
| Fixed-slot strings | Menus, help, item and ability texts, system dialogs (`main.dol`) | `ui_strings.py` | `translation/strings/<file>.tsv` |
| Message scripts | Pennant news: text pieces with codes for new line, page, inserted names | `ui_messages.py` | `translation/messages/<file>.tsv` |
| Sprite lettering | Words drawn in the `.arc` sprite sheets (and `.rom` menu art) | `ui_textures.py` (pages), `ui_labels.py` + `ui_type.py` (typeset, repack) | `ui_specs/<arc>.json` |

`rebuild_scripts.py build` turns `_work/translation.json` and `_work/strings.json` into the built modules, builds
the pair font (`pair_font.py`: two Latin letters per kanji cell), checks every file and installs it into
`DATA/files`. `ui_labels.py apply` writes a spec into its `.arc`. Originals are kept in `_work/orig*`.

## Other tools

| File | Purpose |
|---|---|
| `extract_from_iso.py` | Wii disc to files (partition, title key, AES clusters, FST) |
| `extract_all_text.py`, `pawapuro15_text_tools.py` | Glyph table, text decoding, shared helpers |
| `ram_scan.py` | Loaded modules and memory map from a Dolphin save state |
| `mlb_assets.py` | Read MLB Power Pros / MLB 2008 discs (project.bin, .pack textures, English strings) |
| `mlb_labels.py` | Index of MLB's English lettering: every label cut out and read by text recognition |
| `export_tm.py` | Translation memory: every Japanese / English pair, for reuse in later games |
| `export_labels.py` | Our English sprite lettering as pictures (Japanese and English side by side) |
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
