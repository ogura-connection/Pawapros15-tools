# Architecture

## What the project does

It turns a Japanese Wii baseball game (Jikkyou Powerful Pro Yakyuu 15) into an English one without the source code. The
text lives in game files in several different stores (story scripts, menu strings, names, and lettering painted into
pictures). The tools read each store, let us keep the English in plain text files, and write everything back so that the
game runs unchanged apart from its words. The repository holds code and English text, never the game itself.

## From the Japanese disc to the English disc

1. **Extract**: `pp15 extract-iso` / the Wii tools unpack the disc into `DATA/files` (code modules, picture bundles) and `DATA/sys`.
2. **Read**: `pp15/glyphs.py`, `pp15/script/scan.py` and `pp15/art/textures.py` decode the game's text encoding, its code modules and its picture bundles.
3. **Translate**: the English is kept in `translation/` (story, menu strings, news, names) and, for painted lettering, in `specs/` (one JSON per picture bundle, with the style of each label).
4. **Draw**: `pp15 apply-art` uses `pp15/art/typeset.py` and `pp15/art/styles/` to draw each English label into the pictures and re-pack the pages.
5. **Rebuild**: `pp15 build` (`pp15/build/rebuild.py`) writes the longer or shorter text back into the code modules, moves every pointer behind it, builds the pair font that fits two letters in a cell, and installs the files in `DATA/`.
6. **Release**: `pp15 release` (`pp15/disc/xdelta.py`) lays the files out as a disc and produces a patch against the original image. `tests/golden.py` checks that the installed files are the released ones.

## The folders

- `pp15/` the code
  - `config.py` every path and setting.
  - `cli.py` the `pp15` command; it only starts the tool you name.
  - `glyphs.py` the game's text encoding and code-module format.
  - `script/` story scripts: find, export and re-import scenes.
  - `text/` fixed-size menu strings and in-game news messages.
  - `names/` player, school and pitch names.
  - `build/` rebuilds the code modules and the font from the English.
  - `art/` pictures: `textures.py` reads and writes picture bundles, `labels.py` applies specs, `typeset.py` draws lettering, `styles/` holds the 25,575 lettering styles by screen, `original_arc.py` reads untouched originals.
  - `disc/` unpacks discs and writes the English disc and patch.
  - `reference/` and `kit/` read another game's assets as a model and export results for the translation kit.
- `specs/` the label lists for painted lettering. `translation/` the English text. `tests/` the safety nets. `docs/` method notes, this file and the glossary. `legacy/` old code kept for reference. `DATA/`, `_work/` game data and scratch, never committed.

## Where to start reading

`README.md`, then `docs/GLOSSARY.md` for the vocabulary, then `FINDINGS.md` (how each store of text was found). To follow
one label end to end: open a file in `specs/`, find its style name in `pp15/art/styles/` (`docs/styles_map.md` says which
module), read `pp15/art/typeset.py`, then run `python3 -m pp15 apply-art specs/<name>.json`.
