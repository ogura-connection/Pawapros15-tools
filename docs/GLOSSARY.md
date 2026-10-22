# Glossary

Plain-English meanings of the words this repository uses, in alphabetical order. You need no knowledge of the game, of
the series or of Japanese. "Pawapuro 15" is the game being translated: a Japanese baseball video game for the Nintendo Wii.

**Annex.** Extra room appended behind a module's data when the translated text is longer than the original and the
module has no space left to grow. The build writes the overflow there and points the module at it (a script that finds
its annex by a four-letter marker). See FINDINGS.md ("No room, so an annex"), code in `pp15/build/rebuild.py`.

**ARC.** A game file with the extension `.arc`: a bundle of sprite sheets (pictures) and the tables that say which piece
of a picture goes where on screen. Almost all painted lettering is inside .arc files. Code: `pp15/art/textures.py` reads
and writes them; `specs/<name>.json` describes the English lettering for the file `<name>.arc`.

**Bank.** One group inside an ARC: a set of picture pages, the colour palette they share, and the sprite table that uses
them. Banks have short internal names such as `y3_fa` or `g3_kya00`. Code: `pp15/art/textures.py` (`banks`).

**DOL.** The game's main executable (`main.dol`), the program the Wii starts. Some on-screen system messages live in it.
Code: `pp15/build/rebuild.py` rewrites the message block inside it.

**Eikan Nine.** One of the two stories (scenarios) of Success Mode: you manage a high-school baseball team through the
seasons and try to reach the national tournament. Its files start with `sct_`. Style modules: `pp15/art/styles/eikan_*.py`.

**Glyph.** One character cell of the game's text system, identified by a number. The game draws text by looking glyph
numbers up in its font. Code: `pp15/glyphs.py` (table, encode, decode).

**Golden check.** The safety test that rebuilds the English game files and compares the SHA-1 fingerprint of every one
with the list of fingerprints of the released build. If any file differs by one byte it fails. Code and list:
`tests/golden.py`, `tests/golden_sha1.json`. Run it after every change.

**Kanji cell.** A glyph slot that normally holds a Japanese character (kanji). Because the Japanese text no longer needs
all of them, the build reuses the least used ones to hold English letter pairs (see pair font).

**My Life.** A game mode in which you live a professional player's career: practice, schedule, matches, free agency,
retirement. Its files start with `ore_` or are called `orepena`/`myend`. Style modules: `pp15/art/styles/my_life_*.py`.

**Pair font.** The trick that makes English fit: the game's text has room for one wide Japanese character per cell, so
each cell is drawn with two narrow English letters. Every letter pair the translation uses gets its own cell. Code:
`pp15/build/font.py`; explanation in FINDINGS.md ("The pair font").

**Page.** One picture (a grid of palette indices) inside a bank. Sprites are cut out of pages. Code:
`pp15/art/textures.py` (`decode_indices`).

**Palette.** The list of colours a picture's pixels point into. A pixel stores a palette index, not a colour, so lettering
styles are written in palette indices ("use colour 12 for the fill, 5 for the outline"). Code: `pp15/art/textures.py`.

**Pennant.** A game mode in which you manage a professional team through a season: roster, trades, draft, results. Files
start with `pena`, `pennant`, `pn_`. Style modules: `pp15/art/styles/pennant*.py`.

**Progress icon.** In Eikan Nine, the board of small picture cards on the main screen that shows the events of the coming
weeks. Its card lettering is drawn by `pp15/art/styles/eikan_menus.py`.

**REL.** A game file with the extension `.rel`: a code-and-data module the game loads while it runs (most story text is
in them). They contain relocation tables. Code: `pp15/glyphs.py` parses them, `pp15/build/rebuild.py` rebuilds them.

**Relocation.** An entry in a REL file that says "at this offset, write the address of that other thing when the module
is loaded". When translated text changes lengths, every relocation that points behind the change must be moved; that is
the main job of `pp15/build/rebuild.py`.

**Repack.** Our word for re-laying-out the pictures of an ARC page: after English labels of different sizes replace the
Japanese ones, the pieces of the page are packed again and the sprite table is updated to match. Code:
`pp15/art/typeset.py` (`repack`), driven by the `"repack"` section of a spec.

**Score bug.** The small scoreboard overlay shown in a corner during a match (inning, count, score). Its lettering is
styled in `pp15/art/styles/match.py`.

**Spec.** A JSON file in `specs/`, one per ARC file, that lists every label to draw on its sprite sheets: where the label
goes (page and rectangle), the English wording, and the name of the style to use. `pp15 apply-art specs/<name>.json`
draws them. Code: `pp15/art/labels.py`.

**Sprite.** An on-screen picture assembled from one or more rectangles ("parts") cut out of pages, each with a position,
flip flags and a palette. Code: `pp15/art/textures.py` (`parts`).

**Style.** A recipe that tells the lettering tool how to draw an English label on a sprite sheet: font, size, colours,
outline, shadow. A style is a small Python function; all of them are collected in the dictionary `typeset.RENDER` by name
(25,575 of them). The files in `pp15/art/styles/` define them; `tests/test_registry.py` guards them.

**Success Mode.** The story mode of the game: you build and train your own player through a scenario (two exist, Hakkyu
Dream and Eikan Nine). Its files start with `scs_` or `sct_`. Style modules: `pp15/art/styles/success_*.py`, `eikan_*.py`.
