# Techniques that transfer

What the Pawapuro 15 (Wii) patch had to solve, written so the next game can skip the search. Each entry:
the problem, what worked, **how to spot the same situation in another game**, the traps, and the code
(`T/` = `~/Projects/Pawapuro/pp15/pp15-tools`, `D/` = `~/Projects/Pawapuro/pp15/emulator`). The details and
numbers are in `T/FINDINGS.md`; this file is the general lesson of each.

Contents: A. finding text, B. writing text back, C. the font (fitting English into a kanji font),
D. lettering in pictures, E. translating, F. checking the result, G. project rules.

---

## A. Finding text

### A1. The game's own character table, not Shift-JIS
Pawapuro stores text as **glyph numbers**: the index of a character in its own font (0..3,743, ordered like
JIS X 0208 but with gaps), not Shift-JIS or UTF-16. A search for Shift-JIS finds nothing.
- Spot it: no Shift-JIS hits for words you can see on screen; the font file holds a few thousand glyphs.
- Do: decode the font, render every glyph, and build the index → character table once (by sight or by text
  recognition of the rendered glyphs). Every later tool decodes through that table.
- Code: `T/pp15/glyphs.py` (`char-table`, `dump-font`), `pp15 extract-text`.

### A2. Text that looks like noise: packed units
The story dialogue (about 90% of all text) was missed by an earlier attempt because it is **12 bits a
character** packed back to back (`AAAB BBCC CDDD`), not 16. A 16-bit scan sees noise; the old conclusion
"dialogue is assembled at run time and cannot be patched" was wrong.
- Spot it: you can see lines on screen that no 16-bit or Shift-JIS search finds, the area's entropy is 6 to 6.5
  bits a byte (compressed data is close to 8), and no LZ/Yaz0 stream decompresses there.
- Do: try other unit widths (12, 10, 9 bits; both nibble orders) and score a window by how many units are kana
  (kana are the most common characters in Japanese text). A wrong width scores near zero, the right one
  jumps. Then find the terminator and line-break codes (here `0xFFF` and `0xFFE`), and prove the format by
  decoding and re-encoding every run to identical bytes.
- Code: `T/pp15/script/scan.py` (`unpack_text`, `pack_text`, `find_packed_text`, `entropy`, `scan`).

### A3. Read the code, not only the data
The way to be sure: find the text reader in the code (it masks 12 bits, compares with the terminator) and the
interpreter that calls it. Disassemble with capstone; look for the handler of each script opcode.
- **Opcode lengths from the handlers, by machine**: follow each handler from the jump table to the point
  where it advances the script pointer, and read how far. That gives the length of every instruction without
  understanding what it does, which is all a re-layout needs. Check the table by parsing the whole script:
  no instruction may land mid-way in another, and the parse must reach the end.
- This worked for three different script engines in one game (Success, Eikan Nine with renumbered
  opcodes, My Life with whole-halfword opcodes and `FFF0`/`FFF1` blocks).
- Code: `T/pp15/script/scan.py` (`derive_op_advance`, `Code`, `xref`, `instruction_length`, `BlockScript`, `OreScript`).

### A4. Fixed-slot strings and their real start
Menus, help texts and item descriptions are 16-bit glyph strings in slots of fixed size, padded with spaces
and closed by `0xFFFF`. Multi-line slots have no line-break code: the box wraps at a fixed width and the
Japanese pads each line with spaces (the padding gives the line width).
- Trap: small numbers in front of a string (a header) are valid glyph numbers, so a scanner glues them on.
  **The module's pointers decide**: a pointer that lands inside a slot and none at its start means the text
  starts at the pointer; two pointers into one slot mean two strings share it (one is the tail of the other).
- Trap: packed script text read as 16-bit strings looks plausible. Four such "strings" were translated and
  corrupted a script for two days. The build now refuses a string that lies inside a script region.
- Code: `T/pp15/text/strings.py` (`find`, `line_widths`, `START_TRIM`), `T/_work/tl_bulk/pointer_check.py`.

### A5. Names in cells, with holes
Names are fixed cells per character, and a two-kanji name in a three-cell field has an **empty cell in the
middle** (手塚 = `0773 0000 0A46`). Searches for the characters side by side find nothing, so the name kanji
looked unused and were nearly given away to the font (C1).
- Spot it: names on screen that no search finds; name tables of fixed-size records (here 1,856 surnames of
  five 16-bit values each).
- Code: `T/pp15/build/font.py` (`name_usage`, `_name_cells`).

### A6. Message scripts: pieces with codes
Pennant's news is not a string table: each message is a run of pieces (`codes, 0, text, 0xFFFF`) with codes for
new line, new page and inserted values (club, player, number), and only the message start has a pointer.
- Spot it: "strings" that start with small numbers, several `0xFFFF` per message, pointers only to some of them.
- Do: write each message as one line with tags (`{n}` line, `{p}` page, `{66}` an insert) and let the English be
  free between tags as long as the whole message fits its span.
- Code: `T/pp15/text/messages.py`.

### A7. The same words exist two or three times: prove which copy is drawn
Gear names existed as a string table, as script constants and as sprite lettering; the screen drew the
sprites. The Success start screen drew a byte-identical copy of a sheet stored in another file. Two
translation passes were spent on copies nobody sees.
- Do: before translating a screen, dump the textures the emulator loads on it and match them against the
  decoded pages of every file; for text, search a RAM dump for the glyph numbers. A string on screen that is
  not in memory as glyph numbers is a picture.
- Code: `D/looks/first/steps.py` (keys, a screenshot, the textures dumped since the last step),
  `T/_work/ui_pages/tools/match_all.py`, `mirror_bank.py`, `pp15 ram-scan`.

### A7b. Text on screen that is not a sprite word: a sprite font or a texture drawn at run time
In a match the pitch name ("ストレート 144 km/h") looks like art but is text drawn letter by letter with a small
katakana sprite font (`h3_kyu_0`), and player names are rendered into fresh textures from the main font at run
time (a texture dump shows one texture per name). Both are cheaper than art: translate the text table behind
them (or romanise the names) and the screen follows; a sprite font that already holds A-Z needs no new art.
- Spot it: a texture dump full of near-identical textures that each hold one word or name; a "sheet" that is
  an alphabet; the same lettering style for words that cannot all be pre-drawn (names, numbers).
- Find the table: search RAM during that screen for the word in each candidate encoding (main glyph numbers,
  the sprite font's own indices, Shift-JIS), then the module that holds it.

### A8. Measure everything before planning
An inventory per file (strings, packed runs, cells) and a machine survey of every texture page (render it,
read it with text recognition in Japanese) turned guesses into numbers: the story was 45,661 lines, the
painted lettering about 7,500 boxes, the "rest of the game" about as much text again as Success.
- Code: `T/_work/inventory_text.json`, `T/_work/ui_pages/tools/art_survey.py`.

---

## B. Writing text back

### B1. References are relocation addends: re-lay, then re-aim
Scripts hold no raw pointers: jumps name a label number, and the label tables are filled at load time by
relocations (`R_PPC_ADDR32`). So text may change length freely if every addend that points behind the change
is moved too.
- Do: re-emit the script, keep a map old offset → new offset, rewrite every relocation addend in every
  module that points into the changed section, and the relocation positions inside it. Then **read the built
  file back** and compare instructions, labels, text and every relocation with the original (only the
  expected addends may differ). `check` mode: rebuilding with no changes must give identical bytes.
- Spot it: the platform uses relocatable modules (Wii/GameCube REL, PS2 IRX/ELF overlays, DLLs), or the game
  uses label indices resolved through a table.
- Code: `T/pp15/build/rebuild.py` (`emit_script`, `patch_addends`, `rebuild_module`, `verify`, `check`).

### B2. Memory is the real limit, not file size
The game loads every module at a **fixed address** from a table on the disc (`moduleID2addr.o`: address, memory
size, bytes to read). A grown file not entered in the table is read short and crashes later.
- Find free memory: a region that is zero in memory snapshots of many screens and that no code addresses.
  Here 2.1 MB above the module plan was free; moving the scenario slot there gave the main script 383 KB to grow.
- Code: `T/pp15/build/rebuild.py` (`plan_tables`, `update_plan`, `memory_size`), `pp15 ram-scan`.

### B3. No room at all: lay out again inside the module, or an annex
- Eikan Nine's module could not grow (24 bytes free). Its labels were aligned to 4 bytes with zero gaps
  (6.5 KB); the engine did not need the alignment, so the gaps became the room for the English.
- My Life had 2.8 KB of slack for 245 KB of text. Scenes that do not fit go to an **annex** appended to another
  module that is always loaded with it, moved to free memory; the labels of moved scenes become relocations
  against the main executable (absolute addresses). Islands of other data inside the script stay in place.
- Spot it: the build says "N bytes too long" and the memory plan has no slack.
- Code: `T/pp15/build/rebuild.py` (`emit_block`, `emit_ore`, `ore_relocations`, `update_plan_ore`).

### B4. Movable string blocks
Strings reached only through a pointer table can be laid out back to back again: an entry may grow if
another shrinks, and a string that is the tail of another can share its cells. The same for the system
dialogs in the main executable (264 lines re-laid, 251 relocations re-pointed, fixed strings proven unmoved).
- Code: `T/pp15/text/strings.py` (`BLOCKS`), `T/pp15/build/rebuild.py` (`layout_block`, `layout_dol`, `build_dol`, `verify_dol`).

### B5. English keyed by position and hash, never by Japanese
Each translation file row is `section, offset, 4-hex hash of the original, English`. The hash catches a run
that moved or changed; the files hold no Japanese, so the repository can be public.
- Code: `T/pp15/script/translate.py`, `T/pp15/text/strings.py`, `T/pp15/text/messages.py` (`text_hash`).

---

## C. The font: fitting English into a kanji font

### C1. The pair font (two letters per kanji cell)
The problem: the dialogue font has full-width cells only, a box is 17 cells, and the script space and memory
are sized for Japanese. One Latin letter per cell would need 2 to 2.5 times the room and show 17 letters a line.
The solution, with **no code change in the game**:
- Every two-letter pair the English uses ("Th", "e ", "ba", ...) is drawn as one glyph, half-width letters side
  by side, and stored in the slot of a kanji. The English text is written as those glyph numbers. A line of
  17 cells now holds 34 letters, and English costs about what the Japanese did.
- **Which kanji to give up**: count how often every kanji is used by the text that stays Japanese (untranslated
  script, every string table of every module, name tables), and allocate the least used first. Name kanji
  are taken last (A5). Kanji still used somewhere show as a letter pair until that text is translated too.
- The set of pairs is rebuilt at every build from the whole translation (about 1,900 pairs here), so the
  font changes every build: boot from scratch after a build (save states keep the old font).
- Both fonts of the game (small and large outlined) get the pair; the glyph compression had to be decoded
  and re-implemented, and repacking the originals had to give identical bytes first.
- Traps: a run starts a new pair, so a sentence split over several runs (colour change, inserted name) shows
  half a cell of space if the earlier piece has an odd number of letters; Japanese left in a line is unaffected.
- Spot it: any game with a fixed-cell CJK bitmap font and a known glyph table. If the font has fewer free
  slots than pairs needed, count pairs first (English text uses about 900 to 2,000 distinct pairs).
- Code: `T/pp15/build/font.py` (`split_pairs`, `segments`, `allocate`, `other_text_usage`, `name_usage`, `render_pair`,
  `compress`/`decompress`, `build_font`), `T/pp15/build/rebuild.py` (`assign_pairs`, `build_font_file`, `encode_text`).

### C2. Box widths and sentences the game assembles
- Measure each kind of window in the game: dialogue 17 cells by 2 or 3 lines; one kind of window (type 29)
  **drops the cell after an automatic wrap**, so its lines must never wrap by themselves.
- Sentences built from pieces (a name + " is someone you just met.") are invisible to any check of one
  scene: they were the main source of errors in play. Keep each assembled sentence within one line, or
  start the second piece with a line break; write pieces that work after any of their possible heads.

---

## D. Lettering in pictures

### D1. Decode the texture containers, including the compressed ones
85% of the sprite pages were compressed in a format nobody had decoded; it turned out to be the same
rectangle-fill code as the font glyphs, with a 2-byte header. Look for one compression routine reused for
several kinds of data. Re-encode the originals first and compare. Menu art was in yet another container
(`.rom`), found by searching for the palette of a dumped texture.
- Code: `T/pp15/art/textures.py` (`decompress_page`, `compress_page`, `banks`), `T/_work/menu/make_menu.py`.

### D2. Typeset in the game's own style, then re-pack the page
- Do not squeeze English into the Japanese box (it came out blurry and was rejected). Set the word at its
  natural width, with letters from the official English art where it exists (MLB Power Pros: `references/`)
  or a system font drawn 4x larger and averaged down, and map the ink to the page's **own palette indices by
  role**: fill gradient top to bottom, outline, white band, coloured band, cast shadow, read off the Japanese
  art one palette at a time.
- Then lay out the page again and **re-point the sprite parts** (page, rectangle, offset) at the new
  rectangles. Nothing moves in the file and no size changes.
- Room on the page, not bytes, is usually the limit. What made the match's lettering fit: sharing pieces
  where the Japanese shares them ("Pinch" + Hitter / Runner), storing identical art once, cutting a long word
  across the parts a sprite already has ("ribbon"), and never using a page that no sprite shows (it may be
  drawn by code).
- Keep a fixed baseline and left edge per row; the Japanese pieces are often a pixel or three off, so compute
  per-piece offsets from the sprite's own placement.
- Code: `T/pp15/art/typeset.py` (`typeset`, `ttf_ink`, styles `logo`, `called`, `banded`, `tight`, `repack`, `repack_ribbon`),
  `T/pp15/art/labels.py` (`apply`), specs `T/specs/`, generators `T/_work/ui_pages/gen_*_spec.py`, previews
  `T/_work/ui_pages/tools/after.py`, roles `roles.py`.
- Reusable art: `pawapuro15-wii/labels/` (ours), `references/*/labels/index.tsv` (MLB's, searchable by word).

---

## E. Translating

### E1. Checked batches, one writer
Untranslated unique scenes are cut into batches of 400 to 520 lines; duplicates are filled in afterwards; lines
that repeat hundreds of times get fixed renderings first (presets). One agent per batch with a brief for that
kind of text; it must pass the checker before it stops. Only one collect script writes the shared files.
A pilot of a few batches is read against the Japanese before the run.
- Code: `T/_work/tl_bulk/` (`make_batches.py`, `brief*.md`, `presets.json`, `collect.py`, `view.py`,
  `make_string_batches*.py`, `check_strings.py`, `normalize_strings.py`, `collect_strings.py`).

### E2. Translation memory: reuse whole lines and scenes, not pieces
`pawapuro15-wii/tm/tm.tsv` holds every pair with its scene. Reusing single runs is unsafe: translators move
words between the runs of one sentence. Match whole lines or whole scenes, and give translators the matched
scene as context.

### E3. Voice and terms first
A style guide (voice per character, locked running jokes, terms, names) before the bulk run, and the official
English of the series as the source of terms (MLB Power Pros' `text.tsv` and art).

---

## F. Checking the result

### F1. Let the game play itself and read the frames as text
An auto-player that decides by screenshot (menu recognised by reference pictures and colours), saves a small
frame on every change, and the system's text recognition reads all frames into one line per text box. 3,900
frames of a full scenario became a few thousand lines to read; only frames whose line reads wrong get opened.
- Code: `D/harness.py`, `D/autoplay.py`, `D/ocr/ocr.swift`, `D/ocr/run.py`, `D/ocr/digest.py`.
- Sports games: use the COM-vs-COM watch mode; a watcher saves a frame on every change and presses A only when
  the screen stands still (`D/looks/match/watch.py`). With texture dumping on, the same run proves which sheets
  the match draws.

### F2. Reach any state without playing
Memory codes in the test emulator only (a Gecko code that keeps "scenarios offered" at 3), save-file copies at
useful points, key sequences that wait on the screen. Find the flag by reading the code that sets it.
- Code: `D/GameSettings/RP5JA4.ini`, `D/new_scenario.py`, `D/to_command_menu.py`, `D/nand_backup*`.

### F3. A build that checks itself
Re-read everything that was written and compare with the original under explicit invariants (only these
addends differ, every pointer reads its string, fixed strings unmoved, sizes in the memory plan); refuse to
install on any difference. Each invariant added caught a real bug later.

---

## G. Project rules that saved time

- Prove the source of a screen before translating it (A7). Translate about 20, look in the game, then the rest.
- Report what was seen in game and what was not, every session.
- Game text and art never in a public repository; English keyed by offset and hash (B5).
- On an 8 GB machine: one agent run, build or emulator at a time.
- Edit tool files in a scratch copy and check before copying in (a broken scripted edit was auto-pushed once).
