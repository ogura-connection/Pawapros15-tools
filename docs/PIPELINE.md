# Translating a console game: the pipeline that worked for Pawapuro 15

Each step names the Pawapuro file that does it (`T/` = `~/Projects/Pawapuro/Pawapros15-tools`, `D/` =
`~/Projects/Pawapuro/dolphin-test`) and the traps that cost time. Steps 1 to 4 are reverse engineering and
are different for every game; steps 5 to 9 are mostly the same everywhere. The techniques behind each step,
and how to recognise when a new game needs them, are in `TECHNIQUES.md`.

## 1. Get the files and a test emulator

- Extract the disc to files (`T/extract_from_iso.py`; for Wii/GameCube Dolphin can also extract). Keep the
  disc images and extracted files outside any repository that syncs.
- A separate emulator profile for tests, driven from the shell: start, send keys, take screenshots, load
  states (`D/harness.py`). Make every step wait on what the screen shows, never a fixed time
  (`D/to_command_menu.py`). Run at a fixed speed that does not repeat key presses (Dolphin: OpenGL at 4x).
- Save states hold the old files and textures: after a build, boot from scratch.

## 2. Find every store of text

Typical stores: script/dialogue text (often packed or compressed), fixed-size string tables in code or data,
message scripts with control codes, system dialogs in the main executable, lettering drawn as pictures in
textures, videos. In Pawapuro there were five (FINDINGS.md lists them); the painted lettering was the largest
by count of items.
- Decode the glyph table first (`T/pawapuro15_text_tools.py`), then scan every file for runs of valid text
  (`T/extract_all_text.py`, `T/scan_story.py scan`), and measure: how many runs, in which files, which mode
  (`_work/inventory_text.json`). Survey the art by machine: render every texture page and read it with text
  recognition (`T/_work/ui_pages/tools/art_survey.py`).
- **Prove which copy the screen draws** before translating: the same words often exist two or three times
  (a string table, script constants and a sprite; an identical sheet in a second file). Dump the textures the
  emulator loads on that screen and match them against the decoded pages (`D/looks/first/steps.py`,
  `T/_work/ui_pages/tools/match_all.py`), or search a RAM dump for the glyph numbers.

## 3. Learn the formats well enough to write them back

- Scripts: find the interpreter loop, derive opcode lengths, so the text can be re-laid and its pointers
  re-aimed (`T/scan_story.py`). Check by round trip: decode, re-encode, compare byte for byte (`T/rebuild_scripts.py check`).
- Memory is usually the real limit, not file size: find what the game loads where and how much room is free
  (`T/ram_scan.py`). When a module cannot grow, re-lay its text inside its own bytes or spill into a free
  region of another module that is always loaded (My Life's annex).
- Fonts: if the font is fixed-width kanji cells, two Latin letters per cell doubles the room
  (`T/pair_font.py`); count which kanji the remaining Japanese still needs before taking cells.

## 4. A build that refuses to install anything wrong

`T/rebuild_scripts.py build`: write every store, then re-read the built files and check them (every pointer
reads its string, nothing outside the changed regions moved, counts match), and only then install. Keep
originals untouched (`_work/orig*`). Every check that was added caught a real bug later.

## 5. Decide the voice before translating

A style guide with each character's register, tics and first person, locked renderings of running jokes,
a glossary of terms, and rules for names and honorifics (`T/TRANSLATION_STYLE.md`; the method came from
Conrad's srt-pipeline, `docs/ja-to-en.md`). Use the official English of the series where it exists
(MLB Power Pros here: `references/`). For a new game, first match against an existing translation memory.

## 6. Translate in checked batches

- Cut the untranslated, unique text into batches of 400 to 520 lines, scene by scene, with duplicates filled
  in afterwards (`T/_work/tl_bulk/make_batches.py`). One agent per batch (Sonnet, medium effort, about 125 to
  160k tokens and 5 to 8 minutes a batch); a brief per kind of text (`brief*.md`); the agent must pass the
  checker before it stops (`pp15 script check`, `check_strings.py`): line counts, length limits, codes kept in order.
- Agents never write the shared English files: one collect script stores the batches one after the other
  (`collect.py`), because parallel writers lose data.
- Pilot first: 20 lines, look at them in the game, then the rest. Normalise terms across batches before storing
  (`normalize_strings.py`).
- On an 8 GB machine: one workflow at a time, about 4 to 6 agents, no build or emulator while they run.
- Traps: editors strip trailing spaces (write `\_`), a decoded line break may be the two characters `\n`,
  strings can start with header numbers that decode as glyphs (check the pointers into the table).

## 7. Painted lettering

- Typeset English in the game's own style rather than squeezing it into the Japanese box: take letters from
  the official English art where it exists, or a system font rendered large and averaged down, then map the
  ink to the page's own palette indices by role (fill gradient, outline, white band, shadow), read off the
  Japanese art (`T/ui_type.py`, `T/_work/ui_pages/tools/roles.py`).
- Re-pack the page and re-point the sprite parts at the new rectangles instead of keeping the old ones
  (`T/ui_labels.py`, specs in `T/specs/`, generators in `T/_work/ui_pages/gen_*_spec.py`).
- Space on the page, not bytes, is usually the limit. Share pieces the Japanese shares, cut long words across
  a sprite's parts, keep fixed baselines and columns.
- Quality bar: crisp single-colour borders, no blur from scaling, checked at 4x against the Japanese.

## 8. Read the result back as text

Let the game play itself (`D/autoplay.py`: menu choices by screenshot; for sports games the COM-vs-COM watch
mode, `D/looks/match/watch.py`),
save a small frame on every change, read all frames with the system's text recognition (`D/ocr/run.py`,
`D/ocr/digest.py`: 1,000 frames become about 700 lines), and open only the frames whose line reads wrong.
Cheap enough to do after every build. For states normal play would take hours to reach, use memory codes in
the test emulator only (`D/new_scenario.py`).

## 9. Keep the project restartable

A handoff note per session (what is done, what was seen in game and what was not, next steps in order), a
findings file per discovery, and memory notes for the rules. Report plainly what was seen in game.
Keep game text and art out of public repositories: English keyed by file and offset, Japanese only in ignored
folders and in this kit.
