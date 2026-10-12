# Findings: where the Success Mode dialogue lives

Jikkyou Powerful Pro Yakyuu 15 (Wii, RP5JA4, Rev 1). Sections up to "The same format elsewhere" are static analysis; the patching sections were tested in Dolphin.
Everything here can be reproduced with `scan_story.py` (see the end).

## Answer

The Success Mode dialogue is **on disc, uncompressed, inline in the event scripts**. It can be patched statically.

It was missed before because it is not stored as 16-bit glyph halfwords. It is stored as a stream of **12-bit glyph indices** (three nibbles per character), so a 16-bit scanner sees noise.

| File | Section | Script region (section offset) | Text runs | Glyphs | Pages |
|------|---------|--------------------------------|-----------|--------|-------|
| `scs_main.rel` (common events) | sec5 | 0x0037F8–0x0D086E (820 KB) | 26,019 | 238,578 | 13,008 |
| `scs_sce1.rel` | sec4 | 0x000070–0x0191A4 (100 KB) | 3,378 | 33,782 | 1,769 |
| `scs_sce2.rel` | sec4 | 0x000070–0x03CC0E (242 KB) | 8,624 | 93,115 | 5,369 |
| `scs_sce3.rel` | sec5 | 0x0006E8–0x042D68 (265 KB) | 9,592 | 92,136 | 6,186 |
| **Total** | | | **47,613** | **457,611** | **26,332** |

- A text run is one on-screen line. 1,952 runs are empty, leaving **45,661 lines** to translate.
- A page is one "wait for button" command, so about 26,000 message boxes.
- All 47,613 runs decode and re-encode to the identical bytes, and the parser reaches 98–99% of each script region with no errors. The format is fully understood.

Rough split of the 45,661 lines by window type (the meaning of each type is inferred from samples, not confirmed in game):

| Window type | Lines | Looks like |
|-------------|-------|------------|
| 1–25 | 32,871 | Speech, thoughts, narration, sound effects |
| 26 | 3,217 | Menu choices |
| 29 | 6,847 | Result and status messages |
| 30–31 | 2,726 | Item, ability and place names |

## Format

Scripts are sequences of 16-bit big-endian instructions. The low byte is the opcode, the high byte a small parameter.

**Text mode.** An instruction `XX00` (opcode 0x00) switches the interpreter into text mode. `XX` is the window type (0–31). The text follows immediately:

- Each character is a 12-bit unit, packed back to back. Four halfwords hold five-and-a-bit units: `AAAB BBCC CDDD ...`.
- Units 0x000–0xE9F are the normal glyph indices (same table as everywhere else in the game, see `pawapuro15_text_tools.py`).
- `0xFFE` is a line break inside the run.
- `0xFFF` ends the run. The remaining nibbles of that halfword are padded with `F`, and normal instructions resume at the next halfword. This padding is why the files appear to be "delimited by 0xFFFF".

**Around the text** (inferred from the handlers and from reading decoded scripts):

- `0x46` line break, `0x49` line break and wait, `0x4A` wait for button (end of page).
- `0x4B`–`0x4F`, `0xA5`–`0xA7`, `0xDA` insert a name (player, team mate, and so on) from a runtime buffer. A sentence containing a name is therefore split into several runs.
- `0x7A`–`0x7D` set the portrait of the speaker slot for window types 2–5; the argument identifies the character and expression (`tl.py` maps the ranges seen in scenario 1). `0x73` sets the text colour (high byte), and a run of window type 30 continues the line after a colour change or inserted name.

**Control flow.** Jumps, calls and conditions (`0x9B`, `0x9C`, `0x9D`, `0x9E`, `0x02`, `0x16`–`0x25`) never hold an offset. They hold a **label index**, resolved through label tables in `scs_main.rel` sec5:

- sec5+0x0D0870: three table pointers, one per scenario.
- Each table is 14,101 labels into `scs_main.rel` sec5 (common events) followed by that scenario's labels into `scs_sce1/2/3.rel` (1,051 / 1,588 / 2,484).
- The tables are all zero in the file. They are filled at load time by `ADDR32` relocations stored in `scs_main.rel`.

This matters for patching: every reference into the scripts is a relocation addend, and no relocation is applied inside a script region (scripts hold no raw pointers). Text can therefore change length as long as the addends are updated.

## Evidence in the code (`scs_main.rel` sec1)

| Offset | What it does |
|--------|--------------|
| +0x0356B0 | Opcode 0x00 handler: stores the high byte as window type (r15+0x19C) and sets current opcode to 0 (text mode) |
| +0x034F08 | Text reader: nibble phase at r15+0x1A2 selects which 12 bits to take; `0xFFF` becomes end of text, `0xFFE` becomes a line break |
| +0x033360 | Advances the nibble phase and script pointer after each character |
| +0x0351C8 | End of run: realigns the script pointer to the next halfword |
| +0x05E3F0 | Label lookup: index to pointer through the tables at sec5+0x0D0870 |
| sec5+0x0FF63C | Opcode jump table. `scan_story.py xref` re-derives every opcode's length from its handler and checks it against the parser's table (no mismatches) |

## Corrections to earlier notes

These points in `README.md` / `TECHNICAL_GUIDE.md` do not hold. I have not edited those files.

1. **"Dialogue is assembled at runtime and is not statically patchable."** It is static, as above.
2. **`V+0x911C` / `V+0x91B0` are not dialogue.** They are name fields of a 0x90-byte character record. They are written by `scs_main.rel` itself (name generation at sec1+0x009D90, copying from the surname table at `scc_main.rel` sec5+0xC0; also sec1+0x036EAC and +0x037078). The "scene setup" function at sec1+0x033068 copies them with the 6-glyph name copier, and is called only from `scs_open.rel` and `scs_titl.rel`. No other module touches these offsets.
3. **The 5.5 MB BSS is not `scs_sce2`.** Module 347 is `sct_main.rel` (BSS 5.72 MB). `scs_sce2.rel` is module 320 with a 27 KB BSS. Nothing is unpacked into it.
4. **The "empty" 185 KB region at `scs_main.rel` sec5+0x0D086E–0x0FED8E is not free.** It is the label tables (47,426 pointers written by relocations at load time). Hook code or a translation table placed there would be overwritten.
5. **`scs_main.rel` sec5+0x0037F8 onward is script, not a 40-byte string table.** 1,965 of the 2,088 `scs_main.rel` entries in `translation_high_quality.json` fall inside the script region and are misreads of packed text. Writing 16-bit strings at those offsets would corrupt the scripts.
6. **Several opcode lengths differ** from the guide: `0x26`–`0x45` are 3 halfwords, `0x16`–`0x25` are 4, `0x9B`/`0x9C` are 2, and `0x02` and `0x6E` are variable length.

## Compression and entropy

- The script regions measure 6.0–6.3 bits per byte with no 16 KB window above 7.5. Compressed data would be close to 8.
- No Yaz0, LZ10 or LZ11 stream decompresses cleanly anywhere in `DATA/files`. Video (.thp), sound data (.rsd) and the `sound/` folder were skipped; `scan --all` includes `sound/`.
- The high-entropy files are graphics and audio: 84 `.arc` files, `sound/WaveData.bin`, the `.vas` music streams and `opening.bnr`.
- The per-glyph scheme in `decompress_glyph.py` is specific to font bitmaps and was not tried on other data.

## The same format elsewhere

A heuristic search of all files (it undercounts, by roughly 30% on the files above) also finds 12-bit packed text in other modes. These were not parsed:

| File | Runs found (lower bound) |
|------|--------------------------|
| `orepena.rel` | 3,106 |
| `sct_main.rel` | 2,224 |
| `scs_comi.rel` | 177 |
| `gdt_pn.rel` | 50 |
| `koukai.rel` | 39 |
| `are_main.rel`, `pennant.rel` | about 10 each |

A few `.arc` files and `fonttex2.rel` show 1–4 hits each, which are most likely chance matches.

## Sample lines

| File | File offset | Text |
|------|-------------|------|
| `scs_main.rel` | 0x0CAE18 | あいよ、また来てくれよなっ！ |
| `scs_main.rel` | 0x119028 | 結構大変なんだねー！ |
| `scs_sce1.rel` | 0x000ADE | 身体には気をつけるんだよ。 |
| `scs_sce1.rel` | 0x00A760 | やっぱり高かったでやんす。 |
| `scs_sce2.rel` | 0x0177DE | おいそこのお前。 |
| `scs_sce2.rel` | 0x03889C | なめてんのかぁ？ |
| `scs_sce3.rel` | 0x00CBB2 | え・・・っと、盛田さん？ |
| `scs_sce3.rel` | 0x02358C | もう腕がパンパンだ。 |

## Patching: what works (tested in Dolphin)

`rebuild_scripts.py` rebuilds the scripts with text of any length.

- `check`: rebuilding with no changes gives byte-identical files for all four script modules, and all 2,125 relocation streams in the 476 modules re-encode exactly.
- `build`: re-emits the script, then moves every reference: relocation addends in all modules, relocation positions inside the rebuilt section, the REL header, and the module's entry in `moduleID2addr.o`. It re-reads its own output and compares scripts, labels, text and relocations with the originals before installing.
- Tested: the first Success line (`scs_sce1.rel` +0x623C, 9 glyphs) and the line after it replaced with 17 and 15 glyphs. Both display, and the story continues normally. A second build that also moved all of `scs_main.rel` by 72 bytes ran 50 pages deep (scene changes, portraits, name insertion). That run predates the memory-plan fix below and only worked by luck; the same change was re-tested properly afterwards.

Things learned on the way:

- **The dialogue box is 17 glyphs wide and 2 lines high** (window type 29). A longer run wraps by itself; a third line scrolls the first one away. The font only has full-width Latin, so English needs the pair font described below.
- **Success Mode needs a Nunchuk, Classic Controller or GameCube pad**, and its menus read the stick, not the D-pad.
- The intro narration before name entry (「小さいときから野球が好きで…」) is not in the four script files and was not found as 12-bit, 16-bit or Shift-JIS text anywhere in `DATA`.

## The memory plan (the real limit)

The game does not allocate memory for modules. `/moduleID2addr.o` (an ELF object on the disc, opened by `main.dol`) holds three tables of 477 entries: `moduleID2addr`, `moduleID2size` and `moduleID2relFileSize`. Every module is loaded at its fixed address, and the game reads exactly `moduleID2relFileSize` bytes of the file. The table index is the game's own module number, not the REL id.

- `moduleID2size` = fixSize rounded up to bssAlign (0x80), plus bssSize.
- A grown file that is not entered in the table is read short. The end of its relocation table is then garbage (`OSLink: unknown relocation type` in the log, then a null-pointer crash).
- The plan covers 0x8030D5A0..0x812CB794, and modules that are never loaded together share addresses. MEM1 ends at 0x817F9580.

| Module | Address | Memory | Next module | Room to grow |
|--------|---------|--------|-------------|--------------|
| `scs_main.rel` | 0x807FC200 | 0x363678 | scenario modules at 0x80B5F880 | 8 bytes |
| `scs_sce1.rel` | 0x80B5F880 | 0x24980 | `scs_load.rel` / `scs_face.rel` at 0x80BBD200 | 233 KB |
| `scs_sce2.rel` | 0x80B5F880 | 0x4A280 | same | 79 KB |
| `scs_sce3.rel` | 0x80B5F880 | 0x5D980 | same | 0 |

**Free memory.** `main.dol` (0x8003A938) raises the OS arena to 0x814E0000, so everything below that address is reserved for modules, and the plan stops at 0x812CB794. The 2.1 MB in between is unused: it is all zero in memory snapshots from the main menu, name entry and 50 pages into the story, and nothing in `main.dol` or any module addresses it during play (only the SDK reset/exec code uses 0x81280000..0x81330000, when the game is shutting down).

`rebuild_scripts.py` uses this. When `scs_main.rel` needs room, it moves the scenario slot to 0x812CB800 in the plan and lets `scs_main.rel` grow into the old slot:

| Module | Room to grow (original plan) | Room to grow (scenario slot moved) |
|--------|------------------------------|------------------------------------|
| `scs_main.rel` | 8 bytes | 383 KB |
| `scs_sce1.rel` | 233 KB | 1.9 MB |
| `scs_sce2.rel` | 79 KB | 1.8 MB |
| `scs_sce3.rel` | 0 | 1.7 MB |

Tested: `scs_main.rel` grown by 328 KB and `scs_sce1.rel` by 384 KB, loaded at the new address, no loader errors, 50 pages of story played. Not tested yet: scenarios 2 and 3, a match inside Success Mode, saving and loading a Success game, real hardware.

**Is 383 KB enough for `scs_main.rel`?** Not at one letter per unit: its text is 358 KB (238,578 glyphs at 12 bits) and English needs 2 to 2.5 times as many letters. The pair font below removes the problem.

## The pair font (tested in Dolphin)

`pair_font.py` draws **two half-width letters into one glyph cell** and stores the pairs in kanji slots. English then takes one text unit per two letters: about the size of the Japanese, and no game code changes.

- `fonttex2.rel` section 4 holds two complete fonts with the same 3,744 glyph numbers: a small one at +0 (16x17 pixels used, shades 8 = ink to 15 = background) and the large outlined one the dialogue uses at +0x05DF64 (22x28, shades 1 = ink, 9 = outline, 15 = background). A third set of 68 glyphs follows at +0x117400.
- Format: `u16 0, u16 count, u32 offsets[count]` (little-endian), then the compressed glyphs. Repacking the originals is byte-identical and all 7,488 glyphs survive decompress/compress, so the format is fully understood (`rebuild_scripts.py check`).
- A build collects the letter pairs the translation uses and gives each a kanji slot, least used kanji first (usage = untranslated script text plus a scan of all other modules; `namein.rel`, the name-entry kanji picker, is ignored). Both fonts get the pair, drawn from Menlo Bold, stretched to 11x28.
- Pair glyphs compress smaller than kanji (about 164 against 219 bytes in the large font), so `fonttex2.rel` keeps its size even with every kanji slot replaced.
- **A dialogue line is 17 cells: 34 letters.** Longer lines wrap. The letterbox narration of the opening shows 2 lines; speech bubbles (window types 2 and 4, measured) show 3, and one more line scrolls the first away. The build warns about long lines.
- Pairs restart at every run, line break and Japanese character. When a sentence is split into several runs on one line (colour changes, inserted names), give the earlier run an even number of letters or a half-cell gap appears.
- Tested: the opening scene of scenario 1 (36 lines, 20 boxes) in English, 210 letter pairs. Plain, outlined and coloured text all draw correctly; untouched Japanese text is unaffected. The 36 lines made the script 80 bytes longer.

Still open: the player and team-mate names inserted into sentences are Japanese (name entry and the name tables are not translated), and window types other than 29 have not been measured.

## Testing notes

- A Dolphin save state also holds the disc's file table. After any build that changes a file size, boot from scratch; an old state reads files from the wrong place.
- A state taken inside Success Mode keeps the old scripts in memory.

## Reproduce

```bash
python3 scan_story.py extract      # counts, round-trip check, sample lines
python3 scan_story.py xref         # code evidence (needs capstone)
python3 scan_story.py entropy      # entropy map
python3 scan_story.py scan         # other packed text, compressed data (about 3 minutes)
python3 rebuild_scripts.py check   # round-trip test of the rebuilder
python3 rebuild_scripts.py build   # apply _work/translation.json and install to DATA/files
python3 rebuild_scripts.py restore # put the original files back
python3 ram_scan.py STATE          # loaded modules and memory map from a Dolphin save state
python3 tl.py export|apply|merge   # translation workflow: scenes out, English in translation/*.tsv
```
