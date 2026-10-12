# Findings: where the Success Mode dialogue lives

Jikkyou Powerful Pro Yakyuu 15 (Wii, RP5JA4, Rev 1). Static analysis only, no emulator.
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
- `0x7A`–`0x7D` usually precede a line and appear to select the speaker portrait.

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

## Next step toward patching

Lines average 10 glyphs, and English needs two to three times as many characters, so replacing text in place is not enough for a real translation. The scripts have to be rebuilt.

1. **Proof of concept (about an hour).** Replace one line with ASCII glyphs (indices 187–281) using exactly the same number of units, padding with full-width spaces (glyph 0). Nothing moves, so no relocations change. Boot it in Dolphin to confirm the patched line displays. A shorter run cannot simply be cut off, because the leftover halfwords would be executed as instructions.
2. **Script rebuilder (1–2 days including testing).** Re-emit each script region with new text, record old offset to new offset, then update:
   - every relocation addend that points into the region: the label tables, plus about 45 `ADDR16_HA/LO` pairs from code in `scs_main.rel`, `scs_open.rel`, `scs_b_ed.rel`, `scs_item.rel` and `scs_rens.rel`;
   - the section size, and the file offsets that follow it in the REL header (relocation and import tables, `fixSize`).
   The 1–2% of each region the parser does not reach must be carried over unchanged and remapped the same way.
3. **Open questions that need the emulator.**
   - Whether the game's module memory has room for larger `scs_main.rel` / `scs_sce*.rel` files.
   - Characters per line and lines per window (r15+0x1B8 and r15+0x1BA, set at sec1+0x032938). English text has to be wrapped to these.
   - Whether full-width glyph cells make English readable, or a narrower font is needed.

For translation work, `python3 scan_story.py extract --dump` writes every run with its file, offset, page number and window type to `_work/story_text.json`. That file is game text: it is git-ignored and must not be committed.

## Reproduce

```bash
python3 scan_story.py extract      # counts, round-trip check, sample lines
python3 scan_story.py xref         # code evidence (needs capstone)
python3 scan_story.py entropy      # entropy map
python3 scan_story.py scan         # other packed text, compressed data (about 3 minutes)
```
