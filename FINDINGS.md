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

## UI graphics (import works, first labels patched)

The `.arc` files are not archives. Except for `RFLRes01.arc` they are ELF objects with full symbol tables, and their `.data` holds sprite banks: `tex_*` (textures), `pal_*` (palettes), `opd_*` (sprites) and `*_tbl` pointer lists. Most textures are 8,192 bytes: 128x128, 4 bits per pixel, GX 8x8 tiles, uncompressed, with RGB5A3 palettes (16 colours each); 16,384-byte pages are 8 bits per pixel. An `opd_` is a 10-byte header (byte 0 = number of parts) followed by that many 10-byte parts: page, palette, offset on screen (s16 x, y) and the rectangle on the page as y0, x0, y1, x1. Page numbers count the `tex_` symbols of the bank in file order (not the digits in the names). `ui_textures.py` exports pages, lists parts and writes a page back in place (`import`, same offset and size, existing palette); `ui_textures.py check` re-encodes all 1,557 uncompressed pages and every file comes back byte-identical.

**Compressed pages.** A `tex_` symbol of any other size is the same kind of 128x128 page, packed. There are 8,590 of them against 1,557 plain ones, so most of the game's sprite art was invisible to the tools until this was decoded (10,125 pages in 329 files now export). Format: a 16-bit little-endian header (low 13 bits = number of flag bytes; bit 14 set = 4 bits per pixel in rows of 64 bytes, clear = 8 bits per pixel in rows of 128 bytes), the flag bytes, then the literal bytes, padded to 16 bytes. The page is stored as plain raster rows, not GX tiles. Going left to right and top to bottom, every byte not yet covered takes one flag bit: 0 = one literal, 1 = a rectangle of up to 19x19 (width and height as 2 bits for 1..3, or `00` + 4 bits for 4..19) filled with one literal. It is the code the font glyphs use (`pair_font.py`), with a 2-byte header. `ui_textures.decompress_page` unpacks all but 22 pages (16,400 bytes each, another format, in `m4bg`, `m7bg`, `npn_dum3` and a few more). `compress_page` covers the page with rectangles largest first, which is what Konami's packer appears to do: the result is within 0.1% of the original size (not byte-identical: the tie-breaks differ), and every repacked page unpacks to the same picture. A changed page has to fit the bytes of its symbol; `ui_labels.py apply` stops if it does not. The first untouched copy of any `.arc` it or `ui_labels.py` writes to goes to `_work/orig_arc/`.

`ui_labels.py` + `ui_specs/*.json` put English lettering into those pages, in two ways.

1. Cut a finished MLB label and fit it into the Japanese label's rectangle (the stat labels). Its pixels are sorted into roles (letters, ring, edge); where the slot is narrower than the word, the least important columns are removed, never averaged, so there is no blur. Works when the slot is about as wide as the word; below that the letters lose detail (TRJ, FLD and Position are still squeezed this way).
2. Typeset and repack (`ui_type.py`): the command words and HUD tags. The MLB command-word sheet stores its letters as a brightness ramp, so letters cut from it keep their soft edge (6 ink levels) and look like the Japanese ones. A word MLB drew is used whole; other words are set from single MLB letters. An English word is wider than the Japanese label (練習 is two characters, Practice is 61 pixels against 37), so the labels of a page are laid out again at their natural width and the sprite parts are pointed at the new rectangles: page, rectangle and offset of the 10-byte part are rewritten in place. Nothing moves in the file and no size changes. The new label keeps the old one's centre and baseline.

A label is addressed by its rectangle or by its sprite (a pitch name is one sprite drawn from up to three shared pieces of kana: its first part gets the English name, the others an empty cell). Lettering that is part of a plate (the 天気予報 header) is repainted in place. Three sources of letters, in this order of preference: MLB art (stat labels, command words), MLB letters set into new words (command font), and for styles MLB has nothing in: a pixel font drawn for the patch (`TAG_GLYPHS`, 11 pixels high, for the small tags and the pitch names) and system fonts rendered at 4x and averaged down (Arial Rounded Bold, Times New Roman Bold Italic) for anything larger.

Done: scs_main.arc 75 labels on 15 pages, 88 sprite parts re-pointed; scs_rens.arc 51 labels (practice menu names, Injury, Rating, and the 30 training-gear names of bank `y5_rkz_0`, which sit on four compressed pages) (command bar, HUD tags, stat labels at natural width with the four trajectory arrows moved to a free strip, 29 pitch names, date units, weather, forecast); scs_sce1.arc 4 labels (rank plate). The wording is listed in TRANSLATION_STYLE.md. What is left, sheet by sheet, is in `_work/ui_pages/label_table.md` (not in git).

**Data screen (2026-10-12).** `ui_specs/scs_data.json`: 125 labels on 19 compressed pages of `scs_data.arc` (banks `z3_dt_0` personal page, `z3_dtn_0` team-mate list, `z3_dts_0` screen titles, buttons, form names and trait plates, `y5_mh_0` ratings page). `ui_specs/scs_sys.json`: the 67 labels of the System screen's own copy of `z3_dts` in `scs_sys.arc`. A texture dump taken on every tab matched `scs_data.arc` for all of this; the ability plates on the same screen are `are_abi.arc`, bank `g3_tn00`. What the tools learned for it:

- A sprite that also draws a plate or an icon: `"pages"` / `"palettes"` say which of its parts are lettering (tabs, trait plates with the bomb and the heart). `"layers": 2` is a sprite that draws its lettering twice (the screen titles: a blue shadow copy under the coloured one). `"pieces"` sets one label from several parts with a palette each (the handedness tags, where every letter has its own colour). `"align": "right"`, and `\n` in a text for two lines.
- New styles in `ui_type.py` (`data*`, `title22`..`title28`, `rater147`..`rater150`), each read off the Japanese art: which palette index is outline, band, glow and fill. The screen titles and the rater names use a different order of colours in every palette.
- **A compressed page has to fit its slot, and English lettering packs no smaller than kanji.** One group per bank, with every free rectangle of every page as an area, spreads the labels; the order of the areas decides which page fills first. `apply` stops when a page does not fit.
- `scs_sys.arc` stores the sprites of a bank behind its palette (everywhere else they stand in front of the pages), so `ui_textures.banks` files them under the next bank: the 85 sprites of `z3_dts_sys_0` appear as bank `z3_dts_sys_0_opd` with the 6 pages of `z3_sys`. A repack group names them with `"sprites"`.
- Handedness is shown the English way, bats / throws (`B/T`, as in MLB Power Pros), so 右投左打 is `L/R`.

Seen in game: all four tabs of the personal page, the equipment page, the five tabs of the team-mate list with their column headers, the ratings page, the screen titles My Data / Teammates / Ratings, and Save & Quit / Give Up on the System screen. Not seen (nothing in the save shows them): the trait plates, forms other than Overhand, the player types, Growth, Cond., Kantoku, Scout, the titles Schedule / Equip / Item List / System.

Still Japanese in these two files: the first-team / second-team banners and tags, 一級 / 二級 / 三級, the 継 and 主 marks (meaning not confirmed), the equipment-change page (`z3_ikp_0`: 変更前 / 変更後, stat names, pitch families), league and pro team names (`z4_dtj_0`), and the settings list of the System screen (`scs_sys.arc`, pages `tex_z3_sys`, about 30 labels in 11 palettes). Position plates (投) and person names on the team-mate list come from other files.

**Ability plates (2026-10-12).** `ui_specs/are_abi.json`: the 248 names of bank `g3_tn00` in `are_abi.arc`. Its 30 pages are not compressed, so there is no byte limit, but there is a limit of rows: with 11-pixel capitals the names no longer fit the pages. Arial Narrow Bold in one weight (a bolder cut closes up the i and l of long names): 10-pixel capitals where the name fits in 68 pixels (151 names), 9 pixels and squeezed for longer ones, two lines for 17. Wording: the term sheet for the book abilities, MLB 2008's plate sheet for roles and day / night / home / road, the rest worded for the patch (TRANSLATION_STYLE.md). Seen in game: 17 plates (the pitcher and fielder pages of the player, Consistency and Starter on the team-mate list). Not seen: the other 231, and the Boost screen, where the "Remove ..." plates belong. The other banks of the file (colour names, pitch names, profile labels: `z3_it_0`, `m3_an`) are untouched.

**Shop and item list (2026-10-13).** `ui_specs/scs_item.json`, written by `_work/ui_pages/gen_item_spec.py`: 17 labels of bank `z3_shp_0` in `scs_item.arc` (six tabs, the two Shop titles, Money, the Info hint, Cancel, the `x1 Buy` / `x3 Own` tags, Sold Out!, three larger tabs), the two plates Bought / Owned, and 22 gear names of bank `m4_item1`. A texture dump in the shop matched pages 0-6 and 8 of `z3_shp_0` (page 7 is the "bargain" picture). The item list (Items > List) and the pop-up of the Equip page are not in that file: their tabs and headers (消費アイテム, その他, 装備中, アイテムリスト) are bank `z3_itw_0` of `scs_main.arc`, now a group of `ui_specs/scs_main.json` written by the same generator.

- The shop opens in the Items submenu from November of year 1; nothing offers it in week 1. `dolphin-test/to_command_menu.py resume shop` continues from a save made there (`nand_backup_shop/`). The tabs of the shop and of the item list turn with the D-pad alone (`harness.dpad`).
- Lettering baked into a plate (購入済, 取得済): `"paint"` takes `"copy"` (the same plate with nothing on it, from the original file) and `"style"`.
- New styles in `ui_type.py`: `shoptab`, `shopmoney`, `shopcancel`, `shoptag`, `shophint` (`boxed`: white on a black box), `shoptitle` and `shopsold` (`logo`: gradient letters, outline, white band, rim, cast shadow), `gear`, `itemtab`.
- A tab of the shop is about 60 pixels wide and the Cancel button 40: the icon tabs are set 11 pixels high at 0.9 width, Cancel 9 pixels high.
- Seen in game: every label of the shop screen except Owned (取得済) and the three larger tabs of page 6 (All Items / Accessories / Other: no screen that draws them was found); Consumables / Other on the item list, Equipped / Item List on the equip pop-up. Also seen for the first time: the titles Schedule, Equip and Item List, item effect lines, "use it? Yes / No".
- The gear names of `m4_item1` (ノーミス ... 達人ス, 40x40 sprites filed among the item icons) were not drawn anywhere: not in the shop, the item list or the Equip page, also with a No-Miss Glove bought and equipped. The set is not this game's gear list (no Control, Liner or Brute bat), so it is probably left over from an earlier game. They are English anyway (term sheet names without the Bat / Glove / Spikes / Ball); 見返り has no item here and keeps its Japanese. The five arrows next to them are pictures.
- The clerk's greeting (いらっしゃいませ〜！) is dialogue in the script of `scs_main.rel`, not a string of `scs_item.rel`.

**System settings list (2026-10-13).** Second group of `ui_specs/scs_sys.json` (written by `gen_data_spec.py`): 33 labels on pages 2-5 of `tex_z3_sys` (filed as bank `z3_dts_sys_0_opd`), sprites `opd_z3_sys_0` (filed as bank `z3_sys_0`). Row names in palette 161, values in 162-170 (one colour each: the same piece is drawn grey or red), 難度 in 160. Most Japanese labels come in two pieces across a page edge. The English is set whole in one piece and the other becomes `{"from": [...], "empty": true}`: its parts are pointed at an empty cell and its rectangle is free again, which is what makes room (a label cannot be wider than a page, 128 pixels, so the row names are 12 pixels high at 0.8 width). ウインドウなし and ウインドウあり share their first 64 pixels on the page; both rectangles are labels of their own. Values that the game puts at a fixed x keep the centre of the Japanese (the two halves of `No Window / Window` are centred in their columns), Set / Not Set keep the right edge. ON / OFF were English already. Seen in game: the six row names, Type A, Rumble Off, No Window, Window, Set, Difficulty, Normal. Not seen: Type B, Rumble On, Not Set, Pitcher View, +Control Pad, Control Stick, L Stick, Rookie. Still Japanese behind this list: the controller diagram that In-Game Controls opens (操作 / 振動, OK / Aタイプ / しない and every caption of the drawing; banks `y5_sysx1`..`4` and page 1 of `z3_sys`) and the voice screen (音声設定, 選択タイプ / 入力タイプ / キャンセル, from another file).

**The schedule strings move (2026-10-13).** The 24 strings of the schedule (`scs_data.rel` sec5+22308..22752, 444 bytes) stand back to back, 4-byte aligned, and each is reached through one `R_PPC_ADDR32` of a pointer table of 25 entries at sec5+22752 (the first points at an empty string in front of the block). `ui_strings.BLOCKS` names such a block; `rebuild_scripts.py build` lays its strings out again without the alignment, rewrites the 24 addends in the relocation stream, and checks that every pointer reads its string. `verify` takes the changed addends as the only relocations allowed to differ. A string that is the end of another shares its cells: 日本選手権予選決勝 points into the middle of "Exam, Japan Champ Qual Final" (the shared part has to start on an even letter). With that the block is exactly full: 199 cells and 23 terminators in 222. One entry may be 15 cells (30 letters) wide before it reaches the game icon. In game: 15 of the 24 entries seen, the shared one among them; pointers to addresses that are not multiples of 4 work. 月 and 週 of the date column are two strings of one cell each (sec5+13824, +13828; `SHORT_TEXT` in `ui_strings.py`): now `Mo` and `Wk`, as on the HUD.

**Leftovers of scs_main.arc and scs_data.arc (2026-10-13, second session).** Groups written by `_work/ui_pages/gen_main_spec.py` (groups `captions` and `positions` of `ui_specs/scs_main.json`) and `gen_data_spec.py` (banks `z3_ikp_0` and `z4_dtj_0` of `ui_specs/scs_data.json`).

- Scene captions (`r3_ai`, palette 160, style `caption`): After Practice, Next Day, A Few Days Later..., Tournament Day, Fateful Draft Day... One sprite part shows at most a page width (128 pixels) and a sprite cannot gain parts, so a one-part caption is at most 128 pixels wide (After Practice sets the size: 17-pixel capitals at 0.77 width) and the longer ones are set in two `"pieces"`. The month banner (`r3_ai` page 17, nine sprites sharing one 月) is `Mo` after the game's own numeral (style `month`).
- Position words (`y5_np_0` pages 3 and 7, palettes 32-35, style `position`): Pitcher, Catcher, 1st / 2nd / 3rd Base, Shortstop, Outfield, and P, C, 1B, 2B, 3B, SS, OF in two sizes, on a fixed `"baseline"` (一 is six pixels high, so its own box gives no baseline).
- Before / after panel of the Equip page (`z3_ikp_0`): Before, After (style `equipbefore`), ten stat names and six pitch families (style `equipstat`). A family sprite also draws its arrow, so its lettering is addressed by rectangle.
- Standings (`z4_dtj_0`): the league plates are two pieces of one plate side by side (prefix box 44 pixels, `League` 36, style `plated`: letters on the plate colour), 18 team names in the Japanese short forms (Giants, Chunichi, Hiroshima, Yakult, Yokohama, Hanshin, Rakuten, Nippon-Ham, Seibu, Orix, Lotte, SoftBank, Powerfuls, Kaisers, Cathands, Yankiis, Vulcans, Busters). レ・リーグ is taken to be the Revolution League (`Rev. League`): from memory of the series, not checked in this game.
- **Anti-aliased English packs worse than two-tone kanji.** The team names with seven ink levels needed 4,145 bytes on a page with a 2,560-byte slot. Two grey levels (style `team`, as the Japanese has), the names spread over three pages and the fullest page filled last made it fit; the league plates needed the same cut.
- Seen in game: Next Day (at its first, smaller size), Before / After / E RES on the Equip page (buy a second glove in `resume shop`: select it, then move to OK with LEFT, UP; B or Cancel drops the purchase). Not seen: the other four captions, Mo, the larger Next Day, every position word (the test player is a pitcher and his main screen shows the pitch chart), the other stat names and the pitch families of the panel, the whole standings screen.
- Not done, with the reason:
  - Banners `z4_tem_0` (降格 昇格 開始 合格 不合格, オリジナル変化球取得！) and `z4_smj_0` (1軍昇格, 2軍降格, プレーオフ開幕): one kanji per sprite, placed by code. An English word has to be cut over those sprites, and that needs their spacing on screen; no table with it was found in `scs_main.rel`, and no save reaches one of them.
  - Bench sheets `z4_sod_0` / `_1` / `_2`: each is one 512x360 picture cut into 12 compressed pages, with the headings (ベンチ入りメンバー表, スターティングオーダー, 打順 選手名 守備, 控え野手, 控え投手, 投球) painted on a gradient and running across page edges. `"paint"` works on one page; this needs painting across pages. About 3 hours for the three copies. Shown before a game; no save reaches one.
  - Units `z3_fos_0` (年 月 日 円 next to thin digits): which screen draws them is not known, so there is nothing to word them against.
  - `scs_data.arc`: the 1軍 / 2軍 banners and tags (`z3_dtn_0` pages 6 and 7, gradient italic lettering), 日本一 (`z4_dtj_0` page 5), 一級 / 二級 / 三級 and 継 / 主 (not located on a sheet yet).
- Seen while playing on and still Japanese, from other files: the practice result screen (スタミナUP, the point letters 筋 敏 技 変 精), the result lines 疲れがたまった / やる気がなくなった / 15000円消費した, and the パワプロ15 strip of the month change (a logo: stays).

Testing: a save state keeps the textures it had loaded, so a state taken inside Success Mode shows old labels. The fast loop is an in-game save instead: `dolphin-test/to_command_menu.py resume` loads the main-menu state, enters Success Mode and continues from a save made at the command menu, so every file is read again. About 35 seconds with `harness.py start --speed 0` (no speed limit). Resuming rewrites the save, so the script restores a copy first. `to_command_menu.py new` plays a new game up to the menu (about 2 minutes).

Tested in Dolphin this way: HUD, command bar, Free Time and Items submenus, forecast pop-up, rank plate, practice menu, one work turn. Not tested: the fielder stat labels (the test player is a pitcher), pitch names other than Fastball, Kakaricho/Kacho plates, Fired Up!, Hospital / Date / Game / Treat / Shop / Jobs (not reachable in week 1).

## UI strings: menu and system text outside the scripts (tested in Dolphin)

Tooltips, system-screen help, title-screen help, rating comments and tips are not script text. They are plain tables of big-endian 16-bit glyph numbers in the data sections of the modules: each string sits in a slot of fixed size, padded with glyph 0 (a full-width space) and closed by 0xFFFF. The command tooltips of `scs_main.rel` (sec5+0x3328, before the script) are 18 cells + 0xFFFF + 0 = 40 bytes each. Multi-line strings have no line-break code: the box wraps at a fixed width and the Japanese pads every line with spaces (system help 2 x 18 cells, title help 2 x 16, rating comments 2 x 14, tips 3 x 17).

`ui_strings.py` lists them (`export`, Japanese to `_work/strings/`), keeps the English in `translation/strings/<file>.tsv` (section, offset, hash, English; `|` = new line, padded by the tool) and `merge` writes `_work/strings.json`. `rebuild_scripts.py build` writes each string into its slot with the pair font: two letters per cell, so a slot of 18 cells holds 36 letters. Nothing moves and no file grows. The pairs share the kanji slots with the dialogue, and the kanji of string tables that stay Japanese are counted as in use.

Counts (text strings; tables of numbers that only look like strings are left out): `scs_main.rel` 117, `scs_sys.rel` 63, `scs_rens.rel` 71, `scs_titl.rel` 4, `scs_end.rel` 35, `scs_data.rel` 181 (condition notes, rating comments by 23 characters, schedule entries, a table of rater names), `scs_item.rel` 1,163 (four parallel tables over 239 items: names, effect lines, the shop clerk's comments, result messages), and `main.dol` 264 (system dialogs, below). Translated: 1,808 (1,544 in the modules plus the 264 dialogs). Left: the rater name table (6, person names stay Japanese for now), `scs_end.rel`, and the glyph grids of the other files.

Seen in game: command tooltips, title help, system help (Tamano and dog variants); the save prompt and the give-up warning (`main.dol`); on the Data screen the team-mate comments, Tamano's and the bucho's rating and the schedule (`scs_data.rel`); the item list with names and a description line (`scs_item.rel`). Not seen yet: tips, the confirmations, the other helper voices, the shop (clerk's comments, result messages), item effects, most rating comments, and nearly all of the 264 dialogs.

After the first real rebuild of `scs_main.rel` (script 8 bytes shorter) the 54 strings that sit behind the script were checked in the built file: each is at its shifted place and closed by 0xFFFF, and the 1,323 relocations that point into the data behind the script have the same targets once shifted (19 of them point at these strings).

Found on the way:
- The equipment names shown in the practice menu (タオル ...) are **lettering on sprite pages**: `scs_rens.arc`, bank `y5_rkz_0`, 30 sprites on four compressed pages. They are neither the `scs_rens.rel` table nor the script constants of `scs_main.rel`; both of those were translated first and the screen did not change. The `scs_rens.rel` table (`Ｌｖ１　鉄ゲタ` ...) is still used: the length of its string, padding included, sets how wide the name plate is. Room for the name is about 12 x (Japanese characters) + 19 pixels, so an English name cannot be wider than that (Iron Geta 50 of 55; "Soothing Music" ran into "Injury" and became "Calm Music").
- The window type 30 runs of `scs_main.rel` are not a menu table. 1,410 of them hold text: 831 stand in scenes of their own (names of gear, teams, positions, tournaments, ranks, plus particles such as が and 【 that sentences are assembled from), the rest are pieces of dialogue lines. They matter for sentences ("you got a ..."), not for menus.
- How the source of on-screen lettering was found, for next time: turn on `DumpTextures` in the test Dolphin's `GFX.ini` (with Dolphin stopped: it rewrites the file when it exits), open the screen, and match the dumped PNG against the exported pages. A string that is on screen but not in memory as glyph numbers is a picture.
- プログラム and テキスト on the command sheet are debug commands (tooltips シナリオのデバッグ / プログラムノデバッグ); they need no translation. 特別ルーム is the training room.
- **Multi-line slots.** Where the slot size varies but the box does not (rating comments: 22 or 15 cells a line; item texts: 18), `ui_strings.py` reads the line width of each string from the padding of its Japanese, confirmed by a neighbour of the same table; `LINE_CELLS` and `LINE_WIDTH` override it. 17 strings are marked uncertain (`?` in the export). `ui_strings.py check FILE` validates `ID<tab>English` lines without writing; `apply` stores nothing if any line fails.
- **The blue system dialogs are in `main.dol`** (save and load prompts, the give-up warning, memory and password notices, for every mode): one block at file offsets 0x143AA0..0x145ACE, 4,119 units, 264 strings back to back. A unit is 16 bits, `0x1000 | glyph`; 0x1FFD is a blank cell (written `{}`), used to indent the Yes/No and press-A rows by hand; 0xFFFF ends a string. The long vowel mark is often glyph 0x03C. Each string is one line of a dialog.
  - Pointers: `main.dol` has none. `main_prg.rel` section 5 holds a table of 252 pointers at +0x91AB0 (zero in the file, filled by 251 `R_PPC_ADDR32` relocations to module 0; the 252nd points at the row of stars right behind the block, which is a progress bar). 13 strings have no pointer; they look dead (10 are copies of others) and are kept where they are.
  - The dialogs themselves: 108 lists of 16-bit message numbers at `main_prg.rel` sec5+0x91EA0..0x92450 (1-based index into the pointer table, 0 = separator before the button rows, -1 = end), with their own pointer table at +0x92450. So which lines appear together is known. Lines are shared: the eight `Ｗｉｉ本体保存メモリ` + particle lines open many dialogs, and the give-up warning exists in a 3-line and a 6-line form with common lines.
  - Build: `rebuild_scripts.py` lays the block out again (a line may be longer or shorter than its Japanese, up to the 30 cells of the longest Japanese line), fills what is left with 0xFFFF and re-points the relocations. It then re-reads the built files and refuses to install unless `main.dol` is the original outside the block, the block has 264 strings, every relocation points at the start of its string and the 13 fixed strings have not moved. `DATA/sys/main.dol` and `main_prg.rel` must always be installed together; the original is kept in `_work/orig_sys/`. An independent checker written for the review is in `_work/review/dolcheck.py` (460 random builds, no disagreement).
  - In game: moved strings and the filler work (save prompt and give-up warning seen).
- After a text build the pair slots of the whole font change, and the font is loaded at boot: boot from scratch and retake the main-menu state (`to_command_menu.py boot`).
- Continuing a Success save and then resetting without saving triggers the game's reset penalty event on the next continue. `to_command_menu.py resume` restores the clean save first, so it never shows.

## MLB Power Pros (2007) and MLB Power Pros 2008 as a reference

Both Wii discs hold one `project.bin` (about 2,100 and 2,300 files, mostly `.pack`) and one `ovl_main.rel`. `mlb_assets.py` reads the file table and decodes the UI textures (standard GX C4/C8 with RGB5A3 palettes, uncompressed). The Success Mode packs (`ScsParamPlate`, `ScsComMain`, `ScsButton`, `env_ability_plate` and others) contain the English HUD lettering in the series' own style: stat labels (TRJ, CON, PWR, RUN SPD, ARM STR, FLD, E RES, TOP SPD, CTRL, STAM), Motivation, Vitality, positions, pitch-type abbreviations next to the Japanese sheet they replaced, months and weeks, and command buttons. English text is stored as 16-bit glyph strings with the same glyph numbers as Pawapuro 15. The container and sprite layout differ from Pawapuro 15, so nothing drops in as a file: labels have to be cut out and placed into Pawapuro 15's sheets. The first import (scs_main.arc) is described under UI graphics.

Full scan (`mlb_assets.py text` and `textures`, output in `_scan/` next to each extract, outside this repository): MLB 2008 has 22,682 English strings and 5,091 UI textures in 1,145 sheets; MLB 2007 has 11,362 strings and 5,132 textures in 940 sheets. 3D models, stadiums and motion files were skipped, as were about 100 CMPR textures.

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

Tested: `scs_main.rel` grown by 328 KB and `scs_sce1.rel` by 384 KB, loaded at the new address, no loader errors, 50 pages of story played.

Tested on 2026-10-12 with a translated `scs_main.rel` (the 33 training-gear constants), in both layouts: (a) the real build, script 16 bytes shorter, scenario slot where Konami put it; (b) an earlier build of 21 names padded by 16 KB (`--pad scs_main.rel=0x4000`), which moves the scenario slot to 0x812CB800. Each ran: continue from a save, command menu, practice menu, a work turn with its scenario 1 dialogue, save and quit, continue from the new save. A practice turn was played in layout (a) only (layout (b) opened the practice menu). English text is shorter than katakana at two letters a cell, so `scs_main.rel` may never need the moved slot; it works if it does. Not tested yet: scenarios 2 and 3, a match inside Success Mode, real hardware.

**Is 383 KB enough for `scs_main.rel`?** Not at one letter per unit: its text is 358 KB (238,578 glyphs at 12 bits) and English needs 2 to 2.5 times as many letters. The pair font below removes the problem.

## The pair font (tested in Dolphin)

`pair_font.py` draws **two half-width letters into one glyph cell** and stores the pairs in kanji slots. English then takes one text unit per two letters: about the size of the Japanese, and no game code changes.

- `fonttex2.rel` section 4 holds two complete fonts with the same 3,744 glyph numbers: a small one at +0 (16x17 pixels used, shades 8 = ink to 15 = background) and the large outlined one the dialogue uses at +0x05DF64 (22x28, shades 1 = ink, 9 = outline, 15 = background). A third set of 68 glyphs follows at +0x117400.
- Format: `u16 0, u16 count, u32 offsets[count]` (little-endian), then the compressed glyphs. Repacking the originals is byte-identical and all 7,488 glyphs survive decompress/compress, so the format is fully understood (`rebuild_scripts.py check`).
- A build collects the letter pairs the translation uses and gives each a kanji slot, least used kanji first (usage = untranslated script text plus a scan of all other modules; `namein.rel`, the name-entry kanji picker, is ignored). Both fonts get the pair, drawn from Menlo Bold, stretched to 11x28.
- **Name kanji are given up last (2026-10-13).** Names are 16-bit glyphs in fixed cells, and a two-kanji name is spread out with an empty cell in the middle (手塚 is `0773 0000 0A46`), so a search for the glyphs side by side finds nothing and the usage scan, which wants kana in a run, never counted them. Two layouts: the surname list (1,856 records of five 16-bit values: `1FFF`, the announcer's call, three cells) at file offset 0x1125D6 of `main_prg.rel` (section 5) with a copy in `scc_main.rel` (file offset 0x9EBE), used for team-mates and offered at name entry; and player names in six cells, back to back or behind three other values (real players, `main_prg.rel`). A save keeps team-mate names the same way (`pawa15.dat`, six cells). `pair_font.name_usage` collects these kanji (620) and `allocate` takes them only when nothing else is left; `other_text_usage` now also counts kanji-only strings that end in `FFFF` (positions, school names). With 1,614 pairs all 620 name kanji stay; 988 pair slots are kanji that other Japanese text uses (the least used ones). Seen in the practice menu: 手塚 西田 松本 大田 今井 read correctly again.
- Pair glyphs compress smaller than kanji (about 164 against 219 bytes in the large font), so `fonttex2.rel` keeps its size even with every kanji slot replaced.
- **A dialogue line is 17 cells: 34 letters.** Longer lines wrap. The letterbox narration of the opening shows 2 lines; speech bubbles (window types 2 and 4, measured) show 3, and one more line scrolls the first away. The build warns about long lines.
- Pairs restart at every run, line break and Japanese character. When a sentence is split into several runs on one line (colour changes, inserted names), give the earlier run an even number of letters or a half-cell gap appears.
- Tested: the opening scene of scenario 1 (36 lines, 20 boxes) in English, 210 letter pairs. Plain, outlined and coloured text all draw correctly; untouched Japanese text is unaffected. The 36 lines made the script 80 bytes longer.

Still open: the player and team-mate names inserted into sentences are Japanese (name entry and the name tables are not translated). Glossary pop-ups (window type 31) and choice menus (26) have not been measured in game. With all of scenario 1 in English (3,238 runs, 840 letter pairs) 208 of the pair slots are kanji that the remaining Japanese text still uses, so a few rare kanji in untranslated lines show as letter pairs until those lines are translated too. With the UI strings of 2026-10-12 in (1,806 strings, 1,038 letter pairs) 406 pair slots are kanji that Japanese text still uses: more of the untranslated lines will show a letter pair in place of a rare kanji until they are translated.

## Bulk dialogue translation (2026-10-13, third session)

All four script files are in English: 45,661 runs (`tl.py status`), built, verified and installed. Done in one
session with one Sonnet agent per batch of about 430 runs, six at a time (95 batches, about 12 million tokens,
75 minutes of agent time), after a pilot of six batches read against the Japanese.

- Tools in `_work/tl_bulk/` (not in git): `make_batches.py` (unique, untranslated scenes into batches;
  `dups.json` maps the 1,048 exact duplicate scenes to their first copy), `brief.md` (what a translator reads:
  formats, limits, names, the casts), `presets.json` (154 fixed renderings of lines that repeat, the most common
  one 973 times), `collect.py` (checks and stores finished batches one after the other, then fills the duplicate
  scenes), `reconcile.py`, `view.py` (Japanese and English side by side).
- `tl.py check FILE` is a dry run of `apply`: line counts per scene, stray characters, the line breaks of menu
  runs, and the warnings of `merge`. Translators run it; only `collect.py` runs `apply`, because `apply` rewrites
  the whole TSV and parallel applies would lose rows.
- A decoded run holds a line break as the two characters backslash + n, not as a newline (`check_scene` counted
  the original's lines wrong until this was fixed). In apply input `\_` is a space: editors strip trailing ones.
- A run-level memory of scenario 1's English is not safe to reuse: its translators moved words between the runs
  of a sentence. Only whole-line repeats were fixed in advance.
- The speaker column is right for scenario 1 only. In `scs_main.rel` most runs have no portrait set, and in
  scenarios 2 and 3 the same portrait numbers are other people; their batches show a code per character instead.
- Sizes after the build: `scs_main.rel` script +18 KB (356 KB of room left with the scenario slot moved),
  `scs_sce2.rel` +3 KB, `scs_sce3.rel` +7 KB; 1,614 letter pairs, 1,424 kanji slots left.
- 17 warnings remain in `tl.py merge`, all in debug menus and lookup lists that the checker reads as one line.
- **Seen in play (2026-10-13, later).** Scenario 1 was played by itself from year 1 September to its ending (`dolphin-test/autoplay.py`, about 50 minutes at 4x) and the 3,900 frames were read as text (`dolphin-test/ocr/`, the Mac's Vision text recognition; 1,000 frames become about 700 lines). The dialogue reads well; what was wrong was always a sentence the game puts together from pieces of different scenes, which no check of a single scene can see:
  - too long once assembled (`Breaking Ball Points` + ` went up a little.`, `After that, I` + an ending, a name + ` is someone you just met.`). A speech window wraps in the middle of the word; a window of type 29 or 30 also **drops the cell after the wrap** ("lit" / "e."). Cure: a shorter ending (` rose a bit.`), or `\n` at the start of the second piece.
  - a subject and an ending that both carry the space or neither does (`I` + `, faced `, `rain` + `practicing away,`).
  - a piece the translator could not know the context of ("I'm" + team name: "I'm Pawafuru Corp.").
  About 45 lines were corrected with `tl.py set`. Left as it is: after an inserted name or term with an odd number of letters, a piece starting with `'s` or a comma shows half a cell of space ("Reito-san 's rating"), because a run is padded to whole cells.
- A scenario counts as cleared only when the player is drafted. Played by A presses alone the run ends in the bad ending (not drafted; the run is erased), so scenarios 2 and 3 stay locked. When the player is the starting pitcher the whole game is played by hand: the control settings of the タイム menu (打撃 走塁 投球 守備 監督) are fixed to Manual in Success Mode, nobody fields, and one game took 25 minutes and 59 runs.
- **Opening scenarios 2 and 3 for testing (2026-10-13).** The scenario card that follows "Start from the beginning" is drawn by `scs_titl.rel`. Its routine at sec1+0x56BC sets the byte `work_scs.rel` sec6+0x60AA1 (memory 0x8065FA81, the number of scenarios the card offers): 1, plus 1 if byte 0x25 of a structure is set, plus 1 if byte 0x26 is set, and it leaves the byte alone when it is already 3. A memory code that keeps it at 3 makes the card show its left / right arrows and all three scenarios start. In `dolphin-test/GameSettings/RP5JA4.ini` (Gecko; the first line checks that `work_scs.rel` is loaded, so nothing is written in other modes):
  ```
  205DDB8C 9421FFF0
  0065FA81 00000003
  E0000000 80008000
  ```
  Dolphin needs cheats on: `HARNESS_CONFIG="Dolphin.Core.EnableCheats=True" python3 to_command_menu.py boot`, then `python3 new_scenario.py 2` (a new game in that scenario up to its first screens). It is a test setting of the emulator only: no game file is changed, and a save made this way keeps nothing unlocked. Not checked: the two flag bytes themselves. Bytes 0x24 to 0x26 of the Success save block (`pawa15.dat` +0x1A6F80, 0x58000 bytes, the image of `work_scs.rel` sec6+0x3A20) read 01 00 00 in every save here, which fits "scenario 1 open, 2 and 3 closed"; the last byte of the block changes with its contents and may be a checksum. No published codes exist for this game (searched).
- Item names in the glossary pop-ups of `scs_main.rel` were set to the wording of the shop strings (88 runs).
- **Seen in game** (scenario 1, the resume save, 5 weeks of play, and a new game as an outfielder up to the
  command menu): the build boots and loads; English lines of the common events show (a shop-clerk event, a result
  message with an inserted amount, the opening). **Not seen:** almost all of it. Scenarios 2 and 3 cannot be
  started at all yet: a new game goes straight into scenario 1 until a scenario has been cleared.
- Known weak spot: sentences the game assembles from pieces (a name or term plus a fragment). The pieces were
  written to follow a noun, but which pieces meet on screen was mostly not visible to the translators.
- Still Japanese around the dialogue: the letterbox narration before name entry, the name entry and profile
  screens (handedness, position, forms, face, difficulty), the overwrite warning of New Game, the mode-select
  screens, and the names the player types.
- A fielder save exists now: `dolphin-test/nand_backup_fielder` (outfielder, year 1 September week 1).
  `to_command_menu.py resume fielder` continues from it. Seen with it: the plate `Position: Outfield` and the
  seven fielder stat labels on the main screen.
- New Game with a save present: at the Success title UP, A; at the overwrite warning UP, A (the default is
  cancel). Name entry: LEFT, DOWN x6, A for OK. Voice: RIGHT x3, A. Then six profile screens (position is 02/06),
  difficulty, the save prompt, the opening. `to_command_menu.py new` assumes there is no save and takes Continue.

## Menu strings of the other modes (2026-10-13, fifth session)

The fixed-slot strings outside the Success scripts were translated in two runs of 8 Sonnet batches (16 batches,
4,963 unique strings, about 1.8 million tokens, 20 minutes of agent time). `ui_strings.py status`: 9,171 of 9,947
strings in English, in 62 modules; built, verified and installed.

- `ui_strings.py export FILE` works on any module as it is. The rows it finds are text, name lists and noise
  (glyph grids, tables of numbers); translators leave out what is not text.
- Tools in `_work/tl_bulk/` (not in git): `make_string_batches.py` (unique strings of the listed modules into
  `strings/in/Snn.txt`; a string that appears in many slots goes out once, `strings/dups.json` holds its copies;
  do not rerun, it renumbers), `brief_strings.md`, `check_strings.py Snn` (what a translator runs),
  `normalize_strings.py` (one wording for terms the batches rendered differently, kept only where it fits),
  `view_strings.py` (Japanese and English side by side), `collect_strings.py` (stores batches and their copies;
  only this runs `apply`), `pointer_check.py`.
- **Covered:** the match (`gameplay.rel` 343 of 429), shared menus (`main_prg.rel` 457 of 720), baseball school
  (`school_g.rel` 3,160 of 3,161: 489 lesson texts repeated per controller type), Boost and ability texts
  (`sn_abiup.rel`, `are_abi.rel`), Success leftovers (`scs_end`, `scs_make`, `scs_grad`), records room, cheer
  songs, Arrange, draft, the Eikan Nine screens (`sct_a_*`, `work_sct`, `sct_card`, `sct_rens`, `sct_sugo`),
  championship, and the small Pennant and My Life setup modules.
- **A pointer shows where a string really starts.** `ui_strings.find` starts a string at the first glyph number
  it meets, and small numbers in front of a text (a header: `0007 0008`, `着着`) are valid glyph numbers. The
  module's own relocations settle it: when a pointer lands inside a slot and none at its start, the text starts
  at the pointer (`pointer_check.py`: `inside_only`); when there is one at the start and another inside, two
  strings share the slot (`shared`). `collect_strings.py` holds both kinds back. Four were given a `START_TRIM`
  entry and stored (main menu help of Exhibition, a school greeting, a prompt of `scs_end.rel`, an Arrange
  notice). None of the 1,808 strings translated before is of either kind.
- **Not done, and why:**
  - `pena_sub.rel`, `pennant.rel`, `orepena.rel`, `pn_fa.rel`, `pn_ore_i.rel` (Pennant, My Life: about 7,700
    strings): about a third start with such a header (in `pn_fa.rel` the pointer is at cell 2, behind
    `0007 0008`). They need the start taken from the pointers for the whole file before batches are cut.
  - Name lists: 12,260 school names in `sct_main.rel`, the kana readings of `are_main.rel` (6,950), given names
    in `main_prg.rel` (about 200), foreign players in `scc_main.rel`, `namein.rel`. A job for a romaniser with a
    reading table, not for translators.
  - `main_prg.rel` 5:89202, 5:89900, 5:90076, 5:90224 (which controller to use): the Japanese has gaps, an icon
    or fixed columns; in `strings/hold.txt` until seen in game. `are_sub.rel` 5:11824 (shared slot).
  - 14 real players' forms whose surname does not fit 8 letters (松坂投法 ...), and a few rows with a kanji the
    font table does not decode.
- **Seen in game:** the build boots and continues the Success save; main menu help lines (Remo-Pawa, Success,
  Baseball School); the Boost screen's description line (`Top velocity goes up`, `Learn Slider`); baseball
  school: mode menu, lesson list help, the coach's first line in a lesson. Arrange opens.
  **Not seen:** everything else, above all the match texts and every mode of the second run.
- Still Japanese where looked: the Exhibition help line was Japanese in the look (stored after it); lesson
  titles in the school list; the first prompts of Arrange (どのファイルで ...): another store, not found yet.
- The harness matched the main menu cursor against a picture that included the help box; with English help the
  cursor on Success was no longer recognised. `ref_cursor_mask.npy` now leaves out the bottom fifth of the
  screen (the old mask is kept as `ref_cursor_mask.before_english_help.npy`).
- Font after the build: 1,795 letter pairs (1,614 before), 1,243 kanji slots left; 1,169 pair slots are kanji
  that Japanese text still uses (988 before). The abbreviations of short labels brought many new pairs.
- Weak spots of this pass: labels in slots of 2 to 4 cells are abbreviations made up to fit (prefectures as
  `Aomo`, `Ymgt`; teams as `Gnts`, `Chun`; old team names in the records room); pieces of assembled sentences
  (` breaks record!`, ` Talks`); long help texts of `sct_a_sc.rel` and `chrsong.rel` whose line width the tool
  did not find (written as one line, padded by hand to 32 letters a row).

## Pennant and My Life strings, and the news messages (2026-10-13, sixth session)

**What "a third start with a header" really is.** The strings of Pennant that begin with small numbers are not
slots with a header: they are **message scripts**, the news and reports of Pennant (`pena_sub.rel`
sec5+110936..130016, 241 messages; five more in `pn_fa.rel` sec5+6584..6976). A message is a run of pieces,
each `codes, 0, text, 0xFFFF`:

- `0001` new line, `0007` new page, `0060`..`009F` an inserted value (60-65 a club, 66-6B a player's name, the
  rest numbers and words), then the unit `0000`, then the text. The first `0000` is a marker ("text follows"),
  not a space: lines that are indented have a second `0000` behind it.
- `000F` ends a message in `pena_sub.rel` (`0007 000F` after a full text, `0001 000F` or `000F` alone after the
  short ones), `0008` in `pn_fa.rel`. Seventeen short texts have no `0xFFFF`: the stop code closes them
  (`0 外野手 F`: the scout's 高校生 / 右投げ / 投手 ... labels, セ / パ).
- A unit with its top four bits set is coloured text (`6xxx` and `2xxx`: the lines about the number of fans).
- Only the start of a message has a pointer (two tables of `R_PPC_ADDR32` in sec5, at +108120 and +130016, and
  a few from the code), and in front of it the data is padded with zeros, so the game reads a message piece
  after piece. `pointer_check.py` reports these as `inside_only`: `ui_strings.find` glues the stop code of the
  message before to the first piece.

So the pieces of one message can have any length as long as the message ends before the next pointer target.
`ui_messages.py` (export, check, apply, set, merge, status) writes a message as one line with tags
(`本日、{60}から{n}{66}選手が{n}トレード入団いたしました。`); the English keeps the tags in their order and is free
between them (`Today {60} sent{n}{66}{n}to us in a trade.`). Limits: the room of the span (6,793 cells for 6,590
of Japanese) and 40 letters a line, an inserted name or club counted as 8 and a number as 4 (the longest Japanese
lines; the real width of the box is **not measured**). English in `translation/messages/<file>.tsv`, merged to
`_work/messages.json`; `rebuild_scripts.py build` lays each message out again in its span and `verify` compares
the span. Batch tools in `_work/tl_bulk/`: `make_message_batches.py`, `brief_messages.md`, `check_messages.py`,
`collect_messages.py`.

**Not known:** whether the game puts any space after an inserted value (the English writes its own), and what
each insert above 0x6B stands for beyond what the Japanese next to it shows.

**The plain strings** of `pennant.rel`, `pena_sub.rel`, `pn_fa.rel` and `orepena.rel` went out as batches P01 to
P10 (`make_string_batches2.py`: 3,461 unique strings; `strings/out/P00.txt` holds 174 whose Japanese and capacity
already had English). Left out by the cut: name lists (`orepena.rel` sec5+40880..41290, +91500..92528,
+145256..158700: 1,426 names; `pennant.rel` sec5+40500..44000; all of `pn_ore_i.rel`, the record holders), noise
(tables of numbers that read as glyphs: 834 rows), the message region. Outside the messages only one string
had a pointer inside its slot (`pn_fa.rel` 5:106, now in `START_TRIM`).

**Result (built, verified, installed).** `ui_strings.py status`: 13,334 of 17,159 strings in English
(4,163 new slots in the four modules); `ui_messages.py status`: 246 of 246 messages. Font: 1,897 letter pairs,
1,141 kanji slots left, 1,271 pair slots are kanji that Japanese text still uses. **Seen in game:** the build
boots, the main menu help line shows, the Success save continues to the command menu. **Not seen:** every
Pennant and My Life screen, and not one news message (the line width of 40 letters and the spacing around an
inserted name are guesses until one is seen).

Weak spots of this pass: 44 help texts longer than 30 cells for which no line width was found are stored as one
line and will wrap in the middle of a word (the Pennant help pages are 19 cells wide and start after an inserted
word: the padding of the Japanese shows it, `ui_strings` has no rule for a shorter first line); labels of 2 to 4
cells are made-up abbreviations (`Sapp`, `Mnsn A`, `Tmrw`, `Sawa.`); pieces the game joins to a name or a number
(` was traded!`, ` pk,`, `00M yen player`) were written without seeing what stands in front; in the messages
`{84}`, `{75}`, `{93}` to `{98}` were guessed from the Japanese next to them.

**The packed text of the other modes (looked at, not done).** `sct_main.rel` (Eikan Nine) keeps its packed
text at sec5+14416..189372 and a table of 5,319 `R_PPC_ADDR32` pointers right behind it (sec5+189368..210640):
every text seems to be reached through the table, so it could be laid out again like a block of strings (the
table and everything behind it would move if the English is longer). `orepena.rel` (My Life) has 3,100 runs
in sec5+56522..803124 with 5,312 pointers from its own sec5 spread over the section and 1,844 from its code:
closer to the Success scripts, the control flow is not known yet.

## The videos (2026-10-13, looked at, nothing changed)

26 `.thp` files in `DATA/files` (motion JPEG with ADPCM sound; `ffmpeg` reads them, nothing here writes them).
Frames of every one were read as contact sheets:

- `15_op_043` / `15_op_169` (80 s, the opening in 4:3 and 16:9): no sentences. The PAWAPURO sign, the game's logo
  and katakana sound effects that are part of the drawing. Stays.
- `15_ed_043` / `15_ed_169` (187 s, the staff credits): Japanese on about 30 pages, roles and names. Could stay.
- `15_my` (9 s, My Life intro, 640x480): four captions in the picture: 何のために戦うのか？ (on plain dark blue),
  then 記録のため？, 家族のため？, 誇りのため？ over a burning baseball. The only video text worth translating:
  decode the frames, paint the English over a plate, write JPEG frames no larger than the old ones back into
  the container (a writer is needed: header, frame sizes, picture, sound).
- `15_pe` (8 s, Pennant intro): club logos and a NIPPON CHAMPIONS pennant, all Latin letters.
- `15_scs` (6 s, Success intro): no text.
- `yk15_00` .. `yk15_18` (320x224, 8 to 10 s each, the demo clips of the baseball school): no text.

## Eikan Nine scripts (2026-10-13, seventh session)

`sct_main.rel` holds the story and tutorial text of Eikan Nine as a script of the Success kind: 16-bit instructions, text mode `XX00` followed by 12-bit packed glyphs. 4,263 runs (4,101 not empty, 40,085 glyphs) in 1,980 scenes, in sec5+14416..189368. `tl.py` and the build handle it next to the four Success files (`scan_story.BLOCK_SCRIPTS`, class `BlockScript`).

- **Interpreter**: sec1+0x22C18, script pointer at r31+0x200, opcode = low byte, 207 opcodes, jump table at sec5+0x32A0. Opcodes 0x00..0x66 mean what they mean in Success Mode (text, return 0x01, if 0x02, waits 0x46 / 0x49 / 0x4A, name inserts 0x4B..0x50); the later ones are numbered differently (goto 0x87, call 0x88, the list opcode 0x67). The lengths in `scan_story.EIKAN_OP_LEN` were read off the handlers with `derive_op_advance` (set `VM_IP = "0x200(r31)"`, exits 0x26B18 and 0x22C18) and parse the whole script with no error; the only unreached data is one return at +90684.
- **Labels**: the table of 5,318 pointers stands right behind the script (sec5+189372..210644) and is filled by the module's own relocations. Five entry points are also addressed from code of `sct_card.rel` and `sct_sugo.rel` (ADDR16_HA / LO pairs).
- **The module cannot grow.** In the memory plan `sct_main.rel` (6.4 MB with its BSS) ends 24 bytes before the next modules. So the script is laid out again inside its own 174,952 bytes (`rebuild_scripts.emit_block`): every label is at a multiple of 4 and follows a return or a goto, and the assembler filled the gaps with zeros (2,323 gaps, 6,528 bytes). Those gaps are given up and are the room the English has (about 10% of the text). The Success scripts have run without that alignment since their first rebuild, which was the evidence that the engine does not need it. Seen in game with all 4,101 lines in English (2,774 bytes left): a new Eikan Nine game from the title through the setup into about five weeks of events, tutorials and practice results, no fault. The build then rewrites the 5,317 label addends and the 14 code addends and checks them like every other relocation. If the English is too long the build stops and says by how many bytes.
- A dialogue line is taken as 18 cells (36 letters): the Japanese rarely passes 18. Lines of 36 letters showed whole in the manager's box.
- Names padded with full-width spaces to a column (ability names, 10 cells) are padded again by `_work/tl_bulk/pad_columns.py` after `collect.py`.
- Eikan Nine is entered from the Success screen (the right-hand picture), not from the main menu.
- `scs_comi.rel`, `gdt_pn.rel`, `koukai.rel`: parsed and translated since, see "The three small script modules" below.

## My Life scripts (2026-10-13, eighth session)

`orepena.rel` holds the story text of My Life: **17,695 text runs (159,152 glyphs) in 1,420 scenes**, in sec5+182584..803170. The earlier count of 3,100 runs came from a search that only finds kana-rich lines. It is a script of a third kind, with an engine of its own; `tl.py` and the build handle it as a sixth file (`scan_story.OreScript`, entry `orepena.rel` of `BLOCK_SCRIPTS`).

- **Interpreter**: `ore_work.rel` sec1+0x1CE4 (script pointer at r15+0x58, label table pointer at r15+0x4C). An instruction is a whole halfword, not a low byte. sec1+0x3BE0 skips a block and so lists the length of every instruction; the lengths in `scan_story.ORE_OP_LEN` are read off it and off the interpreter, and parse the script with no error (83 returns that nothing reaches are kept as they are).
- **Instructions**: `0000` text (the 12-bit packing of the Success scripts, read at sec1+0x3F30; a line break is an instruction, never a unit), `0001` new line, `0006` / `0007` wait for a button, `0008` return, `000D` .. `000A` an emphasised span, `0018 w p` window, `001C` (5 halfwords) and `003F n` insert a name or number, `0032 L` call, `0035 L` goto, `0033 n` / `0034 n` mark a place and jump back to it, `0036` / `0037` if (operator, operand types, two operands) and `0038` else, each followed by `FFF0` .. `FFF1` around a block or by one label number, `003C n ...` a list with its count, `003E x` a sound.
- **Labels**: jumps name a label by number. The table (sec5+173464, 1,852 entries) is filled by the module's own relocations, and nothing else points into the script: the 613 code relocations into the area all go to three **islands** of other data that lie between the scenes (sec5+187254..189808, 228090..229016, 779308..780240: tables with relocations of their own, debug strings). The islands stay where they are. Behind the script: other data to 807216, then a table of romanised names (16-bit letters, 1 = A) with its own pointer table at sec5+808964.
- **No room, so an annex.** In the memory plan `orepena.rel` ends exactly where the next modules start, and the padding in front of its labels is only 2.8 KB for 245 KB of text. The build lays each stretch between two islands out again in place and moves the scenes that do not fit to an **annex behind the data of `ore_work.rel`**, which it then loads at 0x81400000, in the free memory above the plan (the scenario modules of Success use the lower part of that area). A label of a moved scene is filled by a relocation against `main.dol`, which is an absolute address; such relocations lie behind `fixSize` like the module's own, so `orepena.rel` needs the same memory and keeps its file size. The annex starts with `OREX` and its own address, so a built file can be read back without the plan (`OreScript` appends the annex to the section's halfwords). `rebuild_scripts.emit_ore`, `ore_relocations`, `update_plan_ore`; the verification compares instructions, labels, text and every relocation as for the other scripts.
- Tested offline (written files read back): unchanged text, every run one and six units longer (24 KB and 158 KB in the annex, 50 and 272 labels moved), every run halved.
- **Built and seen in game (2026-10-13)** with the first 9 batches (4,637 of 17,695 runs; 1,933 pieces stay in place, 720 bytes and 2 labels are in the annex, `ore_work.rel` at 0x81400000..0x81434F78): a new My Life from its title through team choice, name entry and the settings into the signing scene and the first spring camp, about 180 key presses, no fault. English scenes play between the Japanese ones (camp opening, the manager's team policy with its coloured span, practice results, "My Spirit went up!"); three lines of 34 letters fit the box. Frames: `dolphin-test/looks/mylife/`, `looks/mylife_english.jpg`. Which scenes are the two in the annex was not looked up, so the annex itself is proven by the build's checks and by the module running at its new address, not by a scene seen from it.
- Seen to fix later: an inserted practice name is padded to a fixed width, so "Weight training" + " done!" shows a wide gap; Japanese lines not yet translated show letter pairs in place of some kanji ("Gntsの名に").
- Four "menu strings" of `orepena.rel` translated in the sixth session (sec5+343716, 539938, 540188, 541840: `All`, ` box` three times) were packed script text read as 16-bit strings; they overwrote script bytes in the builds since then. Removed from `translation/strings/orepena.rel.tsv`; the build now stops when a string lies inside the script.
- `verify_dol` skips its "same size, only addends differ" test for the two My Life modules (their relocations are compared as a set in `verify`) and pairs their `main.dol` relocations by position.
- A line is taken as 17 cells (34 letters), like the Success box: 1,101 Japanese lines are 16 characters and a few are 17.
- Scene files show the window set by `0018` as 100 + its number, an insert as `{name}`, a called routine's text as `{sub}`, and `if` / `else` / `end` around alternatives. Brief for translators: `_work/tl_bulk/brief_mylife.md`; 35 batches of about 520 lines.
- `gdt_pn.rel` and `koukai.rel` hold scripts of this kind too; `scs_comi.rel` is of the Success kind (see "The three small script modules").

## The three small script modules (2026-10-14, sixteenth session; built and verified)

All three are English, built, verified (the build re-reads every script, label and relocation) and installed.
`tl.py` and the build handle them through `scan_story.BLOCK_SCRIPTS`; translations in `translation/<file>.tsv`,
batches in `_work/tl_bulk/<file>/` (one batch each, translated by Opus in the session, checker clean apart from
debug menus whose Japanese breaks the same limits).

- **`koukai.rel` is the signing and contract scene of My Life** (the "Giants signing scene" of the handoffs; it is
  not in `gdt_pn.rel`): the man in glasses ("...That completes your signing."), the executive's speech, the
  yearly salary announcement for every career stage (zero salary, rookie, veteran), the agent sitting in, the
  team's finish (pennant / Japan Series / bottom half / last), free agency, and the speaker plates. 242 runs in
  27 scenes, a My Life script (`OreScript`) at sec5+1328..8672, the end of its data; 32 labels in a table at
  sec5+112. The module imports `ore_work.rel` and `orepena.rel`, so it only runs with `ore_work.rel` loaded.
- **`gdt_pn.rel`**: the playing-manager prompts during a match ("Can you keep pitching?", "Let me qualify for
  the win", the coaches' closer and pinch-hitter suggestions with the ◎ mark, the situation pieces "9th, 2 up"),
  plus debug menus. 208 runs in 42 scenes, a My Life script at sec5+1240..7440, 61 labels at sec5+768. Its
  module shares its slot with gdt_o_c6 .. gdt_scc and cannot grow.
- **Annexes.** Neither module has room (64 and 52 bytes of padding), so both use the My Life annex: the build
  appends one annex per script behind the data of `ore_work.rel` (loaded at 0x81400000), each starting with its
  own magic (`OREX` orepena, `PNEX` gdt_pn, `KKEX` koukai) and its own address. `OreScript` finds its annex by
  scanning from `annex_from` in 8-byte steps for its magic whose address field agrees with the first header.
  `rebuild_scripts.build` keeps a list `ores` (was one `ore`); verify maps each script's labels with its own
  remap. Present build: gdt_pn 96 bytes and koukai 56 bytes in the annex, `ore_work.rel` ends at 0x814356A0.
- **`scs_comi.rel`**: the rival showdowns of a Success match (each opposing team's taunts, the player's answer
  choices, pitch announcements, a pitch-name slot filled from scenes s0050..s0076, debug lists of faces and
  teams). A script of the Success kind with an interpreter of its own: sec1+0x1CF8, script pointer at r15+0x154,
  141 opcodes, jump table at sec5+0x3DC (0x3D8 is the end of a 3-word structure). Lengths from
  `derive_op_advance` (`VM_IP = "0x154(r15)"`, exits 0x2B0C / 0x2B20) except 0x66 / 0x67, whose helpers
  (sec1+0x2B58 / 0x2C20) move the pointer by one argument. 0x75 goto / 0x76 call read the label table that
  sec5+0x2D90 points to (sec5+11672, 347 labels); the last label points behind the table to a lone ダミー run,
  left out. Laid out in place like Eikan Nine (`emit_block`): 188 bytes left. Empty runs (the pitch slot) must
  stay empty: the checker rejects text there.
- Not seen in game yet, except as noted in HANDOFF.md.

## Art survey: every sprite page read by machine (2026-10-13, seventh session)

`_work/ui_pages/tools/art_survey.py` renders every page of every `.arc` (each palette its sprite parts use, 3 at most), 4x, and reads it with the Mac's text recognition in Japanese (`dolphin-test/ocr/ocr ja-JP en-US`; the helper takes the languages as arguments now). 15 minutes for everything. Results in `_work/art_survey/`: `pages_text.tsv` (page, Japanese read, other text), `banks_japanese.tsv` (the work list: mode, file, bank, pages, boxes, sample).

| Mode (by file name) | Pages | With Japanese | Text boxes | Banks |
|---|---|---|---|---|
| Pennant (pena*, pennant, pn_*, draft) | 1,178 | 367 | 1,297 | 85 |
| Success (scs_*, gdt_scs) | 3,184 | 340 | 904 | 90 |
| My Life (ore*, myend) | 591 | 303 | 1,376 | 47 |
| Match and common (gameplay, vs*, main_prg, ctrler, option, order) | 882 | 283 | 969 | 70 |
| Arrange and edit (arr*, are_*, chrsong) | 581 | 267 | 1,196 | 51 |
| Records (rec_room, record, koukai) | 281 | 167 | 666 | 26 |
| Eikan Nine (sct_*) | 1,418 | 137 | 438 | 42 |
| Home Run, Remote, camp, calorie, scc_* | 268 | 110 | 391 | 20 |
| Championship | 163 | 59 | 176 | 16 |
| Baseball school | 126 | 52 | 133 | 7 |
| Online (the service is closed) | 478 | 132 | 308 | 36 |
| Staff roll (stays) | 231 | 38 | 222 | 7 |

Without the staff roll and the online screens: **about 2,085 pages, 7,500 text boxes, 450 banks**, and almost nothing repeats between files (2,069 different pages). A text box is what the recogniser saw as one piece: a label, a line of a list, or lettering inside a picture; pictures (logos, sound effects) are not told apart. For scale: everything translated so far in sprite sheets is about 700 labels. Limits of the reading: stylised display lettering is missed (the eleven main menu words were not found, see below), a page shared by several colourings is read in three of them at most, and 250 pages in banks whose name occurs twice in a file are reported under one name.

## Main menu and the Success start screens: where the art is (2026-10-13)

Found with a texture dump taken screen by screen (`dolphin-test/looks/first/steps.py`: keys, one screenshot, the list of textures new since the last step) and `_work/ui_pages/tools/match_all.py` (dumped textures against all pages of all files at once; the decoded pages are cached).

- **Main menu**: not in an `.arc`. `SMDL_TOP.rom` holds four 256x256 textures, 8 bits per pixel (GX C8, 8x4 tiles), stored plain, each right behind its 512-byte RGB5A3 palette: palettes at 6176, 93920, 160640 and 239328, pixels 512 bytes later. They decode to exactly the dumped textures. Texture at 93920: the blue button plates and ペナント サクセス 野球教室 アレンジ; 160640: the orange plates, サウンド (stored turned by 90 degrees) and リモパワ; 239328: 対戦 マイライフ ホームラン競争 応援曲 and the game logo; 6176: データあれこれ (turned) and the background. The other `.rom` files were not surveyed: `SMDL_*.rom` are probably the same kind of menu art for other modes. **English since 2026-10-13**: `_work/menu/make_menu.py --write` reads the colours of each Japanese word (fill from top to foot, the darker side, outline, white band, blue rim, shadow), sets the English word in Arial Rounded Bold with the same layers, centres it on the Japanese word's box and maps it to the texture's own 256 colours; the two sideways words are set upright and turned back. Seen in game on the plain and the selected plate.
- MLB Power Pros and MLB 2008 have their menu words in `env_mainmenu.pack` (`MLB*/_scan/tex/env_mainmenu.png`): Exhibition, Success, Home Run, Arrange, Practice, My Data, Wii Remote, Season, MLB Life, League, Shop, Display Style, Baseball Cards, in a metallic small-caps style.
- **Success screen** (mode select, title, 最初から / つづきから / 選手名鑑, the overwrite warning, クリア人数): `scs_titl.arc`, banks `y5_scs_tit_0`, `y5_sge_0`, `y5_tic_h1`, `r4_sta`, `r4_staz`; the Eikan Nine side is `sct_titl.arc` `r4_eikz`.
- **Scenario start card** and loading pictures: `scs_load.arc` (`y5_tlog_*`, `z5_sop_0`).
- **Name entry**: `namein.arc` `s3_nam` (pages 0 to 7). **Voice setup**: `arevoice.arc` `m3_onsei` (most of its dumps did not match a page: look again).
- **Profile screens** (handedness, position, form, face, confirm, difficulty) and the application form behind them: `scs_make.arc`, banks `y5_cmk_0` (the lists and headings), `y5_cmc_0`, `y5_nan_0` (difficulty), `y5_pho_p`, `y5_make_bg_opd` (the form).
- Keys from the main menu: DOWN, A (Success screen), A (白球ドリーム), A (title, cursor on Continue), UP, A (overwrite warning, cursor on "cancel"), UP, A starts a new game; then A through the opening card to name entry.

## First screens of Success in English (2026-10-13, eighth session; seen in game)

Three files, each with a generator in `_work/ui_pages/` that writes its spec (`gen_titl_spec.py`, `gen_make_spec.py`, `gen_name_spec.py`); `python3 ui_labels.py apply ui_specs/<file>.json` writes the sheet, the originals are in `_work/orig_arc/`.

- **`scs_titl.arc`**: the start screen (`y5_scs_tit_0`: Start, My Players, Linked World, Registered / Pit. / Fld., New Game, Continue, Players, Album, Cleared, Turned Pro) and the overwrite warning (`r4_sta`: Warning! and three lines, the two answers, Cleared, Ending Movie). Left: `r4_staz`, `y5_sge_0` (the three scenario names) and `y5_tic_h1` are 8-bit pages, which `compose.py` cannot show and the label tools have not been tried on.
- **`scs_make.arc`**: the profile screens (`y5_cmk_0`: five headings, Is this OK?, six handedness lines, seven positions, four pitching and eight batting forms, Yes / No) and the difficulty screen (`y5_nan_0`: the heading, Normal, Rookie). Left: `L・Rで視点変更` and `⊖で視点変更` (sprites 36 and 45), the two subtitles painted on the difficulty plates (〜 いつものサクセス 〜, 〜 初めて遊ぶ人でも安心 〜), the application form (`y5_cmc_0`, `y5_make_bg_opd`).
- **`namein.arc`** (`s3_nam`): six headings (Enter a name / a song title / a tourney name / a school name / the cap mark / a nickname) and the eight button words (Cancel, Kana, Kata, ABC, Kanji, Symbol, Delete, OK). Left: 選択タイプ音声あり (sprite 1c).

**Seen in game** (`dolphin-test/looks/first/walk.py` walks the screens, frames in `looks/first/walk/`): the Success screen (Start, My Players, Linked World, Registered / Pit. / Fld. with the counts), the title (New Game, Continue, Players, Cleared), the overwrite warning with both answers and the team plate Pawafuru Corp., name entry (heading and the seven buttons shown), the five profile screens with all their lists, Is this OK? Yes / No, the difficulty screen. Not seen: Album, Turned Pro and the Eikan side, the other five name headings, Cancel, Kagurazaka Group, Otori Phoenix, the batting form list, L / R: Turn View, Ending Movie. The "Enter a name" heading is small on its wide plate (capitals 13 pixels): room to grow.

**The Success screen draws a copy.** `scc_tops.arc` holds the same six pages and the same sprite table as `y5_scs_tit_0` of `scs_titl.arc` (under the bank name `y5_tic_scc_h0_opd`, whose sprite table the bank reader does not attach to it); the mode-select screen uses that copy, the title uses `scs_titl.arc`. `_work/ui_pages/tools/mirror_bank.py scs_titl.arc y5_scs_tit_0 scc_tops.arc y5_tic_scc_h0_opd --write` copies the English pages and the moved sprite parts across (it checks that pages and table are the same bytes in the two originals). Run it again after every apply of `ui_specs/scs_titl.json`. When a changed sheet still shows Japanese in game, search the other files for the original page before anything else.

Still Japanese on this path, seen: the opening card of scenario 1 (プロ野球選手になることが...) and its start card (GAME START, クリア人数 投手 野手: `scs_load.arc`), the whole voice screen (`arevoice.arc` `m3_onsei`, 43 pages), the application form beside the lists, ⊖で視点変更, the two subtitles of the difficulty plates. In My Life: its title buttons (最初から, つづきから, 名鑑), the two story buttons, 入団チーム選択, the System screen, the HUD (マイ魂, 疲労, 軍, 歳).

What made these quick, and what to know for the next sheets:

- **Sprites share pieces** (右投 + 左打; 二 + 塁手; 投球 + フォームを決めて + ください; 名前 / 曲名 / 大会名 + を入力してください). A label is addressed by its rectangle (`"from"`), and `"left"` + `"baseline"` put it on a fixed column and row of the sprite, measured from where the old rectangle stood (the part's x). So a row is set as words side by side: measure each word as its style draws it (`ui_type.RENDER[style](*ui_type.typeset(text, font))`), then give every piece its column. A shared piece gets one column for all the sprites that use it: a shared word goes first ("Enter" + "a name"), or the changing word gets a slot of one width ("Choose your" + pitching / batting + "form").
- A part shows at most 128 pixels, so a long line is two or three pieces; the bands of neighbours overlap by twice the style's padding.
- A piece that English does not need is `{"from": [...], "empty": true}`; a sub-rectangle of another label (を入 inside 名前を入) is a label of its own.
- A sprite drawn twice (black or one-colour shadow, then colour) needs nothing special when both layers show the same rectangle.
- "compressed page needs N bytes, its slot has M": fewer ink levels in the style (the soft colours between outline and fill, the ramp of the letters) fixed it both times.
- New styles in `ui_type.RENDER`: `titlestart` / `titleview` / `titlelink`, `titleitem`, `titlecount`, `titleclear`, `warnline`, `warnhead`, `albumclear`, `albummovie`, `makehead`, `makeitem`, `nannormal`, `nanrookie`, `namehead`, `namebutton`; `logo` takes a `thick` outline, `dropped` is letters with a cast shadow and no outline.

## The match: where its text is, and the first sheets (2026-10-13, ninth session; applied, calls seen in game)

Done offline while another session held the emulator and the build (My Life batches): three specs written,
checked by rendering in memory, not applied to `DATA/files`. Generator: `_work/ui_pages/gen_match_spec.py`
(writes `ui_specs/gameplay.json`, `main_prg.json`, `time.json`). Apply them, prove the sheets with a texture dump,
then look (see "Next" below).

- **The match's strings are done already.** `gameplay.rel` has 429 string slots, 343 English since the fifth
  session; the 86 left are glyph grids and a few player names. The 24,000 cells of the inventory are mostly
  such grids. So step 5 is sprite art.
- **The art**, by machine survey and by looking at every bank: `gameplay.arc` (umpire's calls `h3_stf_0`, pause
  menu `h3_tim_0`, records banner `h3_lo_0`, turning/attack point `y5_tnp_1`, shift tags `h3_aps_0`, the HUD
  candidate `h3_ap_ps2`, the original-pitch font `h3_kyu_0`), `main_prg.arc` (line score `g3_sb` / `g3_sbn` /
  `g3_sbk`, player panel `g3_np`, pitch chart `g3_np2`, at-bat result tags `g3_nk` / `g3_tij`, team logos
  `r4_12h`), `time.arc` (`g3_tim`: the substitution screen that Bullpen / Defense / Pinch Hitter open),
  `option.arc` (`g3_ops`: the options screen, 20 compressed pages, about 50 buttons and 45 help texts drawn as
  pictures), `ctrler.arc` (controller diagrams, 4 banks), `order.arc`, `shift_ed.arc`, `vs.arc` / `vs_st.arc`
  (exhibition setup, stadiums; the stadium ads are real sponsors and stay).
- **No copies**: a hash of every decoded page of all `.arc` files finds none of these pages in another file
  (one page of `g3_hk` is also in `scg_camp.arc`). Still to prove in game that these banks are what the screen
  draws.
- **Pitch names in a match** are whole-word sprites (`g3_np2`, 31 names). `h3_kyu_0` (katakana, A-Z, 魔 球 改 真 超
  号) is the font for the names of original pitches, which the player types; nothing to translate there.
- **Not located**: the score bug (inning 回表 and the count). `gameplay.arc` `h3_ap_ps2` (orange / navy plates,
  S and B letters, 244 sprites) is the likely bank, but its pages decode with wrong colours; needs a texture dump.

**In game (22:05-22:20, applied, COM vs COM exhibition + a 1P game; dolphin-test/looks/match/):** STRIKE, BALL, FOUL,
SAFE, CHANGE, WARMING UP seen, centred and crisp; every call page was among the loaded textures. Proven by the
texture dump for what is still Japanese: score bug and batter / pitcher panels (率 本 打点, 防, 試合 勝 敗, 球, ポイント)
= `gameplay.arc` `h3_ap_ps2`; inning 回 表 裏, 号, 飛距離 = `main_prg.arc` `h3_ulk_0`. **The pitch name shown after a
pitch and on the pitch selector is text drawn with the `h3_kyu_0` katakana font**, so `g3_np2` is only the
pitch chart; the table behind it is not found yet (not standard glyphs, kyu sprite indices or Shift-JIS in any
module: search RAM during a pitch). Player names are rendered into textures at run time from the font. The pause
menu could not be opened (+ does nothing in watch mode or a 1P game; HOME is the Wii system menu): pause menu,
substitution screen, pitch chart, `g3_np` panel and line-score boards are applied but not seen.

Specs (193 labels):
- `gameplay.json` `calls` (20): STRIKE, BALL, FOUL, FAIR, SAFE, OUT, TIME, PLAY BALL, WARMING UP, WALK, HIT BY
  PITCH, GROUND RULE / DOUBLE, HIT, CHANGE, GAME SET, INFIELD / FLY, HOME RUN, 2-RUN / 3-RUN HOME RUN, GRAND /
  SLAM. MLB Power Pros wording (`env_game_mlb`) except where space ruled: GAME SET and CHANGE keep the
  Japanese-English umpire words (MLB: THAT'S THE BALLGAME, CHANGE OF SIDES), WALK (MLB: BASE ON BALLS).
  Style `call0`..`call5`, one per palette (fill gradient, purple outline, white band, coloured band, shadow).
- `gameplay.json` `pause menu` (28): Play, Fast Game, Normal Game, End, Quit, Replay (+ the A / B tags, kept),
  Score, Continue, Pitcher Data, Controller, Controller Setup, Audio, Options, Display Options, Turn Setup,
  Bullpen, Defense, Pinch + Hitter / Runner, Instructions, Game Data, Give Up, Retry, Forfeit, Team Analysis,
  Controls (MLB `env_game` wording where it has the item). Style `pausemenu`, fixed baseline (screen row 20).
- `main_prg.json` line score (51 cells in three banks): 1..18 and R; H and E were Latin already.
- `main_prg.json` `pitch chart` (31): the Success chart's wording, style `pitchchart` (white in a blue ring).
- `main_prg.json` `player panel` (18 + 3 emptied): CON PWR SPD ARM FLD TRJ AVG HR RBI POS, ERA, Control,
  Stamina, Age, Pro Yrs, FA, Salary, Loyalty; 本 and 点 (units behind HR and RBI) emptied; km/h kept.
- `time.json` (46): column headers AB AVG HR RBI TRJ CON PWR SPD ARM FLD POS, R SB E; pitching IP BF NP SO WP BB
  ER R H HR; Batter / Bench; runner tags 3rd / 2nd / 1st + Runner; the screen's two sets of menu words.

New in the tools (`ui_type.py`; all ten older specs still render byte-identical to what is installed):
- `"ribbon": true` group (`repack_ribbon`): big lettering set line by line and poured into the page rows,
  cut where a row ends; piece n goes to part n of the sprite. A sprite has a fixed number of parts (a 2-part
  call can show two pieces at most), so long lines take whole empty rows first. Lines drawn twice in one style
  are stored once (HOME RUN of the 2-run and 3-run homers). Without this the calls did not fit: the English
  needs about 3,700 columns of 54-pixel rows, the 14 pages hold 3,584.
- `"slices": true` label: one label cut into strips over the parts of its sprite (kept; the ribbon replaced it
  for the calls).
- `"sprites": [ids]` on a `"from"` label: only those sprites' parts of a shared piece (走 is SPD in the column
  headers and Runner on the base tags); the plain label for the same piece leaves them alone.
- `"share": true` group: labels whose art comes out identical are stored once (the two sets of menu words).
- Styles `called(...)` (`call0`..`call5`, `pausemenu`, `submenu`), `tight(style)` (drops the empty rows round
  a style's art: 16-pixel rows), `pitchchart`, `panel`, `subhead`, `subtab`.
- `"left"` / `"baseline"` per cell where the Japanese cells sit a pixel or three off their row (pitching lines,
  player panel): computed from the sprite's own offsets in the generator.
- Previews: `_work/ui_pages/tools/after.py SPEC BANK OUT.png [scale] [sprite ...]` composes a bank's sprites with
  the spec applied in memory (each part in its own palette; `ui_labels.py preview` colours a page with one
  palette), `bank_sheet.py ARC BANK OUT.png [scale]` every sprite of a bank from the original.

Room is the limit everywhere in the match, not the byte budget: pages hold little free space, the pause menu
needed 96% of its label rows until Pinch and Replay were shared again as in the Japanese. Pages that no sprite
shows are not free: page 2 of `g3_tim` is fully painted (probably drawn by code); leave such pages alone.

Left for the match, with what blocks each:
- Score bug and count: find the bank (texture dump in a match).
- At-bat result tags `g3_nk` / `g3_tij` (投安, 左本, 三振 ...): a position cell and a result cell on a coloured
  plate, 24-pixel cells, so they can be re-lettered cell by cell (LF + 1B). Undecided: what ス and ギ stand for
  (seen in 左ス, 左ギ), and 三 is both "third base" and the first half of 三振: needs `"sprites"` overrides.
- `time.arc`: 今日の成績 (Today's Stats, two headers with « »), the tabs on a stripe (控え投手, 控え野手, 右投手,
  左投手, 投手: the stripe is in the same cell, needs a synthetic plate), 攻撃中 (vertical), 時間 / 分, the R / L / S
  handedness icons.
- `g3_np`: position marks 遊 外 投 捕 一 二 三 and handedness / form / type plates (letters on a plate: "paint").
- `option.arc`, `ctrler.arc`, `order.arc`, `shift_ed.arc`, `vs.arc`, `y5_tnp_1`, `h3_lo_0`, `h3_aps_0`; small
  pieces of `h3_stf_0` (投球練習 small, あと N 球, やめる).
- Bench sheet: Success's `scs_main.arc` `z4_sod_*` (needs the cross-page paint).

## Banks that hold several sprite sets (2026-10-14, tenth session)

Some files keep several sprite sets behind one palette: the pages run tex_<set1>00.., tex_<set2>00.., and the sprites of
every set number their pages from 0 again. `ui_textures.banks` now returns one bank per set (`split_merged`; shared
palette). It splits only when every set maps to its own run of pages by name and uses no page beyond its own; in all
12 files where it fires each set uses exactly its pages 0..n-1: ore_ini.arc (y3_mym, y3_mys, y3_myk, y3_kzo: the My Life
profile card), gdt_ore.arc, ore_ren.arc, gameplay.arc, gdt_sch.arc, pena_sub.arc, pennant.arc, pn_civt.arc, pn_gaijn.arc,
pn_kivt.arc, pn_tgrow.arc, vs.arc. Before it, the later sets of such a bank were drawn from the wrong pages by every
tool. Every spec renders byte-identical with it. The art survey TSV still counts the pages of the merged banks.

## Strings with a coloured tail (2026-10-14, tenth session)

A unit above the glyph range with a glyph number in its low 12 bits is that glyph drawn in colour (top 4 bits):
the My Life title help lines of ore_ini.rel end in プレイ年数：最大20年 in colour 6, the Pennant report options in
（日程早送りの場合、早送りを中断します。）. ui_strings.find takes such a tail as part of the string only when it is one
colour, behind real text and closed by 0xFFFF (a looser rule found 7,800 false strings in binary tables). The export
writes it {6:...}; the English writes it the same way and the build ORs the colour into every unit of the run (the
letter pairs start again in each run). The neighbours' line widths shifted for eight Pennant help lines: three of
their English lines were one line in a 25-cell box and are now split with |.

## Testing notes

- A Dolphin save state also holds the disc's file table. After any build that changes a file size, boot from scratch; an old state reads files from the wrong place.
- A state taken inside Success Mode keeps the old scripts in memory.
- A round is about 20 seconds: build 2 s, `to_command_menu.py boot` 10 s, `resume` 6 s. The scripts look at a screenshot before each step instead of waiting a fixed time, and Dolphin runs the game at 4x.
- Dolphin's default renderer on the Mac (Metal) never runs faster than the screen refreshes (2x on a 120 Hz screen), whatever the speed limit says. The harness starts Dolphin with the OpenGL renderer at a fixed 4x. With no limit OpenGL reaches about 9x, but then a button press of 0.04 s is long enough to repeat in menus; 6.0 hung and 8.0 ran at 2x.
- The Data screen turns its ability pages with the D-pad alone. In the test Dolphin the D-pad and the Nunchuk stick share the pipe buttons, so the D-pad is also mapped to the pipe's C axis: `harness.dpad("RIGHT")`.
- `harness.py start` does not check for a running instance: a second one on the same folder makes state loads fail. Stop first.
- `to_command_menu.py resume shop` continues from a second save (year 1, November week 1, `nand_backup_shop/`): the shop is open there (Items > Shop), Date is offered and the Schedule shows another stretch of the year.
- A hotkey sent before the game runs can make Dolphin exit. `harness.py start` waits for the game's own boot messages in `dolphin.log`.

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
python3 ui_strings.py export|apply|merge   # menu and system strings, English in translation/strings/*.tsv
python3 ui_labels.py apply ui_specs/scs_main.json   # English lettering into a sprite sheet (.arc)
```


## Pitch names of a match (2026-10-14, eleventh session)

The name under the pitcher after a pitch ("ストレート 146 km/h") and on the pitch selector is **text in a
code of its own**, not glyphs, sprites of a word or Shift-JIS: `gameplay.rel` sec5+0x29CD4 holds the 26
standard names, one byte per letter, each closed by 0x7D, reached through 26 `R_PPC_ADDR32` at sec5+0x29DA8
(the pitch type is the index; code reads the table at sec1+0x176A6). A byte indexes a table of sprite
pointers that the game fills at run time (0x80A5CDB8 in a match) with the sprites of `gameplay.arc`
`h3_kyu_0`, the font of the original-pitch names: blank, katakana in JIS order, ー, 0-9, A-Z, 号 超 真 改 魔 球
(`kyu_names.CODES`). No lower case, no punctuation.

How it was found: every search for the text (any 1-, 2- or 4-byte code, 12-bit packing, glyph numbers, SJIS,
JIS, EUC, UTF-16, in the files and in memory) missed or was misread: one byte-pattern search did hit the block (ス = 0x19), but it was
dismissed because the code had been assumed to be the sprite order. What worked: the font's sprite data (`opd_h3_kyu_0_*`)
found in a save state by the bytes of one part rectangle (km/h), then a search for 32-bit pointers to those
sprites, which lands on the code -> sprite table; the names sit right behind it. Save states were taken by
`dolphin-test/looks/pitchnames/catch2.py` at the moment a name is on screen.

`kyu_names.py` (list, check) and `translation/pitch_names.tsv`; the build lays the names out again in the
212 bytes (shared tails) and rewrites the 26 addends; verify checks them. **The game draws 9 letters at
most** (9 sprite slots, 12 pixels apart: "DROP CURVE" showed as "DROP CURV"), and a space leaves a gap wider
than a letter, so the long names are SLOWBALL, SLOWCURVE, DROPCURVE, KN-CURVE, H-SLIDER, H-SINKER, H-SHUUTO,
C-CHANGE, MOVING-FB; "-" is drawn with the long-vowel bar. Seen in game (COM vs COM, two games, about 290
pitches read): FASTBALL, 2-SEAMER, SLIDER, FORK, CURVE, SHUUTO, CUTTER, CHANGEUP, C-CHANGE
(`dolphin-test/looks/pitchnames/`). Not seen: the pitch selector of a 1P game; the rarer names.
Original pitches keep the names the player typed (katakana); the font has A-Z, so English names
can be typed there too.

## Match leftovers and the bench sheets (2026-10-14, twelfth session)

**Seen in game (1P exhibition, dolphin-test/looks/match3/):**
- **The pause button is +, but only while the game waits for the player's pitch** (the pitch selector is up). During
  the warm-up, a batter's turn or COM vs COM it does nothing, which is why it was "not found" before. It opens the
  pause menu (TIME call, Play / Score / Bullpen / Pitcher Data / Defense / Controller / Options / Audio / Replay /
  Quit, all English); Score, Bullpen and Pitching open the substitution screens of `time.arc`.
- **The "右 / 左 tag" of the batter panel is the fielding position** (右 = right field), a plate of `main_prg.arc`
  `g3_pur` (投 捕 一 二 三 遊 右 中 左 DH 走 打 外, あき). Each plate is a 32x32 plate part plus a 24x24 letter part in
  the plate's palette, so only the letter part is re-lettered: P C 1B 2B 3B SS LF CF RF DH PR PH OF, EMPTY (style
  `pur_pos` / `pur_empty`). The same plates show on the batter panel, the lineup screens and the score screen.
- `gameplay.arc` `h3_sc_ps2`: 打席目 (the batter's Nth time up, a piece shared by the number sprites) is AT-BAT
  set left of the number ("AT-BAT 1", seen on the pitch-count panel). Ordinals (1st, 2nd ...) would need four
  pieces; its two pages have no room. サイン is SIGN, painted into its plate (not seen yet: it shows with a sign).
- `time.arc` `g3_tim`: the bar buttons hold about 62 pixels, so the bar says Pitching / Pinch Hit / Pinch Run (the
  wide buttons of the score screen use the same words: no room for two sets). Painted: Pitcher / Bullpen / Bench /
  Righties / Lefties on their stripes, Today's Stats (bar and « » plate), the R / L / S hand plates, and the
  vertical 攻撃中 as BATTING turned to read top to bottom (style wrapper `turned`). Still Japanese there: 分
  (game minutes, a 16x24 cell) and 時間.
- `ui_labels.py` paint: a `"copy"` narrower than the rectangle is repeated across it (a clean strip of a stripe
  or plate), and `"copy": "clear"` empties it (lettering with nothing behind it).

**Bench sheets (`scs_main.arc` z4_sod_*), applied, not seen yet.** Three sheets, each a 512x360 picture on 12
compressed 8-bit pages (page n at 128 * (n % 4), 128 * (n // 4)): `tex_z4_sodp` (the player's team, (株)パワフル),
`tex_z4_sodk` (Kagurazaka Group), `tex_z4_sodf` (Otori Phoenix). sodp's pages sit in a bank of the same name
without sprites, so specs find a sheet by its page names. New tool `ui_sheet.py` ("sheet" entries of a spec, read
by `ui_labels.render`): it assembles the picture, rebuilds the background under a heading (per row, per column or
a flat cell's commonest colour), sets the English in RGB (letters, rings, a shadow) and maps every pixel to the
nearest colour the picture already uses, then cuts the pages back out as byte patches. Wording (generator
`_work/ui_pages/gen_sod_spec.py`): Lineup Card, team name, Starting Lineup, No. / Player / Pos, Bench, Bullpen,
Player / Pos / Thr. ("Throws" does not fit the 26-pixel cell). Small cell words are drawn without anti-alias
levels: one page of sodk was 11 bytes over its compressed slot with them.

**Banners `z4_tem_0` / `z4_smj_0`: still blocked.** Each glyph sprite is centred on its own origin (x -64 for a
128 cell), so the code alone sets the spacing; a list of the sprite numbers in `scs_main.rel` sec5+0x10616c turned
out to be part of a calendar table (3 x 12 words read at sec1+0x6b410), not the banner layout. An English word cut
over the glyph sprites needs the spacing seen on screen once.

## Surnames in Latin letters (2026-10-14, fourteenth session; seen in game)

The surname list (1,856 names: team-mates, generated players, Eikan Nine squads) is English in two forms. Tool:
`name_table.py` (doc string has the detail); English in `translation/names/surnames.tsv`, romanised from the
announcer's own readings (each record's call id), so a kanji with several readings comes out as the game says it.

- **A main.dol data section cannot hold it.** The apploader refuses any DOL section above 0x80900000 ("One of the
  sections in the dol file exceeded its boundary ... (production mode)"); the game does not start. Real hardware too.
- **scc_main.rel has a fixed slot** (0x807E8380, plan row 25; the size column there is the file size, not
  fixSize + BSS) that ends 28 bytes before scs_main.rel. Grown in place it overwrote scs_main.rel ("OSLink: unknown
  relocation type"). The build now moves it to 0x81460000 in the free area (like ore_work.rel) and appends a
  16-byte-record table to its section 5 (six cells, 0x1FFF, call id). Readers in scc_main / scs_main / sct_main /
  work_sct: relocations re-aimed (TableRemap), mulli 0xA -> 0x10, call id at +0xE, and the four-cell copiers turned
  into six-cell loops in their own space. Watch out: `addi rD, r0, x` is `li` (rA = 0 is the value 0): use addic.
- main_prg.rel cannot grow (next module 16 bytes behind): its own copy keeps 10-byte records with four cells
  (8 letters) in the slot that held 0x1FFF; 187 longer names use a Kunrei short form (Takahasi), 21 stay kanji.
  Its reader is reached through a function pointer; where those names show is not known yet.
- **Layout, seen on the Eikan Nine squad list and in result messages:** a name plate spreads a name's cells over
  its width (trailing blank cells dropped, a leading one kept); text drops blank cells but shows the space of a
  half-filled pair. So odd names start with a space (" Fujii") and names of four letters or fewer start with a
  blank cell ("  Goto"): plates read cleanly (short names sit right of centre), text reads "Goto's", "Fujii's".
  Left: the chatter labels over the field drop the leading blank and spread two-cell names ("An  do").
- Rosters made before the patch keep their kanji: Success team-mates live in the system save, so the test saves
  still show kanji team-mates. A fresh Eikan Nine squad shows Latin names (dolphin-test/looks/eikan/).

### Real players (same session; seen in game)
- The 2008 rosters: 480 records in main_prg.rel sec5+0x68826.. of **six cells, then (a, b, call id)** (read with the
  cells after the values the call ids look shifted by one record). Calls 46,735+ are past the surname voice list;
  their readings come from the reading list of are_main.rel (`_work/voice_readings.json`, 6,942 entries) through
  a parallel u16 table at halfword 16575 + entry index (aligned by brute force against the known surname calls:
  652 hits). A reading can be a full name (たかはしひさのり): names written surname + one kanji (高橋尚) become
  "Takahashi H"; surnames whose reading carries a given name for the announcer (緒方 / 尾形) get the initial too.
- English: `translation/names/players.tsv` (roster offset, call id, English); 56 foreign players and a few
  registered names by hand (Greisinger, Kroon, Ramirez, Lee S.Y., Darvish, G.G. Sato ...; "Inche" (いんちぇ) unsure).
- Every copy is a six-cell field in main_prg.rel: the roster, a names-only list by team (sec5+0x3C738..) and the
  144-byte player records (sec5+0x579F0..): 1,437 places, written in place by `name_table.player_patches`. Two
  kanji patterns stand for two English names (中島 Nakashima / Nakajima, 林 Hayashi / Lin): the roster record or
  a call id nearby decides. Copies in pn_ore_i.rel, pennant.rel and draft.rel are not real players (draft
  prospects and others with the same surnames): a later pass.
- Seen: Giants vs Fighters, COM vs COM (dolphin-test/looks/players1): lineup screens, NEXT panel, batter and
  pitcher panels, fielder tags. Names of five or six cells are squeezed on the lineup plates (as long names were
  in Japanese) but readable.

### Other name stores, written in place (2026-10-14, fifteenth session; built and verified, not seen)
One mechanism for every store whose names sit in fixed six-cell fields: `translation/names/in_place/<module>.tsv`
(section, offset, English; no Japanese), checked against the original (glyph cells, blank cells 0) and laid out
with `name_table.plate`. `name_table.py export-given / -draft / -holders / -foreign` write the TSVs; the build
(`name_table.inplace_patches`) writes them. Detail in the doc comments of `name_table.py`.
- **Given names** (main_prg.rel sec5+0x3B288, 200 x 16 bytes: 0-99 boys, 100-199 girls; Hepburn from the kana,
  long vowels kept where two names would meet: Yuuki / Yuki, Miyuu / Miyu, Koutaro / Kotaro). Read only by the
  team set-up at main_prg.rel sec1+0x8F690 for teams 0x31..0x34, called from camp.rel (Practice) and
  school_g.rel (Baseball School). Not on screen in Baseball School lessons 1, Practice with a real team or the
  team select (RAM checked): those teams come later in the lessons.
- **Draft prospects** (draft.rel sec5+0x2C08, 2,000 x 144 bytes, call id at +0x3C): the surname list's English
  for the same call (1,105), else the call's reading romanised (895). Scouting / draft screens of Pennant.
- **Record holders** (pn_ore_i.rel sec4, 809 fields of 303 historical players, records `FFFF|FFFE, 0x0100,
  kind<<8|team, year, six cells, value` or a dated variant with the cells one later): English by hand
  (Oh, Kaneda, Starffin, Ichiro, G.G. Sato, Michael ...). ローズ is Rose for team 4 (Yokohama), else Rhodes.
  Rare glyphs read from the font: 礒部 Isobe, 廣瀬 Hirose, 廣澤 Hirosawa, 髙橋慶 Takahashi Y, 簑田 Minoda,
  毒嶌 Busujima. Codes 0xF00.. are pictures of whole names (G.G. Sato, Michael), not font glyphs.
- **Foreign players**: pennant.rel sec5, 656 fields (pointer table sec5+0x7AE8: 45 Korean / Taiwanese
  single-kanji surnames, then katakana given names). The game's jersey spellings (sec5+0xC6F8, A = 1:
  ANDOREW, EDWARZ) are a parallel list in the same order; they stay. English: real names (Andrew, Edwards,
  Gagne); invented katakana kept close to the jersey (Agle, Zatto). Success uses its own copy: scc_main.rel
  sec5+0x4AF0..0x68D0, 360 records (six cells, 0x1FFF, call id) incl. 88 Korean / Taiwanese full names
  (Lee Kyungho, Kim Sangil, Lin Tsunghan; too long: initials, Lee D.K.). Taiwanese names written in
  Japanese readings are a best guess at the Mandarin. scc_main.rel moves in the build, so its fields are
  written into section 5 before the surname table is appended.
- Font: 2,022 letter pairs (1,016 slots left).
- Harness: in Pennant, A does nothing on the coach screen (long setup) and on the main-menu commands
  (新戦力 ...); "Start right away with basic settings? Yes" reaches the main screen (state slot 2). The
  menu needs another input (pointer?) before draft, scouting or foreign players can be seen.
- Left: coaches' names (kanji, Pennant coach screen), the jersey spellings, Eikan Nine school names.
