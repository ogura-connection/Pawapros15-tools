# Refactor notes (stages 1, 2 and 3 done)

Stage 1 moved the code into the `pp15` package with no behaviour change (`tests/run_all.sh` passes: all 126 modules import,
`build-check`, and the golden check of 1,089 installed files). What was seen on the way and left alone on purpose:

## Stage 2: names and files (done)
The 91 `ui_styles_*.py` files became 32 modules named after the screen or mode they style, plus `styles/common.py` (shared
helpers); the table is `docs/styles_map.md`. `tests/test_registry.py` (in `tests/run_all.sh`) checks that every one of the
25,575 style names still gives the same style (fingerprint of byte code, constants, closure values and the module-level
values the function reads, independent of module names) and that no style name is defined in two modules, so the order in
which `typeset.py` imports the folder no longer matters. It also compares the fonts the style modules register
(`typeset.TTF`, `typeset.FONTS`). Notes:
- 179 names had been defined twice (a later module overrode an earlier one); only the winning definition is kept, in the
  module of its screen (list in `docs/styles_map.md`). The overridden lines are gone from the code.
- Styles of `eikan_school.py` and `logo_pictures.py` used to import helper scripts from `_work/ui_pages` through
  `config.use_scratch()`; the few functions they use are now `pp15/art/original_arc.py`. Their import lines changed, so
  their fingerprints are in `tests/render_registry_changes.json` (100 names); apply-art of `school` and `homerun` gives the
  same files (golden check).
- `arrange_edit.py` reads `STYLES["f7_kkw"]` where the old file read `typeset.RENDER["f7_kkw"]` (same object).
- Two modules are still longer than 700 lines (`main_menu.py` 1,165, `camp_remopawa.py` 982): one-line style definitions
  in a long list; they could be split by sprite file. Two modules are under 100 lines (`records_room.py`,
  `records_room_extra.py`) and the others near 100 because the helpers of the neighbouring modules
  have the same names with different bodies (`flat`, `win`, `_load`, `grow`, `CELLS`), so they cannot share one file
  without renaming code.
- Style loading is still eager (about half a second at import). Making `RENDER` lazy touches every `typeset.RENDER[...]`
  user: stage 3.
- Not fixed, seen on the way: many modules define their own `win`/`_win`/`flat` with the same idea and different text;
  `d_run2`-style `enable_lazy()` replaces `typeset.RENDER` with a subclass at run time.
- The scratch scripts in `_work/ui_pages` still use the old names. `docs/one_off_rewrite_work_imports.py DIR --write`
  rewrites them mechanically (tried on a copy: 205 files, 508 lines, all `from pp15.art.styles... import` targets resolve);
  it was not run on the real `_work`. Delete the script afterwards.
- `pp15/kit/export_labels.py` needs `compose.sprite_image` from `_work/ui_pages/tools/compose.py` (git-ignored). Move
  `sprite_image` into `pp15/art/textures.py`.
- `translation/**.tsv` headers say `(see tl.py)`, `(see ui_strings.py)`, `(see ui_messages.py)`: the strings are written by
  `script/translate.py`, `text/strings.py` and `text/messages.py` (and one in `strings.py` into generated review files).
  Left as they were so that saved files stay byte-identical; change them together with a one-off rewrite of the TSV headers.
- `translation_high_quality.json` (git-ignored, repository root) is used by nothing.

## Stage 3 (done): one area per agent, no behaviour change
Every module has a plain-English docstring, public functions have docstrings and type hints, one-letter module aliases and
history comments are gone, big modules are split by job (biggest now about 600 lines), command-line tools use argparse
with `--help`, and each area has unit tests that need no game data. Per-area notes with the old-to-new location tables, the
bugs and the dead code that were found but deliberately not touched:
- `docs/refactor_notes_build.md` (`pp15/build/`: `rebuild.py` is only the command line; the work is in `pipeline.py` and small stage modules)
- `docs/refactor_notes_script_text.md` (`pp15/script/`, `pp15/text/`, `pp15/glyphs.py`)
- `docs/refactor_notes_art.md` (`pp15/art/*.py`; style modules were left as moved because of the fingerprint test)
- `docs/refactor_notes_names_disc_kit.md` (`pp15/names/`, `disc/`, `reference/`, `kit/`, `config.py`, `cli.py`)

Run everything with `tests/run_all.sh` (about 20 seconds with the game data; the unit tests alone need no data).

### Still open (the useful next steps, in order)
1. The `translation/*.tsv` headers still say `(see tl.py)` / `(see ui_strings.py)` / `(see ui_messages.py)`: one-off rewrite of the headers, then update the three writers.
2. Style modules keep one-letter names and a few long lists (`styles/main_menu.py`, `styles/camp_remopawa.py`): changing them means re-recording `tests/render_registry.json` and `tests/font_registry.json` on purpose.
3. Small shared pieces to move: `text_segments` out of `build/font.py` (pulls Pillow into the text tools), `parse_imports` duplicated in `names/schools.py`.
4. Bugs found and not fixed (each area's notes list them): the build's `ensure_orig` adopts patched files as originals if `_work/orig` is empty; `names export-given|draft|holders|foreign` overwrite checked-in files with fewer rows (never run without `git diff`); `extract.py` and `xdelta.py` pick different disc partitions.


## Stage 3: code
- Module aliases keep the old names inside the code (`from pp15.text import strings as ui_strings`, `... as name_table`,
  `... as pair_font`, `import ... scan as S`, `... textures as U`, `... labels as L`, `... mlb_assets as G`): rename the uses
  to what the module is called now. Single-letter module names (S, U, L, G, R, A, C, F) are the worst.
- Size: `build/rebuild.py` (1,534 lines), `art/typeset.py` (1,373), `script/scan.py` (1,112), `text/strings.py` (947) each hold
  several jobs (script emit, memory plan, dol block, font assignment, ... / formats, reader, writer, CLI). Split them.
- Import cycles worked around with imports inside functions: `text/strings.py` <-> `build/font.py`, `names/schools.py` and
  `names/kyu.py` -> `build/rebuild.py`, `art/labels.py` <-> `art/typeset.py` <-> `art/sheet.py`. Break them by moving the
  shared pieces (glyph/pair cell counting, `L.render` patches, `bank_of`) into a small module both sides import.
- `art/labels.py` keeps its render state in function attributes (`render.patches`); `cmd_restore` reaches through
  `U.shutil` and `U.S.DATA_FILES`; `textures.py` calls `mlb_assets._rgb5a3` and `_blocks` (private names of another module).
- `DATA_FILES` / `WORK_DIR` are still re-exported by `glyphs.py` and `script/scan.py` (many modules write `S.WORK_DIR`);
  switch those uses to `config`.
- Tools that read `sys.argv` by hand (`translate`, `strings`, `messages`, `labels`, `textures`, `sheet`, `mlb_*`, `kyu`, `font`,
  `names`) take `argv` now but still parse it with `if a[:1] == [...]` chains. Move them to argparse sub-commands like
  `rebuild.py` and `scan.py`, so every command has its own `--help` (today `pp15 COMMAND --help` prints the module docstring).
- `pp15 art` (= `labels.py`: boxes, preview, apply, restore) and `pp15 apply-art` / `restore-art` overlap; `check-art` is
  `textures check` (there was no separate art check before).
- `names export-given|draft|holders|foreign` overwrite `translation/names/in_place/*.tsv` with fewer rows than are checked in
  (656 lines lost when run on the current tree, with the old code too). Never re-run them without looking at `git diff`.
- `disc/extract.py` imports `Crypto` (pycryptodome) at the top, which is why the import test skips it where the package is
  missing; `disc/ram_scan.py` has its own slow LZ4 fallback; `disc/extract_text.py` has the module list hard-coded.
- `disc/xdelta.py` shells out to `openssl`, `wit` and `xdelta3` (found through `PATH`, else `config.WIT_FALLBACK`).
- `art/typeset.py` imports all style modules at import time, which takes about half a second; load them on first use of `RENDER`.
- Type hints and docstrings are missing from most functions; many docstrings describe the history of a decision, which
  belongs in `FINDINGS.md`.

## Outside the repository
- Scratch scripts under `_work` (all `*.py`, `*.sh`, not only `ui_pages/`) had their imports and `python3 tl.py ...` style
  commands rewritten mechanically; `_work/ui_pages/README.txt` says they are historical. Several still set
  `T = ~/Projects/Pawapuro/Pawapros15-tools` and write into that folder when run.
- `~/Projects/translation-kit/probe_pp9_pp11/` (`setup.sh` copies `Pawapros15-tools/*.py`; `overlap.py`, `packed.py`, `c16.py`
  import `scan_story` / `pawapuro15_text_tools`) and the briefs under `agent-briefs/` still use the old names.
- `~/Projects/Pawapuro/dolphin-test/harness.py` points at `Pawapros15-tools/DATA/sys/main.dol`; fine while the folder keeps its name.
