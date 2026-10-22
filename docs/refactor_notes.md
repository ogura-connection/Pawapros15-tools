# Refactor notes (stage 1 done, stages 2 and 3 to do)

Stage 1 moved the code into the `pp15` package with no behaviour change (`tests/run_all.sh` passes: all 126 modules import,
`build-check`, and the golden check of 1,089 installed files). What was seen on the way and left alone on purpose:

## Stage 2: names and files
- `pp15/art/styles/` still holds the 91 `ui_styles_*.py` files under their old names (`a_run1` ... `zzzz_leftd`: named after
  the art run and agent that wrote them, not after the screen). Rename by screen, merge the near-empty ones, then drop the
  `ui_styles_` prefix. Keep the import order: `typeset.py` imports them by file name and a later module may override an
  earlier style (25,575 entries in `typeset.RENDER` today; `tests/test_imports.py` checks the count).
- Two style modules import helper scripts that live in `_work/ui_pages` (`ui_styles_c_run4` -> `gen_c_lib`,
  `ui_styles_b_run9` -> `kit`): they go through `config.use_scratch()`, the only `sys.path` edit left in the package
  (`names/table.py` and `kit/export_labels.py` use it too, for `_work/names/romaji.py` and `compose.py`). Vendor the helpers into the package (or drop the styles) so that the package needs nothing from `_work`.
- `pp15/kit/export_labels.py` needs `compose.sprite_image` from `_work/ui_pages/tools/compose.py` (git-ignored). Move
  `sprite_image` into `pp15/art/textures.py`.
- `translation/**.tsv` headers say `(see tl.py)`, `(see ui_strings.py)`, `(see ui_messages.py)`: the strings are written by
  `script/translate.py`, `text/strings.py` and `text/messages.py` (and one in `strings.py` into generated review files).
  Left as they were so that saved files stay byte-identical; change them together with a one-off rewrite of the TSV headers.
- `translation_high_quality.json` (git-ignored, repository root) is used by nothing.

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
- `art/typeset.py` imports its 91 styles at import time, which takes about half a second; load them on first use of `RENDER`.
- Type hints and docstrings are missing from most functions; many docstrings describe the history of a decision, which
  belongs in `FINDINGS.md`.

## Outside the repository
- Scratch scripts under `_work` (all `*.py`, `*.sh`, not only `ui_pages/`) had their imports and `python3 tl.py ...` style
  commands rewritten mechanically; `_work/ui_pages/README.txt` says they are historical. Several still set
  `T = ~/Projects/Pawapuro/Pawapros15-tools` and write into that folder when run.
- `~/Projects/translation-kit/probe_pp9_pp11/` (`setup.sh` copies `Pawapros15-tools/*.py`; `overlap.py`, `packed.py`, `c16.py`
  import `scan_story` / `pawapuro15_text_tools`) and the briefs under `agent-briefs/` still use the old names.
- `~/Projects/Pawapuro/dolphin-test/harness.py` points at `Pawapros15-tools/DATA/sys/main.dol`; fine while the folder keeps its name.
