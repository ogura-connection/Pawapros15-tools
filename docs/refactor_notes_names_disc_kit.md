# Refactor notes: names, disc, reference, kit, config, cli (stage 3)

Area: `pp15/names/**`, `pp15/disc/**`, `pp15/reference/**`, `pp15/kit/**`, `pp15/config.py`, `pp15/cli.py`, `pp15/__main__.py`,
`pyproject.toml`. Tests: `tests/test_names_disc_kit.py` (44 tests, no game data needed, a few seconds).

## What changed (no behaviour change)
- Proof: `pp15 build` and `tests/golden.py check` (1,089 files identical), and a before/after comparison of every command that
  can run offline: `release` (both ISOs byte for byte identical, `wit verify` OK), `extract-text`, `export-tm`, `export-labels`,
  `ram-scan`, `mlb-assets list|sheet|text|textures`, `kyu-names list|check`, `names check`. `extract-iso` could not be run
  (pycryptodome is not installed); its decrypt and file-table code is covered by the unit tests with a stand-in cipher.
- `names/table.py` (620 lines) lost its PowerPC word builders (`names/ppc_words.py`), its TSV writers (`names/export_tsv.py`) and its
  command line (`names/commands.py`, argparse). `pp15 names` now starts `pp15.names.commands`. The public names the build uses
  (`CODE_NAMES`, `READERS`, `patch_code`, `place_host`, `short_table`, ...) are unchanged in `names/table.py`.
- Import cycles: `names/kyu.py` no longer imports the build (it reads the original module with `scan.Rel`, same file, same result);
  `names/schools.py` has its own `relocation_entries` (same walk as `build.rebuild.parse_imports`; a unit test checks they agree).
  Suggestion for the build owner: move `parse_imports` into one small shared module and let both use it.
- `disc/extract.py` imports pycryptodome lazily with a clear message (`pip install pycryptodome`); `tests/test_imports.py` no
  longer needs to skip it. The Wii sizes and keys that `extract.py` and `xdelta.py` both used are in `disc/wii_format.py`.
- `disc/ram_scan.py`: the pure-Python LZ4 decoder is `disc/lz4_fallback.py` (tested); `ram_scan` uses the `lz4` package if present.
- `disc/extract_text.py`: the module list is the constant `TEXT_MODULES`; the duplicated dictionary-building code is one helper.
- `reference/mlb_assets.py`: `_blocks` and `_rgb5a3` (used by `pp15/art/labels.py` and `pp15/art/textures.py`) are now
  `undo_gx_blocks` and `rgb5a3_array`; the two old names are kept as plain aliases until those modules switch (then delete the two
  lines marked in `mlb_assets.py`).
- Command line: argparse sub-commands with `--help` for `names`, `kyu-names`, `release`, `extract-iso`, `ram-scan`, `export-tm`,
  `export-labels`, `mlb-assets`, `mlb-labels` (all in `cli.NATIVE_HELP`). Same arguments. Differences: a wrong argument count is
  argparse's error (exit code 2, was the module docstring or exit 1); `kyu-names` / `mlb-assets` with no command print the help.
- `pyproject.toml`: comments, a `dev` extra and the pytest settings.

## For the person merging
- `cli.NATIVE_HELP` lists the commands whose module answers `--help` itself. When the other areas move `script`, `strings`,
  `messages`, `art`, `textures`, `sheet`, `font` to argparse, add those names to that set (without it `pp15 COMMAND --help` still
  prints the docstring, which is fine but not the argparse text).
- Add `echo "== names/disc/kit"; python3 tests/test_names_disc_kit.py` to `tests/run_all.sh` (I did not edit it, other areas do).

## Bugs and oddities seen (not fixed)
- `pp15 names export-given|export-draft|export-holders|export-foreign` overwrite `translation/names/in_place/*.tsv` with fewer rows than are
  checked in (656 lines fewer). Never run them without looking at `git diff`. (Not re-run in this stage: it would rewrite the files.)
- `disc/extract.py` takes the first data partition of the disc, `disc/xdelta.py` the last one. Same on a retail disc (one data
  partition); different in principle. `parse_fst` decodes names as ASCII (errors replaced), `xdelta.fst_files` as Shift-JIS.
- `disc/extract_text.glyph_to_char` is a second glyph table: it differs from `pp15.glyphs.glyph_to_char` for 226 of the glyphs 0..3799
  (e.g. 0 and 108..) where `glyphs` has the game's own symbols. Left as it is because `extract-text` output must not change.
- `kit/export_labels.py` still needs `compose.sprite_image` from `_work/ui_pages/tools/compose.py` (git-ignored); it belongs in
  `pp15/art/textures.py` (the art owner's file).
- `reference/mlb_assets.py` has two picture decoders (`decode_c4_c8`, plain Python, C4/C8 only; `decode_all`, numpy, all formats). They agree
  (unit test). `Project` keeps its file open (no `close`).
- `disc/xdelta.py` shells out to `openssl` once per cluster, twice per cluster on write: slow (about 10 minutes for the full release).
- `mlb-labels` needs the macOS OCR helper; in this environment it read nothing (0 labels kept), before and after the refactor alike.

## Dead code
- Deleted: `extract.r_u16` (grep: no user), the unused `G`/`S`/`struct` imports, the `if True:` in `mlb_labels`.
- Left: `config.UI_PAGES_DIR`, `config.use_scratch` are used by art styles and the name exports (see `grep`).
