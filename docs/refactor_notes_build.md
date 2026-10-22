# Refactor notes: area `build` (stage 3)

`pp15/build/rebuild.py` (1,534 lines) and `font.py` (420) were split by job into 24 modules, none over 250 lines and no
function over 70 lines. No behaviour change: the output of `pp15 build` (every printed line), the 77 files it leaves in
`_work/build/`, `pp15 build-check` and `tests/golden.py check` are identical before and after.

## Where things went

| Old place | New place |
|---|---|
| `rebuild.parse_imports`, `encode_stream`, `rebuild_module`, `patch_addends` | `relocations.py` |
| `rebuild.encode_text` | `text_encode.py` |
| `rebuild.Remap`, `BlockRemap`, `emit_script`, `emit_block`, `SECTION_ALIGN` | `script_emit.py` |
| `rebuild.OreRemap`, `ore_chunks`, `emit_ore`, `ore_relocations` | `ore_script.py` |
| `rebuild.plan_tables`, `memory_size`, `plan_index`, `update_plan`, `update_plan_ore`, `PLAN_FILE`, `ORE_WORK_ADDR`, memory constants | `memory_plan.py` |
| `rebuild.encode_dol` ... `verify_dol`, `DOL_BUILT`, `DOL_END` | `dol_block.py` |
| `rebuild.assign_pairs`, `build_font_file` | `font_assign.py` |
| `rebuild.CODE_PATCHES`, `patch_code_words`, `rel_art` | `code_patches.py` |
| `rebuild.encode_string`, `layout_block`, the UI-string / message / pitch-name parts of `build()` | `ui_write.py` |
| the name parts of `build()` | `name_stage.py` (tables), `name_patches.py` (writing into modules) |
| `rebuild.load_translation`, `LINE_CELLS`, `POPUP_*` | `translation_file.py` |
| `rebuild.verify` | `verify.py` |
| `rebuild.ensure_orig`, `load_dir`, `load_scripts`, `install` | `module_files.py` |
| `rebuild.cmd_check` | `roundtrip_check.py` |
| `rebuild.build` (400 lines) | `pipeline.py` (stages), `script_stage.py`, `module_stage.py`, `build_state.py` (the shared state) |
| `font.text_segments`, `segments`, `split_pairs` | `pair_text.py` (still importable from `font`) |
| `font.compress`, `decompress`, `to_grid`, `font_glyphs`, `pack_font`, `game_glyph` | `glyph_codec.py` |
| `font.other_text_usage`, `name_usage`, `allocate`, `KANJI_SLOTS`, `RESERVED_GLYPHS` | `font_usage.py` |
| `font.cmd_preview` | `font.preview` (argparse `pp15 font preview TEXT [OUT.png]`) |

`rebuild.py` is now the command line (`build`, `build-check`, `build-restore`) and still exports `ORIG_DIR`, `PLAN_FILE`,
`plan_tables`, `parse_imports`, `load_dir` because `names/kyu.py`, `names/schools.py` and `disc/ram_scan.py` import them
from there. `font.py` still exports `text_segments` (used by `text/strings.py`).
FINDINGS.md and TECHNICAL_GUIDE.md still name the old places (`pp15.build.script_emit.emit_block`, `emit_ore`,
`pp15.build.font_usage.name_usage`, `allocate`); they are not in this area.

## Import cycles
Inside `pp15/build` there are none and no import sits inside a function. The cycles that remain are in files of
other areas, and can now be removed there because the pieces they need live in small modules with no dependency on
`names`, `art` or `text`:
- `text/strings.py` (twice, inside `block_fit` and `letters`): `from pp15.build.pair_text import text_segments` at the top.
- `names/schools.py` (`patch_pointers`): `from pp15.build.relocations import parse_imports` at the top.
- `names/kyu.py` (`load_module`): `from pp15.build.module_files import ORIG_DIR, load_dir` at the top.
- `disc/ram_scan.py`: `from pp15.build.memory_plan import PLAN_FILE, plan_tables` and `from pp15.build.module_files import ORIG_DIR`.
- `cli.py`: `font` now parses its arguments with argparse; adding `"font"` to `NATIVE_HELP` makes `pp15 font --help` show the
  argparse help instead of the module docstring (not changed here, the file is another area's).
After those edits `rebuild.py` can drop its three compatibility imports.

## Tests
`tests/test_build.py` (28 tests, 0.2 s, no game data): pair splitting, glyph compression round trip, font dataset,
text encoding, relocation streams (including gaps over 16 bits), a synthetic REL module rebuilt unchanged and grown,
`Remap`, `emit_script`, `OreRemap`, a synthetic ELF memory plan (unchanged, scenario slot moved, overflow stops),
`allocate`, the dialog block layout, `load_translation`, `patch_code_words`, `verify` helpers, `BuildState`.
`tests/run_all.sh` gets one line for it (before `build-check`).
Not unit tested because they need the Menlo font or the real game files: `font.render_pair`, `build_font_file`,
`pipeline.build` (covered by `build-check` and the golden check).

## Bugs and oddities seen (not changed)
- `ensure_orig` copies the "originals" from `DATA/files` on first use: if `DATA/files` already holds built files, they silently
  become the originals. A check against `tests/golden_sha1.json` or a size/hash list of the untouched game would catch it.
- `font_usage.other_text_usage` and `name_usage` cache their result in `_work/glyph_usage2.json` / `name_kanji.json` without
  recording which modules or `skip` set made it; a stale file after a change in the originals is not noticed.
- `pp15 build --pad` only reaches the four Success Mode scripts; block scripts ignore it.
- `code_patches.rel_art()` re-reads `rel_art.json` once per module (about 250 times per build); harmless, a cache would do.
- `update_plan` / `plan_index` find a module's row by its file size and memory size; two modules with the same pair would be
  reported as "not found" (it does not happen with this game).
- `load_translation` line-width limits (`LINE_CELLS`, `POPUP_CELLS`) only warn, they never stop the build.

## Dead code
Nothing was deleted that grep and the tests do not prove unused. Removed: the one-letter module aliases and the
`R_NOP, R_SECTION, R_END` copies in `rebuild.py`, the private `_cache` / `_faces` names of `font.py` (now `_shade_cache`,
`_face_cache`). No unused functions were found in the area.
