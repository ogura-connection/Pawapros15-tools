# Refactor notes: pp15/art (stage 3)

Scope: `pp15/art/*.py` except `pp15/art/styles/**`. No behaviour change: all 118 specs render to the same bytes and the same
report rows as before (checked by rendering every `specs/*.json` with the old and the new package), `pp15 art apply` on a copy of
`scs_main.arc` gives the installed file, `pp15 textures check|parts|page`, `pp15 art boxes|preview` and `pp15 sheet preview` give
identical output, `tests/test_registry.py` (25,575 styles, the fonts) and the golden check pass.

## New layout
| Old | Now |
|---|---|
| `typeset.py` (1,373 lines) | `typeset.py` (entry point, 94), `pixel_ops.py` (grow, shift), `lettering_fonts.py` (fonts), `lettering_styles.py` (style factories), `named_styles.py` (the table of named styles), `style_registry.py` (lazy tables), `repack.py` (page layout) |
| `labels.py` (678) | `labels.py` (MLB sheet reading and fitting, 364), `spec_render.py` (draw a spec), `spec_io.py` (load_spec, bank_of), `strips.py` (text-atlas names), `spec_cli.py` (`pp15 art`) |
| `textures.py` (701) | `textures.py` (page images and the CLI, 373), `arc_banks.py` (ELF symbols, banks), `page_codec.py` (page bytes), `gx_pixels.py` |

`labels.py` no longer imports the lettering tool, which breaks the cycle `labels <-> typeset <-> sheet`; the imports now run
`gx_pixels, pixel_ops, arc_banks, page_codec -> textures, labels -> lettering_fonts -> typeset -> repack, sheet, strips -> spec_render -> spec_cli`.
The names the rest of the repository uses are still importable where they were: `labels.render` (with `render.patches`, which
`pp15/kit/export_labels.py` reads), `labels.bank_of`, `labels.load_spec`, `labels.main` (a four-name module `__getattr__` in
`labels.py` forwards them to the new modules; `pp15/cli.py` keeps working without edits), `labels.mlb_texture`, `labels.find_boxes`,
and every `textures.*` name the style modules and the kit use (`banks`, `bank_named`, `elf_symbols`, `decode_indices`, `page_bits`,
`encode_indices`, `palette_colours`, `pack_part`, `PAGE`, `ORIG_ARC_DIR`, `S`, ...).

## Lazy style loading
`typeset.RENDER`, `typeset.FONTS` and `typeset.TTF` are `OnDemandDict`s (`style_registry.py`): the 32 style modules are imported the
first time one of the tables is read. `import pp15.art.typeset` takes 0.14 s instead of 0.67 s. Writes do not trigger the load, so a
style module that registers a font while it is imported does not load itself again; a module that is still being imported is
skipped and merged by the next read. `tests/test_art.py` checks that importing `typeset` loads no style module.

## Frozen code (why some functions look unchanged)
`tests/test_registry.py` fingerprints each style by byte code, constants, **docstring**, local variable names and the global names it
reads. Editing any of these in `grow`, `shift`, the style factories (`banded`, `logo`, ...), `style_command`, `style_stat`,
`command_font`, `tag_font` and the helpers they call (`sheet_ink`, `segment`, `clean`, `trim`) or renaming the constants they read
(`COMMAND_WORDS`, `COMMAND_GLYPHS`, `G_ROWS`, `TAG_GLYPHS`, `TAG_DROP`, `_fonts`) changes the fingerprint of thousands of styles
(tried: adding one docstring to `shift` flagged 24,513 styles). So these were only moved (module docstrings, comments and type
hints added; no body, name or docstring changed). Consequences left in place:
- `lettering_fonts.py` imports `pp15.art.labels` as `L` (one-letter alias): `command_font` reads the global `L`, and its name is part
  of the font fingerprint. To remove it, re-record `tests/font_registry.json` and `tests/render_registry.json` after the rename.
- Short locals (`m`, `p`, `h`, `w`) and docstring-less `shift`, `trim`, `tag_font` inside those functions.

## Things other agents / the coordinator should do
- `pp15/cli.py`: add `art`, `apply-art`, `check-art`, `restore-art`, `textures` and `sheet` to `NATIVE_HELP`, so that
  `pp15 textures --help` shows the argparse help of each sub-command instead of the module docstring. They work without it.
- `pp15/kit/export_labels.py` can drop the `_work` helper: `textures.sprite_image(d, bank, parts, bg, only)` is the moved
  `compose.sprite_image` (same body). The cli/kit agent can then call `spec_render.render_spec(...)` instead of reading
  `L.render.patches`.
- Style modules still say `U.S.DATA_FILES` / `_U.S.DATA_FILES` (`styles/match.py`, `styles/my_life_match.py`). `textures.S` exists
  only for them (it is `pp15.config`); delete it when they say `config.DATA_FILES`.
- `gx_pixels.py` calls the private `mlb_assets._blocks` and `mlb_assets._rgb5a3` (two lines). Publish them in
  `pp15/reference/mlb_assets.py` and change those two lines.
- Style modules and `FINDINGS.md` mention `pp15.art.textures.split_merged`, `pp15.art.typeset.RENDER`; both still resolve.

## Bugs / oddities noticed (not fixed)
- `render.report["full"]` (list of `(label name, used the unscaled "full" variant)`) is `True` for every label: the old code copied
  the label (`variant = dict(lab)`) and then tested `variant is not lab`. Kept (`spec_render._choose_variant` returns `dict(lab)`);
  nothing reads the flag.
- `labels.split_words(min_gap=...)`, `Arc.share_pal` and `ribbon_pack`'s `empty` are never given by any caller in the repository
  (kept: not provable unused for `_work` scripts). `labels.draw` lost its unused `halo=()` argument and `textures.page_colours` its
  unused `n_used=0`; no caller passed them.
- `DERIVED` in `lettering_fonts.py` is documentation only (nothing reads it).
- The old `repack()` computed a variable `spare` that nothing used; removed with the split of the function.
- `typeset.TTF` entries for fonts that are not installed (`DIN Condensed Bold.ttf`, Hiragino) fail only when a label uses them.
- `cmd_check` of `pp15 textures` takes 40 s (it decodes and re-encodes all 1,565 raw pages).

## Verified
`python3 tests/test_art.py` (43 tests, 2 s, no game data), `tests/test_registry.py`, `tests/test_imports.py`, `build-check`, golden.
