# Refactor notes, area `script-text` (stage 3)

Files: `pp15/script/**`, `pp15/text/**`, `pp15/glyphs.py`, `pp15/glyph_cli.py`. No behaviour change: every fixed-slot
string, message and scene is identical to the old code (hash of `strings_of` for every module and main.dol, `messages_of`,
`scenes` for all scripts; `judge` on 80,000 real and mutated English strings; the three `merge` outputs byte for byte;
`scan extract/xref/entropy/scan`, `script/strings/messages export`; `pp15 build` writes 0 changed files; golden check).

## What moved where
| old | now |
|---|---|
| `script/scan.py` (1,112 lines) | `scan.py` (the `extract` command, parser, and the imports below), `rel.py` (REL reader), `packed_text.py` (12-bit text), `scripts.py` (Success Mode script), `block_scripts.py` (Eikan Nine, match lines, My Life), `disassembly.py` (`xref`), `survey.py` (`entropy`, `scan`) |
| `text/strings.py` (947 lines) | `strings.py` (commands, export/merge/status, build loaders), `string_tables.py` (the hand-found lists), `colour_text.py`, `line_layout.py`, `movable_blocks.py`, `dol_dialogs.py`, `slot_finder.py`, `string_rules.py`, `string_tsv.py` |
| `text/messages.py` | `messages.py` (same module, argparse, docs) and the shared `tsv_store.py` |
| `script/translate.py` | same module, argparse |
| `glyphs.py`, `glyph_cli.py` | same modules, documented, constants named |

`scan.py` and `strings.py` still import the names other areas read through them (`scan.Rel`, `scan.Script`,
`scan.BLOCK_SCRIPTS`, `scan.WORK_DIR`, `strings.DOL_BLOCK`, `strings.block_layout`, ...); those lines are the public interface and say so.
Checked against every user in the current tree (`build/*`, `names/*`, `art/*`, `kit/*`, `disc/*`, tests): all names resolve.
The old `scan.py` names that nobody outside used (`Code`, `derive_op_advance`, `entropy`, `decompress_*`, `cmd_xref`, ...) now live
only in `disassembly.py` / `survey.py`.

## Changes outside pure refactoring (all in output text, not in data)
- `glyph_cli.py extract-text` used `defaultdict` without importing it, so it crashed at the end (NameError). The import is added.
- The printed row labels of `glyphs char-table` and `glyphs info` and the docstring of `glyph_to_char` named the wrong JIS rows
  (hiragana is row 4, katakana row 5, Greek row 6, Cyrillic row 7, line drawing row 8; verified by printing the characters). Labels corrected.
- `pp15 script|strings|messages ... --help` now print the argparse help (a bad argument exits with status 2 and a usage line,
  where the old tools printed the module docstring and exited 0).

## To apply by hand (shared files other agents also edit)
- `pp15/cli.py`: add `"script", "merge-script", "strings", "merge-strings", "messages", "merge-messages"` to `NATIVE_HELP`.
- `tests/run_all.sh`: add `echo "== script and text unit tests"; python3 tests/test_script_text.py | tail -1` after the imports line.

## Left alone, for the coordinator
- `translation/**/*.tsv` headers still say `(see tl.py)`, `(see ui_strings.py)`, `(see ui_messages.py)` (the constants `TSV_HEADER` in
  `translate.py`, `string_tsv.py`, `messages.py`). Changing the string changes the saved files; do it with a one-off rewrite of the headers.
- `pp15/text/colour_text.py` and `slot_finder.py` import `text_segments` from `pp15/build/font.py` (the letter-pair counter). There is no
  import cycle (font.py imports neither), but a pure-text helper living in the font module drags Pillow into the text tools; moving
  `split_pairs / segments / text_segments` to a small module such as `pp15/text/pair_text.py` that `font.py` also imports would be cleaner.
- `translate.py` is 477 lines and keeps scene extraction, translation files, checks and commands together; it is under the 600-line limit
  and splitting it needs `build/` users to be re-pointed (`pp15.script.translate` is only used by `cli.py`), so it can be cut later.
- `block_scripts.OreScript.__init__` duplicates the label loop of `BlockScript.__init__` (the My Life version also accepts labels
  in the annex); merging them needs a hook in the base class and was not worth the risk.

## Dead or doubtful code (not deleted)
- `glyphs.decode_glyph_string`: used by nothing but its test.
- `colour_text.plain`: re-exported by `strings`, used by nothing.
- `survey.is_kana` is only used inside `survey.py`; `Script.offset_of` only by `scan extract`.
- `glyphs.parse_rel_header / read_section_data` are a smaller second REL reader used only by `glyph_cli extract-text`; `script/rel.py::Rel` does the same.
- `strings.load_mods` is `script.rel.load_all_rels` under another name (`_work/orig` is `config.ORIG_DIR`); kept because `messages`, `kit/export_tm.py` call it.

## Bugs / oddities seen (not changed)
- `messages set FILE ID ""` and `strings set FILE ID ""` (remove) with an ID that is not `section:offset` raise `ValueError` instead of printing a message.
- `strings.strings_of` caches the module list in a module global on first use; a later change to `_work/orig` in the same process is not seen.
- `translate.cmd_export` writes `index.txt` with the platform's default encoding (no `encoding=`); harmless, all ASCII.
- `glyphs.load_glyph_data` assumes the last picture is 256 bytes long (there is no following offset to measure).
