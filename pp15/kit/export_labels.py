"""Our English sprite lettering as pictures, for reuse in later games (the same art and colours turn up in other
Pawapuro titles).

    pp15 export-labels [OUT_DIR] [SPEC ...]   default OUT_DIR <translation-kit>/pawapuro15-wii/labels, all specs/*.json

What it does: for every label of a spec (specs/<arc>.json: the list of painted labels of one picture bundle, see
docs/GLOSSARY.md "Spec"), it writes the sprites that show the label, composed as the game draws them, once from the
original file (OUT_DIR/ja/) and once with the spec applied in memory (OUT_DIR/en/). OUT_DIR/index.tsv lists arc, bank,
sprite, English, style, font and both files. Nothing in DATA/files is read or written for the English: the spec is
rendered from the saved original, which is what `pp15 apply-art` writes. The output is game art: keep it out of this
repository.

The sprite composer `sprite_image` is still a scratch helper in _work/ui_pages/tools/compose.py (git-ignored); it should
move into pp15/art/textures.py.

Public functions: render_spec, labels_of_spec, export_spec, main.
"""
import argparse
import glob
import json
import os
import sys
from typing import Iterator, List, Optional, Tuple

from pp15 import config
from pp15.art import labels, textures

INDEX_HEADER = "arc\tbank\tsprite\tenglish\tstyle\tfont\tjapanese_png\tenglish_png\n"


def render_spec(spec: dict) -> tuple:
    """Render a spec in memory. Returns (original bytes, its banks, bytes with the spec applied, the banks of those)."""
    original = open(spec["source"], "rb").read()
    banks = textures.banks(original, textures.elf_symbols(original))
    pages = labels.render(spec, original, banks, spec.get("project"))
    changed = bytearray(original)
    for (bank_name, page), indices in pages.items():
        bank = next(b for b in banks if b["name"] == bank_name)
        offset, size = bank["pages"][page]
        changed[offset:offset + size] = textures.encode_indices(indices, size, textures.page_bits(original, offset, size))
    for offset, data in labels.render.patches:
        changed[offset:offset + len(data)] = data
    changed = bytes(changed)
    return original, banks, changed, textures.banks(changed, textures.elf_symbols(changed))


def labels_of_spec(spec: dict, banks: list) -> Iterator[tuple]:
    """Every label with text of the spec: (repack group, sprite id, English, style, font). A label given by its
    source rectangle stands for every sprite that uses that rectangle."""
    for group in spec.get("repack", ()):
        bank = labels.bank_of(banks, group)
        rectangle = lambda part: [part.page, part.x0, part.y0, part.x1, part.y1]
        for label in group["labels"]:
            text = label.get("text") or "".join(piece["text"] for piece in label.get("pieces", ()))
            if not text:
                continue
            style = label.get("style", group.get("style", "command"))
            font = label.get("font", group.get("font", "command"))
            if "sprite" in label:
                sprite_ids = [label["sprite"]]
            else:
                sprite_ids = sorted({name.rsplit("_", 1)[1] for name, parts in bank["sprites"].items() for part in parts
                                     if rectangle(part) == label["from"]
                                     and (not label.get("sprites") or name.rsplit("_", 1)[1] in label["sprites"])})
            for sprite_id in sprite_ids:
                yield group, sprite_id, text, style, font


def export_spec(path: str, out: str, sprite_image) -> Optional[Tuple[str, List[Tuple[str, ...]]]]:
    """Write the Japanese and English pictures of every label of one spec file under `out`.

    `sprite_image` is the composer function. Returns (arc file name, index rows (arc, bank, sprite, English, style,
    font, Japanese file, English file)), or None if the file is a style file and not a spec, or the spec cannot be
    rendered (that case is reported on the screen)."""
    try:
        if "arc" not in json.load(open(path)):          # a style file, not a spec
            return None
        spec = labels.load_spec(path)
        arc = os.path.basename(spec["arc"])
        original, banks, changed, banks_after = render_spec(spec)
    except Exception as e:                              # report and go on with the other specs
        print("%-14s skipped: %s %s" % (os.path.basename(path), type(e).__name__, e), flush=True)
        return None
    rows = []
    done = set()
    for group, sprite_id, text, style, font in labels_of_spec(spec, banks):
        bank_name = group["bank"]
        key = (bank_name, sprite_id)
        files = {}
        for tag, data, bank_list in (("ja", original, banks), ("en", changed, banks_after)):
            bank = labels.bank_of(bank_list, group)
            parts = next((p for n, p in bank["sprites"].items() if n.endswith("_" + sprite_id)), None)
            if not parts:
                break
            try:
                image = sprite_image(data, bank, parts, bg=(0, 0, 0, 0))
            except Exception:
                break
            relative = "%s/%s/%s_%s.png" % (tag, arc[:-4], bank_name, sprite_id)
            if key not in done:
                os.makedirs(os.path.dirname(os.path.join(out, relative)), exist_ok=True)
                image.save(os.path.join(out, relative))
            files[tag] = relative
        if len(files) == 2:
            done.add(key)
            rows.append((arc, bank_name, sprite_id, text.replace("\n", " / "), style, font, files["ja"], files["en"]))
    return arc, rows


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 export-labels [OUT_DIR] [SPEC ...]`. `argv` defaults to sys.argv[1:]."""
    parser = argparse.ArgumentParser(prog="pp15 export-labels", description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("paths", nargs="*", metavar="PATH",
                        help="an output folder (a first argument that does not end in .json), then spec files "
                             "(default: all of specs/); output default: %s" % config.KIT_LABELS_DIR)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    config.use_scratch("ui_pages", "tools")      # compose.sprite_image is a scratch helper (see the module docstring)
    from compose import sprite_image
    given = args.paths
    out = given[0] if given and not given[0].endswith(".json") else config.KIT_LABELS_DIR
    specs = [x for x in given if x.endswith(".json")] or sorted(glob.glob(os.path.join(config.SPECS_DIR, "*.json")))
    rows = []
    for path in specs:
        exported = export_spec(path, out, sprite_image)
        if exported is None:
            continue
        arc, spec_rows = exported
        rows += spec_rows
        print("%-14s %4d labels" % (os.path.basename(path), sum(1 for r in rows if r[0] == arc)), flush=True)
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8") as f:
        f.write(INDEX_HEADER)
        for row in rows:
            f.write("\t".join(row) + "\n")
    print("%d labels -> %s" % (len(rows), os.path.join(out, "index.tsv")))


if __name__ == "__main__":
    main()
