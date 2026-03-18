# Pawapuro 15 — Reverse Engineering & Translation Toolkit

Reverse engineering research and translation tools for **Jikkyou Powerful Pro Yakyuu 15** (Wii, RP5JA4, Rev 1). The game uses a custom PowerPC bytecode VM, a proprietary glyph-indexed text encoding, and a compressed bitmap font system — all of which have been fully decoded.

This repository contains the tools needed to extract text, build an English font, inject translations, and capture runtime dialogue. It does **not** contain the game ROM, extracted game files, or copyrighted translation content.

## What's Here

### Pipeline Tools

| File | Purpose |
|------|---------|
| `extract_from_iso.py` | Extracts files from an encrypted Wii ISO (partition discovery, title key decryption, AES-128-CBC clusters, FST parsing) |
| `extract_all_text.py` | Scans all REL data sections for glyph-encoded text runs. Outputs JSON with file/section/offset metadata |
| `build_font.py` | Generates `font_patch.bin` — 95 ASCII glyphs (19px, I4+RLE compressed) for injection at font indices 187–281 |
| `insert_text.py` | Reads a translation JSON, patches REL data sections in-place. Includes scs_sce exclusion list and real terminator detection to prevent crashes |

### Analysis Tools

| File | Purpose |
|------|---------|
| `pawapuro15_text_tools.py` | CLI toolkit: `extract-text`, `decode-bytes`, `char-table`, `dump-font`, `info` |
| `vm_text_extractor.py` | Maps all 254 VM opcodes, identifies 7 text display opcodes, extracts text references |
| `decompress_glyph.py` | Standalone font decompressor (BitReader, variable-length integers, backref algorithm) |

### Dialogue Capture Tools

| File | Purpose |
|------|---------|
| `inject_dialogue_logger.py` | Patches scs_main.rel to intercept dialogue at runtime, logging VM return addresses + glyph data to a capture buffer |
| `read_dialogue_log.py` | Reads the capture buffer from a Dolphin RAM dump, outputs CSV mapping `vm_addr → japanese_text` |

### Data

| File | Purpose |
|------|---------|
| `translation_high_quality.json` | 11,073 Japanese source strings with file/section/offset metadata (no translations) |
| `font_patch.bin` | Pre-built compressed ASCII font glyphs for injection into fonttex2.rel |

### Documentation

| File | Purpose |
|------|---------|
| `TECHNICAL_GUIDE.md` | Dense technical reference: text encoding, font system, all 254 VM opcodes, dialogue pipeline, hook design, MLB comparison, key addresses |

## The Unsolved Problem

4,539 strings across 51 REL files (menus, items, abilities, tutorials, mode descriptions) have been translated via static data section patching. That covers all text that exists as glyph-encoded strings in REL data sections.

**Success Mode story dialogue is not statically patchable.** The VM bytecodes in scs_sce1/2/3.rel do not contain inline dialogue text — the 7 text display opcodes pull from runtime game state structures in work_scs.rel BSS (populated ephemerally during event processing and cleared after copy). The full dialogue pipeline has been traced through RAM dumps:

```
work_scs BSS +0x3460 → V (game state in EXRAM)
  V+0x911C → dialogue line 1    (source, ephemeral)
  V+0x91B0 → dialogue line 2    (source, ephemeral)
    ↓ scene setup at sec1+0x033068 copies to VM context
  r15+0x0280 → dialogue buffer  (destination, live)
  r15+0x02D8 → VM IP            (unique key per dialogue line)
```

A PPC code hook design exists (documented in TECHNICAL_GUIDE.md) that intercepts the text copier call at sec1+0x03326C, performs a binary search on VM return address → English text, and substitutes translations at runtime. The hook code fits in a verified-empty 185KB region of sec5. What's needed:

1. **Capture dialogue data** — Play through Success Mode with `inject_dialogue_logger.py` active, dump RAM, run `read_dialogue_log.py` to collect `vm_addr → text` pairs
2. **Write translations** for each captured pair
3. **Build and inject** the binary translation table into the sec5 hook region

## How to Use

### Extract → Translate → Inject → Play

```bash
# 1. Extract game files from ISO
python3 extract_from_iso.py "game.iso"

# 2. Extract all Japanese text to JSON
python3 extract_all_text.py --output translation_source.json

# 3. Build English font (or use pre-built font_patch.bin)
python3 build_font.py

# 4. Create translation JSON (translation_source.json with "english" fields filled in)
# ... (manual or automated translation step) ...

# 5. Inject translations into REL files in DATA/files/
python3 insert_text.py

# 6. Launch in Dolphin with DATA/files/ as folder override
```

**Critical:** Always restore original REL files from ISO before running `insert_text.py`. The pipeline reads originals, detects real string boundaries via 0xFFFF scanning, then writes within those bounds. Running against already-patched files breaks terminator detection and causes crashes.

### Capture Dialogue (for the hook system)

```bash
# 1. Patch scs_main.rel with the logger
python3 inject_dialogue_logger.py DATA/files/scs_main.rel

# 2. Play Success Mode in Dolphin, advance through dialogue scenes

# 3. Dump RAM in Dolphin (MEM1 + MEM2)

# 4. Extract captured dialogue
python3 read_dialogue_log.py mem1.raw --output dialogue_captures.csv
```

## MLB Power Pros 2008 Reference

MLB Power Pros 2008 (Wii, RP8E54) is 2K Sports' English localization of the same engine. Key findings:

- Uses identical glyph encoding (indices 187–281 for ASCII)
- English Success Mode dialogue exists in two regions of `project.bin`: ~1MB of event text (6,968 strings) and ~768KB of story dialogue with extended script control codes (0xF0xx speaker/expression/scene markers, 0xFFDF spaces)
- 2K merged all 476 REL files into a single `ovl_main.rel` and packed data into 2,358 .pack files inside project.bin
- The VM bytecodes were left untouched — 2K translated the data tables the VM references, not the bytecode itself

MLB's English text can serve as a translation reference, though content was adapted for a US audience (school system, character names, cultural references).

## Applicability

The VM architecture (two-level jump table dispatch, 254 opcodes, halfword-encoded instructions with expression evaluator) is likely shared across the Konami Power Pro series (PS2/Wii era). The text encoding system (JIS X 0208 glyph indices, compressed I4 font atlas) appears consistent across titles. Tools and findings here may transfer to other games in the series with minimal adaptation.
