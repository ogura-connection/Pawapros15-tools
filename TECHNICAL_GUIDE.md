# Pawapuro 15 Technical Guide

Reverse engineering reference for Jikkyou Powerful Pro Yakyuu 15 (Wii, RP5JA4, Rev 1).
Covers text encoding, font system, VM architecture, dialogue pipeline, and hook design.

---

## Platform

- **CPU:** PowerPC 32-bit big-endian (Wii Broadway)
- **Module format:** Wii REL (relocatable modules)
- **Main executable:** `StaticModule.elf` (2.1MB)
- **SDA base:** r13 = 0x802FF660

---

## Text Encoding

### Format

16-bit big-endian halfwords. The lower 13 bits encode a glyph index (`value & 0x1FFF`); the upper 3 bits are control flags (meaning undetermined, low priority).

### Terminators

| Value  | Meaning                          |
|--------|----------------------------------|
| 0xFFFF | Dialogue / general terminator    |
| 0x1FFF | Name terminator                  |
| 0x0000 | Null separator between strings   |

### Glyph Index → JIS X 0208 → Unicode

The font contains 3,744 glyphs mapped to JIS X 0208 rows:

| Glyph Range | JIS Rows   | Count | Content                          |
|-------------|------------|-------|----------------------------------|
| 0–657       | 0x21–0x27  | 658   | Symbols, numbers, Latin, kana    |
| 658–705     | 0x28       | 48    | Partial row 8                    |
| 706–3743    | 0x30+      | 3038  | Kanji                            |

**Critical note:** JIS row 0x28 has only 48 columns (not 94) in this font. Kanji start at glyph 706, not 752. Getting this wrong shifts every kanji decode by 46 indices.

### Conversion: Glyph Index → Unicode

```python
def jis_to_char(j1, j2):
    """JIS X 0208 row/col → Unicode via Shift-JIS intermediate."""
    if j1 % 2 == 1:
        s1 = (j1 + 1) // 2 + 0x70
        if s1 > 0x9F: s1 += 0x40
        s2 = j2 + 0x1F if j2 <= 0x5F else j2 + 0x20
    else:
        s1 = j1 // 2 + 0x70
        if s1 > 0x9F: s1 += 0x40
        s2 = j2 + 0x7E
    return bytes([s1, s2]).decode('shift_jis')

def glyph_to_char(g):
    """Glyph index → Unicode character."""
    if g <= 657:
        return jis_to_char((g // 94) + 0x21, (g % 94) + 0x21)
    elif g <= 705:
        return jis_to_char(0x28, (g - 658) + 0x21)
    elif g <= 3743:
        k = g - 706
        return jis_to_char((k // 94) + 0x30, (k % 94) + 0x21)
```

### Forward Conversion: Unicode → Glyph Index

The reverse direction (encoding text for injection). The `char_to_jis_FIXED` function corrects a bug where odd-row SJIS characters with `s2 <= 0x7E` had `j2` offset by +32 (using `s2 - 0x1F` boundary at 0x7E instead of the wrong 0x9E). This affected all JIS row 0x21 symbols — punctuation, ー, ！, katakana prolonged sound marks, etc.

```python
def char_to_jis_FIXED(ch):
    """Unicode character → JIS X 0208 row/column via Shift-JIS.

    Bug fix: odd-row boundary check uses s2 <= 0x7E (correct)
    not s2 <= 0x9E (wrong, which adds +32 to j2 for row 0x21 symbols).
    """
    try:
        sjis = ch.encode('shift_jis')
        if len(sjis) != 2:
            return None, None
        s1, s2 = sjis
        if s1 >= 0xE0:
            s1 -= 0x40
        j1_base = (s1 - 0x70) * 2
        if s2 >= 0x9F:
            # Even row
            j1 = j1_base
            j2 = s2 - 0x7E
        else:
            # Odd row
            j1 = j1_base - 1
            j2 = s2 - 0x1F if s2 <= 0x7E else s2 - 0x20
        return j1, j2
    except Exception:
        return None, None

def char_to_glyph(ch):
    """Unicode character → glyph index. Returns None if not in font."""
    j1, j2 = char_to_jis_FIXED(ch)
    if j1 is None:
        return None
    if 0x21 <= j1 <= 0x27:
        return (j1 - 0x21) * 94 + (j2 - 0x21)
    elif j1 == 0x28:
        col = j2 - 0x21
        return 658 + col if 0 <= col < 48 else None
    elif j1 >= 0x30:
        g = 706 + (j1 - 0x30) * 94 + (j2 - 0x21)
        return g if g <= 3743 else None
    return None
```

### ASCII Glyph Injection

English text uses 95 ASCII glyphs injected into the font at indices 187–281:

| Character   | Glyph Index | JIS Row |
|-------------|-------------|---------|
| Space (0x20)  | 187         | 0x23    |
| `!`–`~` (0x21–0x7E) | 188–281 | 0x23 |

```python
def encode_english_to_glyphs(text):
    glyphs = []
    for ch in text:
        code = ord(ch)
        if code == 0x20:
            glyphs.append(187)
        elif 0x21 <= code <= 0x7E:
            glyphs.append(188 + (code - 0x21))
    return glyphs
```

### Where Text Lives

All player-facing text uses glyph encoding exclusively. No Shift-JIS, UTF-16, or other encoding appears in game data. Text resides in REL data sections (sec5/sec6):

| File            | Strings | Content                                    |
|-----------------|---------|--------------------------------------------|
| scs_item.rel    | 2,009   | Item names and descriptions                |
| scs_data.rel    | 553     | Player evaluations, status descriptions    |
| scs_main.rel    | ~2,713  | Menu/UI strings (40-byte fixed entries)    |
| scs_rens.rel    | 69      | Scout evaluation dialogue                  |
| scs_comi.rel    | 154     | Communication event text                   |
| scs_end.rel     | 129     | Ending sequences                           |
| scs_sys.rel     | 204     | System messages                            |
| school_g.rel    | 5,724   | Tutorial lessons and strategy              |
| orepena.rel     | 803     | My Life / Pennant events                   |
| pennant.rel     | 439     | Pennant mode UI                            |
| pena_sub.rel    | 971     | Season mode management                     |
| rec_room.rel    | 317     | Record room stats                          |
| are_abi.rel     | 144     | Player ability descriptions                |
| gameplay.rel    | 140     | Batting/pitching/fielding instructions     |
| + ~37 more      | various | Draft, roster, arrangements, etc.          |

**Total identified:** ~11,073 strings across 51+ REL files.

---

## Font System

### Structure (fonttex2.rel)

File is 1,158,184 bytes. Section 4 (DATA) at offset 0x2A0 contains three fonts:

| Font      | Offset in sec4 | Glyphs |
|-----------|----------------|--------|
| FontTex2  | +0x000000      | 3,744  |
| FontMain  | +0x05DF64      | Unknown (untested) |
| FontGaiji | +0x117400      | Unknown (untested) |

Header format: 4 bytes (`0x0000` + LE u16 glyph_count), then LE u32 offset table, then compressed glyph data. Glyph data base for FontTex2: file offset 0x3D24.

### Glyph Rendering

- **Size:** 22×28 pixels (11 bytes × 28 rows)
- **Format:** GX I4 texture — 4-bit intensity per pixel, each byte = 2 pixels (high nibble, low nibble)
- **Decompressed output:** 512 bytes = 28 rows × 16 bytes (11 data + 5 padding) + 64 trailing 0xFF

### Compression Algorithm

Location: `main_prg.rel` sec1+0x078800 to sec1+0x078FA4.

Custom bit-by-bit entropy compression with variable-length integers:

1. **BitReader:** MSB-first, reads from bitstream portion of compressed data
2. **Variable-length integer:** Read 2 bits. If nonzero, return value (1–3). If zero, read 4 more bits, return 4+value (4–19).
3. **Per-slot algorithm:**
   - If `counts[slot] != 0`: output `values[slot]`, decrement count
   - Else read bit1:
     - `bit1=0` → LITERAL: read one byte from literal stream
     - `bit1=1` → BACKREF: read fill_count (varlen), read repeat_count (varlen), read one literal byte; set counts/values for fill_count consecutive slots

Compressed data layout: `[flag_count: u8] [bitstream: flag_count bytes] [literals: remaining bytes]`

Context: `counts[]` zeroed per call; `values[]` persists in BSS but zero-init works standalone.

### Decompressor Relocations

```
sec1+0x07880A → BSS+0x10D9F4 (counts buffer)
sec1+0x078816 → BSS+0x10D9F4 (counts buffer)
sec1+0x07881A → sec4+0x1258   (bitmask table: 80 40 20 10 08 04 02 01)
sec1+0x078846 → sec4+0x1258   (bitmask table)
sec1+0x07883A → BSS+0x10DA00  (values buffer)
sec1+0x07887A → BSS+0x10D9F4  (counts buffer, row loop reset)
sec1+0x07887E → BSS+0x10DA00  (values buffer)
```

### Font Patch (font_patch.bin)

Pre-built binary: 95 ASCII glyphs at 19px height, I4+RLE compressed, for injection at glyph indices 187–281 in fonttex2.rel. Built by `build_font.py`.

### SDA Font Pointers

```
g_pFontTex2  = 0x802F8FE8  (r13 - offset)
g_pFontMain  = 0x802F8FE0
g_pFontGaiji = 0x802F8FE4
```

---

## VM Architecture

### Overview

`scs_main.rel` section 1 (544KB code) is a bytecode interpreter. It executes immutable scripts from three data modules:

| Module | File           | Size   | Content                    |
|--------|----------------|--------|----------------------------|
| 319    | scs_sce1.rel   | 131KB  | Year 1 bytecode (~3KB)     |
| 320    | scs_sce2.rel   | 277KB  | Year 2 bytecode (170KB)    |
| 321    | scs_sce3.rel   | 308KB  | Year 3 bytecode (385KB)    |

One-way dependency: scs_main → scs_sce (5,558 relocations). The scs_sce modules have zero references back. Pure data packages.

### Bytecode Format

- **Delimiter:** `0xFFFF` separates script procedures
- **Block structure:** `[FIRST_OPCODE] [instruction stream...] [0xFFFF]`
- **Instructions:** Variable-length halfword sequences. First halfword = `[hi_byte:lo_byte]` where lo_byte = opcode (0x00–0xFD), hi_byte = first implicit parameter.

### Dispatch Architecture (Two-Level)

**Level 1** (sec1+0x035274): Dispatches on `r15+0x19C` (0–31 scene handler states). Set by opcode 0x00's hi-byte.

**Level 2** (sec1+0x0356AC): Main instruction dispatch. 286-entry jump table at sec5+0x0FF63C. Opcode (low byte, 0x00–0xFD) → case handler.

**Instruction fetch** (sec1+0x035664):
1. Load IP from `r15+0x2D8`
2. Fetch halfword: `lhz r6, 0(r3)`
3. Advance IP: `addi r3, r3, 2`
4. Store opcode: `sth r6, 0x1A0(r15)`
5. Extract low byte: `clrlwi r5, r6, 0x18`
6. Bounds check: `cmplwi r5, 0xFD`
7. Jump table dispatch: `lwzx r4, table, opcode*4` → `bctr`

**Dispatcher return:** All 209 case handlers branch to sec1+0x039174, which checks flags at `r15+0x1A4` and loops or exits.

### Complete Instruction Set (254 Opcodes)

**Size distribution:** 149 × 1-HW, 87 × 2-HW, 17 × 3-HW, 1 × 4-HW. 33 NOPs (handler = dispatcher return).

#### 4-Halfword (1 opcode)

| Opcode | Handler    | Description                               |
|--------|------------|-------------------------------------------|
| 0x02   | 0x03901C   | Assignment — 3 operands via expr eval     |

#### 3-Halfword (17 opcodes)

| Opcodes   | Handler    | Description                             |
|-----------|------------|-----------------------------------------|
| 0x16–0x1D | 0x035C30  | Conditional/comparison (8 variants)     |
| 0x1E–0x25 | 0x035C98  | Conditional/comparison (8 variants)     |
| 0x6E      | 0x036D1C  | Two-operand instruction                 |

#### 2-Halfword (87 opcodes)

| Opcodes     | Handler(s)  | Description                           |
|-------------|-------------|---------------------------------------|
| 0x36–0x3D   | 0x035D40    | Arithmetic/set (8 variants) + expr    |
| 0x3E–0x45   | 0x035D90    | Arithmetic/set (8 variants) + expr    |
| 0x71        | 0x035A38    | Branch/jump                           |
| 0x7A–0x7D   | various     | Data handlers                         |
| 0x7E–0x81   | various     | Computation + expr eval               |
| 0x83–0x85   | various     | Data operations                       |
| 0x87–0x88   | various     | Operations                            |
| 0x89–0x93   | 0x037D9C+   | Scene/display control                 |
| 0x95        | 0x0362B8    | Operation                             |
| 0x9D–0x9E   | various     | Operations                            |
| 0x9F–0xA4   | various     | Computation + expr eval               |
| **0xA5**    | **0x03743C**| **Text: char name from expr eval**    |
| **0xA6**    | **0x037508**| **Text: roster lookup from expr eval**|
| **0xA7**    | **0x037724**| **Text: char field 0xEC + copier**    |
| 0xA8–0xBE   | various     | Game state, data, expr eval           |
| 0xBF–0xC6   | various     | Scene control + expr eval             |
| 0xD5        | 0x0372E0    | Numeric display (formats number)      |
| 0xD6        | 0x036198    | Operation + expr eval                 |
| 0xDA        | 0x037330    | Integer-to-text converter             |

#### 1-Halfword (149 opcodes)

| Opcodes     | Handler(s)  | Description                           |
|-------------|-------------|---------------------------------------|
| 0x00        | 0x0356B0    | Hi-byte dispatch (sub-opcode)         |
| 0x01        | 0x0357C8    | Return/yield                          |
| 0x03–0x15   | 0x039174    | NOPs (19 opcodes)                     |
| 0x26–0x2D   | 0x038F88    | Context flag ops (8 variants)         |
| 0x2E–0x35   | 0x038FC8    | Context flag ops (8 variants)         |
| 0x46–0x55   | various     | Block/state management                |
| 0x56–0x58   | 0x039174    | NOPs                                  |
| 0x59–0x6B   | various     | Game state operations                 |
| 0x6F–0x79   | various     | Control flow, state management        |
| 0x82, 0x86  | various     | Operations                            |
| 0x94        | 0x0384DC    | Operation                             |
| 0x96–0x99   | 0x0377A0+   | Display control (r15+0x180/181)       |
| 0x9A–0x9C   | various     | Control                               |
| 0xC7–0xCF   | various     | Scene parameter operations            |
| 0xD0–0xD4   | various     | State operations                      |
| 0xD7–0xD8   | 0x039174    | NOPs                                  |
| 0xD9–0xDE   | various     | Text preparation, state setup         |
| **0xDF**    | **0x036E84**| **Text: 2D char lookup + 2 copiers**  |
| **0xE0**    | **0x037044**| **Text: PRNG random name from kanji** |
| **0xE1**    | **0x037298**| **Text: current char name (common)**  |
| **0xE2**    | **0x037274**| **Text: direct 12-byte data copy**    |
| 0xE3–0xFD   | various     | Misc ops, many NOPs                   |

### Key Functions

| Address (sec1) | Purpose                                                        |
|----------------|----------------------------------------------------------------|
| +0x032E8C      | **Text copier** — dual-path (compact table / direct copy)      |
| +0x033068      | **Scene setup** — dialogue writer, 3 text copier calls         |
| +0x035274      | First-level dispatcher (scene state machine)                   |
| +0x035664      | Instruction fetch                                              |
| +0x0356AC      | Second-level dispatcher (opcode jump table)                    |
| +0x039174      | Dispatcher return (all handlers branch here)                   |
| +0x03D814      | **Expression evaluator** — resolves halfword to concrete value |
| +0x05C4F0      | **Roster search** — finds character by ID (13×3 slots, stride 0x1CC) |

### Expression Evaluator (sec1+0x03D814)

Takes a halfword index, dispatches via 13-entry type table, resolves to a concrete value (variable/register read). Used by opcodes 0xA5–0xA7 and many arithmetic/conditional opcodes.

### Pointer Table (sec5+0xED194 to +0xEEA60)

1,588 consecutive u32 pointers (NULL in file, filled by R_PPC_ADDR32 relocations at load time). Indexes into scs_sce2 sec4 bytecode. Points to 618 of 6,705 blocks; 99.9% are mid-block positions.

---

## Text Copier (sec1+0x032E8C)

Leaf function, 11 callers. Two paths:

**Path A — Compact table:** If first source halfword is in 0x0F00–0x0FFF → index = `(value - 0xF00) / 4` → lookup 20-byte entry (10 halfwords) at `main_prg.rel sec5+0x07A1F8` → unrolled copy, 0x1FFF terminated. Content: player names (ウッズ, フェルナンデス, ホームランくん, etc.).

**Path B — Direct copy:** Copy up to 6 halfwords from source, masking each to 12 bits (`AND 0x0FFF`), skipping 0x0000 and 0x1FFD, terminating at 0x1FFF.

**Arguments:** r3 = source text pointer, r4 = destination buffer. Returns glyph count.

**11 call sites:** 0x033248, 0x03326C, 0x033280, 0x036EF8, 0x036FC4, 0x037248, 0x037290, 0x0372D8, 0x0374EC, 0x037650, 0x037784.

---

## Text Display Opcodes (Fully Decoded)

Seven opcodes trigger the text copier:

### 0xA5 (2 HW, handler 0x03743C)

Reads 1 extra halfword → expression eval. If result == 0: pushes IP to call stack, redirects VM execution to `r15+0x025E` (script buffer pre-loaded by scene setup). If result != 0: treats as character ID → roster search → copies name from struct+0x5C → text copier to `r18-0x7DD0`.

### 0xA6 (2 HW, handler 0x037508)

Reads 1 extra halfword → expression eval → result-1 → byte lookup at `r26→+0x48`. If byte == 0 (unoccupied): counts roster slots (0x52–0x5B), stores count. If byte != 0 (occupied): char ID → roster search → text copier to `r18-0x7DD0`.

### 0xA7 (2 HW, handler 0x037724)

Reads 1 extra halfword → expression eval → char index → checks field 0xEC for 0xFFFF sentinel. If not sentinel: stores text address, pushes IP, text copier via `mulli × 0x1C4`.

### 0xDF (1 HW, handler 0x036E84)

No extra halfwords. Loads game state via pointer getter + struct loader, computes 2D character index via `mulli 0x28 × mulli 0x90` into a 40×144-byte database, copies 0x90 bytes via memcpy. Calls text copier TWICE: once for name at `r15+0x280`, once for second name at `r15+0x294`.

### 0xE0 (1 HW, handler 0x037044)

No extra halfwords. Calls PRNG with range 1000, uses result × 0x0A as index into kanji name table at `scc_main.rel sec5+0xC0`, copies up to 6 halfwords terminated by 0x1FFF. Text copier to `r15+0x280`. Purpose: random name generation.

### 0xE1 (1 HW, handler 0x037298)

No extra halfwords. Reads character ID from VM context (`r22→struct+0x08`), roster search, indexes into 460-byte struct via `mulli × 0x1CC`, copies 12 bytes from struct+0x5C. Text copier to `r17+0xA4`. Purpose: display current character's name.

### 0xE2 (1 HW, handler 0x037274)

No extra halfwords. Copies 12 bytes from `r26→+0x10` to stack, text copier to `r15+0x2BC`. Purpose: display name from current data context.

**None of these opcodes read text inline from the bytecode stream.** All text comes from game state structures, other modules' data sections, or runtime computation.

---

## Dialogue Pipeline

### The Problem

Success Mode story dialogue does not exist as static strings in any REL file. The 7 text opcodes pull from runtime game state, not from bytecode. A search of all 1,111 game files in all encodings found no hidden dialogue cache.

### Complete Pointer Chain (confirmed via RAM dump)

```
work_scs.rel BSS (MEM1:0x805FEFE0, 389KB)
  +0x3460 → V = MEM2:0x927F67C0 (game state block in EXRAM)
    V+0x9118: u8  flag_byte (0xFF = no dialogue)
    V+0x911C: u16[] dialogue_line_1 (glyph halfwords)
    V+0x91B0: u16[] dialogue_line_2 (glyph halfwords)
    V+0x91AC: u8  character_expression
             ↓ scene setup copies V+0x911C → r15+0x0280
VM context (MEM2:0x926DCCC0)
  +0x0280 → dialogue text buffer
  +0x0294 → secondary text buffer
  +0x025E → script fragment buffer
  +0x02D8 → VM instruction pointer (u32)
             ↓ display descriptor links to render pipeline
Display descriptor (MEM2:0x92742A38)
  +0x38: text start pointer
  +0x3C: text end pointer
  +0x40: VM bytecode return address
             ↓ render system copies to output buffer
Render buffer (MEM2:0x92717220)
```

### Three-Layer Display System

**Layer 1 — Scene setup** (sec1+0x033068): Called via function pointer callback (not direct `bl`). Copies dialogue text from work_scs BSS into VM context buffers:

| Call Site    | Source                  | Destination    | Purpose              |
|-------------|-------------------------|----------------|----------------------|
| sec1+0x033248 | BSS+0x3468 (script ptr) | r30+0x025E     | Script fragment      |
| sec1+0x03326C | V+0x911C (via BSS+0x3460) | r30+0x0280  | Dialogue line 1      |
| sec1+0x033280 | V+0x91B0 (via BSS+0x3460) | r30+0x0294  | Dialogue line 2      |

**Layer 2 — VM IP redirect** (sec1+0x036C4C): Sets `r15+0x2D8` (the VM instruction pointer) to point at `r15+0x0280`. The dispatcher then "executes" the glyph halfwords as display commands.

**Layer 3 — First-level dispatch** (state machine at sec5+0x0FFA34): Opcode 0x00's hi-byte selects among 32 scene handler states via `r15+0x019C`. State 31 = silent mode (skip dialogue).

### Source Buffer Lifecycle

The dialogue source at V+0x911C is **ephemeral** — it is cleared after the scene setup copies it. RAM dumps captured during display show zeroed source buffers but live text in the destination buffers. The text arrives at V+0x911C as a complete, pre-formed string (not assembled character-by-character — glyph clustering analysis ruled out per-character VM assembly).

### What Writes to V+0x911C

Unknown. Candidates:

1. A native PPC function (not VM) that reads from a dialogue table and writes to the game state block
2. The scs_sce2 BSS (5.5MB at runtime) could contain staging buffers indexed by the VM

**To identify the writer:** Set a Dolphin write breakpoint on the MEM2 address corresponding to V+0x911C. When dialogue appears, the break will fire on the exact function and reveal its data source.

---

## Hook Design

### Strategy

Patch the `bl 0x032E8C` (text copier call) at sec1+0x03326C with a branch to custom hook code in the sec5 zero region. The hook checks the VM bytecode return address (`r15+0x2D8`) against a binary-searchable translation table. Match → substitute English text. No match → pass through original Japanese.

### Hook Location

sec5 contains a 185,728-byte zero region from +0x0D086E to +0x0FED8E (between data and the jump table at +0x0FF63C). Confirmed unused: all zero, no relocations target it. The Wii Broadway CPU does not enforce NX on data pages, so code in sec5 executes normally.

Layout:
```
sec5+0x0D0880: Hook code (~120 bytes)
sec5+0x0D0900: Translation table header (8 bytes)
sec5+0x0D0908: Index array (sorted, 8 bytes/entry)
sec5+0x0XXXXX: Text data (packed glyph halfwords)
               ...up to sec5+0x0FED00 (~183KB budget)
```

### Hook Code (PPC Assembly)

```ppc
dialogue_hook:              # at sec5+0x0D0880
    mflr    r0
    stw     r0, -4(r1)
    stw     r3, -8(r1)         # save Japanese source ptr
    stw     r4, -12(r1)        # save dest ptr
    stwu    r1, -48(r1)

    lwz     r5, 0x02D8(r30)    # r5 = VM IP (dialogue line key)

    lis     r6, TABLE_BASE@ha  # [RELOC → sec5+0x0D0900]
    addi    r6, r6, TABLE_BASE@lo
    lwz     r7, 0(r6)          # entry_count
    addi    r8, r6, 8          # &index[0]
    li      r9, 0              # lo = 0
    mr      r10, r7            # hi = entry_count

.loop:
    cmpw    cr0, r9, r10
    bge     .not_found
    add     r11, r9, r10
    srwi    r11, r11, 1        # mid
    slwi    r12, r11, 3        # mid * 8
    lwzx    r0, r8, r12        # index[mid].vm_addr
    cmpw    cr0, r5, r0
    beq     .found
    blt     .upper
    addi    r9, r11, 1         # lo = mid + 1
    b       .loop
.upper:
    mr      r10, r11           # hi = mid
    b       .loop

.found:
    add     r12, r8, r12       # &index[mid]
    lwz     r3, 4(r12)         # text_offset (relative to TABLE_BASE)
    lis     r6, TABLE_BASE@ha
    addi    r6, r6, TABLE_BASE@lo
    add     r3, r6, r3         # r3 = &english_text
    lwz     r4, 36(r1)         # restore dest
    bl      text_copier        # [RELOC → sec1+0x032E8C]
    b       .epilogue

.not_found:
    lwz     r3, 40(r1)         # restore original source
    lwz     r4, 36(r1)         # restore dest
    bl      text_copier

.epilogue:
    addi    r1, r1, 48
    lwz     r0, -4(r1)
    mtlr    r0
    blr
```

Register contract: clobbers r0, r5–r12, CR0. Preserves r3 (modified), r4, r29, r30, r31.

### Translation Table Format

**Header (8 bytes):** `[u32 entry_count] [u32 reserved]`

**Index array (8 bytes/entry, sorted by vm_addr):** `[u32 vm_addr] [u32 text_offset]`

`vm_addr` = absolute runtime pointer from `r15+0x2D8`. Deterministic (fixed module load order). `text_offset` = byte offset from TABLE_BASE to the English glyph halfword sequence (0x1FFF terminated).

**Capacity:** ~4,400 entries at 20 chars/line average within the 183KB budget.

### Patch Point

At sec1+0x03326C, replace original `bl 0x032E8C` (`4BFFFC21`) with `bl dialogue_hook`. Requires adding an R_PPC_REL24 relocation in the module 311→311 self-referencing block, or hardcoding the branch offset from a captured runtime session.

### Text Copier 6-Halfword Limit

The direct copy path copies at most 6 halfwords. Sufficient for names. For longer dialogue body text, either:

- **Option A:** Replace the `bl text_copier` in the hook with a direct `sthx` loop (bypasses limit)
- **Option B:** Hook the 0xDF handler's 0x90-byte memcpy at sec1+0x036EC0 for full-length replacement

### Required Relocations

| What                    | Type              | From              | To                |
|-------------------------|-------------------|-------------------|-------------------|
| TABLE_BASE (×2 pairs)   | ADDR16_HA + LO    | sec5+0x0D0880+    | sec5+0x0D0900     |
| bl text_copier (×2)     | REL24             | sec5 (hook)       | sec1+0x032E8C     |
| bl dialogue_hook         | REL24             | sec1+0x03326C     | sec5+0x0D0880     |

---

## Dialogue Capture Tools

### inject_dialogue_logger.py

Patches scs_main.rel to intercept dialogue text at runtime. Writes a log entry (VM return address + glyph data) to a capture buffer in the sec5 zero region each time the scene setup function copies dialogue. Designed for use with Dolphin's RAM dump feature.

### read_dialogue_log.py

Reads the capture buffer from a Dolphin RAM dump, decodes the glyph halfwords to Unicode, and outputs a CSV mapping `vm_return_addr → japanese_text`. This CSV feeds into the translation table builder.

### Capture Workflow

1. Apply logger patch to scs_main.rel
2. Play through Success Mode in Dolphin
3. At each dialogue scene, dump RAM (or let the logger accumulate)
4. Run `read_dialogue_log.py` on the dump to extract `vm_addr, text` pairs
5. Write English translations for each pair
6. Build the binary translation table and inject via the hook

---

## MLB Power Pros 2008 Comparison

MLB Power Pros 2008 (Wii, RP8E54) is 2K Sports' English localization of the same engine.

### Structural Differences

| Aspect              | Pawapuro 15                  | MLB Power Pros 2008               |
|---------------------|------------------------------|------------------------------------|
| Game code           | 476 individual REL files     | 1 file: ovl_main.rel (11MB)       |
| Data archive        | project.bin (12KB listing)   | project.bin (388MB, 2,358 .pack)   |
| Dialogue storage    | Runtime VM assembly          | Inline in .pack files              |

### Where English Dialogue Lives

**Region 1** (project.bin 0x09770000–0x09860000, ~1MB): 6,968 event notification strings. Standard glyph encoding. Control codes: 0xD000 (line break), 0x0003–0x0009 (expression markers), 0xD017/0xD019 (variable refs).

**Region 2** (project.bin 0x0E640000–0x0E700000, ~768KB): Full Success Mode story dialogue with extended encoding. Uses 0xFFDF (space), 0xF0xx–0xF2xx (inline script control: speaker changes, expressions, scene transitions, name highlights). This is the complete dialogue corpus that Pawapuro 15 assembles at runtime.

**Region 3** (ovl_main.rel sec4/sec5, ~1.8MB): 1,570 UI words stored individually, assembled at runtime.

### Key Insight

2K translated the dialogue data tables, not the VM bytecode. The VM scripts (scs_sce equivalent) are flow control only. The dialogue text tables that Pawapuro 15 loads into work_scs BSS at runtime are stored as .pack files inside MLB's project.bin. The glyph encoding (indices 187–281 for ASCII) is identical between both games.

MLB's English dialogue can serve as a translation reference, though 2K adapted content for a US audience (school system, character names, cultural references).

---

## Cross-Module Text Tables

### Table 1: Player Name Compact Table (main_prg.rel)

Location: sec5+0x07A1F8. Format: 20-byte entries (10 halfwords), 0x1FFF terminated. Accessed by text copier compact path when source halfword is 0x0F00–0x0FFF. Content: player names.

### Table 2: Name Kanji Table (scc_main.rel)

Location: sec5+0x0000C0. Format: 10-byte entries (5 halfwords), accessed via `mulli × 0x0A`. Purpose: surname kanji generation for character creation.

### Table 3: Menu/UI Strings (scs_main.rel sec5)

Location: sec5+0x3328 to sec5+0x1F280. Format: fixed 40-byte entries (20 halfwords), 0x0000 padded. 2,713 non-empty entries. First 21 entries accessed via pointer table at sec5+0x2B24. Remaining entries accessed via inline ADDR32 pointers in VM bytecode.

### Runtime Context

Location: work_scs.rel (mod 473) sec6+0x003460. Type: BSS (zero-initialized). Central game state pointer used by text handlers and script engine.

---

## Module Map

### Module ID → Filename

```
0   = StaticModule.elf    288 = scc_main.rel     311 = scs_main.rel
102 = main_prg.rel        319 = scs_sce1.rel     320 = scs_sce2.rel
321 = scs_sce3.rel        347 = scs_sce2 (runtime ID)
473 = work_scs.rel
```

### Key File Sizes and Sections

| File             | Size   | sec1 (CODE)  | sec5 (DATA)  | sec6 (BSS)     |
|------------------|--------|-------------- |--------------|----------------|
| StaticModule.elf | 2.1MB  | —             | —            | —              |
| main_prg.rel     | 1.9MB  | 0xF94AC       | 0x929F0      | 0x11BED0       |
| scs_main.rel     | 2.2MB  | 544KB         | 1.1MB        | —              |
| scs_sce1.rel     | 131KB  | —             | 117KB (sec4) | 19KB           |
| scs_sce2.rel     | 277KB  | —             | 262KB (sec4) | 27KB           |
| scs_sce3.rel     | 308KB  | 4KB           | 287KB (sec5) | 78KB           |
| work_scs.rel     | —      | 108KB         | 13KB         | 389KB          |
| fonttex2.rel     | 1.2MB  | —             | sec4 = fonts | —              |

### Runtime Memory Map (from RAM dump during Success Mode)

| Module     | ID  | Code            | Data            | BSS              |
|------------|-----|-----------------|-----------------|------------------|
| work_scs   | 473 | 0x805DDB8C (108KB) | 0x805F9150 (13KB) | 0x805FEFE0 (389KB) |
| scs_sce2   | 347 | 0x807FC2D4 (200KB) | 0x8082E3A0 (418KB) | 0x808A1380 (5,589KB) |

### .arc Files

385 files are Metrowerks ELF objects (pre-linked .rel sources with `.text`, `.data`, `.debug`, `.symtab` sections). 12 files are U8 archives (HomeButton2 UI). None contain extractable text. The .arc ELF `.data` sections contain graphical assets (textures, models), not dialogue.

### File Type Distribution

| Type  | Count | Content                                |
|-------|-------|----------------------------------------|
| .rel  | 476   | Relocatable modules. All game text.    |
| .arc  | 386   | ELF objects / U8 archives. No text.    |
| .rom  | 121   | 3D model/texture part tables.          |
| .rsd  | 40    | Sound data.                            |
| .thp  | 26    | Video files.                           |
| Other | 12    | Misc (tpl, bin, elf, bnr).             |

---

## Key Addresses Quick Reference

### scs_main.rel sec1

| Offset     | Purpose                                          |
|------------|--------------------------------------------------|
| +0x032E8C  | Text copier entry (dual-path)                    |
| +0x033068  | Scene setup function (dialogue writer)            |
| +0x033248  | Text copier call — script fragment (hook target) |
| +0x03326C  | Text copier call — dialogue line 1 (**PRIMARY HOOK POINT**) |
| +0x033280  | Text copier call — dialogue line 2               |
| +0x035274  | First-level dispatcher                           |
| +0x035664  | Instruction fetch                                |
| +0x0356AC  | Second-level dispatcher                          |
| +0x036C4C  | VM IP redirect to dialogue buffer                |
| +0x039174  | Dispatcher return                                |
| +0x03D814  | Expression evaluator                             |
| +0x05C4F0  | Character roster search                          |

### scs_main.rel sec5

| Offset      | Purpose                                        |
|-------------|------------------------------------------------|
| +0x3328     | Menu/UI string table start (40-byte entries)   |
| +0x1F280    | Menu/UI string table end                       |
| +0x2B24     | Pointer table (21 ADDR32 → first 21 strings)  |
| +0x0D0880   | Zero region start (hook code location)         |
| +0x0D0900   | Translation table location                     |
| +0x0FED8E   | Zero region end                                |
| +0x0FF63C   | Opcode jump table (286 entries)                |
| +0x0FFA34   | First-level dispatch jump table (32 entries)   |
| +0xED194    | scs_sce2 entry point pointer table             |

### VM Context (r15/r30)

| Offset  | Purpose                                          |
|---------|--------------------------------------------------|
| +0x019C | Scene handler state (0–31)                       |
| +0x01A0 | Current opcode                                   |
| +0x01A4 | Execution flags                                  |
| +0x01D2 | Call stack depth                                 |
| +0x01D4 | Call stack (IP array)                            |
| +0x025E | Script fragment buffer                           |
| +0x0280 | Dialogue line 1 buffer                           |
| +0x0294 | Dialogue line 2 buffer                           |
| +0x02BC | Data context text buffer                         |
| +0x02D8 | VM instruction pointer (u32, unique dialogue key)|

### work_scs BSS Pointers

| Offset   | Runtime Value    | Purpose                          |
|----------|------------------|----------------------------------|
| +0x3460  | 0x927F67C0 (V)   | Main game state pointer          |
| +0x3464  | 0x927F6280       | Secondary game state             |
| +0x3468  | 0x927F6560       | Script text pointer              |
| +0x346C  | 0x927FFB60       | Tertiary game state              |

---

## Critical Implementation Notes

### Bugs That Crash the Game

1. **scs_sce bytecode corruption:** The text scanner produces false positives in scs_sce1/2/3.rel because VM opcodes and glyph indices share the 16-bit value space. Patching these files corrupts VM instructions → crashes Success Mode. Fix: EXCLUDE_FILES set in insert_text.py.

2. **String overflow (PC=0x800eb0bc):** The scanner's `length` field overcounts by merging adjacent data fields past 0xFFFF sentinels. Writing to the overcounted length overwrites sentinels → crashes the text renderer in main_prg.rel. Fix: Real terminator detection scans original binary for first 0xFFFF.

3. **Stale DATA/files/:** If already-patched RELs are in DATA/files/ when insert_text.py runs, terminator detection fails (terminators were overwritten). Always restore originals from ISO first.

### Translation Constraints

- English text must fit in the same halfword count as the original Japanese (up to the first 0xFFFF terminator)
- 1 halfword = 1 character. English typically needs ~1.1× the characters of Japanese.
- Garbled-string filter regex: `[菟芦紡嚇穫叫冩冕樗呰漉夘]`
