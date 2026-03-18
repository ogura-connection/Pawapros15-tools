#!/usr/bin/env python3
"""
inject_dialogue_logger.py — Inject a PPC dialogue logging hook into scs_main.rel
(and optionally sct_main.rel) to capture ALL text copier calls at runtime.

Instead of translating, this hook LOGS every call to the text copier function,
recording:
  - VM return address (r30+0x2D8) — unique dialogue line identifier
  - Source pointer — where the text comes from
  - Destination buffer ID (0x025E / 0x0280 / 0x0294 / other)
  - Up to 20 glyph halfwords being copied
  - Caller return address (LR) — which call site triggered this

The log is written to a circular buffer in sec5's zero region so it can be
read via Dolphin's memory viewer or a RAM dump.

Usage:
    # Patch scs_main.rel (Success Mode):
    python3 inject_dialogue_logger.py --rel DATA/files/scs_main.rel

    # Patch sct_main.rel (Eikan Nine):
    python3 inject_dialogue_logger.py --rel DATA/files/sct_main.rel --mode eikan

    # Dry run (show what would be patched, don't write):
    python3 inject_dialogue_logger.py --rel DATA/files/scs_main.rel --dry-run

    # Restore original (undo patch):
    python3 inject_dialogue_logger.py --rel DATA/files/scs_main.rel --restore

See DIALOGUE_HOOK_DESIGN.md for architecture context.
Does NOT modify insert_text.py or any translation files.
"""

import argparse
import struct
import sys
import os
import shutil
from pathlib import Path


# ============================================================
# REL Layout Constants
# ============================================================

# scs_main.rel (module 311) — Success Mode
SCS_MAIN = {
    'module_id': 311,
    'name': 'scs_main.rel',
    'sec1_file_offset': 0xCC,
    'sec1_size': 0x084FAC,
    'sec5_file_offset': 0x087E10,
    'sec5_size': 0x10CD20,
    # Text copier function entry point in sec1
    'text_copier_sec1': 0x032E8C,
    # All 11 callers of the text copier in sec1
    'callers': [
        # (sec1_offset, description)
        (0x033248, 'scene_setup: body text → r30+0x025E'),
        (0x03326C, 'scene_setup: name1 → r30+0x0280'),
        (0x033280, 'scene_setup: name2 → r30+0x0294'),
        (0x036EF8, '0xDF handler: char data → r15+0x0280'),
        (0x036FC4, '0xDF handler: char data → r15+0x0294'),
        (0x037248, '0xE0 handler: PRNG name → r15+0x0280'),
        (0x037290, '0xE2 handler: context → r15+0x02BC'),
        (0x0372D8, '0xE1 handler: char name → r17+0xA4'),
        (0x0374EC, '0xA5 handler: roster name → r18-0x7DD0'),
        (0x037650, '0xA6 handler: roster name → r18-0x7DD0'),
        (0x037784, '0xA7 handler: char field → r18-0x7DD0'),
    ],
    # Hook code placement in sec5 zero region
    'hook_sec5_offset':   0x0D0880,  # 128 bytes for hook trampoline
    'log_header_sec5':    0x0D1000,  # Log header (16 bytes)
    'log_buffer_sec5':    0x0D1010,  # Circular log buffer start
    'log_buffer_end_sec5': 0x0FE000, # End of log buffer (~180KB)
}

# sct_main.rel (module 347) — Eikan Nine
SCT_MAIN = {
    'module_id': 347,
    'name': 'sct_main.rel',
    'sec1_file_offset': 0xD4,
    'sec1_size': 0x031E20,
    'sec5_file_offset': 0x0321A0,
    'sec5_size': 0x06895C,
    # Text copier function entry point in sec1
    'text_copier_sec1': 0x020ADC,
    # All 12 callers in sct_main sec1
    'callers': [
        (0x020DB4, 'sct caller 1'),
        (0x020DC0, 'sct caller 2'),
        (0x020DD8, 'sct caller 3'),
        (0x020DEC, 'sct caller 4'),
        (0x020DFC, 'sct caller 5'),
        (0x020E38, 'sct caller 6'),
        (0x0244C0, 'sct caller 7'),
        (0x024514, 'sct caller 8'),
        (0x024540, 'sct caller 9'),
        (0x02456C, 'sct caller 10'),
        (0x024734, 'sct caller 11'),
        (0x0247E4, 'sct caller 12'),
    ],
    # Hook placement in sec5 zero region (sct_main has different layout)
    # We need to find a safe zero region in sct_main sec5.
    # sec5 is at file offset 0x0321A0, size 0x06895C
    # We'll use the end of sec5 data region.
    'hook_sec5_offset':   0x060000,
    'log_header_sec5':    0x060080,
    'log_buffer_sec5':    0x060090,
    'log_buffer_end_sec5': 0x067800,  # Data starts at ~0x067C00, leave margin
}


# Log entry format (64 bytes each):
#   +0x00: u32  entry_magic  (0x4C4F4700 = "LOG\0")
#   +0x04: u32  entry_index  (sequential counter)
#   +0x08: u32  caller_lr    (return address of the bl instruction)
#   +0x0C: u32  vm_ip        (r30+0x2D8 or r15+0x2D8)
#   +0x10: u32  source_ptr   (r3 on entry — where text comes from)
#   +0x14: u32  dest_ptr     (r4 on entry — destination buffer)
#   +0x18: u16  dest_buf_id  (low 16 of (dest - context_base), e.g. 0x025E/0x0280)
#   +0x1A: u16  glyph_count  (number of valid glyphs logged)
#   +0x1C: u16[20] glyphs   (up to 20 glyph halfwords from source)
#   +0x4C: padding to 64 bytes
LOG_ENTRY_SIZE = 64
LOG_MAGIC = 0x4C4F4700  # "LOG\0"

# Log header format (16 bytes at log_header_sec5):
#   +0x00: u32  header_magic   (0x444C4F47 = "DLOG")
#   +0x04: u32  write_index    (next entry index to write, wraps)
#   +0x08: u32  total_entries   (total entries written, never wraps)
#   +0x0C: u32  max_entries    (capacity of circular buffer)
LOG_HEADER_MAGIC = 0x444C4F47  # "DLOG"


def compute_max_entries(cfg):
    """How many 64-byte log entries fit in the buffer region."""
    buf_size = cfg['log_buffer_end_sec5'] - cfg['log_buffer_sec5']
    return buf_size // LOG_ENTRY_SIZE


def verify_zero_region(data, cfg):
    """Verify the hook/log region is all zeros (safe to use)."""
    sec5_base = cfg['sec5_file_offset']

    regions = [
        ('hook code', cfg['hook_sec5_offset'], 128),
        ('log header', cfg['log_header_sec5'], 16),
        ('log buffer start', cfg['log_buffer_sec5'], 256),
        ('log buffer end', cfg['log_buffer_end_sec5'] - 256, 256),
    ]

    all_clear = True
    for name, sec5_off, size in regions:
        file_off = sec5_base + sec5_off
        region = data[file_off:file_off + size]
        nonzero = sum(1 for b in region if b != 0)
        if nonzero > 0:
            print(f"  WARNING: {name} at sec5+0x{sec5_off:06X} has {nonzero}/{size} non-zero bytes!")
            all_clear = False
        else:
            print(f"  OK: {name} at sec5+0x{sec5_off:06X} ({size} bytes all zero)")

    return all_clear


# ============================================================
# PPC Hook Code Assembly
# ============================================================

def assemble_logger_hook(cfg):
    """Assemble the PPC logging hook that wraps the text copier.

    The hook is called INSTEAD of the original text copier. It:
    1. Logs the call parameters to the circular buffer
    2. Calls through to the original text copier
    3. Returns to the caller transparently

    Register usage at entry (same as text copier):
        r3 = source text pointer
        r4 = destination buffer pointer
    Additional context available:
        r30 (or r15) = VM context base (has IP at +0x2D8)
        LR = return address to caller

    The hook uses a 64-byte stack frame and clobbers only volatile regs
    (r0, r5-r12, CR0). r3, r4, r29-r31 are preserved for the text copier.

    Returns: (hook_bytes, reloc_info_dict)
    """
    instructions = []
    labels = {}

    def add(insn, comment=''):
        instructions.append((insn, comment))

    def current_offset():
        return len(instructions) * 4

    def patch_branch(idx, target_label, link=False, cond=None):
        """Patch instruction at idx with branch to target_label."""
        src_off = idx * 4
        dst_off = labels[target_label]
        delta = dst_off - src_off
        if cond == 'beq':
            instructions[idx] = (0x41820000 | (delta & 0xFFFC), f'beq {target_label}')
        elif cond == 'bge':
            instructions[idx] = (0x40800000 | (delta & 0xFFFC), f'bge {target_label}')
        elif cond == 'blt':
            instructions[idx] = (0x41800000 | (delta & 0xFFFC), f'blt {target_label}')
        elif link:
            instructions[idx] = (0x48000001 | (delta & 0x03FFFFFC), f'bl {target_label}')
        else:
            instructions[idx] = (0x48000000 | (delta & 0x03FFFFFC), f'b {target_label}')

    # ================================================================
    # PROLOGUE — save state, grab parameters for logging
    # ================================================================
    add(0x7C0802A6, 'mflr r0')               # save LR (this is the CALLER's return addr)
    add(0x9001FFFC, 'stw r0, -4(r1)')        # stash LR in red zone
    add(0x9061FFF8, 'stw r3, -8(r1)')        # save source ptr
    add(0x9081FFF4, 'stw r4, -12(r1)')       # save dest ptr
    add(0x93C1FFF0, 'stw r30, -16(r1)')      # save r30 (will restore)
    add(0x9421FFC0, 'stwu r1, -64(r1)')      # allocate frame (64 bytes)

    # r0 still has caller LR — keep it for the log entry
    # r3 = source, r4 = dest — saved on stack

    # ================================================================
    # LOAD LOG HEADER — get write pointer
    # ================================================================
    # lis/addi pair for log header address (RELOC PLACEHOLDERS)
    add(0x3D400000, 'lis r10, LOG_HEADER@ha [RELOC]')    # +0x18
    add(0x394A0000, 'addi r10, r10, LOG_HEADER@lo [RELOC]')  # +0x1C

    # Load header fields
    add(0x816A0004, 'lwz r11, 4(r10)')       # r11 = write_index
    add(0x80EA000C, 'lwz r7, 12(r10)')       # r7 = max_entries

    # Compute buffer entry address: buf_base + (write_index % max) * 64
    # First, write_index % max_entries (for wrap-around)
    # Use divwu + mullw to compute modulo
    add(0x7D0B3BD6, 'divwu r8, r11, r7')     # r8 = write_index / max
    add(0x7D0839D6, 'mullw r8, r8, r7')      # r8 = (write_index / max) * max
    add(0x7D2B4050, 'subf r9, r8, r11')      # r9 = write_index % max (slot index)

    # r9 * 64 = slot byte offset
    add(0x1D290040, 'mulli r9, r9, 64')      # r9 = slot * 64

    # Load log buffer base address (RELOC PLACEHOLDERS)
    add(0x3D000000, 'lis r8, LOG_BUFFER@ha [RELOC]')     # +0x30
    add(0x39080000, 'addi r8, r8, LOG_BUFFER@lo [RELOC]')  # +0x34

    # r8 = &log_buffer[slot]
    add(0x7D084A14, 'add r8, r8, r9')        # r8 = buffer base + slot offset

    # ================================================================
    # WRITE LOG ENTRY (64 bytes at r8)
    # ================================================================

    # +0x00: magic
    add(0x3CC04C4F, 'lis r6, 0x4C4F')        # "LO"
    add(0x60C64700, 'ori r6, r6, 0x4700')    # "G\0"
    add(0x90C80000, 'stw r6, 0(r8)')         # entry.magic = "LOG\0"

    # +0x04: entry_index
    add(0x916B0004, 'stw r11, 4(r8)')        # entry.index = write_index (pre-increment)

    # +0x08: caller_lr (still in r0 from mflr)
    add(0x80010044, 'lwz r0, 68(r1)')        # r0 = saved LR (at r1_old - 4 = r1_new + 60... wait)
    # Frame is 64 bytes: r1_new = r1_old - 64
    # LR was saved at r1_old - 4 = r1_new + 60
    # Source was at r1_old - 8 = r1_new + 56
    # Dest was at r1_old - 12 = r1_new + 52
    # r30 was at r1_old - 16 = r1_new + 48

    # Fix: recalculate stack offsets. stwu r1, -64(r1) means:
    # r1_new = r1_old - 64
    # stw r0, -4(r1_OLD) = at r1_new + 60 = 0x3C(r1)
    # stw r3, -8(r1_OLD) = at r1_new + 56 = 0x38(r1)
    # stw r4, -12(r1_OLD) = at r1_new + 52 = 0x34(r1)
    # stw r30, -16(r1_OLD) = at r1_new + 48 = 0x30(r1)

    # Actually those stw's used r1 BEFORE stwu, so the addresses are r1_old - N.
    # After stwu, r1 = r1_old - 64. So r1_old - 4 = r1 + 60 = 0x3C(r1).

    # Let me redo the offset. The LR stw was: stw r0, -4(r1) — this uses r1 BEFORE
    # the stwu. So at that point r1 was still r1_old.
    # -4(r1_old) = (r1_new + 64) - 4 = r1_new + 60 = 0x3C(r1_new)

    # Clear the wrong instruction and redo:
    instructions.pop()  # remove the wrong lwz

    add(0x8001003C, 'lwz r0, 60(r1)')        # r0 = caller LR
    add(0x90080008, 'stw r0, 8(r8)')         # entry.caller_lr

    # +0x0C: vm_ip — try r30+0x2D8 first, then r15+0x2D8
    # In scs_main, both r30 and r15 can be the VM context.
    # At the text copier call sites, r30 is typically the context.
    # We'll read r30+0x2D8. If r30 is not valid context, this reads garbage
    # but won't crash (reading from valid mapped memory in the game heap).
    add(0x80DE02D8, 'lwz r6, 0x2D8(r30)')    # r6 = VM IP (may be garbage if r30 != context)
    add(0x90C8000C, 'stw r6, 12(r8)')        # entry.vm_ip

    # +0x10: source_ptr
    add(0x80610038, 'lwz r3, 56(r1)')        # reload source ptr
    add(0x90680010, 'stw r3, 16(r8)')        # entry.source_ptr

    # +0x14: dest_ptr
    add(0x80810034, 'lwz r4, 52(r1)')        # reload dest ptr
    add(0x90880014, 'stw r4, 20(r8)')        # entry.dest_ptr

    # +0x18: dest_buf_id = low 16 of (dest - r30)
    # This gives us 0x025E, 0x0280, 0x0294, etc. if r30 is the context base
    add(0x7CC41850, 'subf r6, r4, r3')       # WRONG — we want dest - r30
    instructions.pop()
    add(0x7CC4F050, 'subf r6, r30, r4')      # r6 = r4 - r30 = dest offset from context
    # Actually subf is: subf rD, rA, rB => rD = rB - rA
    # subf r6, r30, r4 => r6 = r4 - r30  ✓
    instructions.pop()
    add(0x7CC3F050, 'subf r6, r30, r4')      # This is wrong encoding. Let me compute:
    # subf r6, rA=r30, rB=r4: rD=r6 (6), rA=r30 (30), rB=r4 (4)
    # subf = 31 | rD<<21 | rA<<16 | rB<<11 | 40<<1 | 0
    # = (31<<26) | (6<<21) | (30<<16) | (4<<11) | (40<<1)
    instructions.pop()
    subf_insn = (31 << 26) | (6 << 21) | (30 << 16) | (4 << 11) | (40 << 1)
    add(subf_insn, 'subf r6, r30, r4')       # r6 = r4 - r30

    add(0xB0C80018, 'sth r6, 24(r8)')        # entry.dest_buf_id (low 16)

    # +0x1A: glyph_count (filled after copy loop)
    add(0x38C00000, 'li r6, 0')              # glyph_count = 0
    add(0xB0C8001A, 'sth r6, 26(r8)')        # placeholder

    # +0x1C: Copy up to 20 glyph halfwords from source
    # r3 = source ptr (already loaded above)
    add(0x38C00000, 'li r6, 0')              # offset = 0
    add(0x38E00014, 'li r7, 20')             # max = 20

    labels['copy_loop'] = current_offset()
    add(0x2C070000, 'cmpwi r7, 0')           # check remaining
    copy_done_idx = len(instructions)
    add(0x41820000, 'beq copy_done [PATCH]')  # branch if done

    add(0x7C03342E, 'lhzx r0, r3, r6')      # r0 = source[offset]
    add(0x2800FFFF, 'cmplwi r0, 0xFFFF')     # terminator check
    copy_done2_idx = len(instructions)
    add(0x41820000, 'beq copy_done [PATCH]')
    add(0x28001FFF, 'cmplwi r0, 0x1FFF')     # name terminator check
    copy_done3_idx = len(instructions)
    add(0x41820000, 'beq copy_done [PATCH]')

    # Store glyph to log entry +0x1C + offset
    add(0x39280000, 'addi r9, r8, 0')        # r9 = entry base (temp)
    # We need entry + 0x1C + offset. Use r9 = r8 + 0x1C, then sthx r0, r9, r6
    instructions.pop()
    add(0x3928001C, 'addi r9, r8, 0x1C')     # r9 = &entry.glyphs[0]
    add(0x7C09362E, 'sthx r0, r9, r6')       # entry.glyphs[offset/2] = glyph (wrong: offset is byte offset, sthx uses byte index)
    # sthx rS, rA, rB: EA = rA + rB, store halfword. r6 is byte offset. This is correct.

    add(0x38C60002, 'addi r6, r6, 2')        # offset += 2
    add(0x38E7FFFF, 'addi r7, r7, -1')       # remaining--
    b_loop_idx = len(instructions)
    add(0x48000000, 'b copy_loop [PATCH]')

    labels['copy_done'] = current_offset()
    # Write actual glyph count: offset / 2
    add(0x54C6F87E, 'srwi r6, r6, 1')        # r6 = byte_offset / 2 = glyph count
    # Actually srwi r6, r6, 1 encoding: rlwinm r6, r6, 31, 1, 31
    # rlwinm rA, rS, SH, MB, ME: (21<<26) | rS<<21 | rA<<16 | SH<<11 | MB<<6 | ME<<1
    # srwi r6, r6, 1: rS=6, rA=6, SH=31, MB=1, ME=31
    instructions.pop()
    srwi_insn = (21 << 26) | (6 << 21) | (6 << 16) | (31 << 11) | (1 << 6) | (31 << 1)
    add(srwi_insn, 'srwi r6, r6, 1')         # glyph_count = offset / 2
    add(0xB0C8001A, 'sth r6, 26(r8)')        # entry.glyph_count

    # ================================================================
    # UPDATE LOG HEADER — increment write_index and total_entries
    # ================================================================
    # Reload header pointer
    add(0x3D400000, 'lis r10, LOG_HEADER@ha [RELOC]')    # +xx
    add(0x394A0000, 'addi r10, r10, LOG_HEADER@lo [RELOC]')

    # Increment write_index
    add(0x816A0004, 'lwz r11, 4(r10)')       # write_index
    add(0x396B0001, 'addi r11, r11, 1')      # ++
    add(0x916A0004, 'stw r11, 4(r10)')       # store back

    # Increment total_entries
    add(0x816A0008, 'lwz r11, 8(r10)')       # total_entries
    add(0x396B0001, 'addi r11, r11, 1')
    add(0x916A0008, 'stw r11, 8(r10)')

    # ================================================================
    # CALL ORIGINAL TEXT COPIER
    # ================================================================
    # Restore r3 (source) and r4 (dest)
    add(0x80610038, 'lwz r3, 56(r1)')        # source
    add(0x80810034, 'lwz r4, 52(r1)')        # dest

    # bl text_copier (RELOC PLACEHOLDER — will be patched with correct offset)
    text_copier_bl_idx = len(instructions)
    add(0x48000001, 'bl text_copier [RELOC]')

    # ================================================================
    # EPILOGUE — restore and return
    # ================================================================
    labels['epilogue'] = current_offset()
    add(0x83C10030, 'lwz r30, 48(r1)')       # restore r30
    add(0x38210040, 'addi r1, r1, 64')       # dealloc frame
    add(0x8001FFFC, 'lwz r0, -4(r1)')        # restore LR
    add(0x7C0803A6, 'mtlr r0')
    add(0x4E800020, 'blr')

    # ================================================================
    # PATCH BRANCH TARGETS
    # ================================================================
    patch_branch(copy_done_idx, 'copy_done', cond='beq')
    patch_branch(copy_done2_idx, 'copy_done', cond='beq')
    patch_branch(copy_done3_idx, 'copy_done', cond='beq')
    patch_branch(b_loop_idx, 'copy_loop')

    # ================================================================
    # ASSEMBLE TO BYTES
    # ================================================================
    code = bytearray()
    for insn, comment in instructions:
        code.extend(struct.pack('>I', insn))

    # Collect relocation offsets
    reloc_info = {
        'log_header_ha_offsets': [],
        'log_header_lo_offsets': [],
        'log_buffer_ha_offsets': [],
        'log_buffer_lo_offsets': [],
        'text_copier_bl_offset': text_copier_bl_idx * 4,
    }

    # Find all LOG_HEADER and LOG_BUFFER lis/addi pairs
    for i, (insn, comment) in enumerate(instructions):
        if 'LOG_HEADER@ha' in comment:
            reloc_info['log_header_ha_offsets'].append(i * 4)
        elif 'LOG_HEADER@lo' in comment:
            reloc_info['log_header_lo_offsets'].append(i * 4)
        elif 'LOG_BUFFER@ha' in comment:
            reloc_info['log_buffer_ha_offsets'].append(i * 4)
        elif 'LOG_BUFFER@lo' in comment:
            reloc_info['log_buffer_lo_offsets'].append(i * 4)

    # Print disassembly
    print(f"\n  Assembled hook code ({len(code)} bytes, {len(instructions)} instructions):")
    for i, (insn, comment) in enumerate(instructions):
        print(f"    +0x{i*4:02X}: {insn:08X}  {comment}")

    return bytes(code), reloc_info


def build_log_header(max_entries):
    """Build the initial log header (16 bytes)."""
    return struct.pack('>IIII',
        LOG_HEADER_MAGIC,   # "DLOG"
        0,                  # write_index = 0
        0,                  # total_entries = 0
        max_entries,        # max_entries
    )


# ============================================================
# REL Patching
# ============================================================

def compute_bl_instruction(src_file_offset, dst_file_offset):
    """Compute a PPC bl instruction from source to destination file offsets.

    IMPORTANT: This assumes sections are at contiguous file offsets in memory,
    which is true for Dolphin's REL loader for sections within the same module.
    The Wii REL loader may allocate sections separately — in that case,
    relocations must be injected. For Dolphin testing, file-offset-based
    offsets work because Dolphin loads the entire REL as a contiguous block
    and then fixes up individual section addresses.

    Returns the 4-byte bl instruction.
    """
    delta = dst_file_offset - src_file_offset
    if delta < -0x02000000 or delta > 0x01FFFFFF:
        raise ValueError(f"Branch offset 0x{delta:X} out of ±32MB range")
    insn = 0x48000001 | (delta & 0x03FFFFFC)
    return struct.pack('>I', insn)


def patch_lis_addi(code, ha_offset, lo_offset, sec5_offset, sec5_file_offset):
    """Patch lis/addi pair in hook code with file-offset-based address.

    For the in-file patching approach, we use the file offset as a proxy
    for the runtime address. The actual runtime address resolution happens
    via relocations at load time.

    For the file-offset method: we compute what address the REL loader will
    assign. Since we can't know this statically, we instead embed the sec5
    offset and add relocation entries.

    FOR NOW: We leave these as zeros and document that relocations are needed.
    The hook will work if we add relocation entries to the REL.
    As an alternative, we provide a --runtime-base option to hardcode addresses
    from a captured Dolphin session.
    """
    pass  # Handled by add_relocation_entries or runtime base


def add_relocation_entries(rel_data, cfg, hook_code_len, reloc_info):
    """Add new self-referencing relocation entries to patch the lis/addi pairs
    and bl instructions in the hook code.

    We find the module's self-referencing relocation block (mod X → mod X),
    locate the R_RVL_STOP terminator, and insert new entries before it.

    Relocation entry format (8 bytes):
        u16 offset_delta  (delta from previous relocation in same section)
        u8  type          (R_PPC_ADDR16_HA=6, R_PPC_ADDR16_LO=4, R_PPC_REL24=10)
        u8  target_section
        u32 addend        (offset within target section)
    """
    mod_id = cfg['module_id']

    # Parse import table to find self-referencing block
    imp_off = struct.unpack_from('>I', rel_data, 0x28)[0]
    imp_size = struct.unpack_from('>I', rel_data, 0x2C)[0]
    n_imports = imp_size // 8

    self_reloc_off = None
    for i in range(n_imports):
        target = struct.unpack_from('>I', rel_data, imp_off + i * 8)[0]
        roff = struct.unpack_from('>I', rel_data, imp_off + i * 8 + 4)[0]
        if target == mod_id:
            self_reloc_off = roff
            break

    if self_reloc_off is None:
        print("  ERROR: Could not find self-referencing relocation block")
        return False

    # Find the R_RVL_STOP entry in the self-referencing block
    pos = self_reloc_off
    stop_pos = None
    while pos < len(rel_data) - 7:
        rtype = rel_data[pos + 2]
        if rtype == 203:  # R_RVL_STOP
            stop_pos = pos
            break
        pos += 8

    if stop_pos is None:
        print("  ERROR: Could not find R_RVL_STOP in self-referencing relocation block")
        return False

    print(f"  Found self-ref reloc block at 0x{self_reloc_off:06X}, STOP at 0x{stop_pos:06X}")

    # Build new relocation entries for the hook code in sec5
    new_entries = bytearray()
    hook_sec5 = cfg['hook_sec5_offset']

    # We need a R_RVL_SECT entry to switch to section 5 first
    # R_RVL_SECT: offset=0, type=202, section=5, addend=0
    new_entries += struct.pack('>HBBI', 0, 202, 5, 0)

    # Now emit relocations for each lis/addi pair in the hook code
    # These are at offsets within sec5, starting from hook_sec5_offset
    # The relocation offset_delta is relative to the previous entry in sec5

    # Sort all relocation sites by their sec5 offset
    reloc_sites = []

    # LOG_HEADER references: R_PPC_ADDR16_HA (type 6) and R_PPC_ADDR16_LO (type 4)
    for off in reloc_info['log_header_ha_offsets']:
        reloc_sites.append((hook_sec5 + off, 6, 5, cfg['log_header_sec5']))
    for off in reloc_info['log_header_lo_offsets']:
        reloc_sites.append((hook_sec5 + off + 2, 4, 5, cfg['log_header_sec5']))
        # +2 because LO reloc patches the low 16 bits (halfword at offset+2)

    # LOG_BUFFER references
    for off in reloc_info['log_buffer_ha_offsets']:
        reloc_sites.append((hook_sec5 + off, 6, 5, cfg['log_buffer_sec5']))
    for off in reloc_info['log_buffer_lo_offsets']:
        reloc_sites.append((hook_sec5 + off + 2, 4, 5, cfg['log_buffer_sec5']))

    # bl text_copier: R_PPC_REL24 (type 10) targeting sec1+text_copier
    bl_off = hook_sec5 + reloc_info['text_copier_bl_offset']
    reloc_sites.append((bl_off, 10, 1, cfg['text_copier_sec1']))

    # Sort by sec5 offset
    reloc_sites.sort(key=lambda x: x[0])

    prev_off = 0
    for sec5_off, rtype, target_sec, addend in reloc_sites:
        delta = sec5_off - prev_off
        # If delta > 0xFFFF, we need to insert R_RVL_NONE entries to advance
        while delta > 0xFFFF:
            new_entries += struct.pack('>HBBI', 0xFFFF, 201, 0, 0)  # R_RVL_NONE
            delta -= 0xFFFF
        new_entries += struct.pack('>HBBI', delta, rtype, target_sec, addend)
        prev_off = sec5_off

    # Also need relocations for the CALLER patches (sec1 bl instructions)
    # These go in a separate R_RVL_SECT block for section 1
    new_entries += struct.pack('>HBBI', 0, 202, 1, 0)  # Switch to sec1

    # Sort callers by sec1 offset
    caller_sites = sorted(cfg['callers'], key=lambda x: x[0])
    prev_off = 0
    for caller_sec1_off, desc in caller_sites:
        delta = caller_sec1_off - prev_off
        while delta > 0xFFFF:
            new_entries += struct.pack('>HBBI', 0xFFFF, 201, 0, 0)
            delta -= 0xFFFF
        # R_PPC_REL24 targeting sec5+hook_sec5_offset
        new_entries += struct.pack('>HBBI', delta, 10, 5, hook_sec5)
        prev_off = caller_sec1_off

    print(f"  Built {len(new_entries)} bytes of new relocation entries")
    print(f"  WARNING: Injecting relocations into the REL is EXPERIMENTAL.")
    print(f"  The safe approach is to use --runtime-base to hardcode addresses.")

    # For safety, we do NOT inject relocations automatically.
    # Instead, we return the entries so the user can review them.
    return new_entries


def patch_rel(rel_path, cfg, output_path=None, dry_run=False, runtime_sec1=None, runtime_sec5=None):
    """Patch a REL file with the dialogue logging hook.

    If runtime_sec1 and runtime_sec5 are provided, hardcode the runtime
    addresses directly (no relocation injection needed). These values
    come from a Dolphin debugging session.

    If not provided, use file-offset-based branch calculation (works
    for Dolphin's contiguous REL loading but may not work on real Wii).
    """
    with open(rel_path, 'rb') as f:
        rel_data = bytearray(f.read())

    original_size = len(rel_data)

    # Verify module ID
    mod_id = struct.unpack_from('>I', rel_data, 0)[0]
    if mod_id != cfg['module_id']:
        print(f"ERROR: Expected module {cfg['module_id']}, got {mod_id}")
        sys.exit(1)

    print(f"\nPatching {cfg['name']} (module {mod_id})...")
    print(f"  sec1: file offset 0x{cfg['sec1_file_offset']:06X}, size 0x{cfg['sec1_size']:06X}")
    print(f"  sec5: file offset 0x{cfg['sec5_file_offset']:06X}, size 0x{cfg['sec5_size']:06X}")

    # Verify zero region is safe
    print(f"\nVerifying zero region safety...")
    if not verify_zero_region(rel_data, cfg):
        print("WARNING: Zero region contains non-zero data!")
        print("  The REL may already be patched or the offsets are wrong.")
        if not dry_run:
            resp = input("  Continue anyway? [y/N] ")
            if resp.lower() != 'y':
                sys.exit(1)

    # Verify original bl instructions at caller sites
    print(f"\nVerifying {len(cfg['callers'])} call sites...")
    copier_sec1 = cfg['text_copier_sec1']
    all_ok = True
    for caller_off, desc in cfg['callers']:
        file_off = cfg['sec1_file_offset'] + caller_off
        insn = struct.unpack_from('>I', rel_data, file_off)[0]

        # Check it's a bl instruction (opcode 18, LK=1)
        if (insn & 0xFC000003) != 0x48000001:
            print(f"  FAIL: sec1+0x{caller_off:06X} is not a bl: 0x{insn:08X}")
            all_ok = False
            continue

        # Verify it targets the text copier
        offset = insn & 0x03FFFFFC
        if offset & 0x02000000:
            offset -= 0x04000000
        target = caller_off + offset
        if target != copier_sec1:
            print(f"  WARN: sec1+0x{caller_off:06X} targets 0x{target:06X} (expected 0x{copier_sec1:06X})")
            # This can happen if the bl uses a relocation stub (bl 0x0090 pattern)
            # In unresolved RELs, all cross-module calls go to 0x0090.
            # For intra-module calls to the text copier, this should resolve correctly.
        else:
            print(f"  OK: sec1+0x{caller_off:06X} → 0x{copier_sec1:06X} ({desc})")

    # Assemble hook code
    hook_code, reloc_info = assemble_logger_hook(cfg)
    max_entries = compute_max_entries(cfg)
    print(f"\n  Log buffer: {max_entries} entries × {LOG_ENTRY_SIZE} bytes = "
          f"{max_entries * LOG_ENTRY_SIZE / 1024:.1f} KB")

    if dry_run:
        print("\n  DRY RUN — no files modified.")
        return

    # Determine address resolution method
    use_hardcoded = (runtime_sec1 is not None and runtime_sec5 is not None)

    if use_hardcoded:
        print(f"\n  Using hardcoded runtime addresses:")
        print(f"    sec1 base: 0x{runtime_sec1:08X}")
        print(f"    sec5 base: 0x{runtime_sec5:08X}")

        # Patch lis/addi pairs with actual runtime addresses
        hook_code = bytearray(hook_code)

        # LOG_HEADER runtime address
        log_header_addr = runtime_sec5 + cfg['log_header_sec5']
        ha = (log_header_addr >> 16) + (1 if (log_header_addr & 0x8000) else 0)
        lo = log_header_addr & 0xFFFF
        for off in reloc_info['log_header_ha_offsets']:
            struct.pack_into('>H', hook_code, off + 2, ha & 0xFFFF)
        for off in reloc_info['log_header_lo_offsets']:
            struct.pack_into('>H', hook_code, off + 2, lo)

        # LOG_BUFFER runtime address
        log_buffer_addr = runtime_sec5 + cfg['log_buffer_sec5']
        ha = (log_buffer_addr >> 16) + (1 if (log_buffer_addr & 0x8000) else 0)
        lo = log_buffer_addr & 0xFFFF
        for off in reloc_info['log_buffer_ha_offsets']:
            struct.pack_into('>H', hook_code, off + 2, ha & 0xFFFF)
        for off in reloc_info['log_buffer_lo_offsets']:
            struct.pack_into('>H', hook_code, off + 2, lo)

        # bl text_copier: compute relative branch from hook to copier
        hook_runtime = runtime_sec5 + cfg['hook_sec5_offset']
        copier_runtime = runtime_sec1 + cfg['text_copier_sec1']
        bl_hook_off = reloc_info['text_copier_bl_offset']
        bl_src = hook_runtime + bl_hook_off
        bl_delta = copier_runtime - bl_src
        bl_insn = 0x48000001 | (bl_delta & 0x03FFFFFC)
        struct.pack_into('>I', hook_code, bl_hook_off, bl_insn)

        hook_code = bytes(hook_code)

    # Write hook code into sec5
    hook_file_off = cfg['sec5_file_offset'] + cfg['hook_sec5_offset']
    print(f"\n  Writing hook code at file offset 0x{hook_file_off:06X}")
    rel_data[hook_file_off:hook_file_off + len(hook_code)] = hook_code

    # Write log header
    header_file_off = cfg['sec5_file_offset'] + cfg['log_header_sec5']
    log_header = build_log_header(max_entries)
    print(f"  Writing log header at file offset 0x{header_file_off:06X}")
    rel_data[header_file_off:header_file_off + len(log_header)] = log_header

    # Patch all caller bl instructions to branch to hook instead of copier
    hook_sec5 = cfg['hook_sec5_offset']
    for caller_off, desc in cfg['callers']:
        caller_file_off = cfg['sec1_file_offset'] + caller_off
        hook_file = cfg['sec5_file_offset'] + hook_sec5

        if use_hardcoded:
            # Compute runtime bl offset
            caller_runtime = runtime_sec1 + caller_off
            hook_runtime = runtime_sec5 + hook_sec5
            delta = hook_runtime - caller_runtime
        else:
            # File-offset-based (works for Dolphin contiguous loading)
            delta = hook_file - caller_file_off

        bl_insn = 0x48000001 | (delta & 0x03FFFFFC)
        struct.pack_into('>I', rel_data, caller_file_off, bl_insn)
        print(f"  Patched sec1+0x{caller_off:06X}: bl +0x{delta & 0x03FFFFFC:06X} ({desc})")

    # Verify file size unchanged
    assert len(rel_data) == original_size, "File size changed!"

    # Write output
    if output_path is None:
        output_path = rel_path
    else:
        output_path = str(output_path)

    # Create backup
    backup_path = str(rel_path) + '.bak'
    if not os.path.exists(backup_path):
        shutil.copy2(rel_path, backup_path)
        print(f"\n  Backup saved to: {backup_path}")

    with open(output_path, 'wb') as f:
        f.write(rel_data)

    print(f"\n  Patched REL written to: {output_path}")
    print(f"  File size: {len(rel_data)} bytes (unchanged)")
    print(f"\n  === LOGGING HOOK ACTIVE ===")
    print(f"  Log header at sec5+0x{cfg['log_header_sec5']:06X} (look for 'DLOG' = 0x{LOG_HEADER_MAGIC:08X})")
    print(f"  Log entries at sec5+0x{cfg['log_buffer_sec5']:06X}")
    print(f"  Max entries: {max_entries}")
    print(f"  Entry size: {LOG_ENTRY_SIZE} bytes")
    print(f"  Entry magic: 0x{LOG_MAGIC:08X} ('LOG\\0')")


def restore_rel(rel_path):
    """Restore a REL from its .bak backup."""
    backup_path = str(rel_path) + '.bak'
    if not os.path.exists(backup_path):
        print(f"ERROR: No backup found at {backup_path}")
        sys.exit(1)
    shutil.copy2(backup_path, rel_path)
    print(f"Restored {rel_path} from backup.")


# ============================================================
# Verify sct_main zero region
# ============================================================

def find_sct_zero_region():
    """Find a suitable zero region in sct_main.rel sec5 for the hook."""
    # sct_main sec5: offset 0x0321A0, size 0x06895C
    # We need to scan for a large zero region
    # For now, use the pre-defined offsets. The caller should verify.
    pass


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Inject dialogue logging hook into Pawapuro 15 REL files')

    parser.add_argument('--rel', type=str, required=True,
                       help='Path to the REL file to patch (scs_main.rel or sct_main.rel)')
    parser.add_argument('--mode', type=str, default='auto', choices=['auto', 'success', 'eikan'],
                       help='Game mode: success (scs_main), eikan (sct_main), or auto-detect')
    parser.add_argument('--output', type=str, default=None,
                       help='Output path (default: overwrite input with backup)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be patched without modifying files')
    parser.add_argument('--restore', action='store_true',
                       help='Restore from backup (.bak file)')
    parser.add_argument('--runtime-sec1', type=str, default=None,
                       help='Runtime base address of sec1 (hex, from Dolphin debugger)')
    parser.add_argument('--runtime-sec5', type=str, default=None,
                       help='Runtime base address of sec5 (hex, from Dolphin debugger)')
    parser.add_argument('--dump-relocs', action='store_true',
                       help='Dump the relocation entries that would be needed')

    args = parser.parse_args()

    rel_path = Path(args.rel)
    if not rel_path.exists():
        print(f"ERROR: File not found: {rel_path}")
        sys.exit(1)

    if args.restore:
        restore_rel(rel_path)
        return

    # Auto-detect mode from module ID
    with open(rel_path, 'rb') as f:
        mod_id = struct.unpack('>I', f.read(4))[0]

    if args.mode == 'auto':
        if mod_id == 311:
            cfg = SCS_MAIN
        elif mod_id == 347:
            cfg = SCT_MAIN
        else:
            print(f"ERROR: Unknown module ID {mod_id}. Use --mode to specify.")
            sys.exit(1)
    elif args.mode == 'success':
        cfg = SCS_MAIN
    elif args.mode == 'eikan':
        cfg = SCT_MAIN

    # Parse runtime addresses
    runtime_sec1 = int(args.runtime_sec1, 16) if args.runtime_sec1 else None
    runtime_sec5 = int(args.runtime_sec5, 16) if args.runtime_sec5 else None

    if args.dump_relocs:
        hook_code, reloc_info = assemble_logger_hook(cfg)
        with open(rel_path, 'rb') as f:
            rel_data = bytearray(f.read())
        new_entries = add_relocation_entries(rel_data, cfg, len(hook_code), reloc_info)
        if new_entries:
            print(f"\n  Relocation entries ({len(new_entries)} bytes):")
            for i in range(0, len(new_entries), 8):
                chunk = new_entries[i:i+8]
                if len(chunk) == 8:
                    delta, rtype, rsec, addend = struct.unpack('>HBBI', chunk)
                    type_names = {4: 'ADDR16_LO', 6: 'ADDR16_HA', 10: 'REL24',
                                  201: 'RVL_NONE', 202: 'RVL_SECT', 203: 'RVL_STOP'}
                    tname = type_names.get(rtype, f'type_{rtype}')
                    print(f"    +{i:3d}: delta=0x{delta:04X} type={tname} sec={rsec} addend=0x{addend:06X}")
        return

    patch_rel(rel_path, cfg, args.output, args.dry_run, runtime_sec1, runtime_sec5)


if __name__ == '__main__':
    main()
