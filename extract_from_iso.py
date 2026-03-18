#!/usr/bin/env python3
"""
extract_from_iso.py — Extract individual files from an encrypted Wii ISO.

Usage:
    python3 extract_from_iso.py <iso_path> <filename_to_extract> [output_path]

Handles full Wii disc encryption:
  1. Reads partition table to find DATA partition
  2. Reads ticket to get encrypted title key
  3. Decrypts title key using Wii common key
  4. Reads and decrypts cluster data (AES-128-CBC per cluster)
  5. Parses FST to locate the requested file
  6. Extracts and writes it out
"""

import sys
import os
import struct
from Crypto.Cipher import AES

# =============================================================================
# Wii common key (well-known, used by all Wii homebrew tools)
# =============================================================================
WII_COMMON_KEY = bytes.fromhex("ebe42a225e8593e448d9c5457381aaf7")

# =============================================================================
# Constants
# =============================================================================
PARTITION_INFO_OFFSET = 0x40000
CLUSTER_TOTAL = 0x8000
CLUSTER_HASH  = 0x400
CLUSTER_DATA  = 0x7C00

def r_u32(data, off):
    return struct.unpack_from('>I', data, off)[0]

def r_u16(data, off):
    return struct.unpack_from('>H', data, off)[0]

# =============================================================================
# Partition discovery
# =============================================================================

def find_data_partition(f):
    """Find the DATA partition (type 0) offset."""
    f.seek(PARTITION_INFO_OFFSET)
    header = f.read(0x20)

    for group in range(4):
        count     = r_u32(header, group * 8)
        table_off = r_u32(header, group * 8 + 4) << 2
        if count == 0:
            continue

        f.seek(table_off)
        for _ in range(count):
            entry     = f.read(8)
            part_off  = r_u32(entry, 0) << 2
            part_type = r_u32(entry, 4)
            if part_type == 0:
                return part_off

    return None

# =============================================================================
# Ticket / title key decryption
# =============================================================================

def decrypt_title_key(f, partition_off):
    """Read the ticket from the partition header and decrypt the title key.

    The ticket starts at partition_off + 0x000.
    - Encrypted title key at ticket + 0x1BF (16 bytes)
    - Title ID at ticket + 0x1DC (8 bytes, first 8 bytes used as IV)
    """
    f.seek(partition_off)
    ticket = f.read(0x2A4)  # Read enough for the full ticket

    # Encrypted title key
    enc_title_key = ticket[0x1BF:0x1BF + 16]

    # IV = title ID (8 bytes) + 8 zero bytes
    title_id = ticket[0x1DC:0x1DC + 8]
    iv = title_id + b'\x00' * 8

    # Decrypt with Wii common key
    cipher = AES.new(WII_COMMON_KEY, AES.MODE_CBC, iv)
    title_key = cipher.decrypt(enc_title_key)

    return title_key

# =============================================================================
# Partition data reading (encrypted clusters)
# =============================================================================

def get_partition_data_offset(f, partition_off):
    """Get the absolute disc offset where partition data begins."""
    f.seek(partition_off + 0x2B8)
    raw = struct.unpack('>I', f.read(4))[0]
    return partition_off + (raw << 2)

def decrypt_cluster(f, title_key, partition_data_start, cluster_idx):
    """Read and decrypt a single cluster, returning the 0x7C00 data bytes."""
    cluster_off = partition_data_start + cluster_idx * CLUSTER_TOTAL
    f.seek(cluster_off)
    raw_cluster = f.read(CLUSTER_TOTAL)

    if len(raw_cluster) < CLUSTER_TOTAL:
        return b'\x00' * CLUSTER_DATA

    # The hash section (first 0x400 bytes) contains the IV for the data section
    hash_section = raw_cluster[:CLUSTER_HASH]
    encrypted_data = raw_cluster[CLUSTER_HASH:]

    # IV for data decryption: bytes 0x3D0..0x3E0 of the hash section
    data_iv = hash_section[0x3D0:0x3D0 + 16]

    # Decrypt the data section
    cipher = AES.new(title_key, AES.MODE_CBC, data_iv)
    decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data

def read_decrypted(f, title_key, pds, logical_off, size):
    """Read `size` bytes at `logical_off` within the decrypted partition data."""
    buf = bytearray()
    remaining = size
    cur = logical_off

    while remaining > 0:
        cluster_idx = cur // CLUSTER_DATA
        within = cur % CLUSTER_DATA
        chunk = min(remaining, CLUSTER_DATA - within)

        cluster_data = decrypt_cluster(f, title_key, pds, cluster_idx)
        buf.extend(cluster_data[within:within + chunk])

        cur += chunk
        remaining -= chunk

    return bytes(buf)

# =============================================================================
# FST parsing
# =============================================================================

def parse_fst(fst_data):
    """Parse FST and return list of (path, logical_offset, size)."""
    num_entries = r_u32(fst_data, 8)
    string_table_off = num_entries * 12
    string_table = fst_data[string_table_off:]

    def get_name(name_off):
        end = string_table.index(b'\x00', name_off)
        return string_table[name_off:end].decode('ascii', errors='replace')

    files = []
    dir_stack = [("", num_entries)]

    i = 1
    while i < num_entries:
        while dir_stack and i >= dir_stack[-1][1]:
            dir_stack.pop()

        flag     = fst_data[i * 12]
        name_off = r_u32(fst_data, i * 12) & 0x00FFFFFF
        field1   = r_u32(fst_data, i * 12 + 4)
        field2   = r_u32(fst_data, i * 12 + 8)
        name     = get_name(name_off)
        prefix   = dir_stack[-1][0] if dir_stack else ""

        if flag == 1:
            dir_stack.append((prefix + name + "/", field2))
        else:
            file_off = field1 << 2
            file_size = field2
            files.append((prefix + name, file_off, file_size))

        i += 1

    return files

# =============================================================================
# Main
# =============================================================================

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <iso_path> <filename> [output_path]")
        sys.exit(1)

    iso_path = sys.argv[1]
    target_name = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else target_name

    with open(iso_path, 'rb') as f:
        # Disc ID
        f.seek(0)
        disc_id = f.read(6).decode('ascii', errors='replace')
        print(f"[*] Disc ID: {disc_id}")

        # Find DATA partition
        part_off = find_data_partition(f)
        if part_off is None:
            print("ERROR: No DATA partition found.")
            sys.exit(1)
        print(f"[*] DATA partition at 0x{part_off:08X}")

        # Decrypt title key
        title_key = decrypt_title_key(f, part_off)
        print(f"[*] Title key decrypted: {title_key.hex()}")

        # Partition data start
        pds = get_partition_data_offset(f, part_off)
        print(f"[*] Partition data at 0x{pds:08X}")

        # Verify by reading magic at logical offset 0x18
        magic_data = read_decrypted(f, title_key, pds, 0x18, 4)
        magic_val = r_u32(magic_data, 0)
        if magic_val == 0x5D1C9EA3:
            print(f"[*] Wii magic verified: 0x{magic_val:08X}")
        else:
            print(f"WARNING: Expected Wii magic 0x5D1C9EA3, got 0x{magic_val:08X}")
            print("         Continuing anyway...")

        # Read FST location
        hdr = read_decrypted(f, title_key, pds, 0x424, 8)
        fst_off  = r_u32(hdr, 0) << 2
        fst_size = r_u32(hdr, 4) << 2
        print(f"[*] FST at logical 0x{fst_off:08X}, size 0x{fst_size:X}")

        # Read and parse FST
        fst_data = read_decrypted(f, title_key, pds, fst_off, fst_size)
        files = parse_fst(fst_data)
        print(f"[*] {len(files)} files in FST")

        # Find target file
        target_lower = target_name.lower()
        match = None
        for path, off, size in files:
            basename = path.rsplit('/', 1)[-1]
            if basename.lower() == target_lower:
                match = (path, off, size)
                break

        if match is None:
            print(f"ERROR: '{target_name}' not found in FST.")
            print("Available .rel files:")
            for path, _, sz in files:
                if path.lower().endswith('.rel'):
                    print(f"  {path} ({sz:,} bytes)")
            sys.exit(1)

        path, file_off, file_size = match
        print(f"[*] Found: {path} at logical 0x{file_off:08X}, {file_size:,} bytes")

        # Extract
        print(f"[*] Extracting...")
        file_data = read_decrypted(f, title_key, pds, file_off, file_size)

        with open(output_path, 'wb') as out:
            out.write(file_data)

        print(f"[*] Written to: {output_path} ({len(file_data):,} bytes)")

if __name__ == '__main__':
    main()
