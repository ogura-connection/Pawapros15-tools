"""Extract one file from an encrypted Wii disc image (.iso).

    pp15 extract-iso ISO FILENAME [OUTPUT]

What it does: a Wii disc keeps its files in one encrypted partition (see pp15/disc/wii_format.py). This tool finds the
partition, decrypts it cluster by cluster, reads the disc's file table (the "FST": a list of every file with its place
and size) and writes the file you name. Needs the Python package pycryptodome (`pip install pycryptodome`) for AES.

Steps: 1. find the data partition in the partition table; 2. read the ticket and decrypt the title key with the Wii
common key; 3. decrypt clusters on demand (AES-128-CBC); 4. parse the FST; 5. copy the file out.

Public functions: find_data_partition, decrypt_title_key, get_partition_data_offset, decrypt_cluster, read_decrypted,
parse_fst, extract_file, main.
"""
import argparse
import sys
from typing import BinaryIO, List, Optional, Tuple

from pp15.disc import wii_format
from pp15.disc.wii_format import read_u32

WII_MAGIC = 0x5D1C9EA3                   # at 0x18 in the decrypted partition: marks a Wii disc


def _aes():
    """The AES implementation of pycryptodome, imported on first use so that the rest of the package works without it."""
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError as e:
        raise ModuleNotFoundError("pp15 extract-iso needs the Python package pycryptodome: pip install pycryptodome",
                                  name=e.name) from e
    return AES


# ── Partition discovery ────────────────────────────────────────────────────

def find_data_partition(f: BinaryIO) -> Optional[int]:
    """The disc offset of the first DATA partition (the one that holds the game), or None if there is none."""
    f.seek(wii_format.PARTITION_INFO_OFFSET)
    header = f.read(0x20)
    for group in range(4):
        count = read_u32(header, group * 8)
        table_offset = read_u32(header, group * 8 + 4) << 2
        if count == 0:
            continue
        f.seek(table_offset)
        for _ in range(count):
            entry = f.read(8)
            partition_offset = read_u32(entry, 0) << 2
            partition_type = read_u32(entry, 4)
            if partition_type == wii_format.PARTITION_TYPE_DATA:
                return partition_offset
    return None


# ── Ticket / title key ─────────────────────────────────────────────────────

def decrypt_title_key(f: BinaryIO, partition_offset: int) -> bytes:
    """Read the ticket at the start of the partition and decrypt the title key (16 bytes) with the Wii common key.
    The key's IV is the 8-byte title id followed by 8 zero bytes."""
    f.seek(partition_offset)
    ticket = f.read(wii_format.TICKET_SIZE)
    start = wii_format.TICKET_ENCRYPTED_KEY_OFFSET
    encrypted_key = ticket[start:start + 16]
    start = wii_format.TICKET_TITLE_ID_OFFSET
    iv = ticket[start:start + 8] + b"\x00" * 8
    return _aes().new(wii_format.WII_COMMON_KEY, _aes().MODE_CBC, iv).decrypt(encrypted_key)


# ── Partition data (encrypted clusters) ────────────────────────────────────

def get_partition_data_offset(f: BinaryIO, partition_offset: int) -> int:
    """The absolute disc offset where the partition's data begins."""
    f.seek(partition_offset + wii_format.PARTITION_DATA_OFFSET_FIELD)
    raw = read_u32(f.read(4), 0)
    return partition_offset + (raw << 2)


def decrypt_cluster(f: BinaryIO, title_key: bytes, data_start: int, cluster_index: int) -> bytes:
    """Read and decrypt one cluster; returns its CLUSTER_DATA_SIZE bytes of data (zeros if the disc ends before it).
    `data_start` is the offset from get_partition_data_offset."""
    f.seek(data_start + cluster_index * wii_format.CLUSTER_SIZE)
    raw_cluster = f.read(wii_format.CLUSTER_SIZE)
    if len(raw_cluster) < wii_format.CLUSTER_SIZE:
        return b"\x00" * wii_format.CLUSTER_DATA_SIZE
    hash_block = raw_cluster[:wii_format.CLUSTER_HASH_SIZE]
    encrypted_data = raw_cluster[wii_format.CLUSTER_HASH_SIZE:]
    # the IV of the data's encryption is stored inside the (unencrypted) hash block
    iv = hash_block[wii_format.CLUSTER_IV_OFFSET:wii_format.CLUSTER_IV_OFFSET + wii_format.CLUSTER_IV_SIZE]
    return _aes().new(title_key, _aes().MODE_CBC, iv).decrypt(encrypted_data)


def read_decrypted(f: BinaryIO, title_key: bytes, data_start: int, logical_offset: int, size: int) -> bytes:
    """Read `size` bytes at `logical_offset` of the decrypted partition data (the data of all clusters joined)."""
    buf = bytearray()
    remaining = size
    current = logical_offset
    while remaining > 0:
        cluster_index = current // wii_format.CLUSTER_DATA_SIZE
        within = current % wii_format.CLUSTER_DATA_SIZE
        chunk = min(remaining, wii_format.CLUSTER_DATA_SIZE - within)
        cluster_data = decrypt_cluster(f, title_key, data_start, cluster_index)
        buf.extend(cluster_data[within:within + chunk])
        current += chunk
        remaining -= chunk
    return bytes(buf)


# ── File table (FST) ───────────────────────────────────────────────────────

FST_ENTRY_SIZE = 12                      # flag + name offset (4 bytes), then two numbers
FST_DIRECTORY_FLAG = 1


def parse_fst(fst_data: bytes) -> List[Tuple[str, int, int]]:
    """Read the file table. Returns [(path, offset in the decrypted partition data, size)] for every file.

    Each entry is 12 bytes: a flag byte (1 = directory) and a 3-byte offset of the name in the name table that follows
    the entries; for a file then its offset (in 4-byte units) and size; for a directory its parent and the index of
    the first entry after it. The first entry is the root, its third number is the entry count."""
    entry_count = read_u32(fst_data, 8)
    string_table = fst_data[entry_count * FST_ENTRY_SIZE:]

    def get_name(name_offset: int) -> str:
        end = string_table.index(b"\x00", name_offset)
        return string_table[name_offset:end].decode("ascii", errors="replace")

    files = []
    directory_stack = [("", entry_count)]            # (path prefix, index of the first entry after the directory)
    i = 1
    while i < entry_count:
        while directory_stack and i >= directory_stack[-1][1]:
            directory_stack.pop()
        flag = fst_data[i * FST_ENTRY_SIZE]
        name_offset = read_u32(fst_data, i * FST_ENTRY_SIZE) & 0x00FFFFFF
        field1 = read_u32(fst_data, i * FST_ENTRY_SIZE + 4)
        field2 = read_u32(fst_data, i * FST_ENTRY_SIZE + 8)
        name = get_name(name_offset)
        prefix = directory_stack[-1][0] if directory_stack else ""
        if flag == FST_DIRECTORY_FLAG:
            directory_stack.append((prefix + name + "/", field2))
        else:
            files.append((prefix + name, field1 << 2, field2))
        i += 1
    return files


# ── The command ────────────────────────────────────────────────────────────

def extract_file(iso_path: str, target_name: str, output_path: str) -> None:
    """Extract the file whose name (without folders, upper or lower case) is `target_name` from the disc image into
    `output_path`, printing each step. Exits with a message if the partition or the file is not found."""
    with open(iso_path, "rb") as f:
        f.seek(0)
        disc_id = f.read(6).decode("ascii", errors="replace")
        print(f"[*] Disc ID: {disc_id}")

        partition_offset = find_data_partition(f)
        if partition_offset is None:
            print("ERROR: No DATA partition found.")
            sys.exit(1)
        print(f"[*] DATA partition at 0x{partition_offset:08X}")

        title_key = decrypt_title_key(f, partition_offset)
        print(f"[*] Title key decrypted: {title_key.hex()}")

        data_start = get_partition_data_offset(f, partition_offset)
        print(f"[*] Partition data at 0x{data_start:08X}")

        magic = read_u32(read_decrypted(f, title_key, data_start, 0x18, 4), 0)
        if magic == WII_MAGIC:
            print(f"[*] Wii magic verified: 0x{magic:08X}")
        else:
            print(f"WARNING: Expected Wii magic 0x{WII_MAGIC:08X}, got 0x{magic:08X}")
            print("         Continuing anyway...")

        # the boot info at logical 0x424 says where the file table is and how big
        boot_info = read_decrypted(f, title_key, data_start, wii_format.FST_OFFSET_FIELD, 8)
        fst_offset = read_u32(boot_info, 0) << 2
        fst_size = read_u32(boot_info, 4) << 2
        print(f"[*] FST at logical 0x{fst_offset:08X}, size 0x{fst_size:X}")

        files = parse_fst(read_decrypted(f, title_key, data_start, fst_offset, fst_size))
        print(f"[*] {len(files)} files in FST")

        wanted = target_name.lower()
        match = next(((path, off, size) for path, off, size in files if path.rsplit("/", 1)[-1].lower() == wanted), None)
        if match is None:
            print(f"ERROR: '{target_name}' not found in FST.")
            print("Available .rel files:")
            for path, _, size in files:
                if path.lower().endswith(".rel"):
                    print(f"  {path} ({size:,} bytes)")
            sys.exit(1)

        path, file_offset, file_size = match
        print(f"[*] Found: {path} at logical 0x{file_offset:08X}, {file_size:,} bytes")
        print("[*] Extracting...")
        file_data = read_decrypted(f, title_key, data_start, file_offset, file_size)
        with open(output_path, "wb") as out:
            out.write(file_data)
        print(f"[*] Written to: {output_path} ({len(file_data):,} bytes)")


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 extract-iso ISO FILENAME [OUTPUT]`. `argv` defaults to sys.argv[1:]."""
    parser = argparse.ArgumentParser(prog="pp15 extract-iso", description=__doc__.split("\n\n")[0])
    parser.add_argument("iso", help="the Wii disc image (.iso)")
    parser.add_argument("filename", help="name of the file to extract, without folders (e.g. scs_main.rel)")
    parser.add_argument("output", nargs="?", help="where to write it (default: FILENAME in the current folder)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        extract_file(args.iso, args.filename, args.output or args.filename)
    except ModuleNotFoundError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
