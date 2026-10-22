"""Release build: write the English game disc without changing Nintendo's disc layout, and make a patch against the original.

    pp15 release ORIGINAL.iso OUT.iso [PATCH.xdelta]

Why not simply rebuild the disc with `wit copy`: Wii partition data is AES-encrypted in 2 MB groups (64 clusters, see
pp15/disc/wii_format.py). A disc rebuilt from scratch has a new layout, so nearly every group differs and an xdelta
patch would be as big as the game. Here the original ISO is copied and only the groups we touch are rewritten:
- every changed file (DATA/files compared with the original kept in _work/orig*) is appended behind the last used byte
  of the data, from a group boundary on, and its entry in the disc's file table (FST) is pointed there (the old copies
  stay on the disc, unread);
- main.dol is written in place when it fits, else appended and the boot block re-pointed;
- each dirty group is decrypted, patched, its three levels of checksums (H0, H1, H2) recomputed and encrypted again;
  the top-level checksum table (H3), the partition data size and the title metadata (TMD: content hash and size) are
  updated and the TMD is signed with the fake signature the Wii tool `wit` also uses.
Then `wit verify` checks the result and xdelta3 makes the patch. Needs the programs openssl, wit and xdelta3 (found
through PATH; wit also at config.WIT_FALLBACK).

Public: Disc (an editable disc image), fst_files, aes_cbc, main.
"""
import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

from pp15 import config
from pp15.disc import wii_format
from pp15.disc.wii_format import (CLUSTER_DATA_SIZE, CLUSTER_HASH_SIZE, CLUSTER_IV_OFFSET, CLUSTER_IV_SIZE, CLUSTER_SIZE,
                                  CLUSTERS_PER_GROUP, read_u32)

WIT = shutil.which("wit") or config.WIT_FALLBACK
GROUP_DATA_SIZE = CLUSTERS_PER_GROUP * CLUSTER_DATA_SIZE       # game data bytes of one group
FILE_ALIGNMENT = 0x20                                           # files on the disc start on 32-byte boundaries

# Layout of the data in a hash block (0x400 bytes): H0 (31 SHA-1 of the 31 sub-blocks of the cluster's data), 20 spare
# bytes, H1 (8 SHA-1 of the H0 blocks of the sub-group), 32 spare, H2 (8 SHA-1 of the H1 blocks), 32 spare
SUBBLOCKS_PER_CLUSTER = 31
SUBBLOCK_SIZE = CLUSTER_HASH_SIZE                               # data is hashed in 0x400-byte pieces
CLUSTERS_PER_SUBGROUP = 8
SUBGROUPS_PER_GROUP = 8
H3_TABLE_SIZE = 0x18000                                         # H3: one SHA-1 per group

# Offsets in the partition header (the first 0x2C0 bytes of the partition)
HEADER_SIZE = 0x2C0
HDR_TMD_SIZE, HDR_TMD_OFFSET = 0x2A4, 0x2A8
HDR_H3_OFFSET = 0x2B4
HDR_DATA_OFFSET, HDR_DATA_SIZE = 0x2B8, 0x2BC
# Offsets in the title metadata (TMD)
TMD_SIGNATURE_END = 0x104               # the signature occupies bytes 4..0x104
TMD_RESERVED_FIELD = 0x1AA              # a field we vary until the TMD's SHA-1 starts with a zero byte (a "fake signature")
TMD_BODY_START = 0x140
TMD_CONTENT0 = 0x1E4                    # first content record: id, index, type, size (+8, 8 bytes), SHA-1 hash (+0x10, 20 bytes)


def aes_cbc(data: bytes, key: bytes, iv: bytes, decrypt: bool) -> bytes:
    """AES-128-CBC without padding, done by the `openssl` program (so no Python crypto package is needed)."""
    process = subprocess.run(["openssl", "enc", "-aes-128-cbc", "-d" if decrypt else "-e", "-nopad", "-K", key.hex(),
                              "-iv", iv.hex()], input=data, capture_output=True, check=True)
    return process.stdout


class Disc:
    """A Wii disc image opened for editing the data of its game partition.

    `write()` changes the decrypted data in memory (whole groups at a time); `flush()` encrypts the changed groups,
    fixes every checksum and writes them to the image. `read()` gives the decrypted data with the changes."""

    def __init__(self, path: str):
        self.file = open(path, "r+b")
        self.partition_offset = self._find_partition()
        self.file.seek(self.partition_offset)
        self.header = bytearray(self.file.read(HEADER_SIZE))
        ticket = self.header[:wii_format.TICKET_SIZE]
        key_at, id_at = wii_format.TICKET_ENCRYPTED_KEY_OFFSET, wii_format.TICKET_TITLE_ID_OFFSET
        self.title_key = aes_cbc(bytes(ticket[key_at:key_at + 16]), wii_format.WII_COMMON_KEY,
                                 bytes(ticket[id_at:id_at + 8]) + bytes(8), True)
        self.tmd_size, self.tmd_offset = read_u32(self.header, HDR_TMD_SIZE), read_u32(self.header, HDR_TMD_OFFSET) << 2
        self.h3_offset = read_u32(self.header, HDR_H3_OFFSET) << 2
        self.data_offset = read_u32(self.header, HDR_DATA_OFFSET) << 2
        self.data_size = read_u32(self.header, HDR_DATA_SIZE) << 2
        self.dirty_groups: Dict[int, bytearray] = {}        # group number -> its decrypted data (64 clusters)

    def _find_partition(self) -> int:
        """Offset of the (last listed) data partition."""
        self.file.seek(wii_format.PARTITION_INFO_OFFSET)
        info = self.file.read(0x20)
        found = None
        for group in range(4):
            count, table_offset = read_u32(info, group * 8), read_u32(info, group * 8 + 4) << 2
            for k in range(count):
                self.file.seek(table_offset + 8 * k)
                entry = self.file.read(8)
                if read_u32(entry, 4) == wii_format.PARTITION_TYPE_DATA:
                    found = read_u32(entry, 0) << 2
        return found

    def cluster_raw(self, cluster: int) -> bytes:
        """The encrypted bytes of one cluster, as on the disc."""
        self.file.seek(self.partition_offset + self.data_offset + cluster * CLUSTER_SIZE)
        return self.file.read(CLUSTER_SIZE)

    def _decrypt(self, raw_cluster: bytes) -> bytes:
        iv = raw_cluster[CLUSTER_IV_OFFSET:CLUSTER_IV_OFFSET + CLUSTER_IV_SIZE]
        return aes_cbc(raw_cluster[CLUSTER_HASH_SIZE:], self.title_key, iv, True)

    def group_data(self, group: int) -> bytearray:
        """The decrypted data of a group, loaded once and kept (it counts as changed from now on)."""
        if group not in self.dirty_groups:
            buf = bytearray()
            for cluster in range(group * CLUSTERS_PER_GROUP, (group + 1) * CLUSTERS_PER_GROUP):
                if cluster * CLUSTER_SIZE >= self.data_size:       # past the end of the data: new, zero-filled
                    buf += bytes(CLUSTER_DATA_SIZE)
                    continue
                buf += self._decrypt(self.cluster_raw(cluster))
            self.dirty_groups[group] = buf
        return self.dirty_groups[group]

    def read(self, offset: int, size: int) -> bytes:
        """`size` bytes of the decrypted partition data at `offset` (changes made with write() included)."""
        out = bytearray()
        while size:
            cluster, within = divmod(offset, CLUSTER_DATA_SIZE)
            chunk = min(size, CLUSTER_DATA_SIZE - within)
            group = cluster // CLUSTERS_PER_GROUP
            if group in self.dirty_groups:
                start = (cluster % CLUSTERS_PER_GROUP) * CLUSTER_DATA_SIZE + within
                piece = self.dirty_groups[group][start:start + chunk]
            else:
                piece = self._decrypt(self.cluster_raw(cluster))[within:within + chunk]
            out += piece
            offset += chunk
            size -= chunk
        return bytes(out)

    def write(self, offset: int, data: bytes) -> None:
        """Change the decrypted partition data at `offset` (in memory until flush())."""
        done = 0
        while done < len(data):
            cluster, within = divmod(offset + done, CLUSTER_DATA_SIZE)
            group = cluster // CLUSTERS_PER_GROUP
            chunk = min(len(data) - done, CLUSTER_DATA_SIZE - within)
            buf = self.group_data(group)
            start = (cluster % CLUSTERS_PER_GROUP) * CLUSTER_DATA_SIZE + within
            buf[start:start + chunk] = data[done:done + chunk]
            done += chunk

    def flush(self) -> None:
        """Write the changed groups to the image: recompute their checksums, encrypt, update the H3 table, the
        partition data size and the TMD."""
        f = self.file
        f.seek(self.partition_offset + self.h3_offset)
        h3 = bytearray(f.read(H3_TABLE_SIZE))
        for group, buf in sorted(self.dirty_groups.items()):
            # H0: SHA-1 of each 0x400-byte piece of a cluster's data
            h0_blocks = [b"".join(hashlib.sha1(buf[c * CLUSTER_DATA_SIZE + i * SUBBLOCK_SIZE:
                                                   c * CLUSTER_DATA_SIZE + (i + 1) * SUBBLOCK_SIZE]).digest()
                                  for i in range(SUBBLOCKS_PER_CLUSTER))
                         for c in range(CLUSTERS_PER_GROUP)]
            # H1: SHA-1 of each H0 block, collected per 8 clusters; H2: SHA-1 of each H1 block
            h1_blocks = [b"".join(hashlib.sha1(h0_blocks[s * CLUSTERS_PER_SUBGROUP + j]).digest()
                                  for j in range(CLUSTERS_PER_SUBGROUP))
                         for s in range(SUBGROUPS_PER_GROUP)]
            h2_block = b"".join(hashlib.sha1(h1_blocks[s]).digest() for s in range(SUBGROUPS_PER_GROUP))
            for c in range(CLUSTERS_PER_GROUP):
                hash_block = h0_blocks[c] + bytes(20) + h1_blocks[c // CLUSTERS_PER_SUBGROUP] + bytes(32) + h2_block + bytes(32)
                assert len(hash_block) == CLUSTER_HASH_SIZE
                encrypted_hashes = aes_cbc(hash_block, self.title_key, bytes(16), False)
                iv = encrypted_hashes[CLUSTER_IV_OFFSET:CLUSTER_IV_OFFSET + CLUSTER_IV_SIZE]
                encrypted_data = aes_cbc(bytes(buf[c * CLUSTER_DATA_SIZE:(c + 1) * CLUSTER_DATA_SIZE]), self.title_key, iv, False)
                f.seek(self.partition_offset + self.data_offset + (group * CLUSTERS_PER_GROUP + c) * CLUSTER_SIZE)
                f.write(encrypted_hashes + encrypted_data)
            h3[group * 20:(group + 1) * 20] = hashlib.sha1(h2_block).digest()
        f.seek(self.partition_offset + self.h3_offset)
        f.write(h3)
        f.seek(self.partition_offset + self.tmd_offset)
        tmd = bytearray(f.read(self.tmd_size))
        tmd[TMD_CONTENT0 + 0x10:TMD_CONTENT0 + 0x24] = hashlib.sha1(h3).digest()          # content 0 hash
        struct.pack_into(">Q", tmd, TMD_CONTENT0 + 0x8, self.data_size)                  # content 0 size
        tmd[4:TMD_SIGNATURE_END] = bytes(0x100)                                           # fake signature: all zero ...
        for n in range(1 << 32):                                                          # ... which needs a hash starting with 0
            struct.pack_into(">I", tmd, TMD_RESERVED_FIELD, n)
            if hashlib.sha1(tmd[TMD_BODY_START:]).digest()[0] == 0:
                break
        f.seek(self.partition_offset + self.tmd_offset)
        f.write(tmd)
        f.seek(self.partition_offset + HDR_DATA_SIZE)
        f.write(struct.pack(">I", self.data_size >> 2))
        self.dirty_groups = {}


def fst_files(fst: bytes) -> Dict[str, int]:
    """Read a disc's file table. Returns {full path of a file: its entry number} (names are Shift-JIS)."""
    entry_count = read_u32(fst, 8)
    names_start = entry_count * 12
    out = {}

    def name(k: int) -> str:
        o = names_start + (read_u32(fst, k * 12) & 0xFFFFFF)
        return fst[o:fst.index(b"\0", o)].decode("shift_jis")
    directory_ends = [(entry_count, "")]          # (index after the directory, its path)
    i = 1
    while i < entry_count:
        while directory_ends and i >= directory_ends[-1][0]:
            directory_ends.pop()
        prefix = directory_ends[-1][1] if directory_ends else ""
        if fst[i * 12] == 1:
            directory_ends.append((read_u32(fst, i * 12 + 8), prefix + name(i) + "/"))
            i += 1
            continue
        out[prefix + name(i)] = i
        i += 1
    return out


def original_files() -> Dict[str, str]:
    """{file name: path} of the untouched originals the build keeps (modules, picture bundles, main.dol)."""
    originals = {}
    for folder in (config.ORIG_DIR, config.ORIG_ARC_DIR, config.ORIG_SYS_DIR):
        for root, _, names in os.walk(folder):
            for filename in names:
                originals.setdefault(filename, os.path.join(root, filename))
    return originals


def append_changed_files(disc: Disc, fst: bytearray, files: Dict[str, int], position: int) -> Tuple[int, int]:
    """Append every file that differs from its kept original behind `position` and point its FST entry there.

    Arguments: the `disc`, the file table `fst` (changed in place), `files` from fst_files(), `position` the first
    free data offset. Returns (position after the last file, number of files moved)."""
    originals = original_files()
    moved = 0
    for path, entry in sorted(files.items()):
        installed = os.path.join(config.DATA_FILES, *path.split("/"))
        basename = path.split("/")[-1]
        if basename not in originals:
            continue
        with open(installed, "rb") as f:
            new = f.read()
        with open(originals[basename], "rb") as f:
            old = f.read()
        if new == old:
            continue
        old_size = read_u32(fst, entry * 12 + 8)
        assert old_size == len(old), (path, "the kept original differs from the disc")
        disc.write(position, new)
        struct.pack_into(">II", fst, entry * 12 + 4, position >> 2, len(new))
        position = (position + len(new) + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1)
        moved += 1
    return position, moved


def place_main_dol(disc: Disc, boot: bytes, position: int, dol_offset: int, fst_offset: int) -> int:
    """Write config.DOL_SOURCE (the English main.dol) if it differs from the disc's. It goes in place when it fits
    before the file table, else behind `position` with the boot block re-pointed. Returns the new free position."""
    with open(config.DOL_SOURCE, "rb") as f:
        dol = f.read()
    if disc.read(dol_offset, len(dol)) == dol:
        return position
    if dol_offset + len(dol) <= fst_offset:       # the DOL ends where its last section ends; space up to the FST is free
        disc.write(dol_offset, dol)
        return position
    disc.write(position, dol)
    boot_block = bytearray(boot)
    struct.pack_into(">I", boot_block, wii_format.DOL_OFFSET_FIELD, position >> 2)
    disc.write(0, bytes(boot_block))
    return (position + len(dol) + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1)


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 release ORIGINAL.iso OUT.iso [PATCH.xdelta]`. `argv` defaults to sys.argv[1:]."""
    parser = argparse.ArgumentParser(prog="pp15 release", description=__doc__.split("\n\n")[0])
    parser.add_argument("original", metavar="ORIGINAL.iso", help="the Japanese disc image (read only)")
    parser.add_argument("output", metavar="OUT.iso", help="the English disc image to write")
    parser.add_argument("patch", metavar="PATCH.xdelta", nargs="?", help="also write an xdelta patch ORIGINAL -> OUT")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    print("copying", args.original)
    shutil.copyfile(args.original, args.output)
    disc = Disc(args.output)
    boot = disc.read(0, wii_format.DISC_BOOT_BLOCK_SIZE)
    dol_offset = read_u32(boot, wii_format.DOL_OFFSET_FIELD) << 2
    fst_offset, fst_size = read_u32(boot, wii_format.FST_OFFSET_FIELD) << 2, read_u32(boot, wii_format.FST_SIZE_FIELD) << 2
    fst = bytearray(disc.read(fst_offset, fst_size))
    files = fst_files(fst)
    used = max([fst_offset + fst_size] + [(read_u32(fst, i * 12 + 4) << 2) + read_u32(fst, i * 12 + 8) for i in files.values()])
    position = (used + GROUP_DATA_SIZE - 1) // GROUP_DATA_SIZE * GROUP_DATA_SIZE      # new data from a group boundary
    position, moved = append_changed_files(disc, fst, files, position)
    position = place_main_dol(disc, boot, position, dol_offset, fst_offset)
    disc.write(fst_offset, bytes(fst))
    needed = (position + CLUSTER_DATA_SIZE - 1) // CLUSTER_DATA_SIZE * CLUSTER_SIZE
    if needed > disc.data_size:
        group_bytes = CLUSTERS_PER_GROUP * CLUSTER_SIZE
        disc.data_size = (needed + group_bytes - 1) // group_bytes * group_bytes
    disc_end = os.path.getsize(args.output)
    assert disc.partition_offset + disc.data_offset + disc.data_size <= disc_end, "no room on the disc image"
    print("%d files moved behind 0x%X, %d groups rewritten" % (moved, used, len(disc.dirty_groups)))
    disc.flush()
    disc.file.close()
    verify = subprocess.run([WIT, "verify", args.output], capture_output=True, text=True)
    print(verify.stdout.strip().splitlines()[-1] if verify.stdout.strip() else verify.stderr.strip())
    if args.patch:
        subprocess.run(["xdelta3", "-e", "-9", "-f", "-s", args.original, args.output, args.patch], check=True)
        print("patch %s: %.1f MB" % (args.patch, os.path.getsize(args.patch) / 1e6))


if __name__ == "__main__":
    main()
