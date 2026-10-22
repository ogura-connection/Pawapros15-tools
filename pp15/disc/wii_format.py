"""Sizes, offsets and keys of the Wii disc format that both disc tools (extract.py, xdelta.py) use.

What a Wii disc is, in simple words: the game is stored in a "partition" whose data is encrypted in clusters of 32 KB
(0x8000 bytes). Each cluster starts with 0x400 bytes of checksums ("hash block"), then 0x7C00 bytes of data. The data
of a cluster is encrypted with a title key that is itself stored, encrypted, in the partition's ticket; the ticket is
decrypted with the well-known Wii common key. 64 clusters (2 MB) form a "group" that shares a checksum tree.

Contents: the constants below and `read_u32`.
"""
import struct

# The Wii common key: the same on every console, published and used by all Wii homebrew tools. It decrypts the title key.
WII_COMMON_KEY = bytes.fromhex("ebe42a225e8593e448d9c5457381aaf7")

PARTITION_INFO_OFFSET = 0x40000          # where the table of partition groups starts on the disc
CLUSTER_SIZE = 0x8000                    # bytes of one encrypted cluster
CLUSTER_HASH_SIZE = 0x400                # bytes of its checksum block (not encrypted with the title key)
CLUSTER_DATA_SIZE = 0x7C00               # bytes of its game data (CLUSTER_SIZE - CLUSTER_HASH_SIZE)
CLUSTERS_PER_GROUP = 64                  # clusters that share one checksum tree
CLUSTER_IV_OFFSET = 0x3D0                # inside the hash block: the 16 bytes that start the data's encryption
CLUSTER_IV_SIZE = 16

TICKET_SIZE = 0x2A4                      # bytes of the ticket at the start of a partition
TICKET_ENCRYPTED_KEY_OFFSET = 0x1BF      # inside the ticket: the encrypted title key (16 bytes)
TICKET_TITLE_ID_OFFSET = 0x1DC           # inside the ticket: title id (8 bytes), the start of the key's decryption IV
PARTITION_DATA_OFFSET_FIELD = 0x2B8      # in the partition header: where the partition's data starts (in 4-byte units)

PARTITION_TYPE_DATA = 0                  # the partition that holds the game
DISC_BOOT_BLOCK_SIZE = 0x440             # disc.bin + boot info: holds the offsets of the main program and the file table
FST_OFFSET_FIELD, FST_SIZE_FIELD = 0x424, 0x428     # in that block: where the file table is and how big (4-byte units)
DOL_OFFSET_FIELD = 0x420                 # in that block: where the main program (main.dol) is


def read_u32(data: bytes, offset: int) -> int:
    """The big-endian 32-bit number at `offset`."""
    return struct.unpack_from(">I", data, offset)[0]
