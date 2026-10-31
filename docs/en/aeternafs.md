# AeternaFS v2

AeternaFS v2 is the native filesystem of ospab.os. It is a copy-on-write
filesystem with checksums on all metadata and data, atomic commits and cheap
snapshots. It replaces the old toy `vfs/aeternafs.rs` and the periodic dump of
the RAM filesystem in `vfs/disk_sync.rs`.

Status: stage 1. The crate `fs/aeternafs` (no_std + alloc) and the host tool
`tools/oosfs` exist and are tested on the host. The kernel does not use them yet.

## Goals

- Consistent after power loss without a journal and without fsck.
- Every block read from disk is verified. A damaged block gives an error, never
  wrong data.
- File data starts on 4 KiB boundaries in whole pages, so a file page can later
  be mapped into a process without copying (zero-copy).
- Snapshots of the whole filesystem for system update rollback.
- Directories with 100 000 and more entries.

## Layout

The device is an array of 4096-byte blocks. All integers are little-endian.
Every metadata block starts with a CRC-32C (Castagnoli) of the remaining 4092
bytes.

| Blocks   | Content                                                       |
|----------|---------------------------------------------------------------|
| 0 and 1  | Superblock slots. Slot = generation mod 2.                    |
| 2 .. end | Tree nodes, free-space pages and file data, allocated freely. |

### Superblock

| Offset | Size | Field                                              |
|--------|------|----------------------------------------------------|
| 0      | 4    | CRC-32C of bytes 4..4096                           |
| 4      | 8    | Magic `AETERNA2`                                   |
| 12     | 4    | Version (1)                                        |
| 16     | 4    | Block size (4096)                                  |
| 20     | 8    | Generation                                         |
| 28     | 8    | Block count of the filesystem                      |
| 36     | 8    | Root block of the main tree                        |
| 44     | 8    | First free-space page (0 = none)                   |
| 52     | 4    | Number of free-space pages                         |
| 56     | 8    | `last_snap_gen`: newest generation held by a snapshot |
| 64     | 8    | Next inode number                                  |
| 72     | 8    | Next snapshot id                                   |
| 80     | 8    | Hash seed for directory names                      |
| 88     | 8    | Creation time (ns since the ospab epoch)           |
| 96     | 1+63 | Label length and label (UTF-8)                     |

Mount reads both slots and uses the valid one with the higher generation.
If the newer slot is damaged, the older one is used. It is a complete,
consistent older state (see Commit).

### Main tree

One copy-on-write B+tree holds everything. Key (17 bytes), ordered by
`obj`, then `kind`, then `off`:

| Field | Size | Meaning                                  |
|-------|------|------------------------------------------|
| obj   | 8    | inode number (0 for snapshot items)      |
| kind  | 1    | 1 snapshot, 2 inode, 3 dir, 4 extent, 5 symlink |
| off   | 8    | kind-specific                            |

Node block (leaf or internal):

| Offset | Size | Field                                           |
|--------|------|-------------------------------------------------|
| 0      | 4    | CRC-32C                                         |
| 4      | 2    | Magic `0x4E41`                                  |
| 6      | 1    | 1 leaf, 2 internal                              |
| 8      | 4    | Item count                                      |
| 12     | 8    | Generation of the transaction that wrote it     |
| 20     | 8    | Own block number (detects misdirected writes)   |
| 32     | ...  | Items                                           |

Leaf item: key, `u16` value length, value (at most 1000 bytes). Internal item:
key (lowest key of the child), `u64` child block. A child never has a newer
generation than its parent. The reader rejects anything else, so a damaged
pointer cannot form a cycle.

Item kinds:

- Inode (`off` = 0), 56 bytes: mode `u32` (type bits and permissions), flags
  `u32`, size `u64`, parent directory `u64`, atime, mtime, ctime, crtime as
  `i64` nanoseconds since 2012-08-09 00:00 UTC. A directory's size is its
  entry count.
- Directory entries (`off` = 64-bit hash of the name, seeded with the
  superblock seed). The value is a list of `ino u64, type u8, name_len u8,
  name`. Names are 1 to 255 bytes of UTF-8 without `/` and NUL. Names with
  equal hashes share one item, so collisions are handled by comparing names.
  Lookup is one tree search.
- Extent (`off` = first file page): `start u64, pages u32, gen u64`, then one
  CRC-32C per page. An extent covers at most 240 pages. `gen` is the
  generation that wrote the blocks. Pages without an extent read as zeros
  (sparse files).
- Symlink target (`off` = 0): the target bytes.
- Snapshot (`obj` = 0, `off` = id): `root u64, gen u64, time i64, name_len u8,
  name`.

Data pages are written straight to their blocks, not through the node cache.
Each page has its own checksum in the extent item, so reads verify data too.

### Free space

The allocator keeps free extents in memory. On disk they are stored as a chain
of pages (`0x4641`, CRC-32C, generation, own block, next page, up to 253
`start, length` pairs). The chain is rewritten to new blocks at every commit.
The list on disk also contains the blocks freed in the transaction being
committed, because after the commit they are free.

Blocks are freed as follows:

- A block born in the current transaction is not reachable from disk. It is
  free at once.
- A block born earlier is put on a pending list. It becomes allocatable after
  the superblock of the transaction is durable, because the previous root may
  still point to it.
- A block with generation <= `last_snap_gen` may belong to a snapshot. It is
  not freed. Deleting or rolling back a snapshot runs a sweep: it marks
  every block reachable from the live tree and all remaining snapshots, and
  everything else becomes pending.

The last 64 free blocks are kept for metadata. File data gets `NoSpace` first.

## Commit

All changes of a transaction go to free blocks. Nothing reachable from the
current superblock is overwritten. `commit` does:

1. Write the new free-space chain.
2. Write all dirty tree nodes.
3. Flush the device.
4. Write the new superblock into the slot `generation mod 2`.
5. Flush the device.
6. Pending blocks become free.

If power fails before step 4 completes, the old superblock still describes a
complete tree. If the superblock write is torn, its checksum fails and the old
slot is used. Because of the flush in step 3, the superblock can never be
durable before the blocks it points to. No journal, no repair step.

Operations (`create`, `write`, `rename`, ...) change memory and free blocks
only. They become durable at `commit`. A rename is atomic because the old and
new entry change in one transaction.

## Snapshots

`snapshot_create(name)` commits, then stores the committed root, its generation
and the time in a snapshot item. It copies no data. Later changes copy only the
nodes and pages they touch, because blocks of generation <= `last_snap_gen` are
never overwritten or freed in place.

- `snapshot_list`, `snapshot_view(name)` (read-only access by path),
- `snapshot_delete(name)` reclaims exclusive blocks with a sweep,
- `snapshot_rollback(name)` makes the snapshot the live tree. Changes made
  after it are discarded. All snapshots stay. Create a snapshot first if the
  current state may be needed.

Create, delete and rollback are atomic commits.

## API

`Fs<D: BlockDevice>`: `mkfs(dev, label, now)`, `mount(dev)`, `commit`,
`statfs`, `fsck(deep)`, `set_time`. Inode level: `lookup`, `create`, `mkdir`,
`symlink`, `read`, `write`, `truncate`, `unlink`, `rmdir`, `rename`,
`readdir`, `stat`, `readlink`, `set_mode`, `set_times`. Path helpers:
`resolve`, `split_parent`, `write_file`, `read_file`, `mkdir_path`, ...

`BlockDevice` has `block_count`, `read_blocks`, `write_blocks` and `flush`.
`write_blocks` may be cached by the device until `flush` returns. The `std`
feature adds `MemDevice`, `FileDevice` (a file or a region of a file) and
`FaultDevice` (power-loss simulation for tests).

Limits and simplifications:

- Paths are absolute, `..` is not supported, symlinks are stored but not
  followed by `resolve`. No hard links. One writer.
- Deleting entries does not merge under-full tree nodes. Empty nodes are
  removed.
- The free-space chain is rewritten as a whole at each commit.
- No users or groups: rights belong to the capability model of the kernel, not
  to the filesystem. Mode bits are stored for tools.

## Tests

`cargo +stable-x86_64-pc-windows-gnu test --release` in `fs/aeternafs`, run
from a directory outside the repository (the repository `.cargo/config.toml`
selects the OS target):

- `model`: random operations compared with an in-memory model, snapshots and
  rollbacks, many entries in one directory, space accounting, `NoSpace`.
- `crash`: for every block write of a workload the power is cut right after
  it. Unflushed writes are dropped, kept in random order, or torn. The mounted
  result must equal the last committed state or the state being committed, and
  `fsck` must pass.
- `corrupt`: random bit flips in used blocks and superblocks. Mount or read
  must fail or return the original data.
- `perf` (ignored by default): 100 000 small files and a 1 GiB file.

## Tool `oosfs`

```
oosfs mkfs <image> --size 2G [--label L]
oosfs ls|cat|get|put|rm|mkdir|mv|stat|info <image> ...
oosfs put <image> <src> <dest> [-r]
oosfs snap create|list|delete|rollback <image> [name]
oosfs fsck <image> [--deep]
```

Add `--offset <bytes>` or `--part N` (GPT, 512-byte sectors) to work on a
partition inside a disk image. `fsck --deep` also reads every data page.

Build: `cargo +stable-x86_64-pc-windows-gnu build --release` in `tools/oosfs`.
