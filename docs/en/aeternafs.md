# AeternaFS v2

AeternaFS v2 is the native filesystem of ospab.os. It is a copy-on-write
filesystem with checksums on all metadata and data, atomic commits and cheap
snapshots. It replaces the old toy filesystem and the periodic dump of the RAM
filesystem to the `AETERNA` partition.

Status: stage 2. The crate `fs/aeternafs` (no_std + alloc) and the host tool
`tools/oosfs` are tested on the host. The kernel uses the crate as the
persistent layer of `/` (see Kernel integration).

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

## Kernel integration

Files: `vfs/aeternafs.rs` (block device and VFS adapter), `vfs/persist.rs`
(boot, migration, commit thread), `vfs/disk_sync.rs` (where the volume lives,
reader of the old snapshot, entry points of `sync`).

**Block device.** `KDisk` maps 4096-byte blocks to 512-byte sectors of a disk
(`drivers::read/write`). The NVMe driver translates 4K-native namespaces. Flush
is the driver's cache flush: NVMe Flush, virtio FLUSH, ATA FLUSH CACHE (EXT)
through AHCI. The PIO ATA driver flushes after every write command. The commit
protocol flushes twice, so no write barrier flag (FUA) is needed.

**Layout of the `AETERNA` partition** (or of a raw disk from LBA 2048):

| Sectors (512 bytes)              | Content                                   |
|----------------------------------|-------------------------------------------|
| partition start .. +8            | identity record written by the installer  |
| +8 .. +8+16384                   | old RAM snapshot (8 MiB), read once       |
| +8+16384 .. partition end        | AeternaFS v2 volume                       |

**VFS adapter.** `AeFs` implements `FileSystem` over the crate. Every call
takes one mutex (the single writer) and sets the time of new inodes from the
system clock. `write_file`, `write_at`, `append_file`, `touch`, `mkdir` and
`rename` create missing parent directories, like the RamFS. The writable layer
of the root overlay (`vfs/cow.rs`) forwards to a `SwitchFs`. It points to the
RamFS until `vfs/persist.rs` finds a volume and switches it to `AeFs`. Without a
disk (live ISO) nothing changes.

**Commit policy.** Operations change memory and free blocks only. A commit makes
them durable and atomic.

- `fs-commit`, a kernel thread, runs once per second. It commits 3 s after the
  last change and at the latest 15 s after the first uncommitted change. It does
  not depend on the shell, so it also runs while a full-screen program or a long
  command owns the console. The shell idle loop calls the same function.
- `sync` (and `save`) commit at once.
- `reboot`, `shutdown` and the power button commit first (`acpi::reboot`,
  `acpi::shutdown`). The power-button path cannot wait for a lock, so it
  commits only if the volume is free.
- The installer and `persist=ro` set the volume read-only: nothing is committed.

After power loss the volume mounts at the last commit. Changes after it are lost.

**Boot** (`Persistence:` line of the boot log):

| Found on disk                        | Action                                              |
|--------------------------------------|-----------------------------------------------------|
| old RAM snapshot (and parsable)      | migrate (below)                                     |
| AeternaFS v2 superblock              | mount                                               |
| nothing                              | format a new volume                                 |

A new volume is created only inside an `AETERNA` partition. A disk without one
(an empty disk you are about to install onto, another system's disk) is used only
if it already holds a volume or an old snapshot, and is never formatted. A volume that is present but
does not mount (checksum, version) is never formatted: persistence stays off for
that boot and the log line says why.

**Migration of the old snapshot.** The snapshot is read completely into memory
and parsed. A new volume is formatted after the snapshot area, so the snapshot
is not touched. All directories and files are imported and committed, then
`fsck` runs. Only then the snapshot's magic sector is overwritten with zeros
and flushed. Power loss at any point leaves one usable copy: before the clear,
the next boot migrates again. A snapshot that is present always wins over a
volume, so a reinstall that writes a fresh snapshot over a partition with an
older volume is handled the same way.

**Shell.**

- `df`: rows for the volume (size, used, available) and for disks without a
  volume.
- `mount` without arguments lists the volumes. `mount <device> <dir>` mounts
  another v2 volume (`/dev/sdaN`, `/dev/vdaN`, `/dev/nvme0n1pN`).
- `mkfs <device> [label]` formats a partition with a v2 volume (not the one that
  holds `/`).
- `fsck [--deep]` commits, then checks the volume of `/` with the crate's
  `fsck`. `--deep` reads every data page.
- `snap create|list|delete <name>` manage snapshots of the volume of `/`.
  Update integration (snapshot before an update, rollback) is not done yet.

**For the installer.** To create the volume at install time instead of the old
snapshot: take `disk_sync::area(disk)` (`v2_lba`, `v2_sectors`), call
`fs::aeternafs::mkfs(disk, v2_lba, v2_sectors, "AETERNA")`, mount it with
`mount_raw` and `AeFs::register`, write the files, then `commit(true)`. Zero the
sector at `legacy_lba` so that no old snapshot wins at the first boot.

Known limits: one volume is the persistent layer, the layer is chosen by
`select_disk` (first AHCI disk, else disk 0). Writing a very large file holds
the volume mutex for its whole duration. File data is not cached in memory.

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
oosfs shell <image>                       interactive: cd, ls, cat, get, put, rm, mv, fsck
```

Add `--offset <bytes>` or `--part N` (GPT or MBR, 512-byte sectors) to work on a
partition inside a disk image. In the `AETERNA` partition of an installed system the volume
sits after the old snapshot area; `--part` finds it. `fsck --deep` also reads every data page.
`-v` shows the region and the first blocks read.

The image can be a raw file or a VMware disk: a `.vmdk` descriptor with split or flat extents,
or a single-file sparse `.vmdk`. Reading and writing both work; new grains are added at the end
of the extent file and recorded in both grain tables. Power the VM off first: a disk with a
`.vmdk.lck` lock directory is refused (`--force` skips the check). Compressed
(stream-optimized) VMDKs from OVA exports are not supported. To put files into an installed
system in VMware:

```
oosfs put "C:\VMs\ospab\ospab.vmdk" --part 2 os12.rom /usr/share/beeb/os12.rom
oosfs put "C:\VMs\ospab\ospab.vmdk" --part 2 games /home/me/games -r
```

Build: `cargo +stable-x86_64-pc-windows-gnu build --release --target x86_64-pc-windows-gnu` in
`tools/oosfs` (the explicit target overrides the kernel target of the repository's
`.cargo/config.toml`).
