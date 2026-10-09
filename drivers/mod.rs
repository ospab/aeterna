/*
 * AETERNA Storage Driver Subsystem
 *
 * Provides unified disk detection and I/O across:
 *   ata  — ATA PIO (IDE) — QEMU PIIX IDE, legacy hardware
 *   ahci — AHCI SATA    — QEMU ich9-ahci, VMware SATA, modern bare metal
 *   nvme — NVMe         — VMware default, QEMU -device nvme, bare metal (namespace 1)
 *   virtio_blk — virtio-blk (legacy + modern PCI) — QEMU/KVM/cloud
 *
 * Everything in DISKS is addressed in 512-byte sectors; 4K-native NVMe
 * namespaces are translated inside nvme.rs.
 *
 * Usage from terminal / installer:
 *   ospab_os::drivers::init()          — probe all storage
 *   ospab_os::drivers::disk_count()    — total drives found
 *   ospab_os::drivers::disk_info(n)    — DeviceInfo for drive n
 *   ospab_os::drivers::read(n, lba, count, buf) — read sectors
 */

pub mod ata;
pub mod ahci;
pub mod audio;
pub mod gpu;
pub mod nvme;
pub mod virtio_blk;
pub mod gpt;
pub mod block;
pub mod driver_trait;
pub mod registry;

/// Unified disk info for terminal/installer
#[derive(Copy, Clone)]
pub struct DiskInfo {
    pub index:   usize,
    pub kind:    DiskKind,
    pub size_mb: u64,
    pub sectors: u64,
    pub model:   [u8; 41],
}

#[derive(Copy, Clone, PartialEq)]
pub enum DiskKind {
    Ata,
    Ahci,
    Nvme,
    Virtio,
}

static mut DISKS: [DiskInfo; 8] = [DiskInfo {
    index: 0,
    kind: DiskKind::Ata,
    size_mb: 0,
    sectors: 0,
    model: [0u8; 41],
}; 8];
static mut DISK_COUNT: usize = 0;

/// Initialize all storage — call once during boot
pub fn init() -> usize {
    unsafe { DISK_COUNT = 0; }

    // ATA PIO (primary and secondary IDE)
    let ata_count = ata::init();
    for i in 0..ata_count {
        if let Some(d) = ata::drive_info(i) {
            let idx = unsafe { DISK_COUNT };
            if idx >= 8 { break; }
            unsafe {
                DISKS[idx].index   = idx;
                DISKS[idx].kind    = DiskKind::Ata;
                DISKS[idx].size_mb = d.size_mb as u64;
                DISKS[idx].sectors = d.sectors as u64;
                DISKS[idx].model   = d.model;
                DISK_COUNT += 1;
            }
        }
    }

    // AHCI SATA
    let ahci_count = ahci::init();
    for i in 0..ahci_count {
        if let Some(d) = ahci::drive_info(i) {
            let idx = unsafe { DISK_COUNT };
            if idx >= 8 { break; }
            unsafe {
                DISKS[idx].index   = idx;
                DISKS[idx].kind    = DiskKind::Ahci;
                DISKS[idx].size_mb = d.size_mb;
                DISKS[idx].sectors = d.sectors;
                DISKS[idx].model   = d.model;
                DISK_COUNT += 1;
            }
        }
    }

    // NVMe (first controller, namespace 1)
    if registry::try_init_driver("NVMe SSD", || nvme::probe_and_init()) && nvme::is_initialized() {
        let idx = unsafe { DISK_COUNT };
        if idx < 8 {
            let sectors = nvme::sectors512();
            unsafe {
                DISKS[idx].index   = idx;
                DISKS[idx].kind    = DiskKind::Nvme;
                DISKS[idx].size_mb = sectors >> 11;
                DISKS[idx].sectors = sectors;
                DISKS[idx].model   = *nvme::model();
                DISK_COUNT += 1;
            }
        }
    }

    // virtio-blk (any number, legacy or modern transport)
    let vcount = virtio_blk::init();
    for i in 0..vcount {
        if let Some(v) = virtio_blk::drive_info(i) {
            let idx = unsafe { DISK_COUNT };
            if idx >= 8 { break; }
            unsafe {
                DISKS[idx].index   = idx;
                DISKS[idx].kind    = DiskKind::Virtio;
                DISKS[idx].size_mb = v.size_mb;
                DISKS[idx].sectors = v.sectors;
                DISKS[idx].model   = v.model;
                DISK_COUNT += 1;
            }
        }
    }

    unsafe { DISK_COUNT }
}

/// Index of `disk` among disks of its own kind (the n in sdn / vdn / hdn).
pub fn kind_index(disk: usize) -> usize {
    match disk_info(disk) {
        Some(d) => disk_info_count_before(disk, d.kind),
        None => 0,
    }
}

pub fn disk_count() -> usize {
    unsafe { DISK_COUNT }
}

pub fn disk_info(n: usize) -> Option<&'static DiskInfo> {
    unsafe {
        if n < DISK_COUNT { Some(&DISKS[n]) } else { None }
    }
}

/// Count disks of a given kind that appear before index `i` in the list
pub fn disk_info_count_before(idx: usize, kind: DiskKind) -> usize {
    unsafe {
        DISKS[..idx].iter().filter(|d| d.kind == kind).count()
    }
}

/// Read sectors from disk n (unified, handles ATA or AHCI).
/// ATA: batched in 128-sector chunks to stay within u8 limit.
pub fn read(disk: usize, lba: u64, count: u32, buf: &mut [u8]) -> bool {
    let d = match disk_info(disk) { Some(d) => *d, None => return false };
    if buf.len() < count as usize * 512 { return false; }
    match d.kind {
        DiskKind::Ata => {
            let ata_idx = unsafe {
                DISKS[..disk].iter().filter(|d| d.kind == DiskKind::Ata).count()
            };
            const BATCH: u32 = 128;
            let mut done = 0u32;
            while done < count {
                let batch = (count - done).min(BATCH) as u8;
                let off = done as usize * 512;
                let end = off + batch as usize * 512;
                if !ata::read_sectors(ata_idx, (lba + done as u64) as u32, batch, &mut buf[off..end]) {
                    return false;
                }
                done += batch as u32;
            }
            true
        }
        DiskKind::Ahci => {
            let ahci_idx = unsafe {
                DISKS[..disk].iter().filter(|d| d.kind == DiskKind::Ahci).count()
            };
            ahci::read_sectors(ahci_idx, lba, count, buf)
        }
        DiskKind::Nvme => nvme::read512(lba, count, buf),
        DiskKind::Virtio => virtio_blk::read_sectors(kind_index(disk), lba, count, buf),
    }
}

/// Write sectors to disk n.
/// ATA: batched in 128-sector chunks to stay within u8 limit.
pub fn write(disk: usize, lba: u64, count: u32, data: &[u8]) -> bool {
    let d = match disk_info(disk) { Some(d) => *d, None => return false };
    if data.len() < count as usize * 512 { return false; }
    match d.kind {
        DiskKind::Ata => {
            let ata_idx = unsafe {
                DISKS[..disk].iter().filter(|d| d.kind == DiskKind::Ata).count()
            };
            const BATCH: u32 = 128;
            let mut done = 0u32;
            while done < count {
                let batch = (count - done).min(BATCH) as u8;
                let off = done as usize * 512;
                let end = off + batch as usize * 512;
                if !ata::write_sectors(ata_idx, (lba + done as u64) as u32, batch, &data[off..end]) {
                    return false;
                }
                done += batch as u32;
            }
            true
        }
        DiskKind::Ahci => {
            let ahci_idx = unsafe {
                DISKS[..disk].iter().filter(|d| d.kind == DiskKind::Ahci).count()
            };
            ahci::write_sectors(ahci_idx, lba, count, data)
        }
        DiskKind::Nvme => nvme::write512(lba, count, data),
        DiskKind::Virtio => virtio_blk::write_sectors(kind_index(disk), lba, count, data),
    }
}

/// Flush the device write cache of disk n (no-op for ATA/AHCI, which this
/// driver set already drives write-through).
pub fn flush(disk: usize) -> bool {
    match disk_info(disk) {
        Some(d) => match d.kind {
            DiskKind::Nvme => nvme::flush(),
            DiskKind::Virtio => virtio_blk::flush(kind_index(disk)),
            _ => true,
        },
        None => false,
    }
}

/// Short bus label for listings (lsblk / installer)
pub fn bus_label(kind: DiskKind) -> &'static str {
    match kind {
        DiskKind::Ata => "IDE",
        DiskKind::Ahci => "SATA",
        DiskKind::Nvme => "NVMe",
        DiskKind::Virtio => "virtio",
    }
}

/// Get friendly device name for a disk index (sda, sdb, hda...)
pub fn dev_name_for_index(idx: usize) -> &'static str {
    if let Some(d) = disk_info(idx) {
        let before = disk_info_count_before(d.index, d.kind);
        match d.kind {
            DiskKind::Ahci => match before { 0 => "sda", 1 => "sdb", 2 => "sdc", _ => "sdX" },
            DiskKind::Ata  => match before { 0 => "hda", 1 => "hdb", 2 => "hdc", _ => "hdX" },
            DiskKind::Nvme => "nvme0n1",
            DiskKind::Virtio => match before { 0 => "vda", 1 => "vdb", 2 => "vdc", 3 => "vdd", _ => "vdX" },
        }
    } else {
        "unknown"
    }
}

/// Get model name as &str
pub fn model_str(info: &DiskInfo) -> &str {
    let end = info.model.iter().position(|&b| b == 0).unwrap_or(40);
    unsafe { core::str::from_utf8_unchecked(&info.model[..end]) }
}
