/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Reading files from the boot medium.

Two kinds of volume:
- FAT (or anything the firmware exposes as SimpleFileSystem): a GPT disk image,
  an installed ESP.
- ISO9660 read directly over BlockIo: when Limine chainloads us from the hybrid
  ISO, the firmware only exposes the El Torito FAT image as a file system, while
  the kernel lives in the ISO9660 tree. Primary volume descriptor → root
  directory → path lookup; names compare case-insensitively with ";1" dropped.

Paths are written with '/' (like limine.conf) and start at the volume root.
*/
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;

use crate::console::{alloc_pages, bs, PAGE};
use crate::efi::*;

pub enum Volume {
    Fat(*mut File, Handle),
    Iso(Iso),
}

/// A file loaded into page-aligned memory (physical = virtual under UEFI).
#[derive(Clone, Copy)]
pub struct Loaded {
    pub addr: u64,
    pub size: u64,
}

impl Volume {
    pub fn kind(&self) -> &'static str {
        match self {
            Volume::Fat(..) => "FAT",
            Volume::Iso(_) => "ISO9660",
        }
    }

    pub fn exists(&mut self, path: &str) -> bool {
        match self {
            Volume::Fat(root, _) => match fat_open(*root, path) {
                Some(f) => {
                    unsafe { ((*f).close)(f) };
                    true
                }
                None => false,
            },
            Volume::Iso(iso) => iso.lookup(path).is_some(),
        }
    }

    /// Read a whole file into fresh pages of `mem_type`.
    pub fn load(&mut self, path: &str, mem_type: u32) -> Option<Loaded> {
        match self {
            Volume::Fat(root, _) => fat_load(*root, path, mem_type),
            Volume::Iso(iso) => {
                let (lba, size) = iso.lookup(path)?;
                let pages = ((size as u64 + PAGE - 1) / PAGE).max(1) as usize;
                let addr = alloc_pages(pages, mem_type);
                let buf = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size as usize) };
                iso.read(lba as u64 * 2048, buf)?;
                Some(Loaded { addr, size: size as u64 })
            }
        }
    }

    /// Small files (config): into the pool.
    pub fn read_small(&mut self, path: &str) -> Option<Vec<u8>> {
        let f = self.load(path, OSPAB_RECLAIM_MEMORY)?;
        let data = unsafe { core::slice::from_raw_parts(f.addr as *const u8, f.size as usize) };
        let v = data.to_vec();
        let pages = ((f.size + PAGE - 1) / PAGE).max(1) as usize;
        unsafe { (bs().free_pages)(f.addr, pages) };
        Some(v)
    }
}

/// Find the volume holding any of `probes` (config or kernel): the device we were loaded from
/// first, then every file system, then every block device with ISO9660 on it.
pub fn find_volume(image: Handle, probes: &[&str]) -> Option<Volume> {
    let device = unsafe {
        let mut li: *mut c_void = ptr::null_mut();
        if is_error((bs().handle_protocol)(image, &LOADED_IMAGE_GUID, &mut li)) {
            ptr::null_mut()
        } else {
            (*(li as *mut LoadedImage)).device_handle
        }
    };

    let mut candidates: Vec<Handle> = Vec::new();
    if !device.is_null() {
        candidates.push(device);
    }
    candidates.extend(handles(&SIMPLE_FS_GUID));
    candidates.extend(handles(&BLOCK_IO_GUID));

    for &h in &candidates {
        if let Some(mut v) = open_fat(h) {
            if probes.iter().any(|p| v.exists(p)) {
                return Some(v);
            }
        }
        if let Some(mut v) = open_iso(h) {
            if probes.iter().any(|p| v.exists(p)) {
                return Some(v);
            }
        }
    }
    None
}

/// Handle of the FAT volume (if it is one), for building device paths.
impl Volume {
    pub fn fat_handle(&self) -> Option<Handle> {
        match self {
            Volume::Fat(_, h) => Some(*h),
            Volume::Iso(_) => None,
        }
    }
}

/// Directory of the running loader image, e.g. "/EFI/OSPAB" (from LoadedImage.FilePath).
pub fn loader_dir(image: Handle) -> Option<alloc::string::String> {
    use alloc::string::String;
    unsafe {
        let mut li: *mut c_void = ptr::null_mut();
        if is_error((bs().handle_protocol)(image, &LOADED_IMAGE_GUID, &mut li)) {
            return None;
        }
        let mut node = (*(li as *mut LoadedImage)).file_path as *const u8;
        if node.is_null() {
            return None;
        }
        let mut name: Option<String> = None;
        for _ in 0..64 {
            let (typ, sub) = (*node, *node.add(1));
            let len = u16::from_le_bytes([*node.add(2), *node.add(3)]) as usize;
            if typ == 0x7F || len < 4 {
                break;
            }
            if typ == 4 && sub == 4 {
                let units = (len - 4) / 2;
                let mut s = String::new();
                for i in 0..units {
                    let c = u16::from_le_bytes([*node.add(4 + 2 * i), *node.add(5 + 2 * i)]);
                    if c == 0 {
                        break;
                    }
                    s.push(if c == 0x5C { '/' } else { char::from_u32(c as u32).unwrap_or('?') });
                }
                name = Some(s);
            }
            node = node.add(len);
        }
        let name = name?;
        let cut = name.rfind('/')?;
        Some(String::from(&name[..cut]))
    }
}

/// First FAT volume (the one holding `prefer` first) that contains `path`; returns its handle.
pub fn find_fat_file(prefer: Option<Handle>, path: &str) -> Option<Handle> {
    let mut hs: Vec<Handle> = Vec::new();
    if let Some(h) = prefer {
        hs.push(h);
    }
    hs.extend(handles(&SIMPLE_FS_GUID));
    for h in hs {
        if let Some(mut v) = open_fat(h) {
            if v.exists(path) {
                return Some(h);
            }
        }
    }
    None
}

fn handles(guid: &Guid) -> Vec<Handle> {
    unsafe {
        let mut count = 0usize;
        let mut buf: *mut Handle = ptr::null_mut();
        if is_error((bs().locate_handle_buffer)(BY_PROTOCOL, guid, ptr::null_mut(), &mut count, &mut buf)) {
            return Vec::new();
        }
        let v = core::slice::from_raw_parts(buf, count).to_vec();
        (bs().free_pool)(buf as *mut u8);
        v
    }
}

// ─── SimpleFileSystem ───────────────────────────────────────────────────────

fn open_fat(h: Handle) -> Option<Volume> {
    unsafe {
        let mut sfs: *mut c_void = ptr::null_mut();
        if is_error((bs().handle_protocol)(h, &SIMPLE_FS_GUID, &mut sfs)) {
            return None;
        }
        let sfs = sfs as *mut SimpleFileSystem;
        let mut root: *mut File = ptr::null_mut();
        if is_error(((*sfs).open_volume)(sfs, &mut root)) {
            return None;
        }
        Some(Volume::Fat(root, h))
    }
}

fn fat_open(root: *mut File, path: &str) -> Option<*mut File> {
    let mut name: Vec<u16> = path
        .trim_start_matches('/')
        .chars()
        .map(|c| if c == '/' { b'\\' as u16 } else { c as u16 })
        .collect();
    name.push(0);
    unsafe {
        let mut f: *mut File = ptr::null_mut();
        if is_error(((*root).open)(root, &mut f, name.as_ptr(), FILE_MODE_READ, 0)) {
            return None;
        }
        Some(f)
    }
}

fn fat_load(root: *mut File, path: &str, mem_type: u32) -> Option<Loaded> {
    let f = fat_open(root, path)?;
    unsafe {
        let mut size = 0u64;
        ((*f).set_position)(f, u64::MAX);
        ((*f).get_position)(f, &mut size);
        ((*f).set_position)(f, 0);
        let pages = ((size + PAGE - 1) / PAGE).max(1) as usize;
        let addr = alloc_pages(pages, mem_type);
        let mut done = 0u64;
        while done < size {
            let mut n = (size - done) as usize;
            if is_error(((*f).read)(f, &mut n, (addr + done) as *mut u8)) || n == 0 {
                ((*f).close)(f);
                return None;
            }
            done += n as u64;
        }
        ((*f).close)(f);
        Some(Loaded { addr, size })
    }
}

// ─── ISO9660 over BlockIo ───────────────────────────────────────────────────

const BOUNCE_SIZE: usize = 256 * 1024;

pub struct Iso {
    bio: *mut BlockIo,
    media_id: u32,
    block_size: u64,
    bounce: *mut u8,
    root_lba: u32,
    root_len: u32,
}

fn open_iso(h: Handle) -> Option<Volume> {
    unsafe {
        let mut bio: *mut c_void = ptr::null_mut();
        if is_error((bs().handle_protocol)(h, &BLOCK_IO_GUID, &mut bio)) {
            return None;
        }
        let bio = bio as *mut BlockIo;
        let media = &*(*bio).media;
        if media.media_present == 0 || media.block_size == 0 || media.block_size > 4096 {
            return None;
        }
        let mut iso = Iso {
            bio,
            media_id: media.media_id,
            block_size: media.block_size as u64,
            bounce: ptr::null_mut(),
            root_lba: 0,
            root_len: 0,
        };
        let mut pvd = [0u8; 2048];
        // Bounce buffer only after the cheap checks pass (handles are many).
        iso.bounce = alloc_pages(BOUNCE_SIZE / PAGE as usize, LOADER_DATA) as *mut u8;
        if iso.read(16 * 2048, &mut pvd).is_none() || pvd[0] != 1 || &pvd[1..6] != b"CD001" {
            (bs().free_pages)(iso.bounce as u64, BOUNCE_SIZE / PAGE as usize);
            return None;
        }
        iso.root_lba = u32::from_le_bytes([pvd[158], pvd[159], pvd[160], pvd[161]]);
        iso.root_len = u32::from_le_bytes([pvd[166], pvd[167], pvd[168], pvd[169]]);
        Some(Volume::Iso(iso))
    }
}

impl Iso {
    /// Read `buf.len()` bytes starting at byte `offset` of the device.
    fn read(&mut self, mut offset: u64, buf: &mut [u8]) -> Option<()> {
        let bs_ = self.block_size;
        let mut done = 0usize;
        while done < buf.len() {
            let lba = offset / bs_;
            let within = (offset % bs_) as usize;
            let want = (buf.len() - done).min(BOUNCE_SIZE - within);
            let bytes = ((within + want) as u64 + bs_ - 1) / bs_ * bs_;
            let s = unsafe {
                ((*self.bio).read_blocks)(self.bio, self.media_id, lba, bytes as usize, self.bounce)
            };
            if is_error(s) {
                return None;
            }
            unsafe {
                ptr::copy_nonoverlapping(self.bounce.add(within), buf.as_mut_ptr().add(done), want);
            }
            done += want;
            offset += want as u64;
        }
        Some(())
    }

    /// Returns (extent LBA, size) of a file.
    fn lookup(&mut self, path: &str) -> Option<(u32, u32)> {
        let (mut lba, mut len) = (self.root_lba, self.root_len);
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        for (i, part) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            let mut dir = vec![0u8; len as usize];
            self.read(lba as u64 * 2048, &mut dir)?;
            let (l, n, is_dir) = find_entry(&dir, part)?;
            if is_dir == last {
                return None; // a file where a directory was expected or vice versa
            }
            lba = l;
            len = n;
        }
        Some((lba, len))
    }
}

fn find_entry(dir: &[u8], want: &str) -> Option<(u32, u32, bool)> {
    let mut off = 0usize;
    while off < dir.len() {
        let rec_len = dir[off] as usize;
        if rec_len == 0 {
            off = (off / 2048 + 1) * 2048; // records never cross a sector
            continue;
        }
        if off + rec_len > dir.len() || rec_len < 34 {
            break;
        }
        let rec = &dir[off..off + rec_len];
        let name_len = rec[32] as usize;
        if 33 + name_len <= rec.len() {
            let mut name = &rec[33..33 + name_len];
            if let Some(p) = name.iter().position(|&c| c == b';') {
                name = &name[..p];
            }
            if name.last() == Some(&b'.') {
                name = &name[..name.len() - 1];
            }
            if name.eq_ignore_ascii_case(want.as_bytes()) {
                let lba = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]);
                let size = u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]);
                return Some((lba, size, rec[25] & 2 != 0));
            }
        }
        off += rec_len;
    }
    None
}
