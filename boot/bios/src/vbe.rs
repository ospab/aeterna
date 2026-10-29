/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
VBE 2.0 linear framebuffer for the kernel.

Lists the 32-bit direct-colour modes, takes the monitor's native size from EDID (VBE
function 4F15h) and lets boot/common/modesel.rs pick the mode for the config `resolution`
(WxH, hd/fullhd/2k/4k, max, auto). When nothing fits, 1024x768x32 is tried. The mode is
set right before the hand-off; the menu itself runs in VGA text mode.
*/
use alloc::vec::Vec;
use core::ptr;

use crate::config::Resolution;
use crate::modesel::{self, Cand};
use crate::proto::FramebufferInfo;
use crate::rm::{self, Regs};

const INFO: u32 = 0x2000;
const MODE: u32 = 0x2200;
const EDID: u32 = 0x2300;

#[derive(Clone, Copy)]
struct VbeMode {
    id: u16,
    w: u32,
    h: u32,
    pitch: u32,
    fb: u32,
    masks: [u8; 6],
}

fn r8(p: u32) -> u8 { unsafe { ptr::read(p as *const u8) } }
fn r16(p: u32) -> u16 { unsafe { ptr::read_unaligned(p as *const u16) } }
fn r32(p: u32) -> u32 { unsafe { ptr::read_unaligned(p as *const u32) } }

fn mode_info(id: u16) -> Option<VbeMode> {
    unsafe { ptr::write_bytes(MODE as *mut u8, 0, 256) };
    let mut r = Regs::new();
    r.eax = 0x4F01;
    r.ecx = id as u32;
    r.es_di(MODE);
    rm::int(0x10, &mut r);
    if r.ax() != 0x004F {
        return None;
    }
    let attr = r16(MODE);
    // supported, graphics, linear framebuffer; direct colour, 32 bits per pixel
    if attr & 0x0001 == 0 || attr & 0x0010 == 0 || attr & 0x0080 == 0 {
        return None;
    }
    if r8(MODE + 27) != 6 || r8(MODE + 25) != 32 {
        return None;
    }
    let fb = r32(MODE + 40);
    if fb == 0 {
        return None;
    }
    Some(VbeMode {
        id,
        w: r16(MODE + 18) as u32,
        h: r16(MODE + 20) as u32,
        pitch: r16(MODE + 16) as u32,
        fb,
        masks: [r8(MODE + 31), r8(MODE + 32), r8(MODE + 33), r8(MODE + 34), r8(MODE + 35), r8(MODE + 36)],
    })
}

fn list_modes() -> Vec<VbeMode> {
    let mut out = Vec::new();
    unsafe {
        ptr::write_bytes(INFO as *mut u8, 0, 512);
        ptr::copy_nonoverlapping(b"VBE2".as_ptr(), INFO as *mut u8, 4);
    }
    let mut r = Regs::new();
    r.eax = 0x4F00;
    r.es_di(INFO);
    rm::int(0x10, &mut r);
    if r.ax() != 0x004F || unsafe { core::slice::from_raw_parts(INFO as *const u8, 4) } != b"VESA" {
        return out;
    }
    // Far pointer to the mode list; copy it first: the list may live inside the info block.
    let far = r32(INFO + 14);
    let list = ((far >> 16) << 4) + (far & 0xFFFF);
    for i in 0..256u32 {
        let id = r16(list + i * 2);
        if id == 0xFFFF {
            break;
        }
        if let Some(m) = mode_info(id) {
            out.push(m);
        }
    }
    out
}

/// Preferred size from the first detailed timing descriptor of the monitor's EDID.
fn edid_native() -> Option<(u32, u32)> {
    unsafe { ptr::write_bytes(EDID as *mut u8, 0, 128) };
    let mut r = Regs::new();
    r.eax = 0x4F15;
    r.ebx = 1;
    r.ecx = 0;
    r.edx = 0;
    r.es_di(EDID);
    rm::int(0x10, &mut r);
    if r.ax() != 0x004F {
        return None;
    }
    let d = unsafe { core::slice::from_raw_parts(EDID as *const u8, 128) };
    if d[0..8] != [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0] {
        return None;
    }
    let w = d[56] as u32 | ((d[58] as u32 & 0xF0) << 4);
    let h = d[59] as u32 | ((d[61] as u32 & 0xF0) << 4);
    if w >= 320 && h >= 200 { Some((w, h)) } else { None }
}

fn set_mode(m: &VbeMode) -> bool {
    let mut r = Regs::new();
    r.eax = 0x4F02;
    r.ebx = m.id as u32 | 0x4000;
    rm::int(0x10, &mut r);
    r.ax() == 0x004F
}

fn describe(m: &VbeMode) -> FramebufferInfo {
    FramebufferInfo {
        phys_addr: m.fb as u64,
        width: m.w as u64,
        height: m.h as u64,
        pitch: m.pitch as u64,
        bpp: 32,
        memory_model: 1,
        red_mask_size: m.masks[0],
        red_mask_shift: m.masks[1],
        green_mask_size: m.masks[2],
        green_mask_shift: m.masks[3],
        blue_mask_size: m.masks[4],
        blue_mask_shift: m.masks[5],
        _reserved: [0; 7],
    }
}

/// Choose and set a mode. Returns an empty description (`phys_addr == 0`) if there is no VBE.
pub fn setup(res: Resolution) -> FramebufferInfo {
    let none = FramebufferInfo {
        phys_addr: 0, width: 0, height: 0, pitch: 0, bpp: 0, memory_model: 0,
        red_mask_size: 0, red_mask_shift: 0, green_mask_size: 0, green_mask_shift: 0,
        blue_mask_size: 0, blue_mask_shift: 0, _reserved: [0; 7],
    };
    let mut modes = list_modes();
    if modes.is_empty() {
        println!("VBE: no 32-bit linear modes, booting without a framebuffer");
        return none;
    }
    // `keep` has no meaning on BIOS (the console is text mode): treat it like `auto`.
    let res = if res == Resolution::Keep { Resolution::Auto } else { res };
    let native = edid_native();
    if let Some((w, h)) = native {
        println!("VBE: monitor native size {}x{}", w, h);
    }
    loop {
        let cands: Vec<Cand> = modes.iter().map(|m| Cand { w: m.w, h: m.h }).collect();
        let (pick, why) = modesel::choose(res, &cands, native, None);
        let Some(i) = pick else { return none };
        let m = modes[i];
        if set_mode(&m) {
            println!("VBE: {}x{} @ {:#x} ({})", m.w, m.h, m.fb, why);
            return describe(&m);
        }
        println!("VBE: mode {:#x} {}x{} refused, trying another", m.id, m.w, m.h);
        modes.remove(i);
        if modes.is_empty() {
            return none;
        }
    }
}
