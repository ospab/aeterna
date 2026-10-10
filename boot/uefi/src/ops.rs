/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Firmware operations behind the non-kernel menu entries: reboot, power off, firmware
setup, EFI chainload, and the "last chosen entry" UEFI variable.
*/
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;

use crate::console::{bs, st};
use crate::efi::*;
use crate::fs;

fn rt() -> &'static RuntimeServices {
    unsafe { &*st().runtime_services }
}

fn name16(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

pub fn reset(kind: u32) {
    unsafe { (rt().reset_system)(kind, SUCCESS, 0, ptr::null()) };
}

/// Ask the firmware to show its setup UI on the next boot, then reset.
/// Returns an error text when the firmware does not support it.
pub fn firmware_setup() -> Result<(), String> {
    unsafe {
        let mut size = 8usize;
        let mut supported = [0u8; 8];
        let mut attr = 0u32;
        let s = (rt().get_variable)(
            name16("OsIndicationsSupported").as_ptr(), &GLOBAL_VARIABLE_GUID, &mut attr, &mut size, supported.as_mut_ptr());
        if is_error(s) || u64::from_le_bytes(supported) & 1 == 0 {
            return Err(String::from("This firmware does not support booting into its setup (OsIndications BOOT_TO_FW_UI)."));
        }
        let mut cur = [0u8; 8];
        size = 8;
        let s = (rt().get_variable)(
            name16("OsIndications").as_ptr(), &GLOBAL_VARIABLE_GUID, &mut attr, &mut size, cur.as_mut_ptr());
        if is_error(s) {
            cur = [0; 8];
        }
        let val = (u64::from_le_bytes(cur) | 1).to_le_bytes();
        let s = (rt().set_variable)(
            name16("OsIndications").as_ptr(), &GLOBAL_VARIABLE_GUID, VAR_NV | VAR_BS | VAR_RT, 8, val.as_ptr());
        if is_error(s) {
            return Err(alloc::format!("Cannot set OsIndications (status {:#x}).", s));
        }
    }
    reset(RESET_COLD);
    Err(String::from("The firmware did not reset."))
}

/// Id of the entry chosen last time.
pub fn last_choice() -> Option<String> {
    let mut buf = [0u8; 64];
    let mut size = buf.len();
    let mut attr = 0u32;
    let s = unsafe {
        (rt().get_variable)(name16("OspabLastEntry").as_ptr(), &OSPAB_VARIABLE_GUID, &mut attr, &mut size, buf.as_mut_ptr())
    };
    if is_error(s) {
        return None;
    }
    core::str::from_utf8(&buf[..size]).ok().map(String::from)
}

pub fn save_choice(id: &str) {
    if last_choice().as_deref() == Some(id) {
        return; // avoid a flash write on every boot
    }
    unsafe {
        (rt().set_variable)(
            name16("OspabLastEntry").as_ptr(), &OSPAB_VARIABLE_GUID, VAR_NV | VAR_BS | VAR_RT, id.len(), id.as_ptr());
    }
}

/// Load and start another EFI application from a FAT volume. Returns when it exits.
pub fn chainload(image: Handle, prefer: Option<Handle>, path: &str) -> Result<(), String> {
    let dev = fs::find_fat_file(prefer, path).ok_or_else(|| alloc::format!("{} not found on any FAT volume.", path))?;
    unsafe {
        let mut dp: *mut c_void = ptr::null_mut();
        if is_error((bs().handle_protocol)(dev, &DEVICE_PATH_GUID, &mut dp)) {
            return Err(String::from("The volume has no device path."));
        }
        // Copy the device path nodes without the end node, append the file node and a new end node.
        let mut node = dp as *const u8;
        let mut bytes: Vec<u8> = Vec::new();
        for _ in 0..64 {
            let len = u16::from_le_bytes([*node.add(2), *node.add(3)]) as usize;
            if *node == 0x7F || len < 4 {
                break;
            }
            bytes.extend_from_slice(core::slice::from_raw_parts(node, len));
            node = node.add(len);
        }
        let file: Vec<u16> = path.chars().map(|c| if c == '/' { 0x5C } else { c as u16 }).chain([0]).collect();
        let len = 4 + file.len() * 2;
        bytes.extend_from_slice(&[4, 4, len as u8, (len >> 8) as u8]);
        for c in &file {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x7F, 0xFF, 4, 0]);

        let mut handle: Handle = ptr::null_mut();
        let s = (bs().load_image)(false, image, bytes.as_ptr(), ptr::null(), 0, &mut handle);
        if is_error(s) {
            return Err(alloc::format!("LoadImage failed for {} (status {:#x}).", path, s));
        }
        let mut exit_size = 0usize;
        let mut exit_data: *mut u16 = ptr::null_mut();
        let s = (bs().start_image)(handle, &mut exit_size, &mut exit_data);
        if is_error(s) {
            return Err(alloc::format!("{} exited with status {:#x}.", path, s));
        }
    }
    Ok(())
}
