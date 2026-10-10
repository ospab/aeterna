/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Host clipboard in VMware through the legacy backdoor text-selection commands
(the same port 0x5658 as VMMouse; no VMware Tools needed). Text only.

  GETSELLENGTH (6)  → EAX = length of the host clipboard text, or ≥ 0xFFFF0000 if none
  GETNEXTPIECE (7)  → EAX = next 4 bytes (little endian)
  SETSELLENGTH (8)  EBX = length we are about to send
  SETNEXTPIECE (9)  EBX = next 4 bytes

Copy/paste must be allowed for the VM (Settings → Options → Guest Isolation, or
isolation.tools.copy.disable / isolation.tools.paste.disable = "FALSE" in the .vmx).
Outside VMware the port is absent and every call reports "no clipboard".
*/
use alloc::string::String;
use alloc::vec::Vec;

use super::vmmouse::backdoor;

const VMWARE_MAGIC: u32 = 0x564D5868;
const CMD_GETVERSION: u32 = 0x0A;
const CMD_GETSELLENGTH: u32 = 6;
const CMD_GETNEXTPIECE: u32 = 7;
const CMD_SETSELLENGTH: u32 = 8;
const CMD_SETNEXTPIECE: u32 = 9;

/// Longest clipboard text we accept or send.
const MAX_TEXT: usize = 64 * 1024;

/// True when the VMware backdoor answers (cached after the first probe).
pub fn available() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    static STATE: AtomicU8 = AtomicU8::new(0); // 0 unknown, 1 yes, 2 no
    match STATE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let (_, bx, _, _) = unsafe { backdoor(CMD_GETVERSION, 0) };
            let yes = bx == VMWARE_MAGIC;
            STATE.store(if yes { 1 } else { 2 }, Ordering::Relaxed);
            yes
        }
    }
}

/// Text currently on the host clipboard, or None (not VMware, empty, not text,
/// or copy/paste disabled for this VM).
pub fn host_text() -> Option<String> {
    if !available() {
        return None;
    }
    let (len, _, _, _) = unsafe { backdoor(CMD_GETSELLENGTH, 0) };
    let len = len as usize;
    if len == 0 || len > MAX_TEXT {
        return None;
    }
    let mut bytes = Vec::with_capacity(len + 4);
    while bytes.len() < len {
        let (piece, _, _, _) = unsafe { backdoor(CMD_GETNEXTPIECE, 0) };
        bytes.extend_from_slice(&piece.to_le_bytes());
    }
    bytes.truncate(len);
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Put text on the host clipboard. Returns false outside VMware.
pub fn set_host_text(text: &str) -> bool {
    if !available() {
        return false;
    }
    let bytes = &text.as_bytes()[..text.len().min(MAX_TEXT)];
    unsafe {
        backdoor(CMD_SETSELLENGTH, bytes.len() as u32);
        for chunk in bytes.chunks(4) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            backdoor(CMD_SETNEXTPIECE, u32::from_le_bytes(word));
        }
    }
    true
}
