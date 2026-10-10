/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
clip — the host clipboard (VMware; see drivers/gpu/vmclip.rs)

  clip              print the host clipboard text      e.g. ostp import $(clip)
  clip set <text>   put text on the host clipboard     e.g. clip set "$(ostp links)"
  Ctrl+V in the console pastes the clipboard directly.
*/
use crate::userspace::plum::io;

pub fn run(args: &str) {
    let args = args.trim();
    let clip = crate::drivers::gpu::vmclip::host_text;
    if args.is_empty() {
        match clip() {
            Some(text) => {
                io::out(&text);
                if !text.ends_with('\n') { io::out("\n"); }
            }
            None => {
                io::err(if crate::drivers::gpu::vmclip::available() {
                    "clip: the host clipboard is empty or copy/paste is disabled for this VM\n"
                } else {
                    "clip: no host clipboard (works in VMware; elsewhere paste over the serial console)\n"
                });
                io::set_status(1);
            }
        }
    } else if let Some(text) = args.strip_prefix("set") {
        if !crate::drivers::gpu::vmclip::set_host_text(text.trim_start()) {
            io::err("clip: no host clipboard (works in VMware)\n");
            io::set_status(1);
        }
    } else {
        io::err("usage: clip            print the host clipboard\n       clip set <text> copy text to the host clipboard\n");
        io::set_status(2);
    }
}
