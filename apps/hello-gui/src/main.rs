// SPDX-License-Identifier: AGPL-3.0-only
//! hello-gui as a ring-3 program.
//!
//! The compositor does not have an IPC front end yet, so this binary runs the
//! application against an in-process session and renders a few frames into
//! memory.  It proves the app builds for `x86_64-unknown-oos` and runs on
//! liboos; once `oos_ui::proto` is carried over a channel, only the host
//! below changes — `hello_gui::HelloGui` stays as it is.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use liboos::println;
use oos_ui::app::AppHost;
use oos_ui::session::Session;
use oos_ui::theme::DARK;

liboos::entry!(main);

fn main(_args: liboos::Args) -> i32 {
    let theme = DARK;
    let mut text = oos_ui::fonts::default_text_engine();
    let mut session = Session::new(800, 600);
    session.add_app(Box::new(AppHost::new(Box::new(hello_gui::HelloGui::default()), None)), VecDeque::new());
    let mut painted = 0usize;
    for frame in 0..4u64 {
        let rects = session.frame(frame * 16, &mut text, &theme);
        painted += rects.iter().map(|r| r.area() as usize).sum::<usize>();
    }
    println!("hello-gui: {} windows, {} px painted in 4 frames", session.desktop.windows.len(), painted);
    if session.desktop.windows.is_empty() { 1 } else { 0 }
}
