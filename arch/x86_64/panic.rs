/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Global panic handler and the panic / fault screens.

On a panic: interrupts off, report to serial COM1, draw the panic screen on
the framebuffer, then halt forever (hlt loop).

The screen renderer is public so the terminal's `testmode` can show exactly
the same screen in preview mode, without halting.

CPU exceptions in ring 0 end up here via panic!(); the exception handler can
call `record_exception()` first so the register dump appears on screen.
*/

use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::arch::x86_64::framebuffer;
use crate::arch::x86_64::serial;

// Prevent recursive panics
static PANICKED: AtomicBool = AtomicBool::new(false);

// Colors, 0x00RRGGBB (the framebuffer converts to its native layout)
const COLOR_BG: u32     = 0x00000000;
const COLOR_RED: u32    = 0x00DD2222;
const COLOR_WHITE: u32  = 0x00FFFFFF;
const COLOR_GRAY: u32   = 0x00A0A0A0;
const COLOR_YELLOW: u32 = 0x00FFCC44;
const COLOR_CYAN: u32   = 0x0055CCFF;

/// CPU state of a fatal exception, shown on the panic screen.
#[derive(Clone, Copy)]
pub struct ExceptionInfo {
    pub name: &'static str,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub rsp: u64,
    pub cs: u64,
    /// Faulting address for #PF (vector 14), 0 otherwise.
    pub cr2: u64,
}

static mut LAST_EXCEPTION: Option<ExceptionInfo> = None;

/// Remember a fatal ring-0 exception so the panic screen can show it.
/// Call right before `panic!()` in the exception handler.
pub fn record_exception(info: ExceptionInfo) {
    unsafe { LAST_EXCEPTION = Some(info); }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Disable interrupts immediately — no IRQs during panic display
    unsafe { asm!("cli"); }

    // Prevent recursive panics — if we're already in panic handler, just halt
    if PANICKED.swap(true, Ordering::SeqCst) {
        serial::write_str("\r\n[PANIC] Recursive panic detected, halting immediately.\r\n");
        loop {
            unsafe { asm!("cli; hlt"); }
        }
    }

    // === Serial output (always works, even without framebuffer) ===
    serial::write_str("\r\n\r\n========================================\r\n");
    serial::write_str(" KERNEL PANIC - AETERNA\r\n");
    serial::write_str("========================================\r\n");
    if let Some(loc) = info.location() {
        serial::write_str("Location: ");
        serial::write_str(loc.file());
        serial::write_str(":");
        serial_write_u64(loc.line() as u64);
        serial::write_str("\r\n");
    }
    serial::write_str("Message: ");
    let _ = write!(SerialWriter, "{}", info.message());
    serial::write_str("\r\nSystem halted.\r\n========================================\r\n");

    // === Framebuffer output (if available) ===
    let exception = unsafe { LAST_EXCEPTION };
    let location = info.location().map(|l| (l.file(), l.line(), l.column()));
    render_panic_screen(location, &info.message(), exception.as_ref(), false);

    // Safe halt loop — low power, never returns
    loop {
        unsafe { asm!("hlt"); }
    }
}

/// Draw the kernel panic screen.
/// `preview = true` (testmode) changes the title and footer to say it is a
/// test and that the system is still running; the layout is otherwise the
/// same as a real panic. This function never halts.
pub fn render_panic_screen(
    location: Option<(&str, u32, u32)>,
    message: &dyn fmt::Display,
    exception: Option<&ExceptionInfo>,
    preview: bool,
) {
    if !framebuffer::is_initialized() {
        return;
    }
    // A panic can hit while the terminal pager is active; never page here.
    framebuffer::pager_end();
    framebuffer::clear(COLOR_BG);

    let width = framebuffer::info().map(|f| f.width).unwrap_or(640);
    let ch = framebuffer::CHAR_HEIGHT;
    let margin = 2 * framebuffer::CHAR_WIDTH;

    // Title bar
    framebuffer::fill_rect(0, 0, width, ch * 2, COLOR_RED);
    let title = if preview {
        " KERNEL PANIC  (TEST PREVIEW - nothing crashed) "
    } else {
        " KERNEL PANIC "
    };
    framebuffer::draw_string_at(margin, ch / 2, title, COLOR_WHITE, COLOR_RED);

    let mut y = ch * 3;
    let mut w = FbWriter { x0: margin, fg: COLOR_WHITE };

    // Message
    framebuffer::draw_string_at(margin, y, "Cause:    ", COLOR_YELLOW, COLOR_BG);
    w.x0 = margin + 10 * framebuffer::CHAR_WIDTH;
    let _ = write!(w, "{}", message);
    y = framebuffer::cursor_pos().1 + ch;

    // Location
    if let Some((file, line, col)) = location {
        framebuffer::draw_string_at(margin, y, "Location: ", COLOR_YELLOW, COLOR_BG);
        let _ = write!(w, "{}:{}:{}", file, line, col);
        y = framebuffer::cursor_pos().1 + ch;
    }

    // CPU exception context
    if let Some(e) = exception {
        y += ch;
        framebuffer::draw_string_at(margin, y, "CPU exception", COLOR_YELLOW, COLOR_BG);
        y += ch;
        w.x0 = margin;
        w.fg = COLOR_WHITE;
        framebuffer::set_cursor_pos(margin, y);
        let _ = write!(w, "  {} (vector {}), error code {:#x}", e.name, e.vector, e.error_code);
        y += ch;
        framebuffer::set_cursor_pos(margin, y);
        let _ = write!(w, "  RIP {:#018x}   RSP {:#018x}   CS {:#06x} (ring {})",
            e.rip, e.rsp, e.cs, e.cs & 3);
        y += ch;
        if e.vector == 14 {
            framebuffer::set_cursor_pos(margin, y);
            let _ = write!(w, "  CR2 {:#018x}  ({}, {}, {})", e.cr2,
                if e.error_code & 1 != 0 { "protection violation" } else { "page not present" },
                if e.error_code & 2 != 0 { "write" } else { "read" },
                if e.error_code & 4 != 0 { "user mode" } else { "kernel mode" });
            y += ch;
        }
    }

    // Recent kernel events
    y += ch;
    framebuffer::draw_string_at(margin, y, "Last kernel events (newest last):", COLOR_YELLOW, COLOR_BG);
    y += ch;
    let mut buf = [crate::klog::Event::empty_pub(); 10];
    let n = crate::klog::last_events(&mut buf, 10);
    if n == 0 {
        framebuffer::draw_string_at(margin, y, "  (none)", COLOR_GRAY, COLOR_BG);
        y += ch;
    }
    for ev in &buf[..n] {
        framebuffer::draw_string_at(margin, y, "  [", COLOR_GRAY, COLOR_BG);
        framebuffer::draw_string(ev.source.label().trim_end(), COLOR_CYAN, COLOR_BG);
        framebuffer::draw_string("] ", COLOR_GRAY, COLOR_BG);
        framebuffer::draw_string(ev.message(), COLOR_GRAY, COLOR_BG);
        y += ch;
    }

    // Footer
    y += ch;
    if preview {
        framebuffer::draw_string_at(margin, y,
            "This is a test preview. The system is still running.", COLOR_YELLOW, COLOR_BG);
        y += ch;
        framebuffer::draw_string_at(margin, y, "Press Enter to return to the terminal.", COLOR_WHITE, COLOR_BG);
    } else {
        framebuffer::draw_string_at(margin, y,
            "System halted. Details are also on serial COM1. Reboot to continue.", COLOR_RED, COLOR_BG);
    }
}

/// One-line on-screen notice when a ring-3 process is killed for a CPU fault.
/// Intended to be called from the exception handler next to its serial log.
pub fn report_process_fault(pid: u64, exception: &str, addr: u64) {
    if !framebuffer::is_initialized() { return; }
    let (x, _) = framebuffer::cursor_pos();
    if x != 0 {
        framebuffer::draw_char('\n', COLOR_WHITE, COLOR_BG);
    }
    let mut w = FbWriter { x0: 0, fg: COLOR_RED };
    let _ = write!(w, "[pid {}] killed: {} at {:#x}", pid, exception, addr);
    framebuffer::draw_char('\n', COLOR_WHITE, COLOR_BG);
}

/// fmt::Write to the framebuffer; wrapped lines continue at column `x0`.
struct FbWriter {
    x0: u64,
    fg: u32,
}

impl Write for FbWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let width = framebuffer::info().map(|f| f.width).unwrap_or(640);
        for c in s.chars() {
            let (x, y) = framebuffer::cursor_pos();
            if c == '\n' || x + framebuffer::CHAR_WIDTH > width {
                framebuffer::set_cursor_pos(self.x0, y + framebuffer::CHAR_HEIGHT);
                if c == '\n' { continue; }
            }
            framebuffer::draw_char(c, self.fg, COLOR_BG);
        }
        Ok(())
    }
}

struct SerialWriter;

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial::write_str(s);
        Ok(())
    }
}

/// Print u64 to serial (simple, no allocation)
fn serial_write_u64(val: u64) {
    let _ = write!(SerialWriter, "{}", val);
}
