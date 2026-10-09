/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Framebuffer output: pixel-level control + 8x16 bitmap text rendering.
Supports scrolling, cursor tracking, tab stops and an optional pager hook
used by the terminal to pause long output ("--More--").

Colors passed to every function here are 0x00RRGGBB. They are converted to
the framebuffer's native channel layout (from the Limine colour shifts), so
red is 0xFF0000 on both xRGB and xBGR framebuffers.
*/

use core::ptr;
use super::font;

/// Framebuffer hardware info
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Framebuffer {
    pub address: *mut u32,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,   // bytes per scanline
    pub bpp: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

static mut FRAMEBUFFER: Option<Framebuffer> = None;

/// True when the framebuffer layout is already 0x00RRGGBB (no conversion).
static mut NATIVE_RGB: bool = true;

// Text cursor in pixel coordinates
static mut CURSOR_X: u64 = 0;
static mut CURSOR_Y: u64 = 0;

/// Number of times the screen has scrolled (monotonic). Lets callers that
/// remember a screen position (e.g. the prompt) notice that it moved up.
static mut SCROLLS: u64 = 0;

// ─── Pager state ────────────────────────────────────────────────────────────
static mut PAGER_HOOK: Option<fn() -> bool> = None;
static mut PAGER_LINES: u64 = 0;
static mut PAGER_SUPPRESS: bool = false;
static mut PAGER_IN_HOOK: bool = false;

/// Character cell dimensions (8x16 font)
pub const CHAR_WIDTH: u64 = font::FONT_WIDTH;
pub const CHAR_HEIGHT: u64 = font::FONT_HEIGHT;

/// Tab stop width in character cells.
const TAB_WIDTH: u64 = 8;

/// Initialize framebuffer with raw parameters from bootloader
pub unsafe fn init(
    address: *mut u32, width: u64, height: u64, pitch: u64, bpp: u16,
    red_shift: u8, green_shift: u8, blue_shift: u8,
) {
    FRAMEBUFFER = Some(Framebuffer {
        address,
        width,
        height,
        pitch,
        bpp,
        red_shift,
        green_shift,
        blue_shift,
    });
    NATIVE_RGB = red_shift == 16 && green_shift == 8 && blue_shift == 0;
    CURSOR_X = 0;
    CURSOR_Y = 0;
}

/// Check if framebuffer is ready
pub fn is_initialized() -> bool {
    unsafe { FRAMEBUFFER.is_some() }
}

/// Redirect the kernel framebuffer to a new physical base (e.g. after SVGA II takeover).
/// Preserves the current cursor position — only replaces the target address and dimensions.
/// Call this after any hardware that takes over display output and moves the framebuffer.
pub unsafe fn redirect(address: *mut u32, width: u64, height: u64, pitch: u64) {
    if let Some(fb) = FRAMEBUFFER.as_mut() {
        fb.address = address;
        fb.width   = width;
        fb.height  = height;
        fb.pitch   = pitch;
        // bpp + colour shifts stay as Limine reported them
    } else {
        // framebuffer not yet initialised — fall back to a best-effort init
        FRAMEBUFFER = Some(Framebuffer {
            address,
            width,
            height,
            pitch,
            bpp: 32,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        });
        NATIVE_RGB = true;
    }
    // Clamp cursor to new dimensions
    if CURSOR_X >= width  { CURSOR_X = 0; }
    if CURSOR_Y + CHAR_HEIGHT >= height {
        CURSOR_Y = if height > CHAR_HEIGHT { height - CHAR_HEIGHT } else { 0 };
    }
}

/// Convert 0x00RRGGBB to the framebuffer's native pixel value.
#[inline(always)]
fn to_native(rgb: u32) -> u32 {
    unsafe {
        if NATIVE_RGB { return rgb; }
        match FRAMEBUFFER {
            Some(fb) => {
                let r = (rgb >> 16) & 0xFF;
                let g = (rgb >> 8) & 0xFF;
                let b = rgb & 0xFF;
                (r << fb.red_shift) | (g << fb.green_shift) | (b << fb.blue_shift)
            }
            None => rgb,
        }
    }
}

/// Plot single pixel at (x, y) with colour 0x00RRGGBB.
#[inline(always)]
pub fn put_pixel(x: u64, y: u64, color: u32) {
    unsafe {
        if let Some(fb) = FRAMEBUFFER {
            if x < fb.width && y < fb.height {
                let offset = y * (fb.pitch / 4) + x;
                ptr::write_volatile(fb.address.add(offset as usize), to_native(color));
            }
        }
    }
}

/// Clear entire screen with solid color and home the cursor.
pub fn clear(color: u32) {
    let native = to_native(color);
    unsafe {
        if let Some(fb) = FRAMEBUFFER {
            let pixels_per_row = fb.pitch / 4;
            for y in 0..fb.height {
                let row_base = fb.address.add((y * pixels_per_row) as usize);
                for x in 0..fb.width {
                    ptr::write_volatile(row_base.add(x as usize), native);
                }
            }
            CURSOR_X = 0;
            CURSOR_Y = 0;
            PAGER_LINES = 0;
        }
    }
}

/// Draw filled rectangle
pub fn fill_rect(x: u64, y: u64, w: u64, h: u64, color: u32) {
    let native = to_native(color);
    unsafe {
        if let Some(fb) = FRAMEBUFFER {
            let pixels_per_row = fb.pitch / 4;
            let x_end = (x + w).min(fb.width);
            let y_end = (y + h).min(fb.height);
            for py in y..y_end {
                let row_base = fb.address.add((py * pixels_per_row) as usize);
                for px in x..x_end {
                    ptr::write_volatile(row_base.add(px as usize), native);
                }
            }
        }
    }
}

/// Draw single character at pixel position (8x16 font, 1 byte per row, MSB left)
pub fn draw_char_at(x: u64, y: u64, c: char, fg_color: u32, bg_color: u32) {
    let bitmap = match font::get_char_bitmap(c) {
        Some(b) => b,
        None => return,
    };
    let fg = to_native(fg_color);
    let bg = to_native(bg_color);
    unsafe {
        let fb = match FRAMEBUFFER {
            Some(fb) => fb,
            None => return,
        };
        if x + CHAR_WIDTH <= fb.width && y + CHAR_HEIGHT <= fb.height {
            // Fast path: glyph fully on screen.
            let ppr = fb.pitch / 4;
            for row in 0..CHAR_HEIGHT {
                let bits = bitmap[row as usize];
                let base = fb.address.add(((y + row) * ppr + x) as usize);
                for col in 0..CHAR_WIDTH {
                    let px = if bits & (0x80 >> col) != 0 { fg } else { bg };
                    ptr::write_volatile(base.add(col as usize), px);
                }
            }
        } else {
            // Clipped glyph at the screen edge.
            let ppr = fb.pitch / 4;
            for row in 0..CHAR_HEIGHT {
                let py = y + row;
                if py >= fb.height { break; }
                let bits = bitmap[row as usize];
                for col in 0..CHAR_WIDTH {
                    let px_x = x + col;
                    if px_x >= fb.width { break; }
                    let px = if bits & (0x80 >> col) != 0 { fg } else { bg };
                    ptr::write_volatile(fb.address.add((py * ppr + px_x) as usize), px);
                }
            }
        }
    }
}

/// Advance the cursor to the next text line, scrolling if needed.
unsafe fn newline(fb: &Framebuffer) {
    CURSOR_X = 0;
    CURSOR_Y += CHAR_HEIGHT;
    if CURSOR_Y + CHAR_HEIGHT > fb.height {
        scroll_up();
        CURSOR_Y = fb.height - CHAR_HEIGHT;
    }
    pager_line_done();
}

/// Called after every completed text line; runs the pager hook when a
/// screenful has been printed since the last pause.
unsafe fn pager_line_done() {
    if PAGER_IN_HOOK { return; }
    PAGER_LINES += 1;
    if let Some(hook) = PAGER_HOOK {
        let rows = screen_rows();
        if rows > 2 && PAGER_LINES >= rows - 1 {
            PAGER_IN_HOOK = true;
            let keep_going = hook();
            PAGER_IN_HOOK = false;
            PAGER_LINES = 0;
            if !keep_going {
                PAGER_SUPPRESS = true;
            }
        }
    }
}

/// Draw character at current cursor, handle newline/CR/tab, auto-wrap, auto-scroll
pub fn draw_char(c: char, fg_color: u32, bg_color: u32) {
    unsafe {
        if PAGER_SUPPRESS && !PAGER_IN_HOOK { return; }
        if let Some(fb) = FRAMEBUFFER {
            match c {
                '\n' => newline(&fb),
                '\r' => {
                    CURSOR_X = 0;
                }
                '\t' => {
                    let col = CURSOR_X / CHAR_WIDTH;
                    let next = (col / TAB_WIDTH + 1) * TAB_WIDTH;
                    let cols = fb.width / CHAR_WIDTH;
                    if next >= cols {
                        newline(&fb);
                    } else {
                        for _ in col..next {
                            draw_char(' ', fg_color, bg_color);
                        }
                    }
                }
                _ => {
                    // Wrap if at right edge
                    if CURSOR_X + CHAR_WIDTH > fb.width {
                        newline(&fb);
                        if PAGER_SUPPRESS && !PAGER_IN_HOOK { return; }
                    }
                    // Scroll if at bottom
                    if CURSOR_Y + CHAR_HEIGHT > fb.height {
                        scroll_up();
                        CURSOR_Y = fb.height - CHAR_HEIGHT;
                    }
                    draw_char_at(CURSOR_X, CURSOR_Y, c, fg_color, bg_color);
                    CURSOR_X += CHAR_WIDTH;
                }
            }
        }
    }
}

/// Draw string at current cursor position
pub fn draw_string(s: &str, fg_color: u32, bg_color: u32) {
    for c in s.chars() {
        draw_char(c, fg_color, bg_color);
    }
}

/// Draw string starting at specific pixel position
pub fn draw_string_at(x: u64, y: u64, s: &str, fg_color: u32, bg_color: u32) {
    unsafe {
        CURSOR_X = x;
        CURSOR_Y = y;
    }
    draw_string(s, fg_color, bg_color);
}

/// Fill from the cursor to the end of the current text line with `bg`.
/// The cursor does not move.
pub fn clear_to_eol(bg_color: u32) {
    unsafe {
        if let Some(fb) = FRAMEBUFFER {
            if CURSOR_X < fb.width {
                fill_rect(CURSOR_X, CURSOR_Y, fb.width - CURSOR_X, CHAR_HEIGHT, bg_color);
            }
        }
    }
}

/// Scroll screen content up by one text row (CHAR_HEIGHT pixels).
fn scroll_up() {
    unsafe {
        if let Some(fb) = FRAMEBUFFER {
            let pixels_per_row = fb.pitch / 4;

            // One overlapping move of everything below the first text row.
            let src = fb.address.add((CHAR_HEIGHT * pixels_per_row) as usize);
            let count = ((fb.height - CHAR_HEIGHT) * pixels_per_row) as usize;
            ptr::copy(src, fb.address, count);

            // Clear the bottom CHAR_HEIGHT rows
            let clear_start = fb.height - CHAR_HEIGHT;
            for y in clear_start..fb.height {
                let row_base = fb.address.add((y * pixels_per_row) as usize);
                for x in 0..fb.width {
                    ptr::write_volatile(row_base.add(x as usize), 0x00000000);
                }
            }
            SCROLLS = SCROLLS.wrapping_add(1);
        }
    }
}

/// How many times the screen has scrolled since boot.
pub fn scroll_count() -> u64 {
    unsafe { SCROLLS }
}

/// Get current cursor position in pixels
pub fn cursor_pos() -> (u64, u64) {
    unsafe { (CURSOR_X, CURSOR_Y) }
}

/// Set cursor position in pixels
pub fn set_cursor_pos(x: u64, y: u64) {
    unsafe {
        CURSOR_X = x;
        CURSOR_Y = y;
    }
}

// ─── Pager ──────────────────────────────────────────────────────────────────

/// Start paging text output. After every (rows - 1) lines `hook` is called
/// with the cursor at the start of the bottom line; it should show a prompt,
/// wait for a key, erase the prompt and return `false` to discard the rest of
/// the output (e.g. the user pressed `q`) or `true` to show another screen.
pub fn pager_begin(hook: fn() -> bool) {
    unsafe {
        PAGER_HOOK = Some(hook);
        PAGER_LINES = 0;
        PAGER_SUPPRESS = false;
    }
}

/// Stop paging and resume normal output.
pub fn pager_end() {
    unsafe {
        PAGER_HOOK = None;
        PAGER_LINES = 0;
        PAGER_SUPPRESS = false;
    }
}

/// True while the pager is discarding output after the user quit it.
pub fn pager_suppressed() -> bool {
    unsafe { PAGER_SUPPRESS }
}

/// Get framebuffer info (dimensions, address, etc.)
pub fn info() -> Option<Framebuffer> {
    unsafe { FRAMEBUFFER }
}

/// Get screen dimensions in character cells
pub fn screen_cols() -> u64 {
    unsafe {
        if let Some(fb) = FRAMEBUFFER {
            fb.width / CHAR_WIDTH
        } else {
            80
        }
    }
}

pub fn screen_rows() -> u64 {
    unsafe {
        if let Some(fb) = FRAMEBUFFER {
            fb.height / CHAR_HEIGHT
        } else {
            25
        }
    }
}
