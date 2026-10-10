/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

desktop — the ospab.os desktop session (oos-ui).

  desktop            start the session from the console (logout returns here)
  session=desktop    kernel cmdline: the console starts it at boot

Everything is rendered in software by the oos-ui crate (gui/).  The session
runs the compositor/window manager and the applications in one kernel thread
and connects them with the window-system protocol (gui/src/proto.rs); see
docs/en/gui.md for how this becomes a ring-3 compositor with IPC + shared
memory.

Apps: Terminal (the real plum shell), Files (VFS), Text Editor, Settings
(network, OSTP, sound, display, time, about) and DOOM (fullscreen).
*/

extern crate alloc;

pub mod editor;
pub mod files;
mod input;

/// Version strings (the kernel library has no `version` module; the build script sets these).
pub mod ver {
    pub const OS_VERSION: &str = concat!("ospab.os v", env!("CARGO_PKG_VERSION"));
    pub const VERSION_STR: &str = env!("CARGO_PKG_VERSION");
    pub const KERNEL_VERSION: &str = concat!("AETERNA ", env!("CARGO_PKG_VERSION"));
    pub const KERNEL_BUILD: &str = concat!("#", env!("OSPAB_BUILD"), " ", env!("OSPAB_COMMIT"), " ", env!("OSPAB_BUILD_DATE"));
    pub const ARCH: &str = "x86_64";
    pub const LICENSE: &str = "AGPL-3.0-only";
}
pub mod settings;
pub mod term;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use oos_ui::desktop::{ShellAction, ShellStatus};
use oos_ui::event::{Event, MouseButton};
use oos_ui::geom::Rect;
use oos_ui::proto::{ToServer, WinId};
use oos_ui::session::Session;
use oos_ui::text::TextEngine;
use oos_ui::theme::{Theme, DARK};
use oos_ui::app::{AppHost, Application, DirItem, Platform};

use crate::arch::x86_64::{framebuffer, mouse, serial, tsc};
use crate::userspace::plum::io;

// ─── Session-wide requests from apps ─────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppKind {
    Terminal,
    Files,
    Editor,
    Settings,
    Hello,
    Doom,
}

impl AppKind {
    /// Application id (`AppInfo::id`) of the app, "" for DOOM (not an oos-ui app).
    fn app_id(self) -> &'static str {
        match self {
            AppKind::Terminal => "org.ospab.terminal",
            AppKind::Files => "org.ospab.files",
            AppKind::Editor => "org.ospab.editor",
            AppKind::Settings => "org.ospab.settings",
            AppKind::Hello => "org.ospab.hello-gui",
            AppKind::Doom => "",
        }
    }

    fn from_id(id: &str) -> Option<AppKind> {
        [AppKind::Terminal, AppKind::Files, AppKind::Editor, AppKind::Settings, AppKind::Hello, AppKind::Doom]
            .into_iter().find(|k| k.app_id() == id)
    }
}

const DOCK: [(AppKind, &str, oos_ui::icons::Icon); 5] = [
    (AppKind::Terminal, "Terminal", oos_ui::icons::Icon::Terminal),
    (AppKind::Files, "Files", oos_ui::icons::Icon::Folder),
    (AppKind::Editor, "Text Editor", oos_ui::icons::Icon::FileCode),
    (AppKind::Settings, "Settings", oos_ui::icons::Icon::Settings),
    (AppKind::Doom, "DOOM", oos_ui::icons::Icon::Grid),
];

pub enum Request {
    Launch(AppKind, Option<String>),
    /// Run a shell line for terminal window `WinId` on a screen of cols x rows.
    Exec(WinId, String, usize, usize),
    SetResolution(i32, i32),
    Settings(usize),
    Logout,
}

static mut REQUESTS: Vec<Request> = Vec::new();

/// Ask the session to do something (called by apps).
pub fn request(r: Request) {
    unsafe { REQUESTS.push(r); }
}

fn take_requests() -> Vec<Request> {
    unsafe { core::mem::take(&mut REQUESTS) }
}

// ─── Platform services for apps (VFS, launcher) ────────────────────────────

struct KernelPlatform;

impl Platform for KernelPlatform {
    fn list_dir(&mut self, path: &str) -> Option<Vec<DirItem>> {
        let es = crate::fs::readdir(path)?;
        Some(es.into_iter().filter(|e| e.name != "." && e.name != "..").map(|e| DirItem {
            is_dir: e.node_type == crate::fs::NodeType::Directory, size: e.size as u64, name: e.name,
        }).collect())
    }
    fn read_file(&mut self, path: &str) -> Option<Vec<u8>> { crate::fs::read_file(path) }
    fn write_file(&mut self, path: &str, data: &[u8]) -> bool { crate::fs::write_file(path, data) }
    fn rename(&mut self, from: &str, to: &str) -> bool { crate::fs::rename(from, to) }
    fn remove(&mut self, path: &str) -> bool { crate::fs::remove(path) }
    fn mkdir(&mut self, path: &str) -> bool { crate::fs::mkdir(path) }
    fn launch(&mut self, app: &str, arg: Option<&str>) -> bool {
        match AppKind::from_id(app) {
            Some(k) => { request(Request::Launch(k, arg.map(String::from))); true }
            None => false,
        }
    }
    fn uptime_ms(&mut self) -> u64 { tsc::tsc_us() / 1000 }
}

// ─── Terminal output routing (plum screen hook) ─────────────────────────────

static mut HOOK_TARGET: WinId = 0;
static mut TERM_OUT: Vec<(WinId, String, u32)> = Vec::new();
static mut EXEC_DONE: Vec<(WinId, i32)> = Vec::new();
static mut LAST_LIVE_US: u64 = 0;

/// Output for terminal `id` since the last call.
pub fn take_output(id: WinId) -> Vec<(String, u32)> {
    unsafe {
        let mut mine = Vec::new();
        TERM_OUT.retain(|(w, s, c)| if *w == id { mine.push((s.clone(), *c)); false } else { true });
        mine
    }
}

/// Exit status if the command of terminal `id` finished.
pub fn take_done(id: WinId) -> Option<i32> {
    unsafe {
        let i = EXEC_DONE.iter().position(|(w, _)| *w == id)?;
        Some(EXEC_DONE.remove(i).1)
    }
}

fn screen_hook(s: &str, color: u32) {
    unsafe {
        match TERM_OUT.last_mut() {
            Some((w, t, c)) if *w == HOOK_TARGET && *c == color => t.push_str(s),
            _ => TERM_OUT.push((HOOK_TARGET, String::from(s), color)),
        }
        // Stream long-running output: repaint at most every 40 ms.
        let now = tsc::tsc_us();
        if now.saturating_sub(LAST_LIVE_US) > 40_000 {
            LAST_LIVE_US = now;
            if let Some(d) = DESK.as_mut() { d.frame(); }
        }
    }
}

// ─── Framebuffer ─────────────────────────────────────────────────────────────

struct Fb {
    base: *mut u32,
    width: i32,
    height: i32,
    stride: usize,
    native: bool,
    shifts: (u8, u8, u8),
}

impl Fb {
    fn current() -> Option<Fb> {
        let i = framebuffer::info()?;
        if i.bpp != 32 { return None; }
        Some(Fb {
            base: i.address, width: i.width as i32, height: i.height as i32, stride: (i.pitch / 4) as usize,
            native: i.red_shift == 16 && i.green_shift == 8 && i.blue_shift == 0,
            shifts: (i.red_shift, i.green_shift, i.blue_shift),
        })
    }

    fn present(&self, back: &oos_ui::Surface, rects: &[Rect]) {
        for r in rects {
            let r = r.intersect(&Rect::new(0, 0, self.width.min(back.width), self.height.min(back.height)));
            if r.is_empty() { continue; }
            for y in r.y..r.bottom() {
                let src = &back.data[y as usize * back.stride + r.x as usize..][..r.w as usize];
                unsafe {
                    let dst = self.base.add(y as usize * self.stride + r.x as usize);
                    if self.native {
                        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, r.w as usize);
                    } else {
                        let (rs, gs, bs) = self.shifts;
                        for (i, &p) in src.iter().enumerate() {
                            *dst.add(i) = ((p >> 16) & 0xFF) << rs | ((p >> 8) & 0xFF) << gs | (p & 0xFF) << bs;
                        }
                    }
                }
            }
        }
        if !rects.is_empty() { crate::drivers::gpu::flush_screen(); }
    }
}

// ─── The session ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Stats {
    frames: u64,
    total_us: u64,
    max_us: u64,
    area: u64,
}

struct Desk {
    session: Session,
    text: TextEngine,
    theme: Theme,
    fb: Fb,
    start_us: u64,
    stats: Stats,
    first_frame_us: u64,
    full_frame_us: u64,
}

static mut DESK: Option<Box<Desk>> = None;

fn desk() -> &'static mut Desk { unsafe { DESK.as_mut().expect("desktop session") } }

impl Desk {
    fn now_ms(&self) -> u64 { (tsc::tsc_us() - self.start_us) / 1000 }

    /// Pump apps, composite, present. Returns the frame time in µs.
    fn frame(&mut self) -> u64 {
        let t = tsc::tsc_us();
        let now = self.now_ms();
        let rects = self.session.frame(now, &mut self.text, &self.theme);
        if rects.is_empty() { return 0; }
        self.fb.present(&self.session.desktop.back, &rects);
        let us = tsc::tsc_us() - t;
        self.stats.frames += 1;
        self.stats.total_us += us;
        self.stats.max_us = self.stats.max_us.max(us);
        self.stats.area += rects.iter().map(|r| r.area() as u64).sum::<u64>();
        us.max(1)
    }

    fn launch(&mut self, kind: AppKind, arg: Option<String>) {
        let app: Box<dyn Application> = match kind {
            AppKind::Terminal => Box::new(term::Terminal::new()),
            AppKind::Files => Box::new(files::Files::new("/")),
            AppKind::Editor => Box::new(editor::Editor::new()),
            AppKind::Settings => Box::new(settings::Settings::new()),
            AppKind::Hello => Box::new(hello_gui::HelloGui::default()),
            AppKind::Doom => { self.run_doom(); return; }
        };
        self.session.add_app(Box::new(AppHost::new(app, arg.as_deref())), VecDeque::new());
    }

    /// Live windows of an app kind, oldest first.
    fn windows_of(&self, kind: AppKind) -> Vec<WinId> {
        let id = kind.app_id();
        let mut v = Vec::new();
        for a in &self.session.apps {
            if a.app_id() == id { v.extend(a.window_ids().into_iter().filter(|w| self.session.desktop.window(*w).is_some())); }
        }
        v
    }

    fn run_doom(&mut self) {
        crate::doom::run();
        input::reset();
        let _ = mouse::poll();
        self.session.desktop.invalidate_all();
    }

    fn set_resolution(&mut self, w: i32, h: i32) {
        if !crate::drivers::gpu::svga_ready() { return; }
        if !crate::drivers::gpu::set_mode(w as u32, h as u32, 32) { return; }
        crate::drivers::gpu::svga_activate();
        let (cw, ch, bpl) = crate::drivers::gpu::vmware_svga::display_info();
        if let Some(i) = framebuffer::info() {
            unsafe { framebuffer::redirect(i.address, cw as u64, ch as u64, bpl as u64); }
        }
        if let Some(fb) = Fb::current() {
            self.fb = fb;
            let (fw, fh) = (self.fb.width, self.fb.height);
            self.session.desktop.resize_screen(fw, fh, &mut self.session.bus, &self.theme);
        }
    }

    fn status(&mut self) {
        let tz = crate::net::sntp::read_timezone_offset();
        let net_up = crate::net::is_up();
        let net = if net_up {
            let ip = unsafe { crate::net::OUR_IP };
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        } else { String::from("Offline") };
        let volume = if crate::drivers::audio::is_ready() { Some(crate::drivers::audio::volume()) } else { None };
        let st = ShellStatus { clock: clock_text(tz), net, net_up, ostp: crate::net::ostp::is_connected(), volume };
        self.session.desktop.set_status(st, &self.theme);
        let running: Vec<bool> = DOCK.iter().map(|(k, _, _)| !self.windows_of(*k).is_empty()).collect();
        self.session.desktop.set_dock_running(&running);
    }
}

pub fn clock_text(tz_secs: i64) -> String {
    const WD: [&str; 7] = ["Чт", "Пт", "Сб", "Вс", "Пн", "Вт", "Ср"];
    const MON: [&str; 12] = ["янв.", "февр.", "мар.", "апр.", "мая", "июн.", "июл.", "авг.", "сент.", "окт.", "нояб.", "дек."];
    let ns = crate::time::now().saturating_add(tz_secs.saturating_mul(1_000_000_000));
    let t = crate::time::to_civil(ns);
    let days = crate::time::to_unix_secs(ns).div_euclid(86_400);
    format!("{} {} {}  {:02}:{:02}", WD[days.rem_euclid(7) as usize], t.day, MON[(t.month as usize).clamp(1, 12) - 1], t.hour, t.minute)
}

/// Shell command `desktop`.
pub fn run(args: &str) {
    if args.trim() == "--help" || args.trim() == "-h" {
        io::out("usage: desktop     start the graphical session (Log out returns to the console)\n");
        return;
    }
    run_session();
}

/// Start the desktop session; returns on logout.
pub fn run_session() {
    if unsafe { DESK.is_some() } { io::err("desktop: already running\n"); return; }
    let Some(fb) = Fb::current() else { io::err("desktop: no 32-bpp framebuffer\n"); return; };

    // Save the console so logout restores it exactly.
    let saved_len = fb.stride * fb.height as usize;
    let mut saved: Vec<u32> = Vec::with_capacity(saved_len);
    unsafe {
        core::ptr::copy_nonoverlapping(fb.base, saved.as_mut_ptr(), saved_len);
        saved.set_len(saved_len);
    }
    let saved_geom = (fb.width, fb.height, fb.stride);
    let cursor = framebuffer::cursor_pos();

    let t0 = tsc::tsc_us();
    let theme = DARK;
    let text = oos_ui::fonts::default_text_engine();
    let mut session = Session::new(fb.width, fb.height);
    session.desktop.dock = DOCK.iter().map(|(_, n, i)| oos_ui::desktop::DockItem { name: (*n).into(), icon: *i, running: false }).collect();
    {
        use oos_ui::icons::Icon;
        use oos_ui::menu::MenuItem;
        session.desktop.launcher_items = alloc::vec![
            MenuItem::new("Terminal").icon(Icon::Terminal),
            MenuItem::new("Files").icon(Icon::Folder),
            MenuItem::new("Text Editor").icon(Icon::FileCode),
            MenuItem::new("Settings").icon(Icon::Settings),
            MenuItem::new("DOOM").icon(Icon::Grid),
            MenuItem::new("Hello GUI").icon(Icon::Info),
            MenuItem::separator(),
            MenuItem::new("About ospab.os").icon(Icon::Info),
            MenuItem::new("Log out").icon(Icon::Power),
        ];
    }
    unsafe {
        DESK = Some(Box::new(Desk {
            session, text, theme, fb, start_us: tsc::tsc_us(), stats: Stats::default(),
            first_frame_us: 0, full_frame_us: 0,
        }));
        REQUESTS.clear();
        TERM_OUT.clear();
        EXEC_DONE.clear();
    }
    let t_init = tsc::tsc_us() - t0;
    {
        let d = desk();
        oos_ui::app::set_platform(Box::new(KernelPlatform));
        d.launch(AppKind::Files, None);
        d.launch(AppKind::Terminal, None);
        d.status();
        d.first_frame_us = d.frame();
        d.session.desktop.invalidate_all();
        d.full_frame_us = d.frame();
        d.stats = Stats::default();
    }
    serial::write_str("[DESKTOP] session started\r\n");

    input::reset();
    let _ = mouse::poll();
    let mut buttons = 0u8;
    let mut abs_seen = false;
    let mut last_status = 0u64;
    let mut logout = false;
    while !logout {
        let mut busy = false;
        // Keyboard (own decoder: key up/down, modifiers).
        while let Some(ev) = input::poll_key() {
            let d = desk();
            d.session.input(&ev, &mut d.text, &d.theme);
            busy = true;
        }
        // Mouse.
        {
            let d = desk();
            let (dx, dy, b) = mouse::poll();
            let mut nb = b;
            let (cx, cy) = (d.session.desktop.cursor.x, d.session.desktop.cursor.y);
            let (mut nx, mut ny) = (cx + dx, cy - dy);
            if crate::drivers::gpu::is_absolute() {
                if let Some(ev) = crate::drivers::gpu::mouse_poll() {
                    nx = (ev.x as i64 * d.fb.width as i64 / 65536) as i32;
                    ny = (ev.y as i64 * d.fb.height as i64 / 65536) as i32;
                    nb = ev.buttons;
                    abs_seen = true;
                    if ev.scroll != 0 {
                        d.session.input(&Event::Wheel { x: nx, y: ny, dy: -(ev.scroll as i32) }, &mut d.text, &d.theme);
                        busy = true;
                    }
                } else if abs_seen { nb = buttons; }
            }
            let (nx, ny) = (nx.clamp(0, d.fb.width - 1), ny.clamp(0, d.fb.height - 1));
            if nx != cx || ny != cy {
                d.session.input(&Event::PointerMove { x: nx, y: ny }, &mut d.text, &d.theme);
                busy = true;
            }
            for (bit, btn) in [(1u8, MouseButton::Left), (2, MouseButton::Right), (4, MouseButton::Middle)] {
                if nb & bit != buttons & bit {
                    let ev = if nb & bit != 0 { Event::PointerDown { x: nx, y: ny, button: btn } } else { Event::PointerUp { x: nx, y: ny, button: btn } };
                    d.session.input(&ev, &mut d.text, &d.theme);
                    busy = true;
                }
            }
            buttons = nb;
            // Shell chrome actions.
            for a in core::mem::take(&mut d.session.desktop.actions) {
                match a {
                    ShellAction::Launcher(i) => match i {
                        0 => request(Request::Launch(AppKind::Terminal, None)),
                        1 => request(Request::Launch(AppKind::Files, None)),
                        2 => request(Request::Launch(AppKind::Editor, None)),
                        3 => request(Request::Launch(AppKind::Settings, None)),
                        4 => request(Request::Launch(AppKind::Doom, None)),
                        5 => request(Request::Launch(AppKind::Hello, None)),
                        7 => request(Request::Settings(settings::PAGE_ABOUT)),
                        8 => request(Request::Logout),
                        _ => {}
                    },
                    ShellAction::Dock(i) => {
                        let kind = DOCK[i.min(DOCK.len() - 1)].0;
                        let wins = d.windows_of(kind);
                        match wins.last() {
                            Some(&id) if kind != AppKind::Doom => {
                                let (bus, theme) = (&mut d.session.bus, &d.theme);
                                d.session.desktop.activate(id, bus, theme);
                            }
                            _ => request(Request::Launch(kind, None)),
                        }
                    }
                    ShellAction::Status => request(Request::Settings(settings::PAGE_NETWORK)),
                    ShellAction::Clock => request(Request::Settings(settings::PAGE_TIME)),
                }
            }
        }
        // Requests (outside any borrow of the session state).
        for r in take_requests() {
            busy = true;
            match r {
                Request::Launch(k, arg) => desk().launch(k, arg),
                Request::Settings(page) => {
                    let d = desk();
                    match d.windows_of(AppKind::Settings).last() {
                        Some(&id) => {
                            settings::show_page(id, page);
                            let (bus, theme) = (&mut d.session.bus, &d.theme);
                            d.session.desktop.activate(id, bus, theme);
                        }
                        None => { d.launch(AppKind::Settings, None); settings::show_page(0, page); }
                    }
                }
                Request::SetResolution(w, h) => desk().set_resolution(w, h),
                Request::Exec(id, line, cols, rows) => exec(id, &line, cols, rows),
                Request::Logout => logout = true,
            }
        }
        // Clock / status once a second.
        let d = desk();
        let now = d.now_ms();
        if now / 1000 != last_status {
            last_status = now / 1000;
            d.status();
        }
        let us = d.frame();
        if us == 0 && !busy {
            unsafe { core::arch::asm!("hlt"); }
        }
    }

    // Logout: restore the console.
    let d = unsafe { DESK.take().unwrap() };
    let line = format!(
        "desktop: init {} us, first frame {} us, full recomposite {} us; {} frames, avg {} us, max {} us, avg area {} px\n",
        t_init, d.first_frame_us, d.full_frame_us, d.stats.frames,
        if d.stats.frames > 0 { d.stats.total_us / d.stats.frames } else { 0 }, d.stats.max_us,
        if d.stats.frames > 0 { d.stats.area / d.stats.frames } else { 0 });
    io::set_screen_hook(None, 80, 25);
    if let Some(fb) = Fb::current() {
        if (fb.width, fb.height, fb.stride) == saved_geom {
            unsafe { core::ptr::copy_nonoverlapping(saved.as_ptr(), fb.base, saved_len); }
            crate::drivers::gpu::flush_screen();
            framebuffer::set_cursor_pos(cursor.0, cursor.1);
        } else {
            framebuffer::clear(0);
            framebuffer::set_cursor_pos(0, 0);
        }
    }
    drop(d);
    serial::write_str("[DESKTOP] ");
    serial::write_str(&line);
    serial::write_str("\r");
    io::out(&line);
}

/// Run a shell line for a terminal window, streaming output into it.
fn exec(id: WinId, line: &str, cols: usize, rows: usize) {
    unsafe { HOOK_TARGET = id; }
    io::set_screen_hook(Some(screen_hook), cols as u64, rows as u64);
    crate::arch::x86_64::keyboard::clear_interrupt();
    let status = crate::userspace::plum::run_line(line);
    crate::arch::x86_64::keyboard::clear_interrupt();
    io::set_screen_hook(None, 80, 25);
    unsafe { EXEC_DONE.push((id, status)); }
    // Commands may have drawn straight to the framebuffer (grape, top, ...),
    // and the keyboard driver may hold their leftovers: repaint everything.
    while crate::arch::x86_64::keyboard::try_read_key().is_some() {}
    input::reset();
    desk().session.desktop.invalidate_all();
}
