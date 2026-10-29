/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Settings — network, OSTP, sound, display, time and about pages.
Written on the oos-ui application API; the system queries are kernel calls
here and become system calls when this app moves to ring 3.
*/

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use oos_ui::app::prelude::*;

pub const PAGE_NETWORK: usize = 0;
pub const PAGE_OSTP: usize = 1;
pub const PAGE_SOUND: usize = 2;
pub const PAGE_DISPLAY: usize = 3;
pub const PAGE_TIME: usize = 4;
pub const PAGE_ABOUT: usize = 5;

static mut PAGE_REQ: Option<usize> = None;

/// Ask the running Settings window to show `page` (consumed on its next tick).
pub fn show_page(_win: WinId, page: usize) { unsafe { PAGE_REQ = Some(page); } }

pub struct Settings {
    win: WinId,
    sidebar: NodeId,
    headline: NodeId,
    pages: Vec<NodeId>,
    page: usize,
    // dynamic labels
    net_status: NodeId,
    net_ip: NodeId,
    net_gw: NodeId,
    net_dns: NodeId,
    net_mac: NodeId,
    ostp_status: NodeId,
    vol_slider: NodeId,
    vol_label: NodeId,
    mode_btns: Vec<NodeId>,
    modes: Vec<(i32, i32)>,
    mode_note: NodeId,
    auto_btn: NodeId,
    scale_btns: Vec<NodeId>,
    time_label: NodeId,
    tz_label: NodeId,
    tz_minus: NodeId,
    tz_plus: NodeId,
    sync_btn: NodeId,
    sync_note: NodeId,
    timer: u32,
}

fn row_kv(ui: &mut Ui, parent: NodeId, key: &str, val: &str) -> NodeId {
    let row = ui.row(parent);
    ui.size(row, Length::Fill(1), Length::Px(34));
    ui.align(row, Align::Start, Align::Center);
    let k = ui.label(row, key, TextRole::Secondary);
    ui.width(k, Length::Px(140));
    ui.label(row, val, TextRole::Body)
}

fn card(ui: &mut Ui, parent: NodeId, theme: &Theme) -> NodeId {
    let c = ui.container(parent, Axis::Column, BoxStyle { bg: Some(theme.color.surface), border: Some(theme.color.hairline), radius: theme.radius.lg });
    ui.padding(c, Insets::xy(16, 8));
    ui.width(c, Length::Fill(1));
    c
}

fn ip4(a: [u8; 4]) -> String { format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]) }

impl Settings {
    pub fn new() -> Settings {
        Settings {
            win: 0, sidebar: 0, headline: 0, pages: Vec::new(), page: 0, net_status: 0, net_ip: 0, net_gw: 0, net_dns: 0, net_mac: 0,
            ostp_status: 0, vol_slider: 0, vol_label: 0, mode_btns: Vec::new(), modes: Vec::new(), mode_note: 0, auto_btn: 0, scale_btns: Vec::new(), time_label: 0, tz_label: 0,
            tz_minus: 0, tz_plus: 0, sync_btn: 0, sync_note: 0, timer: 0,
        }
    }

    fn show(&mut self, cx: &mut Ctx, page: usize) {
        self.page = page.min(self.pages.len() - 1);
        let (win, pages, sb, hl) = (self.win, self.pages.clone(), self.sidebar, self.headline);
        const NAMES: [&str; 6] = ["Network", "OSTP", "Sound", "Display", "Time", "About"];
        let p = self.page;
        if let Some(ui) = cx.ui(win) {
            for (i, &n) in pages.iter().enumerate() { ui.set_visible(n, i == p); }
            ui.set_selected(sb, Some(p));
            ui.set_text(hl, NAMES[p]);
        }
        self.refresh(cx);
    }

    fn refresh(&mut self, cx: &mut Ctx) {
        let win = self.win;
        let up = crate::net::is_up();
        let (ip, gw, dns, mac) = unsafe { (crate::net::OUR_IP, crate::net::GATEWAY_IP, crate::net::DNS_IP, crate::net::OUR_MAC) };
        let mac_s = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        let ostp = crate::net::ostp::is_connected();
        let audio = crate::drivers::audio::is_ready();
        let vol = if audio { crate::drivers::audio::volume() } else { 0 };
        let tz = crate::net::sntp::read_timezone_offset();
        let clock = super::clock_text(tz);
        let tz_s = if tz == 0 { String::from("UTC") } else { format!("UTC{}{}{}", if tz < 0 { '-' } else { '+' }, tz.abs() / 3600, if tz.abs() % 3600 != 0 { format!(":{:02}", tz.abs() % 3600 / 60) } else { String::new() }) };
        let svga = crate::drivers::gpu::svga_ready();
        let me = (self.net_status, self.net_ip, self.net_gw, self.net_dns, self.net_mac, self.ostp_status, self.vol_label, self.vol_slider, self.time_label, self.tz_label, self.mode_note);
        let Some(ui) = cx.ui(win) else { return };
        ui.set_text(me.0, if up { "Connected" } else { "Offline" });
        ui.set_text(me.1, &if up { ip4(ip) } else { String::from("—") });
        ui.set_text(me.2, &if up { ip4(gw) } else { String::from("—") });
        ui.set_text(me.3, &if up { ip4(dns) } else { String::from("—") });
        ui.set_text(me.4, &mac_s);
        ui.set_text(me.5, if ostp { "Tunnel up — traffic goes through OSTP" } else { "Not connected. Use the ostp command to connect." });
        ui.set_text(me.6, &if audio { format!("{}%", vol) } else { String::from("No sound device") });
        if audio && ui.focused() != Some(me.7) { ui.set_slider(me.7, vol as u16 * 10); }
        ui.set_text(me.8, &clock);
        ui.set_text(me.9, &tz_s);
        let (cw, ch, pitch) = crate::drivers::gpu::display::current();
        let auto = crate::drivers::gpu::display::auto_enabled();
        let note = if svga {
            format!("Now {} x {} (pitch {} bytes). Pick a resolution; the screen is resized without a reboot.", cw, ch, pitch)
        } else {
            format!("Now {} x {}. This display driver has a fixed resolution.", cw, ch)
        };
        ui.set_text(me.10, &note);
        let auto_btn = self.auto_btn;
        let vmware = crate::drivers::gpu::vmrpc::available();
        ui.set_text(auto_btn, if !vmware { "Autofit: needs VMware" } else if auto { "Autofit with the VMware window: on" } else { "Autofit with the VMware window: off" });
    }
}

impl Application for Settings {
    fn info(&self) -> AppInfo { AppInfo::new("org.ospab.settings", "Settings", Icon::Settings) }

    fn start(&mut self, cx: &mut Ctx, _arg: Option<&str>) {
        let theme = *cx.theme();
        let c = theme.color;
        let mut ui = Ui::new(Axis::Row, c.bg1);
        let root = ui.root();
        let side = ui.container(root, Axis::Column, BoxStyle { bg: Some(c.surface), border: None, radius: 0 });
        ui.size(side, Length::Px(190), Length::Fill(1));
        ui.padding(side, Insets::new(10, 12, 10, 10));
        let items = alloc::vec![
            ListItem::new(&["Network"]).icon(Icon::Network, None),
            ListItem::new(&["OSTP"]).icon(Icon::Lock, None),
            ListItem::new(&["Sound"]).icon(Icon::Sound, None),
            ListItem::new(&["Display"]).icon(Icon::Display, None),
            ListItem::new(&["Time"]).icon(Icon::Settings, None),
            ListItem::new(&["About"]).icon(Icon::Info, None),
        ];
        self.sidebar = ui.list(side, alloc::vec![Column::new("", Length::Fill(1))], false, items, 32);
        let sep = ui.separator(root);
        ui.size(sep, Length::Px(1), Length::Fill(1));
        let content = ui.column(root);
        ui.size(content, Length::Fill(1), Length::Fill(1));
        ui.padding(content, Insets::new(28, 22, 28, 20));
        ui.gap(content, 14);
        self.headline = ui.label(content, "Network", TextRole::Headline);

        // Network.
        let p = ui.column(content);
        ui.gap(p, 12);
        let cd = card(&mut ui, p, &theme);
        self.net_status = row_kv(&mut ui, cd, "Status", "");
        ui.separator(cd);
        self.net_ip = row_kv(&mut ui, cd, "IP address", "");
        self.net_gw = row_kv(&mut ui, cd, "Gateway", "");
        self.net_dns = row_kv(&mut ui, cd, "DNS", "");
        ui.separator(cd);
        self.net_mac = row_kv(&mut ui, cd, "MAC address", "");
        self.pages.push(p);

        // OSTP.
        let p = ui.column(content);
        ui.gap(p, 12);
        let cd = card(&mut ui, p, &theme);
        self.ostp_status = row_kv(&mut ui, cd, "Tunnel", "");
        ui.paragraph(p, "OSTP is the ospab secure tunnel. Connect and disconnect with the ostp command in the terminal.", TextRole::Secondary);
        self.pages.push(p);

        // Sound.
        let p = ui.column(content);
        ui.gap(p, 12);
        let cd = card(&mut ui, p, &theme);
        self.vol_label = row_kv(&mut ui, cd, "Output volume", "");
        self.vol_slider = ui.slider(cd, 500);
        ui.height(self.vol_slider, Length::Px(34));
        self.pages.push(p);

        // Display.
        let p = ui.column(content);
        ui.gap(p, 12);
        self.mode_note = ui.paragraph(p, "", TextRole::Secondary);
        let g = ui.grid(p, 3);
        ui.gap(g, 8);
        for (w, h) in crate::drivers::gpu::display::list() {
            let b = ui.button(g, &format!("{} × {}", w, h), ButtonKind::Secondary);
            self.mode_btns.push(b);
            self.modes.push((w as i32, h as i32));
        }
        self.auto_btn = ui.button(p, "", ButtonKind::Secondary);
        self.pages.push(p);

        // Time.
        let p = ui.column(content);
        ui.gap(p, 12);
        let cd = card(&mut ui, p, &theme);
        self.time_label = row_kv(&mut ui, cd, "Local time", "");
        ui.separator(cd);
        let r = ui.row(cd);
        ui.size(r, Length::Fill(1), Length::Px(44));
        ui.align(r, Align::Start, Align::Center);
        ui.gap(r, 8);
        let k = ui.label(r, "Time zone", TextRole::Secondary);
        ui.width(k, Length::Px(140));
        self.tz_minus = ui.button(r, "−", ButtonKind::Secondary);
        self.tz_label = ui.label(r, "UTC", TextRole::Strong);
        ui.width(self.tz_label, Length::Px(80));
        self.tz_plus = ui.button(r, "+", ButtonKind::Secondary);
        let r = ui.row(p);
        ui.align(r, Align::Start, Align::Center);
        ui.gap(r, 12);
        self.sync_btn = ui.button(r, "Sync now", ButtonKind::Primary);
        self.sync_note = ui.label(r, "", TextRole::Secondary);
        self.pages.push(p);

        // About.
        let p = ui.column(content);
        ui.gap(p, 12);
        let cd = card(&mut ui, p, &theme);
        row_kv(&mut ui, cd, "System", super::ver::OS_VERSION);
        row_kv(&mut ui, cd, "Kernel", super::ver::KERNEL_VERSION);
        row_kv(&mut ui, cd, "Build", super::ver::KERNEL_BUILD);
        row_kv(&mut ui, cd, "Architecture", super::ver::ARCH);
        row_kv(&mut ui, cd, "License", super::ver::LICENSE);
        self.pages.push(p);

        let win = cx.open_window(WindowSpec::new("Settings", 760, 500).min_size(560, 380), ui);
        self.win = win;
        self.timer = cx.set_timer(1000, true);
        self.show(cx, 0);
    }

    fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent) {
        match ev {
            AppEvent::CloseRequested => cx.close_window(win),
            AppEvent::Timer(_) => self.refresh(cx),
            AppEvent::Action(Action::Selected(n, i)) if *n == self.sidebar => self.show(cx, *i),
            AppEvent::Action(Action::ValueChanged(n, v)) if *n == self.vol_slider => {
                if crate::drivers::audio::is_ready() { crate::drivers::audio::set_volume((*v / 10) as u8); }
                let label = self.vol_label;
                if let Some(ui) = cx.ui(win) { ui.set_text(label, &format!("{}%", *v / 10)); }
            }
            AppEvent::Action(Action::Clicked(n)) => {
                let n = *n;
                if let Some(i) = self.mode_btns.iter().position(|&b| b == n) {
                    super::request(super::Request::SetResolution(self.modes[i].0, self.modes[i].1));
                } else if n == self.auto_btn {
                    use crate::drivers::gpu::display;
                    if crate::drivers::gpu::vmrpc::available() { display::save_auto(!display::auto_enabled()); }
                    self.refresh(cx);
                } else if n == self.tz_minus || n == self.tz_plus {
                    let cur = crate::net::sntp::read_timezone_offset() / 3600;
                    let new = (cur + if n == self.tz_plus { 1 } else { -1 }).clamp(-12, 14);
                    let s = if new == 0 { String::from("UTC\n") } else { format!("UTC{}{}\n", if new < 0 { '-' } else { '+' }, new.abs()) };
                    crate::fs::write_file("/etc/timezone", s.as_bytes());
                    crate::net::sntp::invalidate_tz_cache();
                    self.refresh(cx);
                } else if n == self.sync_btn {
                    let note = self.sync_note;
                    let msg = if !crate::net::is_up() { "No network." }
                        else if crate::net::sntp::sync_system_time().is_ok() { "Clock synchronised." }
                        else { "Synchronisation failed." };
                    if let Some(ui) = cx.ui(win) { ui.set_text(note, msg); }
                    self.refresh(cx);
                }
            }
            _ => {}
        }
    }

    fn tick(&mut self, cx: &mut Ctx) {
        if let Some(p) = unsafe { PAGE_REQ.take() } { if self.win != 0 { self.show(cx, p); cx.activate(self.win); } }
    }
}
