/*
 * Installer — option pages (step 3 of the wizard).
 *
 *   0 Account            host name, user name, password, auto-login
 *   1 Language & region  installer language, locale, keyboard, time zone, hardware clock
 *   2 Disk               ESP size, size of the data partition (erase mode only)
 *   3 Boot               default menu entry, menu timeout, display resolution
 *   4 Network            DHCP or static, NTP
 *   5 Packages           packages from the medium to preinstall (only if the medium has any)
 *
 * Every page has the same shape: rows, a "Continue" button, ↑↓ to move, ←→ to change a value,
 * Enter to edit or press, Esc for the previous page.
 */

use super::*;
use ospab_os::time::ZONES;

pub const KEYMAPS: [(&str, &str); 4] = [
    ("us", "US QWERTY"),
    ("dvorak", "Dvorak"),
    ("colemak", "Colemak"),
    ("qwertz", "QWERTZ (only Y and Z swapped, ASCII)"),
];
pub const LANGS: [&str; 2] = ["English", "Русский"];
pub const BOOT_ENTRIES: [(&str, &str); 3] = [
    ("ospab", "ospab.os"),
    ("desktop", "ospab.os Desktop"),
    ("debug", "ospab.os (debug)"),
];
pub const TIMEOUTS: [(&str, &str); 6] = [
    ("0", "0 s (no menu)"), ("3", "3 s"), ("5", "5 s"), ("10", "10 s"), ("30", "30 s"), ("off", "wait for a key"),
];
pub const RESOLUTIONS: [(&str, &str); 6] = [
    ("auto", "auto (native size of the screen)"), ("hd", "hd (1280x720)"), ("fullhd", "fullhd (1920x1080)"),
    ("2k", "2k (2560x1440)"), ("4k", "4k (3840x2160)"), ("max", "max (largest mode)"),
];
pub const DATA_GIB: [u64; 9] = [1, 2, 4, 8, 16, 32, 64, 128, 256];
pub const PAGE_COUNT: usize = 6;

pub struct Item { label: &'static str, value: String, hint: &'static str, dim: bool }
fn item(label: &'static str, value: String, hint: &'static str) -> Item { Item { label, value, hint, dim: false } }

#[derive(Clone, Copy, PartialEq)]
enum Act { Left, Right, Enter, PgUp, PgDn }

fn user_char(c: char) -> bool { c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' }
fn ip_char(c: char) -> bool { c.is_ascii_digit() || c == '.' }
fn yes_no(b: bool) -> String { String::from(if b { tr("yes") } else { tr("no") }) }
fn valid_ip(s: &str) -> bool { ospab_os::net::resolver::parse_ipv4(s).is_some() }

fn cycle(v: usize, n: usize, fwd: bool) -> usize { if fwd { (v + 1) % n } else { (v + n - 1) % n } }

/// Does a data partition of `gib` GiB (0 = all) fit behind an ESP of `esp_mb` MiB?
pub fn data_fits(d: &VDisk, esp_mb: u64, gib: u64) -> bool {
    let need = 2048 + esp_mb * 2048 + (if gib == 0 { MIN_ROOT_SECTORS } else { gib * 1024 * 2048 }) + 34;
    need <= d.sectors
}

/// Sector range of the data partition for the chosen sizes.
pub fn data_range(d: &VDisk, cfg: &Config) -> (u64, u64) {
    let start = 2048 + cfg.esp_mb * 2048;
    let all_end = d.sectors.saturating_sub(34);
    if cfg.data_mb == 0 { return (start, all_end); }
    (start, (start + cfg.data_mb * 2048 - 1).min(all_end))
}

/// Which pages are shown: Disk only when erasing, Packages only when the medium has some.
pub fn page_enabled(p: usize, cfg: &Config, img: &Images) -> bool {
    match p {
        2 => !cfg.alongside,
        5 => !img.pkgs.is_empty(),
        _ => true,
    }
}
pub fn next_page(cur: usize, cfg: &Config, img: &Images) -> Option<usize> {
    (cur + 1..PAGE_COUNT).find(|&p| page_enabled(p, cfg, img))
}
pub fn prev_page(cur: usize, cfg: &Config, img: &Images) -> Option<usize> {
    (0..cur).rev().find(|&p| page_enabled(p, cfg, img))
}
pub fn last_page(cfg: &Config, img: &Images) -> usize {
    (0..PAGE_COUNT).rev().find(|&p| page_enabled(p, cfg, img)).unwrap_or(0)
}

pub fn default_config() -> Config {
    let mut c = Config {
        alongside: false, upgrade: false, disk: None, esp_mb: ESP_DEFAULT,
        host: [0u8; 32], host_len: 0, locale: 0,
        user: Field::new(""), pass: Field::new(""), pass2: Field::new(""), autologin: true,
        lang: 0, keymap: 0, zone: 0, rtc_local: false,
        data_mb: 0,
        boot_default: 0, timeout: 2, res: 0,
        net_static: false, addr: Field::new(""), mask: Field::new("255.255.255.0"), gw: Field::new(""), dns: Field::new(""),
        ntp: true,
        pkgs: Vec::new(),
    };
    c.host[..7].copy_from_slice(b"aeterna"); c.host_len = 7;
    c.zone = ZONES.iter().position(|z| z.name == "UTC").unwrap_or(0);
    c
}

/// Generic page: draws `items` + Continue, runs the key loop. `on` handles a key on row `i`
/// (and returns an error text to show), `check` runs when Continue is pressed.
fn run_page(page: usize, cfg: &mut Config, keys_note: bool,
            items: &dyn Fn(&Config) -> Vec<Item>,
            on: &mut dyn FnMut(&mut Config, usize, Act, u64) -> Option<String>,
            check: &dyn Fn(&Config) -> Option<String>,
            extra: &dyn Fn(&Config, usize, u64)) -> Nav {
    const TITLES: [&str; PAGE_COUNT] = ["Account", "Language and region", "Disk layout", "Boot", "Network", "Packages"];
    const SUBS: [&str; PAGE_COUNT] = [
        "Who uses this computer. There is no root user.",
        "Language, keyboard and clock.",
        "How much of the disk the system takes.",
        "What the boot menu does.",
        "How the computer gets its address.",
        "Programs from the installation medium to install now.",
    ];
    let mut cur = 0usize;
    let mut msg: Option<String> = None;
    let mut drawn_lang = usize::MAX;
    loop {
        if drawn_lang != cfg.lang {
            drawn_lang = cfg.lang;
            let sub = format!("{} {}/{}  \u{00B7}  {}", tr("Page"), page + 1, PAGE_COUNT, tr(SUBS[page]));
            chrome(2, tr(TITLES[page]), FG_TITLE, &sub,
                   &[("\u{2191}\u{2193}", tr("Move")), ("\u{2190}\u{2192}", tr("Change")), ("Enter", tr("Edit / Continue")), ("Esc", tr("Back"))]);
        }
        let its = items(cfg);
        let n = its.len();
        cur = cur.min(n);
        for (i, it) in its.iter().enumerate() {
            let selb = i == cur;
            let mut p = Pen::at(0, R_BODY + i as u64).on(if selb { SEL_BG } else { BG });
            p.put(if selb { "\u{25B6} " } else { "  " }, ACCENT);
            if it.label.is_empty() {
                p.put(&it.value, if selb { FG_TITLE } else { FG });
            } else {
                p.put(tr(it.label), if selb { FG_TITLE } else if it.dim { FG_DIM } else { FG }).pad(28);
                let room = (left() + width()).saturating_sub(p.col) as usize;
                let v: String = tr(&it.value).chars().take(room).collect();
                p.raw(&v, if it.dim { FG_DIM } else { FG_TITLE });
            }
            p.pad(width().saturating_sub(24));
            if selb {
                let room = (left() + width()).saturating_sub(p.col) as usize;
                let h: String = tr(it.hint).chars().take(room).collect();
                p.raw(&h, FG_DIM);
            }
            p.pad(width());
        }
        let cr = R_BODY + n as u64 + 1;
        clear_panel_row(cr - 1);
        clear_panel_row(cr);
        Pen::at(2, cr).on(if cur == n { ACCENT } else { KEY_BG }).put(&format!("  {} \u{2192}  ", tr("Continue")), if cur == n { BG } else { FG });
        // Rows below Continue: the error line and the explanation drawn by extra(); a shorter
        // explanation would otherwise leave the tail of the previous one on screen.
        for r in cr + 1..cr + 10 { clear_panel_row(r); }
        match &msg { Some(m) => t(2, cr + 1, m, FG_ERR), None => {} }
        extra(cfg, cur, cr + 3);

        let k = key();
        msg = None;
        let act = match k {
            keyboard::KEY_UP => {
                for _ in 0..=n {
                    cur = if cur == 0 { n } else { cur - 1 };
                    if cur == n || !its[cur].dim { break; }
                }
                continue;
            }
            keyboard::KEY_DOWN | '\t' => {
                for _ in 0..=n {
                    cur = (cur + 1) % (n + 1);
                    if cur == n || !its[cur].dim { break; }
                }
                continue;
            }
            keyboard::KEY_LEFT => Act::Left,
            keyboard::KEY_RIGHT => Act::Right,
            keyboard::KEY_PGUP => Act::PgUp,
            keyboard::KEY_PGDN => Act::PgDn,
            '\n' => Act::Enter,
            ESC => return Nav::Back,
            CTRL_C => return Nav::Quit,
            'q' | 'Q' if false => return Nav::Quit,
            _ => continue,
        };
        if cur == n {
            if act == Act::Enter {
                match check(cfg) { Some(m) => msg = Some(m), None => return Nav::Next }
            }
            continue;
        }
        let was_lang = cfg.lang;
        msg = on(cfg, cur, act, R_BODY + cur as u64);
        if was_lang != cfg.lang { lang::set(cfg.lang); drawn_lang = usize::MAX; }
    }
}

/// Run option page `p`.
pub fn page(p: usize, d: Option<VDisk>, cfg: &mut Config, img: &Images) -> Nav {
    slog(&format!("[INSTALLER] page: options {}\r\n", p));
    match p {
        0 => page_account(cfg),
        1 => page_region(cfg),
        2 => page_disk(d.unwrap(), cfg),
        3 => page_boot(cfg),
        4 => page_network(cfg),
        _ => page_packages(cfg, img),
    }
}

// ── 0 Account ────────────────────────────────────────────────────────────────
fn page_account(cfg: &mut Config) -> Nav {
    run_page(0, cfg, true,
        &|c| alloc::vec![
            item("Host name", String::from(c.hostname()), "Enter to edit"),
            item("User name", if c.user.len == 0 { String::from("-") } else { String::from(c.user.text()) }, "Enter to edit: a-z 0-9 _ -"),
            item("Password", if c.pass.len == 0 { String::from(tr("(none)")) } else { "*".repeat(c.pass.len) }, "Enter to edit; optional"),
            item("Repeat password", if c.pass2.len == 0 { String::from("-") } else { "*".repeat(c.pass2.len) }, "Enter to edit"),
            item("Log in automatically", yes_no(c.autologin), "\u{2190} \u{2192}"),
        ],
        &mut |c, i, a, r| {
            match (i, a) {
                (0, Act::Enter) => {
                    if edit_field(28, r, 34, &mut c.host, &mut c.host_len, false, host_char) && c.host_len == 0 {
                        c.host[..7].copy_from_slice(b"aeterna"); c.host_len = 7;
                    }
                }
                (1, Act::Enter) => { edit_field(28, r, 34, &mut c.user.buf, &mut c.user.len, false, user_char); }
                (2, Act::Enter) => { edit_field(28, r, 34, &mut c.pass.buf, &mut c.pass.len, true, pass_char); }
                (3, Act::Enter) => { edit_field(28, r, 34, &mut c.pass2.buf, &mut c.pass2.len, true, pass_char); }
                (4, _) => c.autologin = !c.autologin,
                _ => {}
            }
            None
        },
        &|c| {
            if !ospab_os::plum::account::valid_name(c.user.text()) {
                return Some(String::from(tr("The user name must start with a letter: a-z, 0-9, _ and - only (not \"root\").")));
            }
            if c.pass.text() != c.pass2.text() { return Some(String::from(tr("The two passwords differ."))); }
            None
        },
        &|c, _cur, row| {
            t(2, row, tr("There is no root user and no permission model yet: every program runs with"), FG_DIM);
            t(2, row + 1, tr("full rights. The account names you and can protect the login with a password."), FG_DIM);
            if c.pass.len == 0 && !c.autologin { t(2, row + 3, tr("No password: the login prompt accepts an empty password."), FG_WARN); }
        })
}

// ── 1 Language and region ────────────────────────────────────────────────────
fn zone_text(i: usize) -> String {
    let z = &ZONES[i];
    let m = z.std_min as i32;
    let (s, a) = if m < 0 { ('-', -m) } else { ('+', m) };
    let mut o = format!("{}  UTC{}{}", z.name, s, a / 60);
    if a % 60 != 0 { o.push_str(&format!(":{:02}", a % 60)); }
    if z.dst != ospab_os::time::Dst::None { o.push_str("  (+1 h summer)"); }
    o
}

fn page_region(cfg: &mut Config) -> Nav {
    run_page(1, cfg, true,
        &|c| alloc::vec![
            item("Installer language", String::from(LANGS[c.lang]), "\u{2190} \u{2192}"),
            item("System locale", String::from(LOCALES[c.locale]), "\u{2190} \u{2192}"),
            item("Keyboard layout", String::from(KEYMAPS[c.keymap].1), "\u{2190} \u{2192}"),
            item("Time zone", zone_text(c.zone), "\u{2190} \u{2192}  PgUp PgDn"),
            item("Hardware clock (RTC)", String::from(if c.rtc_local { tr("local time") } else { tr("UTC") }), "\u{2190} \u{2192}"),
        ],
        &mut |c, i, a, _r| {
            let fwd = a != Act::Left && a != Act::PgUp;
            match i {
                0 => c.lang = cycle(c.lang, LANGS.len(), fwd),
                1 => c.locale = cycle(c.locale, LOCALES.len(), fwd),
                2 => {
                    c.keymap = cycle(c.keymap, KEYMAPS.len(), fwd);
                    keyboard::set_layout(KEYMAPS[c.keymap].0);
                }
                3 => {
                    let n = ZONES.len();
                    c.zone = match a {
                        Act::PgUp => (c.zone + n - 8) % n,
                        Act::PgDn => (c.zone + 8) % n,
                        _ => cycle(c.zone, n, fwd),
                    };
                }
                _ => c.rtc_local = !c.rtc_local,
            }
            None
        },
        &|_| None,
        &|c, _cur, row| {
            if c.rtc_local {
                t(2, row, tr("The clock chip shows local time. Use this when Windows is also installed."), FG_DIM);
            } else {
                t(2, row, tr("The clock chip shows UTC (Linux and ospab.os default). Windows expects local time."), FG_DIM);
            }
            t(2, row + 1, tr("The keyboard layout is active now: try it in the next text field."), FG_DIM);
        })
}

// ── 2 Disk layout ────────────────────────────────────────────────────────────
fn page_disk(d: VDisk, cfg: &mut Config) -> Nav {
    run_page(2, cfg, true,
        &|c| {
            let (s, e) = data_range(&d, c);
            let data = if c.data_mb == 0 { format!("{}  ({})", tr("all free space"), fmt_size((e - s + 1) / 2048)) }
                       else { fmt_size(c.data_mb) };
            alloc::vec![
                item("EFI partition size", format!("{}{}", fmt_size(c.esp_mb), if c.esp_mb == ESP_DEFAULT { "  (recommended)" } else { "" }), "\u{2190} \u{2192}"),
                item("Data partition (AETERNA)", data, "\u{2190} \u{2192}"),
            ]
        },
        &mut |c, i, a, _r| {
            let fwd = a != Act::Left && a != Act::PgUp;
            if i == 0 {
                let fits: Vec<u64> = ESP_SIZES.iter().copied().filter(|&e| esp_fits(&d, e)).collect();
                if !fits.is_empty() {
                    let pos = fits.iter().position(|&e| e == c.esp_mb).unwrap_or(0);
                    c.esp_mb = fits[cycle(pos, fits.len(), fwd)];
                }
            } else {
                let mut sizes: Vec<u64> = alloc::vec![0];
                sizes.extend(DATA_GIB.iter().map(|g| g * 1024).filter(|&mb| data_fits(&d, c.esp_mb, mb / 1024)));
                let pos = sizes.iter().position(|&s| s == c.data_mb).unwrap_or(0);
                c.data_mb = sizes[cycle(pos, sizes.len(), fwd)];
            }
            if !data_fits(&d, c.esp_mb, c.data_mb / 1024) { c.data_mb = 0; }
            None
        },
        &|c| if esp_fits(&d, c.esp_mb) { None } else { Some(String::from(tr("The EFI partition does not fit on this disk."))) },
        &|c, _cur, row| draw_layout(row, &d, c))
}

/// Bar with the ESP, the data partition and the space left over.
fn draw_layout(lr: u64, d: &VDisk, cfg: &Config) {
    let esp_s = cfg.esp_mb * 2048;
    let (ds, de) = data_range(d, cfg);
    let data_s = de + 1 - ds;
    let free_s = d.sectors.saturating_sub(2048 + esp_s + data_s);
    clear_panel_row(lr);
    Pen::at(2, lr).put(tr("Disk layout"), FG_TITLE).put("   /dev/", FG_DIM).put(d.name(), FG).put("  ", FG).put(&fmt_size(d.size_mb), FG_DIM);
    let bw = width() - 4;
    let total = d.sectors.max(1);
    let esp_c = ((bw * esp_s) / total).max(2).min(bw - 2);
    let data_c = ((bw * data_s) / total).max(1).min(bw - esp_c);
    let x = (left() + 2) * CW;
    let y = (lr + 1) * CH;
    framebuffer::fill_rect(x, y, bw * CW, CH, BG);
    framebuffer::fill_rect(x, y + 2, bw * CW, CH - 4, TRACK);
    framebuffer::fill_rect(x, y + 2, esp_c * CW - 2, CH - 4, ESP_COL);
    framebuffer::fill_rect(x + esp_c * CW, y + 2, data_c * CW, CH - 4, ROOT_COL);
    clear_panel_row(lr + 2);
    Pen::at(2, lr + 2).put("\u{2588}", ESP_COL).put(&format!(" EFI (FAT32) {}", fmt_size(cfg.esp_mb)), FG)
        .put("   ", FG).put("\u{2588}", ROOT_COL).put(&format!(" AETERNA {}", fmt_size(data_s / 2048)), FG)
        .put("   ", FG).put("\u{2588}", TRACK).put(&format!(" {} {}", tr("unused"), fmt_size(free_s / 2048)), FG);
}

// ── 3 Boot ───────────────────────────────────────────────────────────────────
fn page_boot(cfg: &mut Config) -> Nav {
    run_page(3, cfg, true,
        &|c| alloc::vec![
            item("Default menu entry", String::from(BOOT_ENTRIES[c.boot_default].1), "\u{2190} \u{2192}"),
            item("Menu timeout", String::from(TIMEOUTS[c.timeout].1), "\u{2190} \u{2192}"),
            item("Display resolution", String::from(RESOLUTIONS[c.res].1), "\u{2190} \u{2192}"),
        ],
        &mut |c, i, a, _r| {
            let fwd = a != Act::Left && a != Act::PgUp;
            match i {
                0 => c.boot_default = cycle(c.boot_default, BOOT_ENTRIES.len(), fwd),
                1 => c.timeout = cycle(c.timeout, TIMEOUTS.len(), fwd),
                _ => c.res = cycle(c.res, RESOLUTIONS.len(), fwd),
            }
            None
        },
        &|_| None,
        &|_c, _cur, row| {
            t(2, row, tr("Written to ospab.cfg on the EFI partition (format: docs/en/boot.md)."), FG_DIM);
        })
}

// ── 4 Network ────────────────────────────────────────────────────────────────
/// Edit an address from scratch; Esc keeps the old one.
fn edit_ip(f: &mut Field, row: u64) {
    let old = *f;
    f.len = 0;
    if !edit_field(28, row, 34, &mut f.buf, &mut f.len, false, ip_char) { *f = old; }
}

fn page_network(cfg: &mut Config) -> Nav {
    run_page(4, cfg, true,
        &|c| {
            let ipv = |f: &Field| if f.len == 0 { String::from("-") } else { String::from(f.text()) };
            let mut v = alloc::vec![
                item("Address assignment", String::from(if c.net_static { tr("static") } else { "DHCP" }), "\u{2190} \u{2192}"),
                item("IP address", ipv(&c.addr), "Enter to edit"),
                item("Network mask", ipv(&c.mask), "Enter to edit"),
                item("Gateway", ipv(&c.gw), "Enter to edit"),
                item("DNS server", ipv(&c.dns), "Enter to edit"),
                item("Set the clock over NTP", yes_no(c.ntp), "\u{2190} \u{2192}"),
            ];
            if !c.net_static { for i in 1..5 { v[i].dim = true; } }
            v
        },
        &mut |c, i, a, r| {
            match (i, a) {
                (0, _) => c.net_static = !c.net_static,
                (5, _) => c.ntp = !c.ntp,
                (1, Act::Enter) if c.net_static => edit_ip(&mut c.addr, r),
                (2, Act::Enter) if c.net_static => edit_ip(&mut c.mask, r),
                (3, Act::Enter) if c.net_static => edit_ip(&mut c.gw, r),
                (4, Act::Enter) if c.net_static => edit_ip(&mut c.dns, r),
                _ => {}
            }
            None
        },
        &|c| {
            if !c.net_static { return None; }
            if !valid_ip(c.addr.text()) { return Some(String::from(tr("The IP address is not valid (example: 192.168.1.50)."))); }
            if !valid_ip(c.mask.text()) { return Some(String::from(tr("The network mask is not valid (example: 255.255.255.0)."))); }
            if c.gw.len > 0 && !valid_ip(c.gw.text()) { return Some(String::from(tr("The gateway is not valid."))); }
            if c.dns.len > 0 && !valid_ip(c.dns.text()) { return Some(String::from(tr("The DNS server is not valid."))); }
            None
        },
        &|c, _cur, row| {
            clear_panel_row(row);
            t(2, row, tr(if c.net_static { "Static settings are written to /etc/network.conf; the kernel uses them instead of DHCP." }
                         else { "DHCP is the default: the router tells the computer its address." }), FG_DIM);
        })
}

// ── 5 Packages ───────────────────────────────────────────────────────────────
/// Persistent layer budget for packages (the layer itself is limited to 8 MiB).
pub const PKG_BUDGET: usize = 6 * 1024 * 1024;

pub fn pkg_total(cfg: &Config, img: &Images) -> usize {
    img.pkgs.iter().enumerate().filter(|(i, _)| cfg.pkgs.get(*i).copied().unwrap_or(false)).map(|(_, p)| p.data.len()).sum()
}

fn page_packages(cfg: &mut Config, img: &Images) -> Nav {
    if cfg.pkgs.len() != img.pkgs.len() { cfg.pkgs = alloc::vec![false; img.pkgs.len()]; }
    run_page(5, cfg, true,
        &|c| img.pkgs.iter().enumerate().map(|(i, p)| {
            let name = String::from(p.file.trim_end_matches(".tmt"));
            Item { label: "", value: format!("[{}] {:<28} {}", if c.pkgs[i] { "x" } else { " " }, name, fmt_bytes(p.data.len() as u64)), hint: "Enter to select", dim: false }
        }).collect(),
        &mut |c, i, _a, _r| {
            let was = c.pkgs[i];
            c.pkgs[i] = !was;
            if !was && pkg_total(c, img) > PKG_BUDGET {
                c.pkgs[i] = false;
                return Some(String::from(tr("Too big: the persistent layer holds 8 MiB in total.")));
            }
            None
        },
        &|_| None,
        &|c, _cur, row| {
            t(2, row, &format!("{}: {} / {}", tr("Selected"), fmt_bytes(pkg_total(c, img) as u64), fmt_bytes(PKG_BUDGET as u64)), FG_DIM);
            t(2, row + 1, tr("They are installed offline with tomato into the saved layer of the new system."), FG_DIM);
        })
}
