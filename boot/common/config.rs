/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ospab-boot configuration: parser for ospab.cfg, format version 1.

Shared by the UEFI and BIOS front-ends (included with #[path]). The parser is strict:
every line that is not understood becomes a `ConfigError` with its line number, the
menu shows them, and a configuration with errors never boots by itself.

Format reference: docs/en/boot.md.
*/
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const CONFIG_VERSION: u32 = 1;
pub const MAX_ENTRIES: usize = 32;
pub const MAX_MODULES: usize = 16;
pub const MAX_CMDLINE: usize = 255;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Resolution {
    Keep,
    /// The display's preferred mode (EDID), else the firmware's current mode.
    Auto,
    Max,
    /// Exact size, or the closest mode when it is missing (also the hd/fullhd/2k/4k presets).
    Exact(u32, u32),
}

#[derive(Clone, Copy, PartialEq)]
pub enum Theme {
    Dark,
    Light,
    Mono,
}

#[derive(Clone, Copy, PartialEq)]
pub enum EntryType {
    Ospab,
    EfiChainload,
    Memtest,
    Firmware,
    Reboot,
    Poweroff,
}

impl EntryType {
    pub fn name(self) -> &'static str {
        match self {
            EntryType::Ospab => "ospab",
            EntryType::EfiChainload => "efi-chainload",
            EntryType::Memtest => "memtest",
            EntryType::Firmware => "firmware",
            EntryType::Reboot => "reboot",
            EntryType::Poweroff => "poweroff",
        }
    }

    fn parse(s: &str) -> Option<EntryType> {
        Some(match s {
            "ospab" => EntryType::Ospab,
            "efi-chainload" => EntryType::EfiChainload,
            "memtest" => EntryType::Memtest,
            "firmware" => EntryType::Firmware,
            "reboot" => EntryType::Reboot,
            "poweroff" => EntryType::Poweroff,
            _ => return None,
        })
    }

    /// Keys an entry of this type may carry (besides the common `title`, `type`, `hidden`).
    fn allows(self, key: &str) -> bool {
        match key {
            "title" | "type" | "hidden" => true,
            "kernel" | "module" => self == EntryType::Ospab,
            "cmdline" => matches!(self, EntryType::Ospab | EntryType::Memtest),
            "path" => self == EntryType::EfiChainload,
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub typ: EntryType,
    pub kernel: String,
    pub cmdline: String,
    /// (path, name)
    pub modules: Vec<(String, String)>,
    /// `efi-chainload` target.
    pub path: String,
    pub hidden: bool,
    pub line: usize,
}

#[derive(Clone)]
pub struct Config {
    /// Seconds before the default entry boots; `None` waits for a key forever.
    pub timeout: Option<u32>,
    /// Index into `entries` (always valid when `entries` is not empty).
    pub default: usize,
    pub remember_last: bool,
    pub resolution: Resolution,
    pub serial: bool,
    pub theme: Theme,
    pub entries: Vec<Entry>,
}

pub struct ConfigError {
    /// 1-based; 0 for errors that belong to the file as a whole.
    pub line: usize,
    pub msg: String,
}

pub struct Parsed {
    pub cfg: Config,
    pub errors: Vec<ConfigError>,
}

fn new_config() -> Config {
    Config {
        timeout: Some(5),
        default: 0,
        remember_last: true,
        resolution: Resolution::Auto,
        serial: false,
        theme: Theme::Dark,
        entries: Vec::new(),
    }
}

fn blank_entry(id: &str, line: usize) -> Entry {
    Entry {
        id: id.to_string(),
        title: String::new(),
        typ: EntryType::Ospab,
        kernel: "/boot/KERNEL".to_string(),
        cmdline: String::new(),
        modules: Vec::new(),
        path: String::new(),
        hidden: false,
        line,
    }
}

/// Used when no configuration file exists: boots the kernel at /boot/KERNEL.
pub fn builtin(loader_efi: Option<&str>) -> Config {
    let mut cfg = new_config();
    let mut e = blank_entry("ospab", 0);
    e.title = "ospab.os".to_string();
    e.cmdline = "mode=live".to_string();
    e.modules.push(("/boot/KERNEL".to_string(), "kernel".to_string()));
    if let Some(p) = loader_efi {
        e.modules.push((p.to_string(), "efi".to_string()));
    }
    cfg.entries.push(e);
    cfg
}

fn parse_bool(v: &str) -> Option<bool> {
    match v {
        "yes" | "true" | "on" | "1" => Some(true),
        "no" | "false" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

fn valid_text(s: &str) -> bool {
    s.chars().all(|c| !c.is_control())
}

struct EntryState {
    e: Entry,
    /// (key, line) in file order, for the per-type key check.
    keys: Vec<(String, usize)>,
    type_set: bool,
}

pub fn parse(text: &str) -> Parsed {
    let mut cfg = new_config();
    let mut errors: Vec<ConfigError> = Vec::new();
    let err = |errors: &mut Vec<ConfigError>, line: usize, msg: String| errors.push(ConfigError { line, msg });

    enum Section {
        Global,
        Entry,
        Bad,
    }
    let mut section = Section::Global;
    let mut cur: Option<EntryState> = None;
    let mut done: Vec<EntryState> = Vec::new();
    let mut seen_global: Vec<String> = Vec::new();
    let mut version_seen = false;
    let mut default_id: Option<(String, usize)> = None;

    // Closing an entry validates what needs the whole entry (type-dependent keys).
    fn close(cur: &mut Option<EntryState>, done: &mut Vec<EntryState>, errors: &mut Vec<ConfigError>) {
        let Some(mut st) = cur.take() else { return };
        let line = st.e.line;
        if st.e.title.is_empty() {
            errors.push(ConfigError { line, msg: alloc::format!("entry '{}': missing 'title'", st.e.id) });
        }
        if !st.type_set {
            errors.push(ConfigError { line, msg: alloc::format!("entry '{}': missing 'type'", st.e.id) });
            return; // unusable
        }
        for (k, l) in &st.keys {
            if !st.e.typ.allows(k) {
                errors.push(ConfigError {
                    line: *l,
                    msg: alloc::format!("key '{}' is not valid for type '{}'", k, st.e.typ.name()),
                });
            }
        }
        if st.e.typ == EntryType::EfiChainload && st.e.path.is_empty() {
            errors.push(ConfigError { line, msg: alloc::format!("entry '{}': type efi-chainload needs 'path'", st.e.id) });
        }
        if st.e.title.is_empty() {
            st.e.title = st.e.id.clone();
        }
        done.push(st);
    }

    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !valid_text(line) {
            err(&mut errors, n, "control character in line".to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let Some(inner) = rest.strip_suffix(']') else {
                err(&mut errors, n, "section header without ']'".to_string());
                section = Section::Bad;
                continue;
            };
            close(&mut cur, &mut done, &mut errors);
            let inner = inner.trim();
            if inner == "global" {
                section = Section::Global;
            } else if let Some(id) = inner.strip_prefix("entry").filter(|r| r.starts_with(' ')) {
                let id = id.trim();
                if !valid_id(id) {
                    err(&mut errors, n, alloc::format!("bad entry id '{}' (letters, digits, '-', '_', '.', max 32)", id));
                    section = Section::Bad;
                } else if done.iter().any(|d| d.e.id == id) {
                    err(&mut errors, n, alloc::format!("duplicate entry id '{}'", id));
                    section = Section::Bad;
                } else if done.len() >= MAX_ENTRIES {
                    err(&mut errors, n, alloc::format!("more than {} entries", MAX_ENTRIES));
                    section = Section::Bad;
                } else {
                    cur = Some(EntryState { e: blank_entry(id, n), keys: Vec::new(), type_set: false });
                    section = Section::Entry;
                }
            } else {
                err(&mut errors, n, alloc::format!("unknown section [{}] (use [global] or [entry <id>])", inner));
                section = Section::Bad;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            err(&mut errors, n, "expected 'key = value' or a [section]".to_string());
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty() {
            err(&mut errors, n, "empty key".to_string());
            continue;
        }
        match section {
            Section::Bad => {} // already reported at the header
            Section::Global => {
                if key != "module" && seen_global.iter().any(|k| k == key) {
                    err(&mut errors, n, alloc::format!("duplicate key '{}'", key));
                    continue;
                }
                seen_global.push(key.to_string());
                match key {
                    "version" => {
                        version_seen = true;
                        match value.parse::<u32>() {
                            Ok(CONFIG_VERSION) => {}
                            Ok(v) => err(&mut errors, n, alloc::format!("unsupported version {} (this loader reads version {})", v, CONFIG_VERSION)),
                            Err(_) => err(&mut errors, n, "version must be a number".to_string()),
                        }
                    }
                    "timeout" => {
                        if value == "off" {
                            cfg.timeout = None;
                        } else {
                            match value.parse::<u32>() {
                                Ok(s) if s <= 3600 => cfg.timeout = Some(s),
                                _ => err(&mut errors, n, "timeout must be 0..3600 seconds or 'off'".to_string()),
                            }
                        }
                    }
                    "default" => {
                        if valid_id(value) {
                            default_id = Some((value.to_string(), n));
                        } else {
                            err(&mut errors, n, "default must be an entry id".to_string());
                        }
                    }
                    "remember_last" => match parse_bool(value) {
                        Some(b) => cfg.remember_last = b,
                        None => err(&mut errors, n, "remember_last must be yes or no".to_string()),
                    },
                    "serial" => match parse_bool(value) {
                        Some(b) => cfg.serial = b,
                        None => err(&mut errors, n, "serial must be yes or no".to_string()),
                    },
                    "theme" => match value {
                        "dark" => cfg.theme = Theme::Dark,
                        "light" => cfg.theme = Theme::Light,
                        "mono" => cfg.theme = Theme::Mono,
                        _ => err(&mut errors, n, "theme must be dark, light or mono".to_string()),
                    },
                    "resolution" => {
                        let r = match value {
                            "auto" => Some(Resolution::Auto),
                            "max" => Some(Resolution::Max),
                            "keep" => Some(Resolution::Keep),
                            "hd" => Some(Resolution::Exact(1280, 720)),
                            "fullhd" => Some(Resolution::Exact(1920, 1080)),
                            "2k" => Some(Resolution::Exact(2560, 1440)),
                            "4k" => Some(Resolution::Exact(3840, 2160)),
                            v => v.split_once('x').and_then(|(w, h)| {
                                let (w, h) = (w.parse::<u32>().ok()?, h.parse::<u32>().ok()?);
                                (w >= 320 && h >= 200 && w <= 16384 && h <= 16384).then_some(Resolution::Exact(w, h))
                            }),
                        };
                        match r {
                            Some(r) => cfg.resolution = r,
                            None => err(&mut errors, n, "resolution must be auto, max, keep, hd, fullhd, 2k, 4k or WIDTHxHEIGHT".to_string()),
                        }
                    }
                    _ => err(&mut errors, n, alloc::format!(
                        "unknown global key '{}' (valid: version timeout default remember_last resolution serial theme)", key)),
                }
            }
            Section::Entry => {
                let st = cur.as_mut().unwrap();
                if key != "module" && st.keys.iter().any(|(k, _)| k == key) {
                    err(&mut errors, n, alloc::format!("duplicate key '{}' in entry '{}'", key, st.e.id));
                    continue;
                }
                match key {
                    "title" => {
                        if value.is_empty() || value.chars().count() > 60 {
                            err(&mut errors, n, "title must be 1..60 characters".to_string());
                        } else {
                            st.e.title = value.to_string();
                        }
                    }
                    "type" => match EntryType::parse(value) {
                        Some(t) => {
                            st.e.typ = t;
                            st.type_set = true;
                        }
                        None => err(&mut errors, n, alloc::format!(
                            "unknown type '{}' (ospab efi-chainload memtest firmware reboot poweroff)", value)),
                    },
                    "kernel" | "path" => {
                        if !value.starts_with('/') || value.len() < 2 {
                            err(&mut errors, n, alloc::format!("'{}' must be an absolute path starting with '/'", key));
                        } else if key == "kernel" {
                            st.e.kernel = value.to_string();
                        } else {
                            st.e.path = value.to_string();
                        }
                    }
                    "cmdline" => {
                        if value.len() > MAX_CMDLINE {
                            err(&mut errors, n, alloc::format!("cmdline longer than {} bytes", MAX_CMDLINE));
                        } else {
                            st.e.cmdline = value.to_string();
                        }
                    }
                    "module" => {
                        let (path, name) = value.split_once(' ').unwrap_or((value, ""));
                        if !path.starts_with('/') {
                            err(&mut errors, n, "module must be '<absolute path> [name]'".to_string());
                        } else if st.e.modules.len() >= MAX_MODULES {
                            err(&mut errors, n, alloc::format!("more than {} modules", MAX_MODULES));
                        } else {
                            st.e.modules.push((path.to_string(), name.trim().to_string()));
                        }
                    }
                    "hidden" => match parse_bool(value) {
                        Some(b) => st.e.hidden = b,
                        None => err(&mut errors, n, "hidden must be yes or no".to_string()),
                    },
                    _ => {
                        err(&mut errors, n, alloc::format!(
                            "unknown entry key '{}' (valid: title type kernel cmdline module path hidden)", key));
                        continue;
                    }
                }
                st.keys.push((key.to_string(), n));
            }
        }
    }
    close(&mut cur, &mut done, &mut errors);

    if !version_seen {
        err(&mut errors, 0, alloc::format!("missing 'version = {}' in the global section", CONFIG_VERSION));
    }
    cfg.entries = done.into_iter().map(|d| d.e).collect();
    if cfg.entries.is_empty() {
        err(&mut errors, 0, "no usable entries".to_string());
    }
    if let Some((id, l)) = default_id {
        match cfg.entries.iter().position(|e| e.id == id) {
            Some(p) => cfg.default = p,
            None => err(&mut errors, l, alloc::format!("default '{}' is not an entry id", id)),
        }
    } else if let Some(p) = cfg.entries.iter().position(|e| !e.hidden) {
        cfg.default = p;
    }
    errors.sort_by_key(|e| e.line);
    Parsed { cfg, errors }
}

/// Splits a memtest/other `key=value key=value` command line.
pub fn cmdline_get<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline.split_whitespace().find_map(|t| {
        let (k, v) = t.split_once('=')?;
        (k == key).then_some(v)
    })
}
