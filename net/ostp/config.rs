/*
 * Persistent OSTP client configuration: /etc/ostp/config.json
 *
 *   { "mode": "client", "config_version": 1,
 *     "subscription": "https://…/sub/<token>" | null,
 *     "name": "…", "update_interval_hours": 12, "updated": <unix secs>,
 *     "usage": { "used_bytes": N, "limit_bytes": N | null } | null,
 *     "selected": 0, "links": ["ostp://…", …] }
 *
 * `links` is the server list ("best first", as the server publishes it); a
 * plain `ostp import ostp://…` stores a single link. The root filesystem is a
 * RAM overlay unless a disk is mounted, so this survives reboots only when /etc
 * is persisted.
 */

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ostp_core::serde_json::{self, json, Value};
use ostp_core::share_link::ShareLink;

pub const DIR: &str = "/etc/ostp";
pub const PATH: &str = "/etc/ostp/config.json";

#[derive(Clone, Default)]
pub struct Config {
    pub subscription: Option<String>,
    pub name: String,
    pub interval_h: u32,
    pub updated: u64,
    pub used: Option<u64>,
    pub limit: Option<u64>,
    pub selected: usize,
    pub links: Vec<String>,
}

pub fn load() -> Result<Option<Config>, String> {
    let Some(raw) = crate::fs::read_file(PATH) else { return Ok(None) };
    let text = String::from_utf8(raw).map_err(|_| "config is not UTF-8".to_string())?;
    let v: Value = serde_json::from_str(&text).map_err(|e| alloc::format!("invalid JSON: {}", e))?;
    if v.get("mode").and_then(Value::as_str) != Some("client") {
        return Err("not a client config (\"mode\" must be \"client\")".to_string());
    }
    let links = v
        .get("links")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let usage = v.get("usage").filter(|u| u.is_object());
    Ok(Some(Config {
        subscription: v.get("subscription").and_then(Value::as_str).map(str::to_string),
        name: v.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
        interval_h: v.get("update_interval_hours").and_then(Value::as_u64).unwrap_or(12) as u32,
        updated: v.get("updated").and_then(Value::as_u64).unwrap_or(0),
        used: usage.and_then(|u| u.get("used_bytes")).and_then(Value::as_u64),
        limit: usage.and_then(|u| u.get("limit_bytes")).and_then(Value::as_u64),
        selected: v.get("selected").and_then(Value::as_u64).unwrap_or(0) as usize,
        links,
    }))
}

pub fn save(c: &Config) -> Result<(), String> {
    let usage = match c.used {
        Some(u) => json!({ "used_bytes": u, "limit_bytes": c.limit }),
        None => Value::Null,
    };
    let v = json!({
        "mode": "client",
        "config_version": 1,
        "subscription": c.subscription,
        "name": c.name,
        "update_interval_hours": c.interval_h,
        "updated": c.updated,
        "usage": usage,
        "selected": c.selected,
        "links": c.links,
    });
    let text = serde_json::to_string_pretty(&v).map_err(|e| alloc::format!("{}", e))?;
    if crate::fs::stat(DIR).is_none() {
        let _ = crate::fs::mkdir("/etc");
        crate::fs::mkdir(DIR);
    }
    if crate::fs::write_file(PATH, text.as_bytes()) {
        Ok(())
    } else {
        Err("cannot write /etc/ostp/config.json".to_string())
    }
}

impl Config {
    pub fn parsed(&self) -> Vec<Result<ShareLink, String>> {
        self.links.iter().map(|l| ShareLink::parse(l).map_err(|e| alloc::format!("{}", e))).collect()
    }

    /// The selected server, if any.
    pub fn current(&self) -> Result<ShareLink, String> {
        let l = self
            .links
            .get(self.selected)
            .ok_or_else(|| "no server configured: ostp import <ostp://link | https://…/sub/token>".to_string())?;
        ShareLink::parse(l).map_err(|e| alloc::format!("{}", e))
    }
}
