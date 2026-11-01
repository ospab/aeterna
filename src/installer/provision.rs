/*
 * Installer — the first contents of the persistent layer on the AETERNA partition.
 *
 * The kernel restores the writable layer from a flat image at partition start + 8 sectors
 * (format: vfs/disk_sync.rs). The installer writes that image itself, so the first boot already
 * has the host name, the user account, the time zone, the network settings and the preinstalled
 * packages. Everything here is plain files; the list of paths is also what the Confirm page
 * shows.
 *
 * Files:
 *   /etc/hostname /etc/passwd /etc/login.conf /etc/locale /etc/keyboard /etc/timezone
 *   /etc/rtc_mode /etc/network.conf [/etc/resolv.conf] /home/<user>/ /var/log/install.log
 *   + the files of the preinstalled packages and their records in /var/lib/tomato/local/
 */

use super::*;
use alloc::collections::BTreeMap;
use ospab_os::fs::ramfs::RamNode;

/// Largest image the kernel reads back (vfs/disk_sync.rs MAX_FS_BYTES).
pub const MAX_STORE_BYTES: usize = 8 * 1024 * 1024;
/// Sectors skipped at the start of the AETERNA partition (identity record and spare).
pub const STORE_OFFSET: u64 = 8;
const SUPER_MAGIC: u64 = 0x41455445524E41;
const MAGIC: &[u8; 10] = b"AETERNA_FS";
const VERSION: u32 = 1;

pub const DEFAULT_RESOLV: &str = "nameserver 1.1.1.1\nnameserver 1.0.0.1\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n";

fn file(tree: &mut BTreeMap<String, RamNode>, path: &str, text: &str) {
    tree.insert(String::from(path), RamNode::File(text.as_bytes().to_vec()));
}

fn dirs(tree: &mut BTreeMap<String, RamNode>, path: &str) {
    let mut cur = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        cur.push('/');
        cur.push_str(part);
        tree.entry(cur.clone()).or_insert(RamNode::Dir);
    }
}

/// (path, short description) of everything the installer puts in the persistent layer,
/// not counting package files.
pub fn planned_files(cfg: &Config) -> Vec<(String, &'static str)> {
    let mut v: Vec<(String, &'static str)> = alloc::vec![
        (String::from("/etc/hostname"), "host name"),
        (String::from("/etc/passwd"), "user account (salted hash)"),
        (String::from("/etc/login.conf"), "auto-login"),
        (String::from("/etc/locale"), "locale"),
        (String::from("/etc/keyboard"), "keyboard layout"),
        (String::from("/etc/timezone"), "time zone"),
        (String::from("/etc/rtc_mode"), "RTC mode"),
        (String::from("/etc/network.conf"), "network"),
    ];
    if cfg.net_static && cfg.dns.len > 0 { v.push((String::from("/etc/resolv.conf"), "DNS server")); }
    v.push((format!("/home/{}/", cfg.user.text()), "home directory"));
    v.push((String::from("/var/log/install.log"), "install log"));
    v
}

/// The network settings file.
pub fn network_conf(cfg: &Config) -> String {
    let mut s = String::from("# ospab.os network configuration (written by the installer)\n");
    if cfg.net_static {
        s.push_str("mode = static\n");
        s.push_str(&format!("address = {}\nmask = {}\ngateway = {}\ndns = {}\n",
            cfg.addr.text(), cfg.mask.text(), cfg.gw.text(), cfg.dns.text()));
    } else {
        s.push_str("mode = dhcp\n");
    }
    s.push_str(if cfg.ntp { "ntp = yes\n" } else { "ntp = no\n" });
    s
}

/// Build the tree of the persistent layer (without packages and log).
pub fn base_tree(cfg: &Config) -> BTreeMap<String, RamNode> {
    let mut t: BTreeMap<String, RamNode> = BTreeMap::new();
    t.insert(String::from("/"), RamNode::Dir);
    for d in ["/etc", "/home", "/var", "/var/log"] { dirs(&mut t, d); }
    let user = cfg.user.text();
    dirs(&mut t, &format!("/home/{}", user));

    file(&mut t, "/etc/hostname", &format!("{}\n", cfg.hostname()));

    let mut salt = [0u8; 16];
    ospab_os::plum::account::random_bytes(&mut salt);
    let hash = ospab_os::plum::account::make_hash_field(cfg.pass.text(), &salt);
    let acct = ospab_os::plum::account::Account {
        name: String::from(user),
        hash,
        uid: ospab_os::plum::account::FIRST_UID,
        home: format!("/home/{}", user),
        shell: String::from(ospab_os::plum::account::SHELL_PATH),
    };
    file(&mut t, "/etc/passwd", &ospab_os::plum::account::passwd_line(&acct));
    file(&mut t, "/etc/login.conf", &format!("# console login\nautologin = {}\nuser = {}\n",
        if cfg.autologin { "yes" } else { "no" }, user));
    file(&mut t, "/etc/locale", &format!("LANG={}\n", LOCALES[cfg.locale]));
    file(&mut t, "/etc/keyboard", &format!("{}\n", opts::KEYMAPS[cfg.keymap].0));
    file(&mut t, "/etc/timezone", &format!("{}\n", ospab_os::time::ZONES[cfg.zone].name));
    file(&mut t, "/etc/rtc_mode", if cfg.rtc_local { "local\n" } else { "utc\n" });
    file(&mut t, "/etc/network.conf", &network_conf(cfg));
    if cfg.net_static && cfg.dns.len > 0 {
        file(&mut t, "/etc/resolv.conf", &format!("# written by the installer\nnameserver {}\n{}", cfg.dns.text(), DEFAULT_RESOLV));
    }
    t
}

/// Install the selected packages the way `tomato install <file.tmt>` does, copy what they wrote
/// into `tree`, and undo it in the live system. Returns (installed names, problems).
pub fn add_packages(cfg: &Config, img: &Images, tree: &mut BTreeMap<String, RamNode>) -> (Vec<String>, Vec<String>) {
    use ospab_os::plum::io;
    let mut done = Vec::new();
    let mut bad = Vec::new();
    // tomato prints its messages; keep them off the installer screen.
    let depth = io::depth();
    io::push(io::Sink::Null, io::ErrSink::Null, io::Stdin::Console);
    for (i, p) in img.pkgs.iter().enumerate() {
        if !cfg.pkgs.get(i).copied().unwrap_or(false) { continue; }
        let hdr = match ospab_os::userspace::tomato::tmt_parse_header(p.data) {
            Some(h) => h,
            None => { bad.push(format!("{}: not a .tmt package", p.file)); continue; }
        };
        let source = format!("/packages/{}", p.file);
        slog("[INSTALLER] preinstall "); slog(&p.file); slog("\r\n");
        // tomato writes into the live file system; nothing of it must reach the live disk copy.
        if !ospab_os::userspace::tomato::install_package_bytes(p.data, &source) {
            bad.push(format!("{}: tomato refused it", p.file));
            continue;
        }
        let rec_path = format!("/var/lib/tomato/local/{}", hdr.name);
        let rec = ospab_os::fs::read_file(&rec_path).unwrap_or_default();
        let mut paths: Vec<String> = Vec::new();
        for line in core::str::from_utf8(&rec).unwrap_or("").lines() {
            if let Some(f) = line.strip_prefix("file=") { paths.push(String::from(f)); }
        }
        let mut ok = true;
        for path in &paths {
            match ospab_os::fs::read_file(path) {
                Some(d) => {
                    if let Some(slash) = path.rfind('/') { dirs(tree, &path[..slash]); }
                    tree.insert(path.clone(), RamNode::File(d));
                }
                None => ok = false,
            }
        }
        dirs(tree, "/var/lib/tomato/local");
        tree.insert(rec_path.clone(), RamNode::File(rec));
        if ok { done.push(format!("{} {}", hdr.name, hdr.pkg_version)); }
        else { bad.push(format!("{}: some files could not be read back", p.file)); }
        // Undo in the live system
        for path in &paths { ospab_os::fs::remove(path); }
        ospab_os::fs::remove(&rec_path);
    }
    io::truncate(depth);
    (done, bad)
}

/// Flat image in the format of vfs/disk_sync.rs, padded to whole sectors.
pub fn serialize(tree: &BTreeMap<String, RamNode>) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&SUPER_MAGIC.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // sector count, patched below
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&VERSION.to_le_bytes());
    b.extend_from_slice(&(tree.len() as u32).to_le_bytes());
    for (path, node) in tree {
        b.extend_from_slice(&(path.len() as u16).to_le_bytes());
        b.extend_from_slice(path.as_bytes());
        match node {
            RamNode::Dir => b.push(1),
            RamNode::File(d) => {
                b.push(0);
                b.extend_from_slice(&(d.len() as u32).to_le_bytes());
                b.extend_from_slice(d);
            }
        }
    }
    let sectors = (b.len() + 511) / 512;
    b.resize(sectors * 512, 0);
    b[8..12].copy_from_slice(&(sectors as u32).to_le_bytes());
    b
}

/// Write the image at `lba` with `write(lba, data)` in chunks of 64 sectors.
pub fn write_store(lba: u64, image: &[u8], write: &mut dyn FnMut(u64, &[u8]) -> bool) -> bool {
    if image.len() > MAX_STORE_BYTES { return false; }
    let mut off = 0usize;
    while off < image.len() {
        let n = (image.len() - off).min(64 * 512);
        if !write(lba + (off / 512) as u64, &image[off..off + n]) { return false; }
        off += n;
    }
    true
}

/// Read the image back from `lba` and compare it with `tree`.
pub fn verify_store(disk: usize, lba: u64, tree: &BTreeMap<String, RamNode>) -> bool {
    let mut hdr = [0u8; 512];
    if !disk_read(disk, lba, 1, &mut hdr) { return false; }
    let sectors = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
    if sectors == 0 || sectors * 512 > MAX_STORE_BYTES { return false; }
    let mut buf = alloc::vec![0u8; sectors * 512];
    let mut done = 0usize;
    while done < sectors {
        let n = (sectors - done).min(64);
        if !disk_read(disk, lba + done as u64, n as u32, &mut buf[done * 512..(done + n) * 512]) { return false; }
        done += n;
    }
    let got = match ospab_os::fs::disk_sync::deserialize_ramfs(&buf) { Some(g) => g, None => return false };
    if got.len() != tree.len() { return false; }
    for (k, v) in tree {
        match (got.get(k), v) {
            (Some(RamNode::Dir), RamNode::Dir) => {}
            (Some(RamNode::File(a)), RamNode::File(b)) if a == b => {}
            _ => return false,
        }
    }
    true
}
