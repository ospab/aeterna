/*
 * Installer — "Upgrade an existing installation".
 *
 * Replaces the loader, the kernel and ospab.cfg on the ESP of an ospab.os installed by this
 * installer (whole-disk install: \EFI\BOOT\BOOTX64.EFI, \boot\KERNEL, \boot\ospab.cfg;
 * alongside install: \EFI\ospab\OSPABLDR.EFI, KERNEL, ospab.cfg) and nothing else:
 *
 *   - the old kernel stays as KERNEL.OLD (the directory entry is renamed, no copy), and the new
 *     ospab.cfg gets the entry "ospab.os (previous)" that boots it;
 *   - the choices in the old ospab.cfg (timeout, default entry, resolution, theme, extra
 *     entries) are kept; the standard entries are regenerated;
 *   - the AETERNA partition (account, settings, packages), the GPT and every other partition are
 *     never written; the guarded writer refuses any LBA outside the ESP.
 *
 * Order of writes: file data into free clusters, then the FAT, then the directory entries (the
 * switch itself), then read-back of everything.
 */

use super::*;

const NAME_BOOT: &[u8; 11] = b"BOOT       ";
const NAME_OLD: &[u8; 11] = b"KERNEL  OLD";
const NAME_BOOTX64: &[u8; 11] = b"BOOTX64 EFI";

/// An ospab.os installation found on a disk.
struct Install {
    disk: VDisk,
    part: Part,
    esp_start: u64,
    host: String,
    version: String,
    identity: [u8; 512],
}

fn field(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from(core::str::from_utf8(&b[..end]).unwrap_or("?").trim())
}

fn detect(disks: &[VDisk]) -> Vec<Install> {
    let mut v = Vec::new();
    for d in disks {
        if d.too_small() { continue; }
        let g = match parse_gpt(d) { Ok(g) => g, Err(_) => continue };
        for p in &g.parts {
            if p.type_guid != LINUX_GUID || p.name != "AETERNA" { continue; }
            let mut id = [0u8; 512];
            if !disk_read(d.index, p.start, 1, &mut id) || &id[0..8] != b"AETERNA " || id[510] != 0xAE || id[511] != 0x05 { continue; }
            let esp_start = rd64(&id, 96);
            if !g.parts.iter().any(|e| e.is_esp() && e.start == esp_start) { continue; }
            slog("[UPGRADE] found an installation on /dev/"); slog(d.name()); slog("\r\n");
            v.push(Install { disk: *d, part: p.clone(), esp_start, host: field(&id[48..80]), version: field(&id[8..24]), identity: id });
        }
    }
    v
}

/// Where the three files live on the ESP.
struct Where {
    alongside: bool,
    kernel_dir: u32,
    loader_dir: u32,
    loader_name: &'static [u8; 11],
    loader_shown: &'static str,
    loader_path: &'static str,
    kernel_path: &'static str,
    old_path: &'static str,
    cfg_path: &'static str,
}

/// Location (sector, byte offset) of a directory entry.
fn dir_loc(fat: &Fat, ov: &Ov, dir: u32, name: &[u8; 11]) -> Result<Option<(u64, usize)>, String> {
    for c in fat.chain(ov, dir)? {
        for s in 0..fat.spc as u64 {
            let lba = fat.clus_lba(c) + s;
            let sec = ov.read(lba)?;
            for e in 0..16 {
                let ent = &sec[e * 32..e * 32 + 32];
                if ent[0] == 0 { return Ok(None); }
                if ent[0] == 0xE5 || ent[11] & 0x0F == 0x0F || ent[11] & 0x08 != 0 { continue; }
                if &ent[0..11] == name { return Ok(Some((lba, e * 32))); }
            }
        }
    }
    Ok(None)
}

fn read_file_data(fat: &Fat, ov: &Ov, hit: &DirHit) -> Option<Vec<u8>> {
    let chain = fat.chain(ov, hit.cluster).ok()?;
    let cb = fat.spc as usize * 512;
    let mut out: Vec<u8> = Vec::with_capacity(hit.size as usize);
    let mut buf = alloc::vec![0u8; cb];
    for c in chain {
        if out.len() >= hit.size as usize { break; }
        if !disk_read(ov.disk, fat.clus_lba(c), fat.spc, &mut buf) { return None; }
        out.extend_from_slice(&buf);
    }
    out.truncate(hit.size as usize);
    Some(out)
}

fn free_chain(fat: &Fat, ov: &mut Ov, first: u32) -> Result<usize, String> {
    let chain = fat.chain(ov, first)?;
    for &c in &chain { fat.set(ov, c, 0)?; }
    Ok(chain.len())
}

/// Point a directory entry at new data.
fn retarget(ov: &mut Ov, loc: (u64, usize), cluster: u32, size: u32) -> Result<(), String> {
    let s = ov.edit(loc.0, "dir-edit")?;
    let e = &mut s[loc.1..loc.1 + 32];
    w16(e, 20, (cluster >> 16) as u16);
    w16(e, 26, (cluster & 0xFFFF) as u16);
    w32(e, 28, size);
    Ok(())
}

struct UpPlan {
    esp: Part,
    fat: Fat,
    ov: Ov,
    wh: Where,
    files: Vec<FileJob>,       // new loader, kernel, ospab.cfg
    old_kernel: (u32, u32),    // first cluster and size of the kernel that becomes KERNEL.OLD
    replaced_old: bool,        // an older KERNEL.OLD existed and is dropped
    kept_entries: Vec<String>,
    old_cfg_found: bool,
    allowed: Vec<(u64, u64)>,
    total: u64,
}

fn build(inst: &Install, img: &Images) -> Result<UpPlan, String> {
    let d = &inst.disk;
    let g = parse_gpt(d)?;
    let esp = g.parts.iter().find(|e| e.is_esp() && e.start == inst.esp_start)
        .ok_or_else(|| String::from("The EFI partition of this installation is gone."))?.clone();
    let fat = parse_fat(d.index, &esp)?;
    let mut ov = Ov::new(d.index);
    if img.efi.is_empty() || img.kernel.is_empty() {
        return Err(String::from("The installer medium has no loader or kernel."));
    }

    // Layout: \EFI\ospab (alongside) or \boot (whole disk)
    let efi = fat.dir_find(&ov, fat.root, NAME_EFI)?.filter(|h| h.is_dir);
    let along_dir = match &efi { Some(h) => fat.dir_find(&ov, h.cluster, NAME_DIR)?.filter(|h| h.is_dir), None => None };
    let wh = if let Some(od) = along_dir {
        Where { alongside: true, kernel_dir: od.cluster, loader_dir: od.cluster, loader_name: NAME_LDR,
                loader_shown: "OSPABLDR.EFI", loader_path: "\\EFI\\ospab\\OSPABLDR.EFI",
                kernel_path: "\\EFI\\ospab\\KERNEL", old_path: "\\EFI\\ospab\\KERNEL.OLD", cfg_path: "\\EFI\\ospab\\ospab.cfg" }
    } else {
        let boot = fat.dir_find(&ov, fat.root, NAME_BOOT)?.filter(|h| h.is_dir)
            .ok_or_else(|| String::from("Neither \\EFI\\ospab nor \\boot exists on the EFI partition:\nthis is not an installation made by this installer."))?;
        let efi = efi.ok_or_else(|| String::from("\\EFI is missing on the EFI partition."))?;
        let bd = fat.dir_find(&ov, efi.cluster, NAME_BOOT)?.filter(|h| h.is_dir)
            .ok_or_else(|| String::from("\\EFI\\BOOT is missing on the EFI partition."))?;
        Where { alongside: false, kernel_dir: boot.cluster, loader_dir: bd.cluster, loader_name: NAME_BOOTX64,
                loader_shown: "BOOTX64.EFI", loader_path: "\\EFI\\BOOT\\BOOTX64.EFI",
                kernel_path: "\\boot\\KERNEL", old_path: "\\boot\\KERNEL.OLD", cfg_path: "\\boot\\ospab.cfg" }
    };
    let k_hit = fat.dir_find(&ov, wh.kernel_dir, NAME_KRN)?.ok_or_else(|| String::from("KERNEL is missing next to ospab.cfg."))?;
    let c_hit = fat.dir_find(&ov, wh.kernel_dir, NAME_CFG)?.ok_or_else(|| String::from("ospab.cfg is missing."))?;
    let l_hit = fat.dir_find(&ov, wh.loader_dir, wh.loader_name)?.ok_or_else(|| String::from("The loader file is missing."))?;
    if k_hit.is_dir || c_hit.is_dir || l_hit.is_dir { return Err(String::from("An expected file is a directory; refusing.")); }
    let old_cfg = read_file_data(&fat, &ov, &c_hit).and_then(|b| String::from_utf8(b).ok());

    // New ospab.cfg: choices of the old one, standard entries regenerated, plus "previous"
    let (globals, extra) = match &old_cfg {
        Some(t) => (Globals::from_old(t), extra_sections(t)),
        None => (Globals::from_old(""), String::new()),
    };
    let cfg_text: &'static [u8] = alloc::boxed::Box::leak(build_cfg(wh.alongside, &globals, true, &extra).into_boxed_str()).as_bytes();
    let kept_entries: Vec<String> = extra.lines().filter_map(|l| l.trim().strip_prefix("[entry ").and_then(|r| r.strip_suffix(']')).map(String::from)).collect();

    // An older KERNEL.OLD goes away (its clusters are freed and its entry is reused)
    let mut replaced_old = false;
    if let Some(loc) = dir_loc(&fat, &ov, wh.kernel_dir, NAME_OLD)? {
        let h = fat.dir_find(&ov, wh.kernel_dir, NAME_OLD)?.unwrap();
        if h.cluster >= 2 { free_chain(&fat, &mut ov, h.cluster)?; }
        ov.edit(loc.0, "dir-edit")?[loc.1] = 0xE5;
        replaced_old = true;
    }

    // New files into free clusters
    let cb = fat.spc as usize * 512;
    let spec: [(&'static str, &'static [u8; 11], &'static [u8]); 3] = [
        (wh.loader_shown, wh.loader_name, img.efi),
        ("KERNEL", NAME_KRN, img.kernel),
        ("ospab.cfg", NAME_CFG, cfg_text),
    ];
    let mut files = Vec::new();
    for (shown, name, data) in spec {
        let n = (data.len() + cb - 1) / cb;
        let clusters = fat.alloc(&mut ov, n)?;
        fat.link(&mut ov, &clusters)?;
        files.push(FileJob { shown, name, data, clusters });
    }

    // Directory switch: old kernel -> KERNEL.OLD, new KERNEL, new cfg and loader in place
    let kloc = dir_loc(&fat, &ov, wh.kernel_dir, NAME_KRN)?.ok_or_else(|| String::from("KERNEL entry not found."))?;
    ov.edit(kloc.0, "dir-edit")?[kloc.1..kloc.1 + 11].copy_from_slice(NAME_OLD);
    fat.dir_add(&mut ov, wh.kernel_dir, &mk_entry(NAME_KRN, 0x20, 0, files[1].clusters[0], img.kernel.len() as u32))?;
    let cloc = dir_loc(&fat, &ov, wh.kernel_dir, NAME_CFG)?.ok_or_else(|| String::from("ospab.cfg entry not found."))?;
    retarget(&mut ov, cloc, files[2].clusters[0], cfg_text.len() as u32)?;
    if c_hit.cluster >= 2 { free_chain(&fat, &mut ov, c_hit.cluster)?; }
    let lloc = dir_loc(&fat, &ov, wh.loader_dir, wh.loader_name)?.ok_or_else(|| String::from("Loader entry not found."))?;
    retarget(&mut ov, lloc, files[0].clusters[0], img.efi.len() as u32)?;
    if l_hit.cluster >= 2 { free_chain(&fat, &mut ov, l_hit.cluster)?; }

    // FSInfo counters are stale now: mark them unknown so the next OS recounts.
    if let Some(l) = fat.fsinfo_lba {
        let s = ov.read(l)?;
        if rd32(&s, 0) == 0x4161_5252 && rd32(&s, 484) == 0x6141_7272 {
            let m = ov.edit(l, "FSInfo")?;
            w32(m, 488, 0xFFFF_FFFF);
            w32(m, 492, 0xFFFF_FFFF);
        }
    }

    let mut total = ov.map.len() as u64;
    for f in &files { total += f.clusters.len() as u64 * fat.spc as u64; }
    let allowed = alloc::vec![(esp.start, esp.end + 1)];
    Ok(UpPlan {
        esp, fat, ov, wh, files, old_kernel: (k_hit.cluster, k_hit.size), replaced_old, kept_entries,
        old_cfg_found: old_cfg.is_some(), allowed, total,
    })
}

// ── Pages ────────────────────────────────────────────────────────────────────

pub fn run(disks: &[VDisk], img: &Images) -> Nav {
    slog("[UPGRADE] scanning for installations\r\n");
    let found = detect(disks);
    chrome(1, tr("Choose the installation to upgrade"), FG_TITLE,
           tr("Only the loader, the kernel and ospab.cfg are replaced. Your data is not touched."),
           &[("\u{2191}\u{2193}", "Select"), ("Enter", "Use this disk"), ("Esc", "Back"), ("Q", "Quit")]);
    if found.is_empty() {
        error_box(R_BODY, tr("Nothing to upgrade"),
            tr("No ospab.os installation was found on the disks of this computer.\nAn installation has an AETERNA partition with an identity record and the\nEFI partition it belongs to. Nothing was changed."));
        footer(&[("Esc", "Back")], "");
        drain_keys();
        loop {
            match key() {
                ESC | '\n' => return Nav::Back,
                CTRL_C | 'q' | 'Q' => return Nav::Quit,
                _ => {}
            }
        }
    }
    Pen::at(2, R_BODY).put("DEVICE", FG_DIM).pad(16).put("HOST", FG_DIM).pad(34).put("VERSION", FG_DIM).pad(52).put("EFI PARTITION", FG_DIM);
    hrule(R_BODY + 1);
    let mut sel = 0usize;
    let mut msg: Option<String> = None;
    loop {
        for (i, f) in found.iter().enumerate() {
            let r = R_BODY + 2 + i as u64;
            let bg = if i == sel { SEL_BG } else { BG };
            let mut p = Pen::at(0, r).on(bg);
            p.put(if i == sel { "\u{25B6} " } else { "  " }, ACCENT);
            p.put("/dev/", FG_DIM).put(f.disk.name(), if i == sel { FG_TITLE } else { FG }).pad(16);
            p.put(&truncate(&f.host, 16), FG).pad(34);
            p.put(&truncate(&f.version, 16), FG).pad(52);
            p.put(&format!("LBA {}", f.esp_start), FG_DIM);
            p.pad(width());
        }
        let mr = R_BODY + 3 + found.len() as u64;
        clear_panel_row(mr);
        if let Some(m) = &msg { show_lines(mr, m, FG_ERR, BG); }
        match key() {
            keyboard::KEY_UP => { sel = if sel == 0 { found.len() - 1 } else { sel - 1 }; msg = None; }
            keyboard::KEY_DOWN | '\t' => { sel = (sel + 1) % found.len(); msg = None; }
            '\n' => {
                match build(&found[sel], img) {
                    Ok(plan) => {
                        match page_confirm(&found[sel], &plan) {
                            Nav::Next => { execute(&found[sel], plan, img); return Nav::Next; }
                            Nav::Quit => return Nav::Quit,
                            Nav::Back => {
                                chrome(1, tr("Choose the installation to upgrade"), FG_TITLE,
                                       tr("Only the loader, the kernel and ospab.cfg are replaced. Your data is not touched."),
                                       &[("\u{2191}\u{2193}", "Select"), ("Enter", "Use this disk"), ("Esc", "Back"), ("Q", "Quit")]);
                                Pen::at(2, R_BODY).put("DEVICE", FG_DIM).pad(16).put("HOST", FG_DIM).pad(34).put("VERSION", FG_DIM).pad(52).put("EFI PARTITION", FG_DIM);
                                hrule(R_BODY + 1);
                            }
                        }
                    }
                    Err(e) => { slog("[UPGRADE] refused: "); slog(&e); slog("\r\n"); msg = Some(e); }
                }
            }
            ESC => return Nav::Back,
            CTRL_C | 'q' | 'Q' => return Nav::Quit,
            _ => {}
        }
    }
}

fn page_confirm(inst: &Install, p: &UpPlan) -> Nav {
    slog("[UPGRADE] page: confirm\r\n");
    chrome(3, tr("Review the upgrade"), FG_TITLE, tr("This is exactly what will be written. Nothing has been written yet."),
           &[("Enter", "Upgrade"), ("Esc", "Back")]);
    let w = (width() as usize).saturating_sub(22);
    let mut rows_v: Vec<(&str, String, u32)> = Vec::new();
    rows_v.push(("System", format!("{}  {} \u{2192} {}", inst.host, inst.version, crate::version::VERSION_STR), FG_TITLE));
    rows_v.push(("Disk", format!("/dev/{}   EFI partition at LBA {} ({})", inst.disk.name(), p.esp.start,
        if p.wh.alongside { "installed alongside" } else { "whole-disk install" }), FG));
    rows_v.push(("Replaced", format!("{}  {}", p.wh.loader_path, fmt_bytes(p.files[0].data.len() as u64)), FG));
    rows_v.push(("", format!("{}  {}", p.wh.kernel_path, fmt_bytes(p.files[1].data.len() as u64)), FG));
    rows_v.push(("", format!("{}  (choices of the old file are kept)", p.wh.cfg_path), FG));
    rows_v.push(("Kept as backup", format!("{}  (the old kernel, {})", p.wh.old_path, fmt_bytes(p.old_kernel.1 as u64)), FG_OK));
    rows_v.push(("New menu entry", String::from("ospab.os (previous)"), FG_OK));
    if p.replaced_old { rows_v.push(("Dropped", format!("the older {}", p.wh.old_path), FG_WARN)); }
    if !p.old_cfg_found { rows_v.push(("Note", String::from("the old ospab.cfg could not be read: default menu settings are used"), FG_WARN)); }
    if !p.kept_entries.is_empty() { rows_v.push(("Kept entries", p.kept_entries.join(", "), FG)); }
    rows_v.push(("Never touched", String::from("the AETERNA partition (your files, account, settings), the GPT, other partitions"), FG_OK));
    rows_v.push(("Total", format!("{} sectors ({}) on the EFI partition", p.total, fmt_bytes(p.total * 512)), FG));
    let mut r = R_BODY;
    for (k, v, fg) in &rows_v {
        Pen::at(2, r).put(k, FG_DIM).pad(22).put(&truncate(v, w), *fg);
        slog("[UPGRADE] "); slog(k); slog(": "); slog(v); slog("\r\n");
        r += 1;
    }
    r += 1;
    Pen::at(2, r).put("Type ", FG).put("upgrade", FG_TITLE).put(" and press Enter:", FG);
    let pr = r + 1;
    drain_keys();
    let mut buf = [0u8; 12];
    let mut len = 0usize;
    let mut wrong = false;
    loop {
        let mut pen = Pen::at(2, pr).on(FIELD_BG);
        pen.put(" ", FG);
        for i in 0..len { cell(pen.col, pr, buf[i] as char, FG_TITLE, FIELD_BG); pen.col += 1; }
        pen.put("_", ACCENT).pad(24);
        clear_panel_row(pr + 1);
        if wrong { t(2, pr + 1, "Type the word upgrade to continue, or press Esc to go back.", FG_ERR); }
        match key() {
            '\n' => {
                if buf[..len].eq_ignore_ascii_case(b"upgrade") { slog("[UPGRADE] confirmed\r\n"); return Nav::Next; }
                wrong = true;
            }
            ESC => return Nav::Back,
            CTRL_C => return Nav::Quit,
            BKSP => { if len > 0 { len -= 1; } }
            c if c.is_ascii_alphabetic() && len < 10 => { buf[len] = c as u8; len += 1; wrong = false; }
            _ => {}
        }
    }
}

const LABELS: [&str; 4] = [
    "Re-checking the installation",
    "Copying loader, kernel and config",
    "Switching to the new version",
    "Verifying (read-back)",
];

fn up_step(i: usize, st: St, detail: &str) {
    let r = R_STEPS + i as u64;
    clear_panel_row(r);
    let (icon, ic, lc, status, sc) = match st {
        St::Pending => ("\u{00B7}", FG_DIM, FG_DIM, "", FG_DIM),
        St::Running => ("\u{25B6}", ACCENT, FG_TITLE, "\u{2026}", ACCENT),
        St::Ok => ("\u{2713}", FG_OK, FG, "OK", FG_OK),
        St::Warn => ("!", FG_WARN, FG, "WARN", FG_WARN),
        St::Fail => ("\u{2717}", FG_ERR, FG_ERR, "FAILED", FG_ERR),
    };
    t(2, r, icon, ic);
    t(4, r, LABELS[i], lc);
    if !detail.is_empty() { t(STEP_BAR_COL, r, detail, if st == St::Fail { FG_ERR } else { FG_DIM }); }
    t(width() - clen(tr(status)) - 1, r, status, sc);
    slog("[UPGRADE] step "); slog_dec(i as u64 + 1); slog(": "); slog(LABELS[i]);
    slog(match st { St::Pending => " pending", St::Running => " running", St::Ok => " ok", St::Warn => " warn", St::Fail => " FAILED" });
    slog("\r\n");
}

fn failed(i: usize, why: &str) {
    up_step(i, St::Fail, why);
    footer(&[("Enter", "Return to shell")], "");
    draw_box(R_CHECKS, 5, FG_ERR, ERR_BG, "Upgrade failed");
    Pen::at(3, R_CHECKS + 1).on(ERR_BG).put(why, FG_ERR);
    Pen::at(3, R_CHECKS + 2).on(ERR_BG).put("The AETERNA partition was not touched. If the EFI partition was partly updated, run", FG);
    Pen::at(3, R_CHECKS + 3).on(ERR_BG).put("the upgrade again from the live system.", FG);
    drain_keys();
    loop { if key() == '\n' { break; } }
}

fn execute(inst: &Install, mut plan: UpPlan, img: &Images) {
    let d = &inst.disk;
    chrome(4, tr("Upgrading"), FG_TITLE,
           &format!("{} /dev/{} \u{2014} {}", tr("Writing to"), d.name(), tr("do not power off or remove the disk.")), &[]);
    footer(&[], tr("Upgrading\u{2026} please wait"));
    for i in 0..LABELS.len() { up_step(i, St::Pending, ""); }
    t(2, R_OVR, "Overall progress", FG_DIM);
    WRITE_ERRS.store(0, Ordering::Relaxed);
    P_TOTAL.store(0, Ordering::Relaxed);
    S_TOTAL.store(0, Ordering::Relaxed);
    draw_overall(0);
    // The live session must not write its own changes into the installed system.
    ospab_os::fs::disk_sync::set_read_only(true);

    // Sectors outside the ESP that must not change
    let guard_lbas = [1u64, inst.part.start, inst.part.start + super::provision::STORE_OFFSET, d.sectors - 1];
    let mut before: Vec<[u8; 512]> = Vec::new();
    for &l in &guard_lbas { let mut b = [0u8; 512]; disk_read(d.index, l, 1, &mut b); before.push(b); }

    // 0 — the disk must still look as planned
    up_step(0, St::Running, "");
    match parse_gpt(d) {
        Ok(g) if g.parts.iter().any(|p| p.is_esp() && p.start == plan.esp.start) => {}
        _ => { failed(0, "the partition table changed since the review; nothing was written"); return; }
    }
    up_step(0, St::Ok, "GPT unchanged since review");

    let mut w = Writer { disk: d.index, allowed: &plan.allowed, total: plan.total, done: 0, last_pm: u64::MAX, errors: 0 };

    // 1 — file data into free clusters
    up_step(1, St::Running, "");
    for f in &plan.files {
        if !write_file(&mut w, &plan.fat, f) { failed(1, "write error while copying files (the old files are intact)"); return; }
    }
    disk_flush(d.index);
    up_step(1, St::Ok, &format!("{}, {}, ospab.cfg", fmt_bytes(img.efi.len() as u64), fmt_bytes(img.kernel.len() as u64)));

    // 2 — FAT, FSInfo, then the directory entries
    up_step(2, St::Running, "");
    let mut order: Vec<(u8, u64)> = plan.ov.map.iter().map(|(l, (_, lab))| {
        (match *lab { "FAT" => 0, "FSInfo" => 1, _ => 2 }, *l)
    }).collect();
    order.sort();
    let mut i = 0usize;
    let mut flushed = false;
    while i < order.len() {
        let (rank, lba) = order[i];
        if rank == 2 && !flushed { disk_flush(d.index); flushed = true; }
        let mut j = i + 1;
        while j < order.len() && order[j].0 == rank && order[j].1 == order[j - 1].1 + 1 && (j - i) < BATCH { j += 1; }
        let mut buf = Vec::with_capacity((j - i) * 512);
        for k in i..j { buf.extend_from_slice(&plan.ov.map[&order[k].1].0); }
        if !w.write(lba, &buf) { failed(2, "write error while updating the EFI partition"); return; }
        i = j;
    }
    disk_flush(d.index);
    P_TOTAL.store(0, Ordering::Relaxed);
    draw_overall(1000);
    up_step(2, St::Ok, "KERNEL.OLD kept, new files linked");

    // 3 — read back
    up_step(3, St::Running, "");
    let mut checks: Vec<Check> = Vec::new();
    let rd = Ov::new(d.index);
    let mut push = |label: &'static str, ok: bool| {
        slog("[VERIFY] "); slog(label); slog(if ok { ": ok\r\n" } else { ": FAILED\r\n" });
        checks.push(Check { label, ok });
    };
    let wh = &plan.wh;
    let path_of = |name: &'static [u8; 11], dir_is_loader: bool| -> Vec<&'static [u8; 11]> {
        if wh.alongside { alloc::vec![NAME_EFI, NAME_DIR, name] }
        else if dir_is_loader { alloc::vec![NAME_EFI, NAME_BOOT, name] }
        else { alloc::vec![NAME_BOOT, name] }
    };
    for (idx, f) in plan.files.iter().enumerate() {
        let hit = plan.fat.lookup(&rd, &path_of(f.name, idx == 0)).ok().flatten();
        let ok = hit.map_or(false, |h| !h.is_dir && plan.fat.compare_file(&rd, &h, f.data));
        push(match idx { 0 => "Loader (new)", 1 => "KERNEL (new)", _ => "ospab.cfg (new)" }, ok);
    }
    let old = plan.fat.lookup(&rd, &path_of(NAME_OLD, false)).ok().flatten();
    push("KERNEL.OLD (previous kernel)", old.map_or(false, |h| h.cluster == plan.old_kernel.0 && h.size == plan.old_kernel.1
        && plan.fat.chain(&rd, h.cluster).map_or(false, |c| !c.is_empty())));
    let mut sig = [0u8; 512];
    push("ESP boot sector intact", disk_read(d.index, plan.esp.start, 1, &mut sig) && sig[510] == 0x55 && sig[511] == 0xAA);
    let mut same = true;
    for (k, &l) in guard_lbas.iter().enumerate() {
        let mut b = [0u8; 512];
        if !disk_read(d.index, l, 1, &mut b) || b != before[k] { same = false; }
    }
    push("AETERNA data and GPT untouched", same);
    let menu_ok = plan.files[2].data.windows(8).any(|x| x == b"previous");
    push("Menu entry \"previous\"", menu_ok);
    let all_ok = checks.iter().all(|c| c.ok) && w.errors == 0;
    if all_ok { up_step(3, St::Ok, &format!("{} checks passed", checks.len())); }
    else { up_step(3, St::Fail, "some checks failed"); }
    slog(if all_ok { "[UPGRADE] complete, all checks OK\r\n" } else { "[UPGRADE] complete WITH ERRORS\r\n" });

    draw_checks(R_CHECKS, &checks);
    Pen::at(2, R_CHECKS + 5, ).put("Press Enter to continue.", FG);
    footer(&[("Enter", "Continue")], "");
    drain_keys();
    loop { if key() == '\n' { break; } }
    page_done(inst, &plan, all_ok, &checks);
}

fn page_done(inst: &Install, p: &UpPlan, ok: bool, checks: &[Check]) {
    let (title, tfg) = if ok { ("Upgrade complete", FG_OK) } else { ("Upgrade finished with problems", FG_WARN) };
    chrome(5, title, tfg, "Your data was not modified.", &[("Enter", "Reboot now"), ("Esc", "Back to shell")]);
    let (border, fill) = if ok { (FG_OK, OK_BG) } else { (FG_WARN, WARN_BG) };
    draw_box(R_BODY, 5, border, fill, "");
    Pen::at(3, R_BODY + 1).on(fill).put(if ok { "\u{2713}  " } else { "!  " }, border)
        .put(&format!("{} {} \u{2192} {}", inst.host, inst.version, crate::version::VERSION_STR), FG_TITLE);
    Pen::at(6, R_BODY + 2).on(fill).put(&format!("{}  \u{00B7}  {}", p.wh.kernel_path, p.wh.cfg_path), FG_DIM);
    Pen::at(6, R_BODY + 3).on(fill).put("Boot menu: \"ospab.os (previous)\" starts the old kernel if the new one fails.", FG_DIM);
    t(2, R_BODY + 6, "Verification", FG_TITLE);
    draw_checks(R_BODY + 7, checks);
    drain_keys();
    loop {
        match key() {
            '\n' | 'r' | 'R' => {
                fill_cells(0, rows() - 1, cols(), 1, BAR_BG);
                abs_text(2, rows() - 1, tr("Syncing disks and rebooting\u{2026}"), FG_TITLE, BAR_BG);
                disk_flush(inst.disk.index);
                slog("[UPGRADE] rebooting\r\n");
                ospab_os::acpi::reboot();
                return;
            }
            ESC | 'q' | 'Q' | CTRL_C => return,
            _ => {}
        }
    }
}
