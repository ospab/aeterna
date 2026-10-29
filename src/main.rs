/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
AETERNA Microkernel entry point.
Boot sequence: hardware init → memory → scheduler → terminal.
All events logged to kernel ring buffer (klog) and serial.
*/
#![no_std]
#![no_main]

extern crate alloc;

mod terminal;
mod version;
mod installer;

use alloc::boxed::Box;
use ospab_os::arch::x86_64::serial;
use ospab_os::arch::x86_64::framebuffer;
use ospab_os::klog;

// ─── C stdlib stubs (LLVM may emit these via optimisation) ───────────────────
// Only needed when building without the DOOM C library (which normally provides them).
// When doom/libdoom.a is linked, its ospab_libc.c supplies these; this fallback
// prevents link errors on clean/no-doom builds.
#[cfg(not(doom_supported))]
#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    while *s.add(n) != 0 { n += 1; }
    n
}

// Boot log types and macros (macro_rules! must precede their use); the
// output format is described with boot_line() at the end of this file.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status { Ok, Warn, Fail, Absent, Info }

/// Fixed-size line buffer for `format_args!` without the heap. Overflow is truncated.
struct LineBuf { buf: [u8; 160], len: usize }

impl LineBuf {
    const fn new() -> Self { LineBuf { buf: [0; 160], len: 0 } }
    fn as_str(&self) -> &str {
        match core::str::from_utf8(&self.buf[..self.len]) {
            Ok(s) => s,
            // A multi-byte character was cut at the end: drop the partial tail.
            Err(e) => core::str::from_utf8(&self.buf[..e.valid_up_to()]).unwrap_or(""),
        }
    }
}

impl core::fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// `boot_log!(Status::Ok, "Subject", "fmt", args..)`
macro_rules! boot_log {
    ($st:expr, $subject:expr) => { boot_line($st, $subject, "") };
    ($st:expr, $subject:expr, $($arg:tt)+) => {{
        let mut l = LineBuf::new();
        let _ = core::fmt::Write::write_fmt(&mut l, format_args!($($arg)+));
        boot_line($st, $subject, l.as_str())
    }};
}

/// Kernel parameter `debug=1`: detail lines (`serial_line!`) also go to the screen.
static DEBUG: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// A `[TAG] message` detail line on serial (and on screen with `debug=1`).
macro_rules! serial_line {
    ($($arg:tt)+) => {{
        let mut l = LineBuf::new();
        let _ = core::fmt::Write::write_fmt(&mut l, format_args!($($arg)+));
        serial::write_str(l.as_str());
        serial::write_str("\r\n");
        if DEBUG.load(core::sync::atomic::Ordering::Relaxed) && framebuffer::is_initialized() {
            framebuffer::draw_string(l.as_str(), COLOR_DIM, COLOR_BG);
            framebuffer::draw_char('\n', COLOR_WHITE, COLOR_BG);
        }
    }};
}

/// Kernel entry. Limine jumps here with every register zeroed; the ospab loaders
/// pass BootInfo / magic / HHDM in RDI / RSI / RDX (arch/x86_64/boot/ospab_proto.rs).
#[no_mangle]
pub extern "C" fn _start(boot_arg0: u64, boot_arg1: u64, boot_arg2: u64) -> ! {
    // SAFETY: first thing on the boot CPU, before anything reads boot data.
    unsafe { ospab_os::arch::x86_64::boot::early_init(boot_arg0, boot_arg1, boot_arg2) };

    // ══════════════════════════════════════════════
    // Phase 0: CPU and platform (arch/x86_64/init.rs)
    // ══════════════════════════════════════════════
    ospab_os::arch::x86_64::init();
    boot_banner();
    klog::boot("AETERNA started");
    if ospab_os::arch::x86_64::boot::cmdline_get("debug") == "1" {
        DEBUG.store(true, core::sync::atomic::Ordering::Relaxed);
        serial_line!("[DEBUG] verbose boot log on screen and serial, cmdline: {}",
            ospab_os::arch::x86_64::boot::kernel_cmdline());
    }
    if ospab_os::arch::x86_64::boot::cmdline_get("persist") == "ro" {
        ospab_os::fs::disk_sync::set_read_only(true);
        boot_log!(Status::Info, "Persistence", "read-only (persist=ro): nothing is written to disk");
    }

    let mhz = ospab_os::arch::x86_64::tsc::mhz();
    let apic = if ospab_os::arch::x86_64::apic::is_present() { ", APIC timer" } else { "" };
    if mhz > 0 {
        let pit = if ospab_os::arch::x86_64::idt::PIT_ALIVE.load(core::sync::atomic::Ordering::Relaxed) { "PIT 100 Hz" } else { "no PIT (ticks from APIC)" };
        boot_log!(Status::Ok, "CPU", "GDT/TSS, IDT, PIC, {}, TSC {} MHz{}", pit, mhz, apic);
    } else {
        boot_log!(Status::Warn, "CPU", "TSC not calibrated, timing falls back to the 100 Hz PIT");
    }

    // ══════════════════════════════════════════════
    // Phase 1: Boot loader hand-off
    // ══════════════════════════════════════════════
    let boot = &ospab_os::arch::x86_64::boot::loader_name;
    if ospab_os::arch::x86_64::boot::base_revision_supported() {
        boot_log!(Status::Ok, "Boot loader", "{}", boot());
    } else {
        boot_log!(Status::Warn, "Boot loader", "{}: base revision not supported", boot());
    }
    {
        let phys = ospab_os::arch::x86_64::boot::kernel_phys_base();
        let virt = ospab_os::arch::x86_64::boot::kernel_virt_base();
        serial_line!("[BOOT] Kernel at phys {:#x}, virt {:#x}", phys, virt);
    }
    match framebuffer::info() {
        Some(fb) => boot_log!(Status::Ok, "Display", "{}x{}, {} bpp boot framebuffer", fb.width, fb.height, fb.bpp),
        None     => boot_log!(Status::Warn, "Display", "no framebuffer: output on serial only"),
    }

    // ══════════════════════════════════════════════
    // Phase 2: Memory
    // ══════════════════════════════════════════════
    if ospab_os::arch::x86_64::boot::memory_map().is_none() {
        boot_log!(Status::Fail, "Memory map", "boot loader provided none");
    }

    boot_step("Physical memory");
    ospab_os::mm::physical::init();
    let stats = ospab_os::mm::physical::stats();
    boot_step("Kernel heap");
    ospab_os::mm::heap::init();
    let pmm_ok = ospab_os::mm::physical::self_test();
    boot_log!(if pmm_ok { Status::Ok } else { Status::Fail }, "Physical memory",
        "{} MiB usable, {} regions{}", stats.usable_bytes >> 20, stats.region_count,
        if pmm_ok { "" } else { ", SELF-TEST FAILED" });

    if ospab_os::mm::heap::is_initialized() {
        boot_log!(Status::Ok, "Kernel heap", "{} MiB", ospab_os::mm::heap::heap_size() >> 20);
        klog::memory("Heap allocator initialized");
    } else {
        boot_log!(Status::Fail, "Kernel heap", "allocation failed");
        klog::fault("Heap init failed");
    }

    boot_step("Virtual memory");
    ospab_os::mm::r#virtual::init();
    ospab_os::mm::numa::init();
    boot_log!(Status::Ok, "Virtual memory", "4-level paging, {} memory domains",
        ospab_os::mm::numa::get_med_info().len());

    // ACPI tables (FADT, \_S5, reset register): needed for power-off and reboot
    boot_step("ACPI");
    if ospab_os::acpi::init() {
        boot_log!(Status::Ok, "ACPI", "power-off and reset available");
    } else {
        boot_log!(Status::Warn, "ACPI", "tables not found: shutdown and reboot may not work");
    }

    // ══════════════════════════════════════════════
    // Phase 2.8: PCI bus enumeration
    // ══════════════════════════════════════════════
    boot_step("PCI");
    let pci_count = ospab_os::pci::enumerate();
    ospab_os::pci::print_devices();
    if pci_count > 0 {
        boot_log!(Status::Ok, "PCI", "{} devices", pci_count);
    } else {
        boot_log!(Status::Warn, "PCI", "no devices found");
    }

    // ══════════════════════════════════════════════
    // Phase 3: Kernel services
    // ══════════════════════════════════════════════
    boot_step("Scheduler");
    ospab_os::core::scheduler::init();
    ospab_os::core::syscall::init_syscall_msr();
    let (smep, smap) = ospab_os::mm::usercopy::init();
    let nx = ospab_os::mm::r#virtual::enable_nx();
    boot_log!(Status::Ok, "Scheduler", "preemptive, ring 3 via SYSCALL/SYSRET");
    let on = |b: bool| if b { "on" } else { "off" };
    boot_log!(if nx { Status::Ok } else { Status::Warn }, "Memory protection",
        "NX {}, SMEP {}, SMAP {}", on(nx), on(smep), on(smap));

    // ══════════════════════════════════════════════
    // Phase 3.2: Virtual Filesystem + RamFS + CowFS
    // ══════════════════════════════════════════════
    boot_step("Root filesystem");
    ospab_os::fs::init();

    // Base layer: read-only system files. Upper layer: writable overlay that is persisted.
    let base_ramfs = Box::leak(Box::new(ospab_os::fs::ramfs::RamFs::with_defaults()));
    base_ramfs.is_readonly = true;
    let upper_ramfs = Box::leak(Box::new(ospab_os::fs::ramfs::RamFs::new()));
    ospab_os::fs::set_syncable_fs(upper_ramfs);

    let cow_root = Box::leak(Box::new(ospab_os::fs::cow::CowFs::new(base_ramfs, upper_ramfs)));
    ospab_os::fs::mount("/", cow_root);
    ospab_os::fs::mount("/proc", ospab_os::fs::procfs::instance());
    boot_log!(Status::Ok, "Root filesystem", "RAM overlay, {} system files, /proc", base_ramfs.node_count());

    // ══════════════════════════════════════════════
    // Phase 3.5: Storage (ATA PIO + AHCI SATA + NVMe + virtio-blk)
    // ══════════════════════════════════════════════
    boot_step("Storage");
    let disk_count = ospab_os::drivers::init();
    if disk_count > 0 {
        boot_log!(Status::Ok, "Storage", "{} disk(s)", disk_count);
        for i in 0..disk_count {
            if let Some(d) = ospab_os::drivers::disk_info(i) {
                boot_log!(Status::Info, "Disk", "{}: {}, {} MiB", i, ospab_os::drivers::model_str(d), d.size_mb);
            }
        }

        // Restore the writable layer saved by `sync` (vfs/disk_sync.rs decides where it lives)
        boot_step("Persistence");
        let target = ospab_os::fs::disk_sync::primary_disk_index()
            .and_then(|i| ospab_os::fs::disk_sync::base_lba(i).map(|lba| (i, lba)));
        match target {
            None => boot_log!(Status::Info, "Persistence",
                "no AETERNA partition: changes stay in RAM"),
            Some((disk, lba)) => {
                serial_line!("[FS] Persistence area: disk {}, LBA {}", disk, lba);
                let restored = ospab_os::fs::disk_sync::read_from_disk().and_then(|data| {
                    let bytes = data.len();
                    ospab_os::fs::disk_sync::deserialize_ramfs(&data).map(|tree| (tree, bytes))
                });
                match restored {
                    Some((tree, bytes)) => {
                        upper_ramfs.restore_from_tree(tree);
                        boot_log!(Status::Ok, "Persistence", "restored {} files ({} bytes) from disk {}",
                            upper_ramfs.node_count(), bytes, disk);
                        klog::boot("Filesystem restored from disk");
                    }
                    None => boot_log!(Status::Info, "Persistence",
                        "disk {}: nothing saved yet, `sync` writes it", disk),
                }
            }
        }
    } else {
        boot_log!(Status::Absent, "Storage", "no ATA/AHCI/NVMe/virtio disks");
    }

    // ══════════════════════════════════════════════
    // Phase 3.4: Optional devices
    // ══════════════════════════════════════════════
    boot_step("GPU");
    if ospab_os::drivers::registry::try_init_driver("GPU (VMware SVGA II)", || {
        ospab_os::drivers::gpu::init()
    }) {
        boot_log!(Status::Ok, "GPU", "VMware SVGA II, VMMouse");
    } else {
        boot_log!(Status::Absent, "GPU", "no VMware SVGA II, using the boot framebuffer");
    }

    boot_step("Audio");
    if ospab_os::drivers::registry::try_init_driver("Audio", || {
        ospab_os::drivers::audio::init()
    }) {
        boot_log!(Status::Ok, "Audio", "{}, {} Hz, 16-bit stereo",
            ospab_os::drivers::audio::active_driver_name(), ospab_os::drivers::audio::sample_rate());
    } else {
        boot_log!(Status::Absent, "Audio", "no supported card (HDA, AC97, ES1371/ES1370)");
    }

    // NVMe controllers are probed inside drivers::init() (and show up in the
    // Storage list above); this step only reads the GPT of the NVMe disk and
    // auto-mounts an AeternaFS partition.
    boot_step("USB");
    if ospab_os::xhci::init() {
        let (kbd, mouse) = ospab_os::xhci::hid_counts();
        boot_log!(Status::Ok, "USB", "xHCI, {} keyboard(s), {} mouse/mice", kbd, mouse);
    } else {
        boot_log!(Status::Absent, "USB", "no xHCI controller");
    }

    boot_step("NVMe");
    if ospab_os::drivers::nvme::is_initialized() {
        let mut nvme_disk = ospab_os::drivers::block::NvmeDisk::new();
        let gpt_parts = ospab_os::drivers::gpt::parse(&mut nvme_disk).unwrap_or(0);
        ospab_os::drivers::block::register_devices();

        if gpt_parts > 0 {
            boot_log!(Status::Ok, "NVMe", "{} GPT partitions", gpt_parts);
            // Auto-mount the first AeternaFS partition at /mnt/target
            for pi in 0..gpt_parts {
                if let Some(part) = ospab_os::drivers::gpt::get_partition(pi) {
                    let ss = ospab_os::drivers::nvme::sector_size();
                    if ospab_os::fs::aeternafs::mount_nvme_partition(part.start_lba, ss) {
                        ospab_os::fs::mount("/mnt/target", ospab_os::fs::aeternafs::instance());
                        boot_log!(Status::Info, "NVMe", "AeternaFS partition {} mounted at /mnt/target", pi);
                        break;
                    }
                }
            }
        } else {
            boot_log!(Status::Ok, "NVMe", "no partition table (use `fdisk`, then `mkfs`)");
        }
    } else {
        boot_log!(Status::Absent, "NVMe", "no controller");
    }

    // /sys/status: boot-time task snapshot (`ps` refreshes it); /dev/audio: writes go to the sound card
    ospab_os::fs::mkdir("/sys");
    refresh_sys_status();
    ospab_os::fs::mkdir("/dev");
    ospab_os::fs::write_file("/dev/audio", b"");

    // ══════════════════════════════════════════════
    // Phase 4: Network (optional — continues if no NIC)
    // ══════════════════════════════════════════════
    boot_step("Network");
    if ospab_os::net::init() {
        let ip = unsafe { ospab_os::net::OUR_IP };
        let nic = ospab_os::net::nic_name();
        if ip[0] == 169 && ip[1] == 254 {
            boot_log!(Status::Warn, "Network", "{}: DHCP failed, link-local {}.{}.{}.{}", nic, ip[0], ip[1], ip[2], ip[3]);
        } else {
            boot_log!(Status::Ok, "Network", "{}, {}.{}.{}.{} via DHCP", nic, ip[0], ip[1], ip[2], ip[3]);
        }
        klog::boot("Network initialized");
    } else {
        boot_log!(Status::Absent, "Network", "no supported network card");
        // List what is there so an unsupported NIC is visible on serial
        ospab_os::net::diag::dump_pci_nics();
    }

    // ══════════════════════════════════════════════
    // Phase 4.5: Userland
    // ══════════════════════════════════════════════
    ospab_os::userspace::seed::init();
    ospab_os::plum::init();
    boot_log!(Status::Ok, "Shell", "plum");

    // ══════════════════════════════════════════════
    // Phase 5: Installer or console (cmdline `mode=`)
    // ══════════════════════════════════════════════
    let boot_mode = ospab_os::arch::x86_64::boot::cmdline_get("mode");
    serial_line!("[BOOT] mode={}", boot_mode);

    if boot_mode == "installer" {
        boot_log!(Status::Ok, "Installer", "starting");
        klog::boot("Entering installer");
        framebuffer::draw_char('\n', COLOR_WHITE, COLOR_BG);
        crate::installer::run();
        // Leaving the installer drops to the normal console.
        framebuffer::clear(COLOR_BG);
    } else {
        ring3_self_test();
        boot_log!(Status::Ok, "Console", "ready");
        framebuffer::draw_char('\n', COLOR_WHITE, COLOR_BG);
    }
    klog::boot("Entering terminal");
    terminal::run();
}

/// Run the boot-time ring-3 programs and check their exit codes and that every
/// frame they used came back. One status line; details go to serial as [RING3].
fn ring3_self_test() {
    use ospab_os::arch::x86_64::ring;
    use ospab_os::core::scheduler::wait_pid_timeout;
    // Every wait is bounded (10 s of uptime, task killed on expiry): a broken test fails, never hangs the boot.
    let wait_pid = |pid: u32| wait_pid_timeout(pid, 1000);

    // Opt-in groups: kernel parameter selftest=ipc, selftest=mem, selftest=ipc,mem or selftest=all.
    let selftest = |group: &str| {
        ospab_os::arch::x86_64::boot::cmdline_get("selftest")
            .split(',')
            .any(|g| g == group || g == "all")
    };

    boot_step("Ring 3 self-test");
    let frames_before = ospab_os::mm::physical::frames_free();
    let objects_before = ospab_os::core::object::live_objects();
    let mut passed = 0u32;
    let mut failed: [&str; 8] = [""; 8];
    let mut nfailed = 0usize;
    let mut check = |name: &'static str, ok: bool| {
        serial_line!("[RING3] {}: {}", name, if ok { "pass" } else { "FAIL" });
        if ok { passed += 1 } else if nfailed < failed.len() { failed[nfailed] = name; nfailed += 1; }
    };

    // getpid → exit(pid): the full ring0 → ring3 → syscall → ring0 round trip
    match ring::launch_ring3_smoke_test() {
        Some(pid) => check("smoke", wait_pid(pid) == Some(pid as i64)),
        None => check("smoke", false),
    }
    // Two tasks at once, one blocking in a syscall: per-task kernel stacks, FPU/SSE switching.
    // Each exits with its pid, or 0xBAD.
    match ring::launch_ring3_stress_test() {
        Some((a, b)) => {
            let ok = wait_pid(a) == Some(a as i64) && wait_pid(b) == Some(b as i64);
            serial_line!("[RING3] ring3<->ring3 switches: {}",
                ospab_os::core::scheduler::USER_TO_USER_SWITCHES.load(core::sync::atomic::Ordering::Relaxed));
            check("stress", ok);
        }
        None => check("stress", false),
    }
    // Bad user pointers rejected, mmap/munmap working: exits 0x600D
    match ring::launch_ring3_usercopy_test() {
        Some(pid) => check("usercopy", wait_pid(pid) == Some(0x600D)),
        None => check("usercopy", false),
    }
    // Two tasks keep different 256-bit patterns in ymm0/ymm15 while being preempted:
    // XSAVE must keep the upper halves apart. Skipped on CPUs without AVX.
    match ring::launch_ring3_avx_test() {
        Some((a, b)) => check("avx (XSAVE)", wait_pid(a) == Some(a as i64) && wait_pid(b) == Some(b as i64)),
        None => serial_line!("[RING3] avx (XSAVE): skipped (no AVX)"),
    }
    // First real program: an ELF built with liboos (user/hello), exits 0
    #[cfg(user_hello)]
    {
        static HELLO: &[u8] = include_bytes!(env!("OOS_USER_HELLO"));
        match ospab_os::core::elf::spawn(
            "hello",
            HELLO,
            &["hello", "from", "AETERNA"],
            alloc::vec![ospab_os::core::scheduler::Capability::Serial],
        ) {
            Ok(pid) => check("hello (ELF)", wait_pid(pid) == Some(0)),
            Err(e) => {
                serial_line!("[RING3] ELF load failed: {}", e.as_str());
                check("hello (ELF)", false);
            }
        }
    }

    // IPC: an echo server and a client, both ELF programs built with liboos. The client
    // checks messages, notifications, handle transfer both ways, rights and error codes,
    // then has the server exit(42). Two more clients block forever inside the kernel
    // (recv / call) and are killed: their handles and objects must be released.
    // Opt-in until the IPC path is proven: a hang here blocks every boot.
    #[cfg(user_ipc)]
    'ipc: {
        if !selftest("ipc") {
            serial_line!("[RING3] ipc tests: skipped (boot with selftest=ipc to run them)");
            break 'ipc;
        }
        use ospab_os::core::object::{self, rights};
        use ospab_os::core::scheduler::{self, Capability, TaskState};
        static SRV: &[u8] = include_bytes!(env!("OOS_USER_IPCSRV"));
        static CLI: &[u8] = include_bytes!(env!("OOS_USER_IPCCLIENT"));
        let serial_cap = || alloc::vec![Capability::Serial];
        let run = || -> Result<(u32, u32), &'static str> {
            let chan = object::kernel_new_channel().ok_or("channel")?;
            let notif = object::kernel_new_notification().ok_or("notification")?;
            let srv = ospab_os::core::elf::spawn_with_handles(
                "ipcsrv", SRV, &["ipcsrv"], serial_cap(),
                &[(chan, rights::READ), (notif, rights::WRITE)],
            ).map_err(|_| "spawn server")?;
            let srv_obj = object::kernel_new_process(srv).ok_or("process object")?;
            let cli = ospab_os::core::elf::spawn_with_handles(
                "ipcclient", CLI, &["ipcclient"], serial_cap(),
                &[(chan, rights::WRITE | rights::DUP), (notif, rights::READ), (srv_obj, rights::READ)],
            ).map_err(|_| "spawn client")?;
            Ok((srv, cli))
        };
        match run() {
            Ok((srv, cli)) => {
                let c = scheduler::wait_pid_timeout(cli, 1500);
                let s = scheduler::wait_pid_timeout(srv, 500);
                serial_line!("[RING3] ipc client exit {:?}, server exit {:?}", c, s);
                check("ipc client/server", c == Some(0) && s == Some(42));
            }
            Err(what) => {
                serial_line!("[RING3] ipc setup failed: {}", what);
                check("ipc client/server", false);
            }
        }

        let mut killed_ok = true;
        for mode in ["block-recv", "block-call"] {
            let spawned = object::kernel_new_channel().and_then(|chan| {
                ospab_os::core::elf::spawn_with_handles(
                    "ipcblock", CLI, &["ipcclient", mode], serial_cap(),
                    &[(chan, rights::ALL)],
                ).ok()
            });
            match spawned {
                Some(pid) => {
                    let until = ospab_os::arch::x86_64::idt::timer_ticks() + 20;
                    while ospab_os::arch::x86_64::idt::timer_ticks() < until {
                        scheduler::sys_yield();
                    }
                    let asleep = scheduler::task_state(pid) == Some(TaskState::Waiting);
                    scheduler::exit_pid(pid);
                    let code = scheduler::wait_pid_timeout(pid, 300);
                    serial_line!("[RING3] ipc {}: asleep={} exit={:?}", mode, asleep, code);
                    killed_ok &= asleep && code == Some(scheduler::EXIT_KILLED);
                }
                None => killed_ok = false,
            }
        }
        check("ipc kill while blocked", killed_ok);
    }

    // Shared memory through handles (ROADMAP 12) and a ring-3 driver (ROADMAP 13).
    // Opt-in: selftest=mem. The COM2 driver needs a second serial port in QEMU
    // (-serial file:com1.log -serial file:com2.log); without one it reports "skipped".
    #[cfg(user_mem)]
    'mem: {
        if !selftest("mem") {
            serial_line!("[RING3] mem/driver tests: skipped (boot with selftest=mem to run them)");
            break 'mem;
        }
        use ospab_os::core::object::{self, rights, resource};
        use ospab_os::core::scheduler::{self, Capability, EXIT_KILLED};
        static MEMTEST: &[u8] = include_bytes!(env!("OOS_USER_MEMTEST"));
        static UARTDRV: &[u8] = include_bytes!(env!("OOS_USER_UARTDRV"));
        let caps = || alloc::vec![Capability::Serial];
        let spawn = |name: &str, image: &[u8], args: &[&str], handles: &[(object::ObjId, u32)]| {
            ospab_os::core::elf::spawn_with_handles(name, image, args, caps(), handles).ok()
        };
        let settle = || {
            for _ in 0..10 {
                scheduler::sys_yield();
            }
        };
        // Reap whatever earlier groups left behind first, so the baseline is exact.
        settle();
        let frames0 = ospab_os::mm::physical::frames_free();

        // (a) Two processes share one region: RW and RO duplicates, live writes both ways.
        let share = object::kernel_new_channel().and_then(|chan| {
            let srv = spawn("memsrv", MEMTEST, &["memtest", "server"], &[(chan, rights::READ)])?;
            // The server's handle keeps the channel alive for the second spawn.
            let cli = spawn("memcli", MEMTEST, &["memtest", "client"], &[(chan, rights::WRITE)]);
            Some((srv, cli))
        });
        match share {
            Some((srv, Some(cli))) => {
                let c = wait_pid_timeout(cli, 1500);
                let s = wait_pid_timeout(srv, 500);
                serial_line!("[RING3] mem share: client exit {:?}, server exit {:?}", c, s);
                check("mem: two processes share a region", c == Some(0) && s == Some(42));
            }
            Some((srv, None)) => {
                scheduler::exit_pid(srv);
                check("mem: two processes share a region", false);
            }
            None => check("mem: two processes share a region", false),
        }

        // A read-only mapping: the write must end in #PF and the kernel killing the writer.
        let ro_killed = object::kernel_new_memory(4096).and_then(|region| {
            let page = object::kernel_memory_page(region, 0)?;
            unsafe { core::ptr::write_volatile(page, 0x5A) };
            let pid = spawn("memro", MEMTEST, &["memtest", "rowrite"], &[(region, rights::READ | rights::MAP)])?;
            Some(wait_pid_timeout(pid, 500))
        });
        serial_line!("[RING3] mem read-only writer: exit {:?} (expected killed = {})", ro_killed, EXIT_KILLED);
        check("mem: write to read-only map killed", ro_killed == Some(Some(EXIT_KILLED)));

        // DMA: contiguous region with PHYS, only with a DMA Resource handle.
        let dma = object::kernel_new_resource(resource::DMA).and_then(|res| {
            let pid = spawn("memdma", MEMTEST, &["memtest", "contig"],
                &[(res, rights::READ | rights::WRITE | rights::DUP)])?;
            Some(wait_pid_timeout(pid, 500))
        });
        check("mem: contiguous DMA region + PHYS", dma == Some(Some(0)));

        // MMIO: the local APIC page mapped read-only and uncached; the driver must read the
        // same version register the kernel reads.
        let apic_phys = {
            let (lo, hi): (u32, u32);
            unsafe { core::arch::asm!("rdmsr", in("ecx") 0x1Bu32, out("eax") lo, out("edx") hi, options(nomem, nostack)) };
            (((hi as u64) << 32) | lo as u64) & 0x000F_FFFF_FFFF_F000
        };
        let hhdm = ospab_os::arch::x86_64::boot::hhdm_offset().unwrap_or(0);
        let version = unsafe { core::ptr::read_volatile((hhdm + apic_phys + 0x30) as *const u32) };
        let hex = alloc::format!("{:x}", version);
        let mmio = object::kernel_new_mmio(apic_phys, 4096).and_then(|m| {
            let pid = spawn("memmmio", MEMTEST, &["memtest", "mmio", hex.as_str()], &[(m, rights::READ | rights::MAP)])?;
            Some(wait_pid_timeout(pid, 500))
        });
        check("mem: MMIO region (local APIC) mapped uncached", mmio == Some(Some(0)));

        settle();
        let leaked = frames0 as i64 - ospab_os::mm::physical::frames_free() as i64;
        serial_line!("[RING3] mem frames: {} not returned after the mem tests", leaked);
        check("mem: frames freed after unmap/exit", leaked == 0);

        // (b) Ring-3 driver: COM2 through an IoPortRange and an Interrupt (IRQ 3).
        let io = object::kernel_new_ioports(0x2F8, 8);
        let irq = object::kernel_new_interrupt(3);
        match (io, irq) {
            (Some(io), Some(irq)) => {
                let code = spawn("uartdrv", UARTDRV, &["uartdrv", "run"],
                    &[(io, rights::READ | rights::WRITE), (irq, rights::READ | rights::WRITE)])
                    .and_then(|pid| wait_pid_timeout(pid, 1500));
                serial_line!("[RING3] uartdrv (COM2, IRQ 3): exit {:?}", code);
                if code == Some(77) {
                    serial_line!("[RING3] ring-3 COM2 driver: skipped (no COM2 in this machine)");
                } else {
                    check("ring-3 driver: COM2 I/O + IRQ notification", code == Some(0));
                }
            }
            _ => {
                if let Some(io) = io { object::kernel_release(io) }
                if let Some(irq) = irq { object::kernel_release(irq) }
                check("ring-3 driver: COM2 I/O + IRQ notification", false);
            }
        }
        // I/O permission bitmap: a port next to the granted range, and a granted port that
        // was never enabled, both end in #GP.
        for mode in ["badport", "noperm"] {
            let code = object::kernel_new_ioports(0x2F8, 8).and_then(|io| {
                let pid = spawn("uartbad", UARTDRV, &["uartdrv", mode], &[(io, rights::READ | rights::WRITE)])?;
                wait_pid_timeout(pid, 500)
            });
            serial_line!("[RING3] uartdrv {}: exit {:?}", mode, code);
            check(if mode == "badport" { "ring-3 driver: port outside range killed" }
                  else { "ring-3 driver: port without enable killed" },
                  code == Some(EXIT_KILLED));
        }
    }

    // Synchronization layer: lock behavior, then concurrent spawn/reap with per-task fds.
    if selftest("sched") {
        check("sync", ospab_os::core::selftest::sync_basic());
        check("sched stress", ospab_os::core::selftest::sched_stress());
    } else {
        serial_line!("[RING3] sched tests: skipped (boot with selftest=sched to run them)");
    }

    // Dead tasks are reaped lazily by the scheduler; give it a few ticks, then every
    // frame the tests used (kernel stacks, page tables, stacks, mmap) must be back.
    for _ in 0..10 {
        ospab_os::core::scheduler::sys_yield();
    }
    let leaked = frames_before.saturating_sub(ospab_os::mm::physical::frames_free());
    check("no frame leak", leaked == 0);
    let live = ospab_os::core::object::live_objects();
    serial_line!("[RING3] kernel objects: {} before, {} after", objects_before, live);
    check("no object leak", live == objects_before);

    if nfailed == 0 {
        boot_log!(Status::Ok, "Ring 3 self-test", "{} checks passed", passed);
    } else {
        let mut list = LineBuf::new();
        for (i, name) in failed[..nfailed].iter().enumerate() {
            let _ = core::fmt::Write::write_str(&mut list, if i == 0 { "" } else { ", " });
            let _ = core::fmt::Write::write_str(&mut list, name);
        }
        boot_log!(Status::Fail, "Ring 3 self-test", "failed: {}", list.as_str());
    }
}

// ─── /sys/status: write current task table to VFS ───

/// Build a text snapshot of all live tasks and write it to /sys/status.
/// Call at boot and whenever the task table changes (e.g. from `ps`).
fn refresh_sys_status() {
    use alloc::vec::Vec;

    let mut snapshots = [ospab_os::core::syscall::TaskInfo {
        pid: 0,
        priority: ospab_os::core::scheduler::Priority::Idle,
        state: ospab_os::core::scheduler::TaskState::Dead,
        cr3: 0,
        cpu_ticks: 0,
        memory_bytes: 0,
        name: [0u8; 24],
        name_len: 0,
    }; 64];
    let n = ospab_os::core::syscall::sys_get_tasks(&mut snapshots);

    let mut out: Vec<u8> = Vec::with_capacity(n * 48 + 32);

    // Header
    for &b in b"PID   TICKS      STATE    NAME\n" { out.push(b); }
    for &b in b"---   -----      -----    ----\n" { out.push(b); }

    for snap in snapshots.iter().take(n) {
        // PID (right-pad to 6)
        let pid_s = dec_str(snap.pid as u64);
        for &b in pid_s.as_bytes() { out.push(b); }
        for _ in pid_s.len()..6 { out.push(b' '); }

        // CPU ticks (right-pad to 11)
        let tick_s = dec_str(snap.cpu_ticks);
        for &b in tick_s.as_bytes() { out.push(b); }
        for _ in tick_s.len()..11 { out.push(b' '); }

        // State (fixed 9 chars)
        let state_str: &[u8] = match snap.state {
            ospab_os::core::scheduler::TaskState::Running => b"running  ",
            ospab_os::core::scheduler::TaskState::Ready   => b"ready    ",
            ospab_os::core::scheduler::TaskState::Waiting => b"waiting  ",
            ospab_os::core::scheduler::TaskState::Dead    => b"dead     ",
        };
        for &b in state_str { out.push(b); }

        // Name
        let name_len = snap.name_len as usize;
        for j in 0..name_len { out.push(snap.name[j]); }
        out.push(b'\n');
    }

    ospab_os::fs::write_file("/sys/status", &out);
}

// ─── Boot log ────────────────────────────────────────────────────────────────
//
// Every boot step reports exactly one status line, identical on serial and screen:
//
//   [  OK  ] Subject: detail     the step worked
//   [ WARN ] Subject: detail     works, but degraded
//   [ FAIL ] Subject: detail     broken
//   [  --  ] Subject: detail     optional hardware not present
//   [ INFO ] Subject: detail     a fact worth seeing
//
// Serial also gets `[ .... ] Subject` when a step starts, so a hang shows where it stopped.
// Drivers and subsystems log their own details to serial as `[TAG] message`.
// Formatting uses a stack buffer: the first lines are printed before the heap exists.

const COLOR_OK: u32    = 0x0000D000;
const COLOR_WARN: u32  = 0x00FFD000;
const COLOR_FAIL: u32  = 0x00FF4040;
const COLOR_INFO: u32  = 0x0040C0FF;
const COLOR_DIM: u32   = 0x00888888;
const COLOR_WHITE: u32 = 0x00FFFFFF;
const COLOR_BG: u32    = 0x00000000;


fn boot_banner() {
    serial::write_str("\r\n[BOOT] ospab.os ");
    serial::write_str(version::VERSION_STR);
    serial::write_str(", AETERNA kernel ");
    serial::write_str(version::KERNEL_BUILD);
    serial::write_str("\r\n");
    if framebuffer::is_initialized() {
        framebuffer::draw_string("ospab.os ", COLOR_WHITE, COLOR_BG);
        framebuffer::draw_string(version::VERSION_STR, COLOR_WHITE, COLOR_BG);
        framebuffer::draw_string("  AETERNA kernel ", COLOR_DIM, COLOR_BG);
        framebuffer::draw_string(version::KERNEL_BUILD, COLOR_DIM, COLOR_BG);
        framebuffer::draw_string("\n\n", COLOR_DIM, COLOR_BG);
    }
}

fn boot_step(subject: &str) {
    serial::write_str("[ .... ] ");
    serial::write_str(subject);
    serial::write_str("\r\n");
}

fn boot_line(st: Status, subject: &str, detail: &str) {
    let (tag, color) = match st {
        Status::Ok     => ("  OK  ", COLOR_OK),
        Status::Warn   => (" WARN ", COLOR_WARN),
        Status::Fail   => (" FAIL ", COLOR_FAIL),
        Status::Absent => ("  --  ", COLOR_DIM),
        Status::Info   => (" INFO ", COLOR_INFO),
    };

    let mut l = LineBuf::new();
    let _ = core::fmt::Write::write_fmt(&mut l, format_args!("[{}] {}{}{}\r\n",
        tag, subject, if detail.is_empty() { "" } else { ": " }, detail));
    serial::write_str(l.as_str());

    if framebuffer::is_initialized() {
        framebuffer::draw_string("[", COLOR_DIM, COLOR_BG);
        framebuffer::draw_string(tag, color, COLOR_BG);
        framebuffer::draw_string("] ", COLOR_DIM, COLOR_BG);
        framebuffer::draw_string(subject, if st == Status::Absent { COLOR_DIM } else { COLOR_WHITE }, COLOR_BG);
        if !detail.is_empty() {
            framebuffer::draw_string(": ", COLOR_DIM, COLOR_BG);
            let detail_color = match st {
                Status::Warn | Status::Fail => color,
                _ => COLOR_DIM,
            };
            framebuffer::draw_string(detail, detail_color, COLOR_BG);
        }
        framebuffer::draw_char('\n', COLOR_WHITE, COLOR_BG);
    }

    match st {
        Status::Fail => klog::fault(subject),
        Status::Warn => klog::boot(subject),
        _ => {}
    }
}

/// Format a u64 into a decimal string (for /sys/status)
fn dec_str(mut n: u64) -> alloc::string::String {
    if n == 0 { return alloc::string::String::from("0"); }
    let mut buf = [0u8; 20];
    let mut pos = 20;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    alloc::string::String::from(core::str::from_utf8(&buf[pos..]).unwrap_or("0"))
}
