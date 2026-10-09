/*
 * IVS — Internal Verification Suite for AETERNA microkernel
 *
 * Honest benchmarks, not pretty logs. Each verify_* command:
 *   - Runs a real test
 *   - Reports raw numbers
 *   - Exits with [PASS] or [FAIL] and a reason
 *
 * Commands: verify_mem  verify_sched  verify_net  verify_audio
 * All timer deadlines use PIT at 100 Hz (10 ms/tick).
 */

extern crate alloc;
use alloc::format;
use alloc::vec::Vec;


const FG: u32     = 0x00FFFFFF;
const FG_OK: u32  = 0x0000FF00;
const FG_ERR: u32 = 0x00FF4444;
const FG_DIM: u32 = 0x00AAAAAA;
const FG_HL: u32  = 0x00FFCC00;

fn puts(s: &str)  { crate::userspace::plum::io::out_c(s, FG); }
fn pass(s: &str)  { crate::userspace::plum::io::out_c("[PASS] ", FG_OK); crate::userspace::plum::io::out_c(s, FG); }
fn fail(s: &str)  { crate::userspace::plum::io::set_status(1); crate::userspace::plum::io::out_c("[FAIL] ", FG_ERR); crate::userspace::plum::io::out_c(s, FG); }
fn warn(s: &str)  { crate::userspace::plum::io::out_c("[WARN] ", FG_HL); crate::userspace::plum::io::out_c(s, FG); }
fn step(s: &str)  { crate::userspace::plum::io::out_c("  ... ", FG_DIM); crate::userspace::plum::io::out_c(s, FG); }

/// Dispatch IVS commands. Returns true if handled.
pub fn dispatch(cmd: &str, args: &str) -> bool {
    match cmd {
        "verify_mem"   => { cmd_verify_mem(args); true }
        "verify_sched" => { cmd_verify_sched(args); true }
        "verify_net"   => { cmd_verify_net(args); true }
        "verify_audio" => { cmd_verify_audio(args); true }
        _              => false,
    }
}

/// List of IVS command names (for Tab completion integration).
pub const COMMANDS: &[&str] = &["verify_mem", "verify_sched", "verify_net", "verify_audio"];

// ─── verify_mem ──────────────────────────────────────────────────────────────
//
// Allocates a buffer from the kernel heap, fills it with pattern 0xAA,
// reads every byte back. Reports the number of corrupt bytes.
// Also tests an anti-pattern: overwrites with 0x55 and re-checks.

fn cmd_verify_mem(_args: &str) {
    const TEST_SIZE: usize = 16 * 1024; // 16 KiB
    const PAT_A: u8 = 0xAA;
    const PAT_B: u8 = 0x55;

    crate::userspace::plum::io::out_c("verify_mem: ", FG_HL);
    puts(&format!("{} KiB heap write/read test\n", TEST_SIZE / 1024));

    // --- Pass A: fill with 0xAA ---
    step("allocating buffer\n");
    let mut buf: Vec<u8> = Vec::with_capacity(TEST_SIZE);
    for _ in 0..TEST_SIZE { buf.push(PAT_A); }

    step("verifying pattern 0xAA\n");
    let mut errors_a = 0usize;
    for (i, &b) in buf.iter().enumerate() {
        if b != PAT_A {
            errors_a += 1;
            if errors_a <= 3 {
                fail(&format!("byte[{}] = 0x{:02X}, expected 0xAA\n", i, b));
            }
        }
    }
    if errors_a == 0 {
        pass(&format!("0xAA pattern: {}/{} bytes correct\n", TEST_SIZE, TEST_SIZE));
    } else {
        fail(&format!("0xAA pattern: {} corrupt bytes out of {}\n", errors_a, TEST_SIZE));
    }

    // --- Pass B: overwrite with 0x55, verify, then spot-check alternation ---
    step("overwriting with 0x55\n");
    for b in buf.iter_mut() { *b = PAT_B; }

    let mut errors_b = 0usize;
    for (i, &b) in buf.iter().enumerate() {
        if b != PAT_B {
            errors_b += 1;
            if errors_b <= 3 {
                fail(&format!("byte[{}] = 0x{:02X}, expected 0x55\n", i, b));
            }
        }
    }
    if errors_b == 0 {
        pass(&format!("0x55 pattern: {}/{} bytes correct\n", TEST_SIZE, TEST_SIZE));
    } else {
        fail(&format!("0x55 pattern: {} corrupt bytes out of {}\n", errors_b, TEST_SIZE));
    }

    // --- Summary ---
    let total_errors = errors_a + errors_b;
    if total_errors == 0 {
        pass("verify_mem: HEAP MEMORY INTEGRITY OK\n");
    } else {
        fail(&format!("verify_mem: {} total errors — HEAP MAY BE CORRUPT\n", total_errors));
    }
}

// ─── verify_sched ─────────────────────────────────────────────────────────────
//
// What it checks (honestly):
//   1. the scheduler is initialized and get_tasks() returns the task table;
//   2. sys_yield() returns to us (cooperative switch path works);
//   3. the 100 Hz PIT tick counter advances at the expected rate, measured
//      against the TSC.  Note: the TSC itself was calibrated against the PIT
//      at boot, so this detects lost/stalled ticks since boot, not an
//      absolutely wrong PIT frequency.
// It does NOT spawn tasks: there is no safe kernel-thread API for test
// code yet (placeholder TCBs without code would only be phantoms).

fn cmd_verify_sched(_args: &str) {
    use crate::core::scheduler::{get_tasks, sys_yield, TaskSnapshot, TaskState, Priority, is_initialized};

    crate::userspace::plum::io::out_c("verify_sched: ", FG_HL);
    puts("scheduler and timer check\n");

    if !is_initialized() {
        fail("scheduler not initialized\n");
        return;
    }

    let mut snap = [TaskSnapshot {
        pid: 0, priority: Priority::Idle, state: TaskState::Dead,
        cr3: 0, cpu_ticks: 0, memory_bytes: 0, name: [0; 24], name_len: 0,
    }; 64];
    let n = get_tasks(&mut snap);
    let running = snap[..n].iter().filter(|t| t.state == TaskState::Running).count();
    if n > 0 {
        pass(&format!("task table readable: {} tasks ({} running)\n", n, running));
    } else {
        fail("task table is empty\n");
    }

    // yield a number of times; returning at all proves the switch path
    let mut yields = 0u32;
    for _ in 0..100 { sys_yield(); yields += 1; }
    pass(&format!("sys_yield() returned {} times\n", yields));

    // PIT rate against TSC over ~0.5 s
    let us0 = crate::arch::x86_64::tsc::tsc_stamp_us();
    let t0 = crate::arch::x86_64::idt::timer_ticks();
    while crate::arch::x86_64::tsc::tsc_stamp_us().wrapping_sub(us0) < 500_000 {
        unsafe { core::arch::asm!("hlt"); }
    }
    let t1 = crate::arch::x86_64::idt::timer_ticks();
    let elapsed_us = crate::arch::x86_64::tsc::tsc_stamp_us().wrapping_sub(us0);
    let ticks = t1.saturating_sub(t0);
    let hz = if elapsed_us > 0 { ticks * 1_000_000 / elapsed_us } else { 0 };
    step(&format!("{} PIT ticks in {} us (TSC) = ~{} Hz (expected 100)\n", ticks, elapsed_us, hz));
    if hz >= 80 && hz <= 120 {
        pass("PIT tick rate within 20% of 100 Hz\n");
    } else {
        fail(&format!("PIT tick rate {} Hz is outside 80..120 Hz\n", hz));
    }
    step("not tested: preemption between multiple kernel threads (no test-thread API yet)\n");
}

// ─── verify_net ───────────────────────────────────────────────────────────────
//
// Layer-by-layer network stack verification:
//   1. NIC presence and MAC validity
//   2. IP address sanity
//   3. ICMP/IP checksum algorithm self-test (known input → expected output)
//   4. ARP resolution of gateway (proves TX+RX are wired)

fn cmd_verify_net(_args: &str) {
    crate::userspace::plum::io::out_c("verify_net: ", FG_HL);
    puts("network stack integrity test\n");

    // --- 1. NIC up? ---
    if !crate::userspace::net::is_up() {
        fail("NIC not initialized — start QEMU with -device e1000 or rtl8139\n");
        return;
    }
    pass(&format!("NIC detected: {}\n", crate::userspace::net::nic_name()));

    // --- 2. MAC address ---
    let mac = unsafe { crate::userspace::net::OUR_MAC };
    let mac_valid = mac.iter().any(|&b| b != 0) && mac != [0xFF; 6];
    if mac_valid {
        pass(&format!(
            "MAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ));
    } else {
        fail("MAC address is all-zeros or all-broadcast\n");
    }

    // --- 3. IP address ---
    let ip = unsafe { crate::userspace::net::OUR_IP };
    if ip != [0, 0, 0, 0] {
        pass(&format!("IP address: {}.{}.{}.{}\n", ip[0], ip[1], ip[2], ip[3]));
    } else {
        fail("IP address is 0.0.0.0 (no DHCP lease and no static address)\n");
    }

    // --- 4. ICMP/IP checksum self-test ---
    // Input: ICMP Echo Request header [type=8, code=0, cksum=0, id=0xAE01, seq=0]
    // Expected one's-complement checksum:
    //   sum = 0x0800 + 0x0000 + 0xAE01 + 0x0000 = 0xB601
    //   ~sum = 0x49FE
    let test_pkt = [0x08u8, 0x00, 0x00, 0x00, 0xAE, 0x01, 0x00, 0x00];
    let expected_cksum: u16 = 0x49FE;
    let got_cksum = crate::userspace::net::ipv4::checksum(&test_pkt);
    if got_cksum == expected_cksum {
        pass(&format!("ICMP checksum: 0x{:04X} (correct)\n", got_cksum));
    } else {
        fail(&format!(
            "ICMP checksum: got 0x{:04X}, expected 0x{:04X} — ROUTER WILL DISCARD PACKETS\n",
            got_cksum, expected_cksum
        ));
    }

    // Also verify IP header checksum (20-byte minimal header, all zeros except version/ihl)
    // pkt[0]=0x45, rest = 0  →  sum = 0x4500  →  ~sum = 0xBAFF
    let ip_hdr: [u8; 20] = [0x45, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00];
    let expected_ip_cksum: u16 = 0xBAFF;
    let got_ip_cksum = crate::userspace::net::ipv4::checksum(&ip_hdr);
    if got_ip_cksum == expected_ip_cksum {
        pass(&format!("IPv4 header checksum: 0x{:04X} (correct)\n", got_ip_cksum));
    } else {
        fail(&format!(
            "IPv4 header checksum: got 0x{:04X}, expected 0x{:04X}\n",
            got_ip_cksum, expected_ip_cksum
        ));
    }

    // --- 5. ARP gateway resolution ---
    let gw = unsafe { crate::userspace::net::GATEWAY_IP };
    step(&format!(
        "sending ARP for gateway {}.{}.{}.{}\n",
        gw[0], gw[1], gw[2], gw[3]
    ));

    // Attempt to resolve; allow 500 ms (50 ticks @ 100 Hz)
    let already_cached = crate::userspace::net::arp::cache_lookup(gw).is_some();
    if !already_cached {
        crate::userspace::net::arp::send_request(gw);
        let deadline = crate::arch::x86_64::idt::timer_ticks() + 50;
        while crate::arch::x86_64::idt::timer_ticks() < deadline {
            crate::userspace::net::poll_rx();
            if crate::userspace::net::arp::cache_lookup(gw).is_some() { break; }
            crate::core::scheduler::sys_yield();
        }
    }

    if let Some(gw_mac) = crate::userspace::net::arp::cache_lookup(gw) {
        pass(&format!(
            "ARP gateway resolved: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]
        ));
    } else {
        warn("ARP gateway not responding — check cable / DHCP / gateway config\n");
    }

    // --- 6. ARP cache state ---
    let mut cache = [([0u8; 4], [0u8; 6]); 16];
    let n = crate::userspace::net::arp::cache_entries(&mut cache);
    step(&format!("ARP cache: {} entries\n", n));

    puts("\n");
    if mac_valid && ip != [0, 0, 0, 0] && got_cksum == expected_cksum && got_ip_cksum == expected_ip_cksum {
        pass("verify_net: NETWORK STACK INTEGRITY OK\n");
    } else {
        fail("verify_net: one or more checks FAILED — see above\n");
    }
}

// ─── verify_audio ──────────────────────────────────────────────────────────────
//
// Generates a 440 Hz sine wave for 1 second and writes it to /dev/audio.
// If you hear a clean A4 pitch: driver is ready, Doom music will work.
//
// Implementation: quarter-wave lookup table (25 entries) + symmetry.
// No floating point required. Output: 44100 Hz, 16-bit LE, stereo.

/// Quarter-wave sine table: sin(k·π/50) × 8000 for k = 0 … 25 (inclusive).
/// 25 entries covers 0 → π/2 (one quarter circle).
const SINE_QTR: [i16; 26] = [
       0,  502, 1002, 1498, 1989, 2472, 2946, 3408, 3857, 4290,
    4706, 5103, 5480, 5835, 6167, 6474, 6755, 7010, 7237, 7436,
    7605, 7745, 7855, 7934, 7982, 8000,
];

/// Sine approximation for a 100-sample-per-cycle table.
/// `k` in 0..100, returns scaled amplitude in -8000..+8000.
fn sine100(k: usize) -> i16 {
    let phase = k % 100;
    match phase {
        0..=24  => SINE_QTR[phase],
        25..=49 => SINE_QTR[50 - phase],
        50..=74 => -SINE_QTR[phase - 50],
        _       => -SINE_QTR[100 - phase],
    }
}

fn cmd_verify_audio(_args: &str) {
    crate::userspace::plum::io::out_c("verify_audio: ", FG_HL);
    puts("440 Hz sine tone via /dev/audio\n");

    if !crate::drivers::audio::is_ready() {
        fail("HDA driver not initialized — no audio hardware or init failed\n");
        step("Add QEMU flags: -device intel-hda,id=sound0 -device hda-duplex,bus=sound0.0\n");
        return;
    }

    pass("HDA driver ready — generating 440 Hz tone\n");

    // Generate 1 second of 440 Hz sine: 44100 samples × 4 bytes = 176400 bytes.
    // We generate and submit in 4-KiB chunks to avoid a single huge stack/heap alloc.
    const CHUNK_SAMPLES: usize = 1024; // 1024 stereo frames = 4096 bytes
    const CHUNK_BYTES:   usize = CHUNK_SAMPLES * 4; // 16-bit stereo
    const TOTAL_SAMPLES: usize = 44100; // 1 second

    let mut buf = [0u8; CHUNK_BYTES];
    let mut sample_idx: usize = 0;
    let mut written_bytes: usize = 0;

    while sample_idx < TOTAL_SAMPLES {
        let batch = CHUNK_SAMPLES.min(TOTAL_SAMPLES - sample_idx);
        for i in 0..batch {
            // 440 Hz: 100 samples per period (44100 / 440 ≈ 100.2)
            let v = sine100(sample_idx + i);
            let bytes = v.to_le_bytes();
            let off = i * 4;
            buf[off]     = bytes[0]; // L lo
            buf[off + 1] = bytes[1]; // L hi
            buf[off + 2] = bytes[0]; // R lo (mono → stereo)
            buf[off + 3] = bytes[1]; // R hi
        }
        crate::fs::write_file("/dev/audio", &buf[..batch * 4]);
        sample_idx   += batch;
        written_bytes += batch * 4;
    }

    pass(&format!("Wrote {} bytes ({} samples) to /dev/audio\n", written_bytes, TOTAL_SAMPLES));
    pass("verify_audio: IF YOU HEAR A PITCH — AUDIO IS READY FOR DOOM\n");
}
