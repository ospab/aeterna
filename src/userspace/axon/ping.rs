/*
 * ping — ICMP echo utility for AETERNA
 *
 * Standalone logical unit.  Operates exclusively through the kernel net stack.
 * Usage: ping [-c N] <ip>
 *
 * PIT runs at 100 Hz → 1 tick = 10 ms.
 */

extern crate alloc;
use alloc::format;
use alloc::vec::Vec;

use crate::arch::x86_64::framebuffer;

const FG: u32     = 0x00FFFFFF;
const FG_OK: u32  = 0x0000FF00;
const FG_ERR: u32 = 0x00FF4444;
const FG_DIM: u32 = 0x00AAAAAA;
const BG: u32     = 0x00000000;

fn puts(s: &str)  { framebuffer::draw_string(s, FG, BG); }
fn ok(s: &str)    { framebuffer::draw_string(s, FG_OK, BG); }
fn err(s: &str)   { framebuffer::draw_string(s, FG_ERR, BG); }
fn dim(s: &str)   { framebuffer::draw_string(s, FG_DIM, BG); }

/// Entry point: `ping [-c N] <ip>`
pub fn run(args: &str) {
    let args = args.trim();

    // parse optional -c N and target IP
    let (target, count) = {
        let mut words = args.splitn(3, ' ');
        let first = words.next().unwrap_or("");
        if first == "-c" {
            let n = words.next().unwrap_or("4").parse::<usize>().unwrap_or(4);
            let host = words.next().unwrap_or("").trim();
            (host, n)
        } else if first.is_empty() {
            err("ping: missing host\n");
            dim("Usage: ping [-c N] <ip>\n");
            return;
        } else {
            (first, 4usize)
        }
    };

    // parse dotted-decimal IP
    let parts: Vec<&str> = target.split('.').collect();
    if parts.len() != 4 {
        err("ping: invalid IP (expected x.x.x.x)\n");
        return;
    }
    let mut ip = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        match p.trim().parse::<u8>() {
            Ok(b) => ip[i] = b,
            Err(_) => { err("ping: bad octet\n"); return; }
        }
    }

    if !crate::net::is_up() {
        err("ping: network is down\n");
        return;
    }

    // ARP warm-up: resolve gateway MAC before sending ICMP
    // so the first packet doesn't get dropped on an ARP miss.
    if crate::net::arp::cache_lookup(ip).is_none() {
        crate::net::arp::send_request(ip);
        let arp_deadline = crate::arch::x86_64::idt::timer_ticks() + 30; // 300 ms
        while crate::arch::x86_64::idt::timer_ticks() < arp_deadline {
            crate::net::poll_rx();
            if crate::net::arp::cache_lookup(ip).is_some() { break; }
            crate::core::scheduler::sys_yield();
        }
    }

    ok("PING ");
    puts(target);
    ok(": 56(84) bytes of data.\n");

    let mut received = 0usize;
    for seq in 1..=count {
        crate::net::icmp::send_ping(ip, seq as u16);

        // Wait up to 3 s for reply — TSC-based timeout (not PIT-dependent)
        let send_us = crate::arch::x86_64::tsc::tsc_stamp_us();
        let timeout_us: u64 = 3_000_000; // 3 seconds in µs
        let mut reply: Option<(u16, u64)> = None;
        loop {
            crate::net::poll_rx();
            reply = crate::net::icmp::poll_reply();
            if reply.is_some() { break; }
            let elapsed = crate::arch::x86_64::tsc::tsc_stamp_us().saturating_sub(send_us);
            if elapsed >= timeout_us { break; }
            crate::core::scheduler::sys_yield();
        }
        if reply.is_none() {
            crate::net::icmp::cancel_wait();
        }

        match reply {
            Some((_s, rtt_us)) => {
                received += 1;
                // Format RTT: show µs if < 1000, else ms with decimals
                ok("64 bytes from ");
                puts(target);
                if rtt_us < 1_000 {
                    puts(&format!(": icmp_seq={} ttl=64 time={} µs\n", seq, rtt_us));
                } else {
                    let ms  = rtt_us / 1_000;
                    let frac = (rtt_us % 1_000) / 10; // two decimal places
                    puts(&format!(": icmp_seq={} ttl=64 time={}.{:02} ms\n", seq, ms, frac));
                }
            }
            None => {
                err(&format!("Request timeout for icmp_seq={}\n", seq));
            }
        }

        // Inter-ping delay: ~1 second using TSC (no PIT dependency)
        if seq < count {
            let delay_start = crate::arch::x86_64::tsc::tsc_stamp_us();
            while crate::arch::x86_64::tsc::tsc_stamp_us().saturating_sub(delay_start) < 1_000_000 {
                crate::net::poll_rx();
                crate::core::scheduler::sys_yield();
            }
        }
    }

    puts("\n");
    dim(&format!("--- {} ping statistics ---\n", target));
    let lost = count - received;
    let loss_pct = if count > 0 { lost * 100 / count } else { 0 };
    dim(&format!("{} packets transmitted, {} received, {}% packet loss\n",
        count, received, loss_pct));
}
