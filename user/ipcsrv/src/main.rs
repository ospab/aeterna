// SPDX-License-Identifier: AGPL-3.0-only
//! ipcsrv — a tiny IPC server for the boot self-test.
//!
//! Bootstrap handles: 1 = channel (READ), 2 = notification (WRITE).
//! Requests (message tag): 1 echo, 2 signal the notification, 3 reply then signal it a bit
//! later, 4 receive a channel handle and send a message through it, 5 drop the reply handle
//! unused, 6 reply carrying a handle to a notification, 7 reply and exit(42).
#![no_std]
#![no_main]

use liboos::ipc::{Channel, Error, Handle, Message, Notification, Rights};
use liboos::{println, uptime_ticks, yield_now};

liboos::entry!(main);

const ECHO: u64 = 1;
const NOTIFY: u64 = 2;
const DELAYED: u64 = 3;
const TAKE: u64 = 4;
const DROP: u64 = 5;
const GIVE: u64 = 6;
const QUIT: u64 = 7;

fn bits_of(m: &Message) -> u32 {
    let d = m.data();
    if d.len() >= 4 { u32::from_le_bytes([d[0], d[1], d[2], d[3]]) } else { 0 }
}

fn main(_args: liboos::Args) -> i32 {
    let chan = Channel(Handle::bootstrap(1));
    let notif = Notification(Handle::bootstrap(2));
    let mut served = 0u32;
    println!("[ipcsrv] up, pid {}", liboos::getpid());
    loop {
        let (mut msg, reply) = match chan.recv(0) {
            Ok(x) => x,
            Err(e) => {
                println!("[ipcsrv] recv failed: {:?}", e);
                return 1;
            }
        };
        served += 1;
        let reply = match reply {
            Some(r) => r,
            None => continue, // one-way message
        };
        match msg.tag {
            ECHO => {
                let _ = reply.reply(Message::with_data(ECHO, msg.data()));
            }
            NOTIFY => {
                let ok = notif.signal(bits_of(&msg)).is_ok();
                let _ = reply.reply(Message::with_data(NOTIFY, &[ok as u8]));
            }
            DELAYED => {
                let bits = bits_of(&msg);
                let _ = reply.reply(Message::with_data(DELAYED, b"later"));
                // The caller is running again and about to sleep in wait(): signal 3 ticks on.
                let until = uptime_ticks() + 3;
                while uptime_ticks() < until {
                    yield_now();
                }
                let _ = notif.signal(bits);
            }
            TAKE => {
                let mut result = [0u8; 2];
                if let Some(h) = msg.take_handle(0) {
                    let ch = Channel(h);
                    // The client sent a WRITE-only handle: receiving through it must be refused.
                    result[0] = match ch.recv(1) {
                        Err(Error::PermissionDenied) => 1,
                        _ => 0,
                    };
                    let mut m = Message::with_data(0x44, b"via-transfer");
                    result[1] = ch.send(&mut m).is_ok() as u8;
                }
                let _ = reply.reply(Message::with_data(TAKE, &result));
            }
            DROP => drop(reply), // never answer: the caller must see PeerClosed
            GIVE => {
                if let Ok(n) = Notification::create() {
                    let _ = n.signal(0x77);
                    let mut m = Message::with_data(GIVE, b"have a notification");
                    if let Ok(d) = n.duplicate(Rights::READ | Rights::TRANSFER) {
                        let _ = m.push_handle(d.0);
                    }
                    let _ = reply.reply(m);
                }
            }
            QUIT => {
                let _ = reply.reply(Message::with_data(QUIT, b"bye"));
                println!("[ipcsrv] served {} requests, exiting", served);
                return 42;
            }
            other => {
                println!("[ipcsrv] unknown request {}", other);
                let _ = reply.reply(Message::new(u64::MAX));
            }
        }
    }
}
