// SPDX-License-Identifier: AGPL-3.0-only
//! ipcclient — drives ipcsrv and checks the IPC rules. Exit 0 = all good, otherwise the
//! number of the check that failed.
//!
//! Bootstrap handles: 1 = channel (WRITE|DUP), 2 = notification (READ), 3 = server process (READ).
//! With argument `block-recv` or `block-call` it instead blocks forever in the kernel (handle 1
//! is a channel with all rights) so the boot test can kill it and check that nothing leaks.
#![no_std]
#![no_main]

extern crate alloc;

use liboos::ipc::{Channel, Error, Handle, Message, Notification, ObjectType, Process, Rights};
use liboos::println;

liboos::entry!(main);

const ECHO: u64 = 1;
const NOTIFY: u64 = 2;
const DELAYED: u64 = 3;
const TAKE: u64 = 4;
const DROP: u64 = 5;
const GIVE: u64 = 6;
const QUIT: u64 = 7;

macro_rules! check {
    ($n:expr, $cond:expr) => {
        if !$cond {
            println!("[ipcclient] check {} FAILED: {}", $n, stringify!($cond));
            return $n;
        }
    };
}

fn main(args: liboos::Args) -> i32 {
    match args.get(1) {
        Some("block-recv") => {
            let ch = Channel(Handle::bootstrap(1));
            let _ = ch.recv(0); // nobody sends: sleeps until killed
            return 99;
        }
        Some("block-call") => {
            let ch = Channel(Handle::bootstrap(1));
            let mut m = Message::new(1);
            let _ = ch.call(&mut m); // nobody receives: sleeps until killed
            return 99;
        }
        _ => {}
    }
    run()
}

fn run() -> i32 {
    let chan = Channel(Handle::bootstrap(1));
    let notif = Notification(Handle::bootstrap(2));
    let server = Process(Handle::bootstrap(3));

    // 1: handles that were installed at start have the types and rights we expect
    check!(1, chan.0.info() == Ok((ObjectType::Channel, Rights::WRITE | Rights::DUP)));
    check!(1, notif.0.info() == Ok((ObjectType::Notification, Rights::READ)));
    check!(1, server.0.info() == Ok((ObjectType::Process, Rights::READ)));

    // 2: 129 echo round trips, payload lengths 0..=128, content checked byte for byte
    for n in 0..=128usize {
        let mut payload = [0u8; 128];
        for (i, b) in payload[..n].iter_mut().enumerate() {
            *b = (i * 7 + n) as u8;
        }
        let mut m = Message::with_data(ECHO, &payload[..n]);
        let r = match chan.call(&mut m) {
            Ok(r) => r,
            Err(e) => {
                println!("[ipcclient] echo {} failed: {:?}", n, e);
                return 2;
            }
        };
        check!(2, r.tag == ECHO && r.data() == &payload[..n]);
    }
    println!("[ipcclient] 129 echoes ok");

    // 3: a payload longer than 128 bytes is refused, not truncated
    let mut big = Message::new(ECHO);
    big.set_len_unchecked(129);
    check!(3, chan.call(&mut big).err() == Some(Error::InvalidArgument));

    // 4: notification signalled by the server before we wait
    let mut m = Message::with_data(NOTIFY, &0x5u32.to_le_bytes());
    check!(4, chan.call(&mut m).is_ok());
    check!(4, notif.wait(100) == Ok(0x5));

    // 5: notification that arrives while we sleep in wait()
    let mut m = Message::with_data(DELAYED, &0x30u32.to_le_bytes());
    check!(5, chan.call(&mut m).is_ok());
    check!(5, notif.wait(100) == Ok(0x30));
    // nothing pending: wait times out (and does not spin)
    let t0 = liboos::uptime_ticks();
    check!(5, notif.wait(5) == Err(Error::Timeout));
    check!(5, liboos::uptime_ticks() >= t0 + 5);

    // 6: hand a channel handle to the server (request direction)
    let mine = match Channel::create() {
        Ok(c) => c,
        Err(_) => return 6,
    };
    let write_only = match mine.duplicate(Rights::WRITE | Rights::TRANSFER) {
        Ok(c) => c,
        Err(_) => return 6,
    };
    let mut m = Message::new(TAKE);
    check!(6, m.push_handle(write_only.0).is_ok());
    let r = match chan.call(&mut m) {
        Ok(r) => r,
        Err(_) => return 6,
    };
    check!(6, r.data() == [1, 1]); // server: recv refused (rights), send through it worked
    let (got, reply) = match mine.recv(100) {
        Ok(x) => x,
        Err(_) => return 6,
    };
    check!(6, got.tag == 0x44 && got.data() == b"via-transfer" && reply.is_none());

    // 7: receive a handle in a reply (reply direction)
    let mut m = Message::new(GIVE);
    let mut r = match chan.call(&mut m) {
        Ok(r) => r,
        Err(_) => return 7,
    };
    check!(7, r.handle_count() == 1);
    let given = match r.take_handle(0) {
        Some(h) => Notification(h),
        None => return 7,
    };
    check!(7, given.0.info() == Ok((ObjectType::Notification, Rights::READ | Rights::TRANSFER)));
    check!(7, given.wait(100) == Ok(0x77));

    // 8: rights and type checks
    let read_only = match mine.duplicate(Rights::READ) {
        Ok(c) => c,
        Err(_) => return 8,
    };
    check!(8, read_only.duplicate(Rights::READ).err() == Some(Error::PermissionDenied)); // no DUP
    check!(8, mine.duplicate(Rights(0x70)).err() == Some(Error::PermissionDenied)); // unknown rights
    check!(8, read_only.send(&mut Message::new(0)).err() == Some(Error::PermissionDenied)); // no WRITE
    // moving a handle without TRANSFER is refused and leaves it in our table
    let mut with_ro = Message::new(0);
    let _ = with_ro.push_handle(Handle::from_raw(read_only.0.raw()));
    check!(8, mine.send(&mut with_ro).err() == Some(Error::PermissionDenied));
    core::mem::forget(with_ro); // the handle is still owned by read_only
    check!(8, read_only.0.info().is_ok());
    // wrong object type
    // (the aliases below must not close the real handles when dropped)
    let as_notif = Notification(Handle::from_raw(chan.0.raw()));
    let r = as_notif.signal(1);
    core::mem::forget(as_notif);
    check!(8, r.err() == Some(Error::WrongType));
    let as_chan = Channel(Handle::from_raw(server.0.raw()));
    let r = as_chan.send(&mut Message::new(0));
    core::mem::forget(as_chan);
    check!(8, r.err() == Some(Error::WrongType));
    // a handle that was never issued
    check!(8, Handle::from_raw(0x7FFF).info().err() == Some(Error::BadHandle));
    check!(8, Handle::from_raw(0).info().err() == Some(Error::BadHandle));
    // a closed handle is dead for good, even if its slot gets reused
    let tmp = match mine.duplicate(Rights::WRITE) {
        Ok(c) => c,
        Err(_) => return 8,
    };
    let stale = tmp.0.raw();
    check!(8, tmp.0.close().is_ok());
    let tmp2 = match mine.duplicate(Rights::WRITE) {
        Ok(c) => c,
        Err(_) => return 8,
    };
    check!(8, tmp2.0.raw() != stale);
    check!(8, Handle::from_raw(stale).info().err() == Some(Error::BadHandle));
    // nothing queued on `mine`: recv times out instead of spinning
    check!(8, mine.recv(2).err() == Some(Error::Timeout));
    // one-way send round trip on our own channel
    check!(8, mine.send(&mut Message::with_data(9, b"self")).is_ok());
    let (m9, rep9) = match mine.recv(100) {
        Ok(x) => x,
        Err(_) => return 8,
    };
    check!(8, m9.tag == 9 && m9.data() == b"self" && rep9.is_none());
    drop(tmp2);
    drop(read_only);
    println!("[ipcclient] rights and type checks ok");

    // 9: the server drops our reply handle: call must fail, not hang
    let mut m = Message::new(DROP);
    let r9 = chan.call(&mut m);
    println!("[ipcclient] drop result: {:?}", r9.as_ref().err());
    check!(9, r9.err() == Some(Error::PeerClosed));

    // 10: server is alive; wait times out, then QUIT and collect its exit code
    check!(10, server.wait(2).err() == Some(Error::Timeout));
    let mut m = Message::new(QUIT);
    let r = match chan.call(&mut m) {
        Ok(r) => r,
        Err(_) => return 10,
    };
    check!(10, r.data() == b"bye");
    check!(10, server.wait(300) == Ok(42));

    // 11: the server's handles were closed with it: the channel has no receiver any more
    check!(11, chan.call(&mut Message::new(ECHO)).err() == Some(Error::PeerClosed));

    // 12: own process/thread handles
    let me = match Process::current() {
        Ok(p) => p,
        Err(_) => return 12,
    };
    check!(12, me.0.info() == Ok((ObjectType::Process, Rights::ALL)));
    check!(12, Process::current_thread().and_then(|t| t.0.info()) == Ok((ObjectType::Thread, Rights::ALL)));
    check!(12, me.kill().err() == Some(Error::InvalidArgument)); // not for yourself: use exit

    println!("[ipcclient] all checks passed");
    0
}
