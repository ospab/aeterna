/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

System calls on kernel objects: handles, channels (IPC), notifications, processes,
memory regions, interrupts and I/O ports.
The logic is in core/object.rs; here only the user-memory copies and error mapping.
ABI of each call: docs/en/syscall-abi.md.
*/

use crate::core::object::{self, Res, UserMessage, USER_MESSAGE_SIZE};
use crate::mm::usercopy;

use super::SyscallError;

fn ret<T: Into<i64>>(r: Res<T>) -> i64 {
    match r {
        Ok(v) => v.into(),
        Err(e) => e,
    }
}

fn ret_unit(r: Res<()>) -> i64 {
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn read_message(ptr: u64) -> Res<UserMessage> {
    let mut m = UserMessage::empty();
    // SAFETY: UserMessage is plain old data (integers and byte arrays); any bytes are valid.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(&mut m as *mut UserMessage as *mut u8, USER_MESSAGE_SIZE)
    };
    usercopy::copy_from_user(bytes, ptr).map_err(|e| SyscallError::from(e) as i64)?;
    Ok(m)
}

fn write_message(ptr: u64, m: &UserMessage) -> Res<()> {
    // SAFETY: as above.
    let bytes = unsafe {
        core::slice::from_raw_parts(m as *const UserMessage as *const u8, USER_MESSAGE_SIZE)
    };
    usercopy::copy_to_user(ptr, bytes).map_err(|e| SyscallError::from(e) as i64)
}

// 200
pub fn handle_close(h: u64) -> i64 {
    ret_unit(object::handle_close(h as u32))
}

// 201
pub fn handle_dup(h: u64, rights: u64) -> i64 {
    ret(object::handle_dup(h as u32, rights as u32))
}

// 202: object type in bits 0..8, rights in bits 8..
pub fn handle_info(h: u64) -> i64 {
    match object::handle_info(h as u32) {
        Ok((t, r)) => (t as i64) | ((r as i64) << 8),
        Err(e) => e,
    }
}

// 210
pub fn channel_create() -> i64 {
    ret(object::channel_create())
}

// 211: call(channel, request*, reply*) -> reply.len
pub fn ipc_call(ch: u64, req: u64, rep: u64) -> i64 {
    let m = match read_message(req) {
        Ok(m) => m,
        Err(e) => return e,
    };
    match object::ipc_call(ch as u32, &m) {
        Ok(reply) => match write_message(rep, &reply) {
            Ok(()) => reply.len as i64,
            Err(e) => e,
        },
        Err(e) => e,
    }
}

// 212: send(channel, message*)
pub fn ipc_send(ch: u64, msg: u64) -> i64 {
    match read_message(msg) {
        Ok(m) => ret_unit(object::ipc_send(ch as u32, &m)),
        Err(e) => e,
    }
}

// 213: recv(channel, message*, timeout_ticks) -> reply handle (0 = one-way message)
pub fn ipc_recv(ch: u64, out: u64, timeout: u64) -> i64 {
    // Probe the destination first: a bad pointer must not cost a queued request.
    if !usercopy::range_ok(out, USER_MESSAGE_SIZE) {
        return SyscallError::BadAddress as i64;
    }
    match object::ipc_recv(ch as u32, timeout) {
        Ok((m, rh)) => match write_message(out, &m) {
            Ok(()) => rh as i64,
            Err(e) => {
                // Could not deliver: drop what we installed so nothing leaks.
                for i in 0..m.nhandles as usize {
                    let _ = object::handle_close(m.handles[i]);
                }
                if rh != 0 {
                    let _ = object::handle_close(rh);
                }
                e
            }
        },
        Err(e) => e,
    }
}

// 214: reply(reply_handle, message*)
pub fn ipc_reply(rh: u64, msg: u64) -> i64 {
    match read_message(msg) {
        Ok(m) => ret_unit(object::ipc_reply(rh as u32, &m)),
        Err(e) => e,
    }
}

// 220
pub fn notify_create() -> i64 {
    ret(object::notification_create())
}

// 221: signal(notification, bits)
pub fn notify_signal(h: u64, bits: u64) -> i64 {
    ret_unit(object::notify_signal(h as u32, bits as u32))
}

// 222: wait(notification, timeout_ticks) -> bits (never 0)
pub fn notify_wait(h: u64, timeout: u64) -> i64 {
    ret(object::notify_wait(h as u32, timeout).map(|b| b as i64))
}

// 230
pub fn process_self() -> i64 {
    ret(object::process_self())
}

// 231
pub fn thread_self() -> i64 {
    ret(object::thread_self())
}

// 232: wait(process or thread handle, exit_code*, timeout_ticks) -> 0
pub fn process_wait(h: u64, code_ptr: u64, timeout: u64) -> i64 {
    match object::process_wait(h as u32, timeout) {
        Ok(code) => {
            if code_ptr != 0 {
                if let Err(e) = usercopy::copy_to_user(code_ptr, &code.to_le_bytes()) {
                    return SyscallError::from(e) as i64;
                }
            }
            0
        }
        Err(e) => e,
    }
}

// 233
pub fn process_kill(h: u64) -> i64 {
    ret_unit(object::process_kill(h as u32))
}

// 240: mem_create(size) -> h
pub fn mem_create(size: u64) -> i64 {
    ret(object::mem_create(size))
}

// 241: mem_map(h, hint, prot) -> user address
pub fn mem_map(h: u64, hint: u64, prot: u64) -> i64 {
    if prot > u32::MAX as u64 {
        return SyscallError::InvalidArgument as i64;
    }
    ret(object::mem_map(h as u32, hint, prot as u32).map(|a| a as i64))
}

// 242: mem_unmap(addr)
pub fn mem_unmap(addr: u64) -> i64 {
    ret_unit(object::mem_unmap(addr))
}

// 243: mem_create_contig(resource, size) -> h (with PHYS)
pub fn mem_create_contig(res: u64, size: u64) -> i64 {
    ret(object::mem_create_contig(res as u32, size))
}

// 244: mem_phys(h) -> physical address
pub fn mem_phys(h: u64) -> i64 {
    ret(object::mem_phys(h as u32).map(|a| a as i64))
}

// 245: mem_size(h) -> bytes
pub fn mem_size(h: u64) -> i64 {
    ret(object::mem_size(h as u32).map(|a| a as i64))
}

// 250: irq_bind(irq, notification, bits)
pub fn irq_bind(irq: u64, notif: u64, bits: u64) -> i64 {
    ret_unit(object::irq_bind(irq as u32, notif as u32, bits as u32))
}

// 251: irq_ack(irq)
pub fn irq_ack(irq: u64) -> i64 {
    ret_unit(object::irq_ack(irq as u32))
}

// 252: ioport_enable(h)
pub fn ioport_enable(h: u64) -> i64 {
    ret_unit(object::ioport_enable(h as u32))
}

// 253: ioport_disable(h)
pub fn ioport_disable(h: u64) -> i64 {
    ret_unit(object::ioport_disable(h as u32))
}
