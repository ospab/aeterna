// SPDX-License-Identifier: AGPL-3.0-only
//! Kernel objects and IPC: handles, channels, notifications, processes.
//! Safe wrappers over the syscalls described in `docs/SYSCALL-ABI.md`.
//!
//! A [`Handle`] owns one reference to a kernel object and closes it when dropped.
//! The kernel checks the object type and the handle's [`Rights`] on every call.

use crate::sys::{self, nr};

/// Largest payload of one message.
pub const MSG_DATA_MAX: usize = 128;
/// Most handles one message can carry.
pub const MSG_HANDLES_MAX: usize = 4;

/// What the kernel reports when a call fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The handle lacks a right the call needs (or a duplicate asked for more rights).
    PermissionDenied,
    InvalidArgument,
    /// The handle value is not valid (never issued, closed, or stale).
    BadHandle,
    /// The handle refers to another kind of object than the call expects.
    WrongType,
    /// The other side is gone: channel closed, or the reply handle was dropped unused.
    PeerClosed,
    TableFull,
    Timeout,
    /// The channel's queue is full.
    Busy,
    BadAddress,
    OutOfMemory,
    Other(i64),
}

impl Error {
    fn from_code(c: i64) -> Error {
        match c {
            sys::err::PERMISSION_DENIED => Error::PermissionDenied,
            sys::err::INVALID_ARGUMENT => Error::InvalidArgument,
            sys::err::BAD_HANDLE => Error::BadHandle,
            sys::err::WRONG_TYPE => Error::WrongType,
            sys::err::PEER_CLOSED => Error::PeerClosed,
            sys::err::TABLE_FULL => Error::TableFull,
            sys::err::TIMEOUT => Error::Timeout,
            sys::err::BUSY => Error::Busy,
            sys::err::BAD_ADDRESS => Error::BadAddress,
            sys::err::OUT_OF_MEMORY => Error::OutOfMemory,
            other => Error::Other(other),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

fn check(r: i64) -> Result<i64> {
    if r < 0 { Err(Error::from_code(r)) } else { Ok(r) }
}

/// What a handle allows. Combine with `|`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rights(pub u32);

impl Rights {
    /// Receive on a channel, wait on a notification, wait for a process.
    pub const READ: Rights = Rights(1);
    /// Call / send on a channel, signal a notification, reply, kill a process.
    pub const WRITE: Rights = Rights(2);
    /// May be duplicated.
    pub const DUP: Rights = Rights(4);
    /// May be moved to another process inside a message.
    pub const TRANSFER: Rights = Rights(8);
    pub const ALL: Rights = Rights(15);

    pub fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, o: Rights) -> Rights {
        Rights(self.0 | o.0)
    }
}

/// Kind of object behind a handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    Process,
    Thread,
    Channel,
    Notification,
    Reply,
}

/// An owned reference to a kernel object. Closed on drop.
#[derive(Debug, PartialEq, Eq)]
pub struct Handle(u32);

impl Handle {
    /// Wrap a raw handle value the program owns (for example one received in a message).
    pub const fn from_raw(raw: u32) -> Handle {
        Handle(raw)
    }

    /// The raw value; the handle stays owned.
    pub const fn raw(&self) -> u32 {
        self.0
    }

    /// Give up ownership without closing.
    pub fn into_raw(self) -> u32 {
        let r = self.0;
        core::mem::forget(self);
        r
    }

    /// Bootstrap handle number `n` (1-based) that the kernel installed before the program
    /// started, in the order its parent listed them.
    pub const fn bootstrap(n: u32) -> Handle {
        Handle(n)
    }

    /// New handle to the same object with the given (equal or fewer) rights.
    /// Needs [`Rights::DUP`].
    pub fn duplicate(&self, rights: Rights) -> Result<Handle> {
        let r = unsafe { sys::syscall2(nr::HANDLE_DUP, self.0 as u64, rights.0 as u64) };
        check(r).map(|h| Handle(h as u32))
    }

    /// Type and rights of the object behind this handle.
    pub fn info(&self) -> Result<(ObjectType, Rights)> {
        let r = check(unsafe { sys::syscall1(nr::HANDLE_INFO, self.0 as u64) })?;
        let ty = match r & 0xFF {
            1 => ObjectType::Process,
            2 => ObjectType::Thread,
            3 => ObjectType::Channel,
            4 => ObjectType::Notification,
            _ => ObjectType::Reply,
        };
        Ok((ty, Rights((r >> 8) as u32)))
    }

    /// Close explicitly and see the result (dropping ignores it).
    pub fn close(self) -> Result<()> {
        let raw = self.into_raw();
        check(unsafe { sys::syscall1(nr::HANDLE_CLOSE, raw as u64) }).map(|_| ())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { sys::syscall1(nr::HANDLE_CLOSE, self.0 as u64) };
    }
}

/// An IPC message: a 64-bit tag, up to 128 bytes of data and up to 4 handles.
///
/// Handles pushed into a message are *moved* to the receiver (they need
/// [`Rights::TRANSFER`]). Handles in a received message belong to the receiver.
/// Same memory layout as the kernel's `UserMessage`.
#[repr(C)]
pub struct Message {
    pub tag: u64,
    len: u32,
    nhandles: u32,
    handles: [u32; MSG_HANDLES_MAX],
    data: [u8; MSG_DATA_MAX],
}

impl Message {
    pub const fn new(tag: u64) -> Message {
        Message { tag, len: 0, nhandles: 0, handles: [0; MSG_HANDLES_MAX], data: [0; MSG_DATA_MAX] }
    }

    /// A message carrying `data` (truncated to 128 bytes).
    pub fn with_data(tag: u64, data: &[u8]) -> Message {
        let mut m = Message::new(tag);
        m.set_data(data);
        m
    }

    pub fn set_data(&mut self, data: &[u8]) {
        let n = data.len().min(MSG_DATA_MAX);
        self.data[..n].copy_from_slice(&data[..n]);
        self.len = n as u32;
    }

    pub fn data(&self) -> &[u8] {
        &self.data[..(self.len as usize).min(MSG_DATA_MAX)]
    }

    /// Move `h` into the message. Fails (returning the handle) when it is full.
    pub fn push_handle(&mut self, h: Handle) -> core::result::Result<(), Handle> {
        if self.nhandles as usize >= MSG_HANDLES_MAX {
            return Err(h);
        }
        self.handles[self.nhandles as usize] = h.into_raw();
        self.nhandles += 1;
        Ok(())
    }

    pub fn handle_count(&self) -> usize {
        self.nhandles as usize
    }

    /// Take ownership of handle `i` of a received message.
    pub fn take_handle(&mut self, i: usize) -> Option<Handle> {
        if i >= self.nhandles as usize || self.handles[i] == 0 {
            return None;
        }
        let raw = core::mem::replace(&mut self.handles[i], 0);
        Some(Handle(raw))
    }

    /// For tests: pretend the payload is `len` bytes long, whatever it really is.
    #[doc(hidden)]
    pub fn set_len_unchecked(&mut self, len: u32) {
        self.len = len;
    }

    fn ptr(&self) -> u64 {
        self as *const Message as u64
    }

    /// The kernel took the handles (or the call failed before it did, in which case
    /// closing them again below is harmless: stale values are rejected).
    fn forget_handles(&mut self) {
        self.nhandles = 0;
        self.handles = [0; MSG_HANDLES_MAX];
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        for i in 0..(self.nhandles as usize).min(MSG_HANDLES_MAX) {
            if self.handles[i] != 0 {
                unsafe { sys::syscall1(nr::HANDLE_CLOSE, self.handles[i] as u64) };
            }
        }
    }
}

/// A channel endpoint. Servers hold it with [`Rights::READ`], clients with [`Rights::WRITE`].
#[derive(Debug, PartialEq, Eq)]
pub struct Channel(pub Handle);

impl Channel {
    /// New channel; the handle has all rights.
    pub fn create() -> Result<Channel> {
        check(unsafe { sys::syscall0(nr::CHANNEL_CREATE) }).map(|h| Channel(Handle(h as u32)))
    }

    pub fn duplicate(&self, rights: Rights) -> Result<Channel> {
        self.0.duplicate(rights).map(Channel)
    }

    /// Send a request and sleep until the server replies. Handles in `msg` move to the server.
    pub fn call(&self, msg: &mut Message) -> Result<Message> {
        let mut reply = Message::new(0);
        let r = unsafe {
            sys::syscall3(nr::IPC_CALL, (self.0).0 as u64, msg.ptr(), &mut reply as *mut Message as u64)
        };
        let r = check(r);
        if r.is_ok() {
            msg.forget_handles();
        }
        r.map(|_| reply)
    }

    /// Queue a one-way message; never blocks. Errors with [`Error::Busy`] when the queue is full.
    pub fn send(&self, msg: &mut Message) -> Result<()> {
        let r = check(unsafe { sys::syscall2(nr::IPC_SEND, (self.0).0 as u64, msg.ptr()) });
        if r.is_ok() {
            msg.forget_handles();
        }
        r.map(|_| ())
    }

    /// Wait for the next request. `timeout_ticks` is in 10 ms units, 0 = wait forever.
    /// A request from `call` comes with a [`Reply`]; a one-way `send` has none.
    pub fn recv(&self, timeout_ticks: u64) -> Result<(Message, Option<Reply>)> {
        let mut msg = Message::new(0);
        let r = check(unsafe {
            sys::syscall3(nr::IPC_RECV, (self.0).0 as u64, &mut msg as *mut Message as u64, timeout_ticks)
        })?;
        let reply = if r == 0 { None } else { Some(Reply(Handle(r as u32))) };
        Ok((msg, reply))
    }
}

/// The right to answer one request. Dropping it unused makes the caller's `call` fail
/// with [`Error::PeerClosed`].
#[derive(Debug, PartialEq, Eq)]
pub struct Reply(pub Handle);

impl Reply {
    /// Answer the caller; handles in `msg` move to it.
    pub fn reply(self, mut msg: Message) -> Result<()> {
        let r = check(unsafe { sys::syscall2(nr::IPC_REPLY, (self.0).0 as u64, msg.ptr()) });
        // Consumed by the kernel when the call got through to the caller (or it was gone).
        if !matches!(r, Err(Error::InvalidArgument) | Err(Error::PermissionDenied) | Err(Error::BadHandle)) {
            core::mem::forget(self);
        }
        if r.is_ok() {
            msg.forget_handles();
        }
        r.map(|_| ())
    }
}

/// A 32-bit signal word: `signal` ORs bits in, `wait` sleeps until any is set and takes them.
#[derive(Debug, PartialEq, Eq)]
pub struct Notification(pub Handle);

impl Notification {
    pub fn create() -> Result<Notification> {
        check(unsafe { sys::syscall0(nr::NOTIFY_CREATE) }).map(|h| Notification(Handle(h as u32)))
    }

    pub fn duplicate(&self, rights: Rights) -> Result<Notification> {
        self.0.duplicate(rights).map(Notification)
    }

    /// Needs [`Rights::WRITE`].
    pub fn signal(&self, bits: u32) -> Result<()> {
        check(unsafe { sys::syscall2(nr::NOTIFY_SIGNAL, (self.0).0 as u64, bits as u64) }).map(|_| ())
    }

    /// Needs [`Rights::READ`]. Returns the bits (never 0) and clears them.
    /// `timeout_ticks` is in 10 ms units, 0 = wait forever.
    pub fn wait(&self, timeout_ticks: u64) -> Result<u32> {
        check(unsafe { sys::syscall2(nr::NOTIFY_WAIT, (self.0).0 as u64, timeout_ticks) }).map(|b| b as u32)
    }
}

/// A process (or thread) handle.
#[derive(Debug, PartialEq, Eq)]
pub struct Process(pub Handle);

impl Process {
    /// A handle to the calling process (all rights).
    pub fn current() -> Result<Process> {
        check(unsafe { sys::syscall0(nr::PROCESS_SELF) }).map(|h| Process(Handle(h as u32)))
    }

    /// A handle to the calling thread.
    pub fn current_thread() -> Result<Process> {
        check(unsafe { sys::syscall0(nr::THREAD_SELF) }).map(|h| Process(Handle(h as u32)))
    }

    /// Sleep until the process exits; returns its exit code. Needs [`Rights::READ`].
    /// `timeout_ticks` is in 10 ms units, 0 = wait forever.
    pub fn wait(&self, timeout_ticks: u64) -> Result<i64> {
        let mut code: i64 = 0;
        check(unsafe {
            sys::syscall3(nr::PROCESS_WAIT, (self.0).0 as u64, &mut code as *mut i64 as u64, timeout_ticks)
        })?;
        Ok(code)
    }

    /// Terminate the process. Needs [`Rights::WRITE`].
    pub fn kill(&self) -> Result<()> {
        check(unsafe { sys::syscall1(nr::PROCESS_KILL, (self.0).0 as u64) }).map(|_| ())
    }
}
