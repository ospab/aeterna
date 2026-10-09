/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Kernel objects, per-process handle tables and IPC (ROADMAP stage 2, items 10-11).

A process can touch a kernel object only through a *handle*: an index into its own
table, paired with a set of *rights*. The kernel checks object type and rights on every
call. Handles are the capabilities; there is no ambient authority in this API.

Objects (all reference-counted, one reference per handle or in-flight message):
  Process       a task, identified by pid; waitable, killable
  Thread        same task seen as a thread (one thread per process for now)
  Channel       IPC endpoint: synchronous call/reply, queued one-way send
  Notification  32-bit signal word; signal ORs bits in, wait blocks and takes them
  Reply         one-shot right to answer one caller, created by `call`, handed to the
                receiver by `recv`; if it is dropped unused the caller gets PeerClosed

Rights: READ (receive / wait / inspect), WRITE (call, send, signal / kill, reply),
DUP (may be duplicated), TRANSFER (may be moved to another process in a message).

Blocking never spins: the caller is marked Waiting, put on the object's wait list and the
CPU halts; the other side wakes it. All entry points run with interrupts disabled (syscall
entry masks IF); `park` re-enables them only around HLT. Single CPU for now, so no locks.

Handle value: (generation << 16) | (slot + 1). Zero is never valid. Slots are reused with
a new generation, so a stale handle is rejected instead of silently hitting a new object.
Bootstrap handles installed by the kernel before a program starts get values 1, 2, 3...
*/

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::core::scheduler;
use crate::core::syscall::SyscallError as E;

pub type Handle = u32;
pub type ObjId = u32;
pub type Res<T> = Result<T, i64>;

pub mod rights {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const DUP: u32 = 4;
    pub const TRANSFER: u32 = 8;
    pub const ALL: u32 = 15;
}
use rights::*;

pub const MSG_DATA_MAX: usize = 128;
pub const MSG_HANDLES_MAX: usize = 4;
/// Requests queued on one channel before `send`/`call` report Busy.
const CHAN_QUEUE_MAX: usize = 16;
/// Handles per process.
pub const TABLE_MAX: usize = 256;
const OBJECTS_MAX: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ObjType {
    Process = 1,
    Thread = 2,
    Channel = 3,
    Notification = 4,
    Reply = 5,
}

/// A message as user space sees it (same layout in liboos). 160 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserMessage {
    /// Free for the protocol (request code, error code...). Copied verbatim.
    pub tag: u64,
    /// Valid bytes in `data`, at most 128.
    pub len: u32,
    /// Handles in `handles` (at most 4). In: handles to move to the peer.
    /// Out: the handle values installed in the receiver's table.
    pub nhandles: u32,
    pub handles: [u32; MSG_HANDLES_MAX],
    pub data: [u8; MSG_DATA_MAX],
}

pub const USER_MESSAGE_SIZE: usize = core::mem::size_of::<UserMessage>();

impl UserMessage {
    pub const fn empty() -> Self {
        UserMessage { tag: 0, len: 0, nhandles: 0, handles: [0; MSG_HANDLES_MAX], data: [0; MSG_DATA_MAX] }
    }
}

// ─── Objects ─────────────────────────────────────────────────────────────────────────

/// A message inside the kernel: the payload and the handles it carries (moved out of the
/// sender's table; each still owns one reference until installed or dropped).
struct Parcel {
    tag: u64,
    len: u32,
    data: [u8; MSG_DATA_MAX],
    nh: usize,
    handles: [(ObjId, u32); MSG_HANDLES_MAX],
}

impl Parcel {
    fn new() -> Parcel {
        Parcel { tag: 0, len: 0, data: [0; MSG_DATA_MAX], nh: 0, handles: [(0, 0); MSG_HANDLES_MAX] }
    }
}

struct Request {
    parcel: Parcel,
    /// Reply object to answer on; None for one-way `send`.
    reply: Option<ObjId>,
}

struct Channel {
    queue: VecDeque<Request>,
    receivers: Vec<u32>,
    /// Handles with READ. When this reaches zero nobody can ever answer: the channel closes.
    recv_refs: u32,
    closed: bool,
}

struct Notification {
    bits: u32,
    waiters: Vec<u32>,
}

enum ReplyState {
    Pending,
    Done(Parcel),
    Failed(i64),
}

struct Reply {
    /// The blocked caller; None once it has collected the answer or died.
    caller: Option<u32>,
    state: ReplyState,
}

enum Kind {
    Process(u32),
    Thread(u32),
    Channel(Channel),
    Notification(Notification),
    Reply(Reply),
}

struct Object {
    /// Handles + in-flight messages referring to this object.
    refs: u32,
    kind: Kind,
}

static mut OBJECTS: Vec<Option<Object>> = Vec::new();
static mut LIVE_OBJECTS: usize = 0;
/// (waiter pid, pid being waited for)
static mut PROC_WAITERS: Vec<(u32, u32)> = Vec::new();

fn objects() -> &'static mut Vec<Option<Object>> {
    // SAFETY: single CPU, callers run with interrupts disabled.
    unsafe { &mut *core::ptr::addr_of_mut!(OBJECTS) }
}

fn obj(id: ObjId) -> &'static mut Object {
    objects()[id as usize].as_mut().expect("object id")
}

fn obj_type(o: &Object) -> ObjType {
    match o.kind {
        Kind::Process(_) => ObjType::Process,
        Kind::Thread(_) => ObjType::Thread,
        Kind::Channel(_) => ObjType::Channel,
        Kind::Notification(_) => ObjType::Notification,
        Kind::Reply(_) => ObjType::Reply,
    }
}

/// Number of live kernel objects (for leak checks).
pub fn live_objects() -> usize {
    unsafe { LIVE_OBJECTS }
}

/// Create an object with no references yet; the caller installs a handle or calls
/// `release_unused`.
fn new_object(kind: Kind) -> Res<ObjId> {
    let v = objects();
    let slot = match v.iter().position(|o| o.is_none()) {
        Some(i) => i,
        None => {
            if v.len() >= OBJECTS_MAX {
                return Err(E::OutOfMemory as i64);
            }
            v.push(None);
            v.len() - 1
        }
    };
    v[slot] = Some(Object { refs: 0, kind });
    unsafe { LIVE_OBJECTS += 1 };
    Ok(slot as ObjId)
}

fn new_channel_obj() -> Res<ObjId> {
    new_object(Kind::Channel(Channel {
        queue: VecDeque::new(),
        receivers: Vec::new(),
        recv_refs: 0,
        closed: false,
    }))
}

fn new_notification_obj() -> Res<ObjId> {
    new_object(Kind::Notification(Notification { bits: 0, waiters: Vec::new() }))
}

fn free_object(id: ObjId) {
    objects()[id as usize] = None;
    unsafe { LIVE_OBJECTS -= 1 };
}

/// Count a new handle (or message slot) referring to `id`.
fn ref_add(id: ObjId, r: u32) {
    let o = obj(id);
    o.refs += 1;
    if let Kind::Channel(c) = &mut o.kind {
        if r & READ != 0 {
            c.recv_refs += 1;
        }
    }
}

fn wake_all(pids: &mut Vec<u32>) {
    for p in pids.drain(..) {
        scheduler::wake(p);
    }
}

/// Drop one reference. Frees the object at zero; closing the last receiving handle of a
/// channel fails every queued request. Iterative: dropping a message can drop more objects.
fn unref(id: ObjId, r: u32) {
    let mut work: Vec<(ObjId, u32)> = Vec::new();
    work.push((id, r));
    while let Some((id, r)) = work.pop() {
        let o = obj(id);
        o.refs -= 1;
        let refs = o.refs;
        let mut keep = false;
        match &mut o.kind {
            Kind::Channel(c) => {
                if r & READ != 0 {
                    c.recv_refs -= 1;
                    if c.recv_refs == 0 && !c.closed {
                        c.closed = true;
                        wake_all(&mut c.receivers);
                        for req in c.queue.drain(..) {
                            for i in 0..req.parcel.nh {
                                work.push(req.parcel.handles[i]);
                            }
                            if let Some(rid) = req.reply {
                                work.push((rid, WRITE));
                            }
                        }
                    }
                }
            }
            Kind::Reply(rp) => {
                if refs == 0 {
                    if let ReplyState::Pending = rp.state {
                        rp.state = ReplyState::Failed(E::PeerClosed as i64);
                        if let Some(c) = rp.caller {
                            scheduler::wake(c);
                        }
                    }
                    // A blocked caller still reads the outcome: it frees the object.
                    keep = rp.caller.is_some();
                }
            }
            _ => {}
        }
        if refs == 0 && !keep {
            let old = objects()[id as usize].take();
            unsafe { LIVE_OBJECTS -= 1 };
            // An unconsumed reply still owns the handles it carries.
            if let Some(Object { kind: Kind::Reply(Reply { state: ReplyState::Done(p), .. }), .. }) = old {
                for i in 0..p.nh {
                    work.push(p.handles[i]);
                }
            }
        }
    }
}

fn drop_parcel(p: &Parcel) {
    for i in 0..p.nh {
        unref(p.handles[i].0, p.handles[i].1);
    }
}

// ─── Handle tables ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct Entry {
    obj: ObjId,
    rights: u32,
    gen: u16,
    used: bool,
}

#[derive(Clone, Debug, Default)]
pub struct HandleTable {
    slots: Vec<Entry>,
}

impl HandleTable {
    pub const fn new() -> HandleTable {
        HandleTable { slots: Vec::new() }
    }

    fn free_slots(&self) -> usize {
        self.slots.iter().filter(|e| !e.used).count() + (TABLE_MAX - self.slots.len())
    }

    fn alloc(&mut self, obj: ObjId, rights: u32) -> Res<Handle> {
        let idx = match self.slots.iter().position(|e| !e.used) {
            Some(i) => i,
            None => {
                if self.slots.len() >= TABLE_MAX {
                    return Err(E::TableFull as i64);
                }
                self.slots.push(Entry { obj: 0, rights: 0, gen: 0, used: false });
                self.slots.len() - 1
            }
        };
        let e = &mut self.slots[idx];
        e.obj = obj;
        e.rights = rights;
        e.used = true;
        Ok(((e.gen as u32) << 16) | (idx as u32 + 1))
    }

    fn get(&self, h: Handle) -> Res<Entry> {
        let idx = (h & 0xFFFF) as usize;
        if idx == 0 || idx > self.slots.len() {
            return Err(E::BadHandle as i64);
        }
        let e = self.slots[idx - 1];
        if !e.used || e.gen != (h >> 16) as u16 {
            return Err(E::BadHandle as i64);
        }
        Ok(e)
    }

    /// Remove the handle from the table, returning what it referred to (its reference moves
    /// to the caller).
    fn take(&mut self, h: Handle) -> Res<Entry> {
        let e = self.get(h)?;
        let s = &mut self.slots[(h & 0xFFFF) as usize - 1];
        s.used = false;
        s.gen = s.gen.wrapping_add(1);
        Ok(e)
    }

    /// Close everything (process exit).
    fn close_all(&mut self) {
        let slots = core::mem::take(&mut self.slots);
        for e in slots {
            if e.used {
                unref(e.obj, e.rights);
            }
        }
    }
}

fn cur_table() -> &'static mut HandleTable {
    scheduler::current_handles()
}

/// Look up a handle of the current process, checking type and rights.
fn lookup(h: Handle, ty: ObjType, need: u32) -> Res<(ObjId, u32)> {
    let e = cur_table().get(h)?;
    if obj_type(obj(e.obj)) != ty {
        return Err(E::WrongType as i64);
    }
    if e.rights & need != need {
        return Err(E::PermissionDenied as i64);
    }
    Ok((e.obj, e.rights))
}

// ─── Handle syscalls ─────────────────────────────────────────────────────────────────

pub fn handle_close(h: Handle) -> Res<()> {
    let e = cur_table().take(h)?;
    unref(e.obj, e.rights);
    Ok(())
}

pub fn handle_dup(h: Handle, new_rights: u32) -> Res<Handle> {
    let e = cur_table().get(h)?;
    if e.rights & DUP == 0 {
        return Err(E::PermissionDenied as i64);
    }
    // A duplicate can only lose rights.
    if new_rights & !e.rights != 0 || new_rights & !ALL != 0 {
        return Err(E::PermissionDenied as i64);
    }
    let nh = cur_table().alloc(e.obj, new_rights)?;
    ref_add(e.obj, new_rights);
    Ok(nh)
}

/// (object type, rights) of a handle.
pub fn handle_info(h: Handle) -> Res<(ObjType, u32)> {
    let e = cur_table().get(h)?;
    Ok((obj_type(obj(e.obj)), e.rights))
}

pub fn channel_create() -> Res<Handle> {
    let id = new_channel_obj()?;
    install_current(id, READ | WRITE | DUP | TRANSFER)
}

pub fn notification_create() -> Res<Handle> {
    let id = new_notification_obj()?;
    install_current(id, READ | WRITE | DUP | TRANSFER)
}

pub fn process_self() -> Res<Handle> {
    let id = new_object(Kind::Process(scheduler::current_pid()))?;
    install_current(id, READ | WRITE | DUP | TRANSFER)
}

pub fn thread_self() -> Res<Handle> {
    let id = new_object(Kind::Thread(scheduler::current_pid()))?;
    install_current(id, READ | WRITE | DUP | TRANSFER)
}

/// Put a fresh object into the current table; frees it again if the table is full.
fn install_current(id: ObjId, r: u32) -> Res<Handle> {
    match cur_table().alloc(id, r) {
        Ok(h) => {
            ref_add(id, r);
            Ok(h)
        }
        Err(e) => {
            release_unused(id);
            Err(e)
        }
    }
}

/// Free an object nobody refers to (e.g. after a failed install).
fn release_unused(id: ObjId) {
    if obj(id).refs == 0 {
        free_object(id);
    }
}

// ─── Messages ────────────────────────────────────────────────────────────────────────

/// Validate a user message and move its handles out of the current table.
fn pack(um: &UserMessage) -> Res<Parcel> {
    let n = um.nhandles as usize;
    if um.len as usize > MSG_DATA_MAX || n > MSG_HANDLES_MAX {
        return Err(E::InvalidArgument as i64);
    }
    let t = cur_table();
    for i in 0..n {
        if um.handles[..i].contains(&um.handles[i]) {
            return Err(E::InvalidArgument as i64);
        }
        let e = t.get(um.handles[i])?;
        if e.rights & TRANSFER == 0 {
            return Err(E::PermissionDenied as i64);
        }
    }
    let mut p = Parcel::new();
    p.tag = um.tag;
    p.len = um.len;
    p.data[..um.len as usize].copy_from_slice(&um.data[..um.len as usize]);
    for i in 0..n {
        let e = t.take(um.handles[i]).expect("validated");
        p.handles[i] = (e.obj, e.rights);
    }
    p.nh = n;
    Ok(p)
}

/// Move a parcel's handles into `t` and build the user-visible message. All or nothing:
/// on error the parcel is untouched.
fn unpack(p: &Parcel, t: &mut HandleTable) -> Res<UserMessage> {
    if t.free_slots() < p.nh {
        return Err(E::TableFull as i64);
    }
    let mut um = UserMessage::empty();
    um.tag = p.tag;
    um.len = p.len;
    um.data = p.data;
    um.nhandles = p.nh as u32;
    for i in 0..p.nh {
        um.handles[i] = t.alloc(p.handles[i].0, p.handles[i].1).expect("capacity checked");
    }
    Ok(um)
}

fn chan_mut(id: ObjId) -> &'static mut Channel {
    match &mut obj(id).kind {
        Kind::Channel(c) => c,
        _ => unreachable!(),
    }
}

/// Queue a request on a channel and wake its receivers.
fn enqueue(chan: ObjId, parcel: Parcel, reply: Option<ObjId>) {
    let c = chan_mut(chan);
    c.queue.push_back(Request { parcel, reply });
    wake_all(&mut c.receivers);
}

fn check_sendable(chan: ObjId) -> Res<()> {
    let c = chan_mut(chan);
    if c.closed {
        return Err(E::PeerClosed as i64);
    }
    if c.queue.len() >= CHAN_QUEUE_MAX {
        return Err(E::Busy as i64);
    }
    Ok(())
}

/// One-way send: queue the message, never block.
pub fn ipc_send(ch: Handle, um: &UserMessage) -> Res<()> {
    let (chan, _) = lookup(ch, ObjType::Channel, WRITE)?;
    check_sendable(chan)?;
    let p = pack(um)?;
    enqueue(chan, p, None);
    Ok(())
}

/// Synchronous call: send a request, sleep until the receiver replies, return the reply.
pub fn ipc_call(ch: Handle, um: &UserMessage) -> Res<UserMessage> {
    let (chan, _) = lookup(ch, ObjType::Channel, WRITE)?;
    check_sendable(chan)?;
    let p = pack(um)?;
    let me = scheduler::current_pid();
    let rid = match new_object(Kind::Reply(Reply { caller: Some(me), state: ReplyState::Pending })) {
        Ok(r) => r,
        Err(e) => {
            drop_parcel(&p);
            return Err(e);
        }
    };
    obj(rid).refs = 1; // held by the queued request, then by the receiver's reply handle
    scheduler::set_ipc_wait(rid + 1);
    enqueue(chan, p, Some(rid));

    loop {
        let done = match &obj(rid).kind {
            Kind::Reply(rp) => !matches!(rp.state, ReplyState::Pending),
            _ => unreachable!(),
        };
        if done {
            break;
        }
        scheduler::park(0);
    }

    // Collect the outcome and release the object if the receiver side is already gone.
    scheduler::set_ipc_wait(0);
    let state = match &mut obj(rid).kind {
        Kind::Reply(rp) => {
            rp.caller = None;
            core::mem::replace(&mut rp.state, ReplyState::Failed(0))
        }
        _ => unreachable!(),
    };
    if obj(rid).refs == 0 {
        free_object(rid);
    }
    match state {
        ReplyState::Done(parcel) => match unpack(&parcel, cur_table()) {
            Ok(m) => Ok(m),
            Err(e) => {
                drop_parcel(&parcel);
                Err(e)
            }
        },
        ReplyState::Failed(e) => Err(e),
        ReplyState::Pending => unreachable!(),
    }
}

/// Receive the next request. Blocks while the queue is empty (`timeout_ticks` 0 = forever).
/// Returns the message and a handle (WRITE) to answer it with, or 0 for a one-way message.
pub fn ipc_recv(ch: Handle, timeout_ticks: u64) -> Res<(UserMessage, Handle)> {
    let (chan, _) = lookup(ch, ObjType::Channel, READ)?;
    let me = scheduler::current_pid();
    let deadline = if timeout_ticks == 0 { 0 } else { now() + timeout_ticks };
    loop {
        // Skip requests whose caller has died meanwhile: nobody is left to answer.
        while let Some(req) = chan_mut(chan).queue.pop_front() {
            if let Some(rid) = req.reply {
                let alive = matches!(&obj(rid).kind, Kind::Reply(rp) if rp.caller.is_some());
                if !alive {
                    drop_parcel(&req.parcel);
                    unref(rid, WRITE);
                    continue;
                }
            }
            let t = cur_table();
            let need = req.parcel.nh + req.reply.is_some() as usize;
            if t.free_slots() < need {
                // Cannot deliver: fail the caller rather than lose the message silently.
                drop_parcel(&req.parcel);
                if let Some(rid) = req.reply {
                    fail_reply(rid, E::TableFull as i64);
                    unref(rid, WRITE);
                }
                return Err(E::TableFull as i64);
            }
            let um = unpack(&req.parcel, t).expect("capacity checked");
            let rh = match req.reply {
                Some(rid) => t.alloc(rid, WRITE).expect("capacity checked"), // ref moves to the handle
                None => 0,
            };
            return Ok((um, rh));
        }
        if chan_mut(chan).closed {
            return Err(E::PeerClosed as i64);
        }
        if deadline != 0 && now() >= deadline {
            return Err(E::Timeout as i64);
        }
        let c = chan_mut(chan);
        if !c.receivers.contains(&me) {
            c.receivers.push(me);
        }
        scheduler::park(deadline);
    }
}

fn fail_reply(rid: ObjId, err: i64) {
    if let Kind::Reply(rp) = &mut obj(rid).kind {
        if let ReplyState::Pending = rp.state {
            rp.state = ReplyState::Failed(err);
            if let Some(c) = rp.caller {
                scheduler::wake(c);
            }
        }
    }
}

/// Answer a request. Consumes the reply handle once the caller got the answer or is gone;
/// a malformed message leaves the handle in place so the server can retry.
pub fn ipc_reply(rh: Handle, um: &UserMessage) -> Res<()> {
    let (rid, _) = lookup(rh, ObjType::Reply, WRITE)?;
    let alive = matches!(&obj(rid).kind, Kind::Reply(rp) if rp.caller.is_some());
    let result = if !alive {
        Err(E::PeerClosed as i64)
    } else {
        let p = pack(um)?;
        if let Kind::Reply(rp) = &mut obj(rid).kind {
            rp.state = ReplyState::Done(p);
            if let Some(c) = rp.caller {
                scheduler::wake(c);
            }
        }
        Ok(())
    };
    let e = cur_table().take(rh).expect("looked up");
    unref(e.obj, e.rights);
    result
}

// ─── Notifications ───────────────────────────────────────────────────────────────────

pub fn notify_signal(h: Handle, bits: u32) -> Res<()> {
    let (id, _) = lookup(h, ObjType::Notification, WRITE)?;
    if let Kind::Notification(n) = &mut obj(id).kind {
        n.bits |= bits;
        if n.bits != 0 {
            wake_all(&mut n.waiters);
        }
    }
    Ok(())
}

/// Wait until any bit is set, then return and clear them all.
pub fn notify_wait(h: Handle, timeout_ticks: u64) -> Res<u32> {
    let (id, _) = lookup(h, ObjType::Notification, READ)?;
    let me = scheduler::current_pid();
    let deadline = if timeout_ticks == 0 { 0 } else { now() + timeout_ticks };
    loop {
        if let Kind::Notification(n) = &mut obj(id).kind {
            if n.bits != 0 {
                return Ok(core::mem::take(&mut n.bits));
            }
            if deadline != 0 && now() >= deadline {
                return Err(E::Timeout as i64);
            }
            if !n.waiters.contains(&me) {
                n.waiters.push(me);
            }
        }
        scheduler::park(deadline);
    }
}

// ─── Process / thread ────────────────────────────────────────────────────────────────

fn task_of(h: Handle, need: u32) -> Res<u32> {
    let e = cur_table().get(h)?;
    let pid = match obj(e.obj).kind {
        Kind::Process(p) | Kind::Thread(p) => p,
        _ => return Err(E::WrongType as i64),
    };
    if e.rights & need != need {
        return Err(E::PermissionDenied as i64);
    }
    Ok(pid)
}

/// Block until the process exits; returns its exit code.
pub fn process_wait(h: Handle, timeout_ticks: u64) -> Res<i64> {
    let pid = task_of(h, READ)?;
    let me = scheduler::current_pid();
    let deadline = if timeout_ticks == 0 { 0 } else { now() + timeout_ticks };
    loop {
        if !scheduler::task_alive(pid) {
            return scheduler::exit_code(pid).ok_or(E::NoSuchProcess as i64);
        }
        if deadline != 0 && now() >= deadline {
            return Err(E::Timeout as i64);
        }
        // SAFETY: interrupts are off.
        let w = unsafe { &mut *core::ptr::addr_of_mut!(PROC_WAITERS) };
        if !w.contains(&(me, pid)) {
            w.push((me, pid));
        }
        scheduler::park(deadline);
    }
}

pub fn process_kill(h: Handle) -> Res<()> {
    let pid = task_of(h, WRITE)?;
    if pid <= 1 || pid == scheduler::current_pid() {
        return Err(E::InvalidArgument as i64);
    }
    if scheduler::exit_pid(pid) { Ok(()) } else { Err(E::NoSuchProcess as i64) }
}

fn now() -> u64 {
    crate::arch::x86_64::idt::timer_ticks()
}

// ─── Hooks for the scheduler ─────────────────────────────────────────────────────────

/// A task has been reaped: close its handles and wake whoever waited for it.
/// `ipc_wait` is the Reply object (+1) it was blocked on in `call`, if any.
pub fn task_reaped(pid: u32, mut handles: HandleTable, ipc_wait: u32) {
    if ipc_wait != 0 {
        let rid = ipc_wait - 1;
        if let Kind::Reply(rp) = &mut obj(rid).kind {
            rp.caller = None;
        }
        if obj(rid).refs == 0 {
            // The receiver side is gone already; nobody else will free it.
            let st = objects()[rid as usize].take();
            if let Some(Object { kind: Kind::Reply(Reply { state: ReplyState::Done(p), .. }), .. }) = st {
                drop_parcel(&p);
            }
            unsafe { LIVE_OBJECTS -= 1 };
        }
    }
    handles.close_all();
    // SAFETY: interrupts are off in the reaper.
    let w = unsafe { &mut *core::ptr::addr_of_mut!(PROC_WAITERS) };
    w.retain(|&(waiter, target)| {
        if target == pid {
            scheduler::wake(waiter);
            false
        } else {
            waiter != pid
        }
    });
}

// ─── Bootstrap API for kernel code (spawning the first programs) ─────────────────────

/// A new channel with no handles yet.
pub fn kernel_new_channel() -> Option<ObjId> {
    scheduler::without_interrupts(|| new_channel_obj().ok())
}

pub fn kernel_new_notification() -> Option<ObjId> {
    scheduler::without_interrupts(|| new_notification_obj().ok())
}

/// A Process object for `pid`.
pub fn kernel_new_process(pid: u32) -> Option<ObjId> {
    scheduler::without_interrupts(|| new_object(Kind::Process(pid)).ok())
}

/// Give process `pid` a handle to `id`. Handles installed before a program starts get the
/// values 1, 2, 3... in the order of installation.
pub fn kernel_install(pid: u32, id: ObjId, r: u32) -> Option<Handle> {
    scheduler::without_interrupts(|| {
        if !exists(id) {
            return None;
        }
        let t = scheduler::handles_of(pid)?;
        let h = t.alloc(id, r).ok()?;
        ref_add(id, r);
        Some(h)
    })
}

/// Drop the kernel's claim on an object it created; frees it if no handle took it.
pub fn kernel_release(id: ObjId) {
    scheduler::without_interrupts(|| {
        if exists(id) {
            release_unused(id)
        }
    });
}

fn exists(id: ObjId) -> bool {
    objects().get(id as usize).map_or(false, |o| o.is_some())
}
