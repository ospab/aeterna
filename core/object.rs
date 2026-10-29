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
  MemoryRegion  a set of physical frames (anonymous, or physically contiguous for DMA)
                that can be mapped into any process holding a handle with MAP
  MmioRegion    a device physical range (BAR); mapped uncached, never freed
  Interrupt     an IRQ line; each interrupt masks the line and signals a Notification,
                the driver unmasks it again with irq_ack
  IoPortRange   x86 I/O ports [base, base+count); enabling it sets bits in the
                process's I/O permission bitmap (loaded into the TSS on switch)
  Resource      authority to create special objects (DMA: contiguous regions with a
                known physical address)

Rights: READ (receive / wait / inspect), WRITE (call, send, signal / kill, reply),
DUP (may be duplicated), TRANSFER (may be moved to another process in a message),
MAP (memory may be mapped), EXEC (memory may be mapped executable), PHYS (the
physical address of a memory object may be read).

Mappings and enabled I/O ranges hold a reference of their own, like a handle: a region
stays alive (and its frames allocated) until the last handle is closed AND the last
mapping is unmapped. Process exit drops both.

Interrupt, IoPortRange, MmioRegion and Resource objects are created only by the kernel
(`kernel_new_*`, the boot-time spawner / future seed) and reach drivers as bootstrap
handles (`core::elf::spawn_with_handles`).

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
use crate::core::sync::{IrqSpinLock, IrqSpinLockGuard};
use core::sync::atomic::Ordering;
use crate::core::syscall::SyscallError as E;

pub type Handle = u32;
pub type ObjId = u32;
pub type Res<T> = Result<T, i64>;

pub mod rights {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const DUP: u32 = 4;
    pub const TRANSFER: u32 = 8;
    /// The four generic rights (what `channel_create`, `process_self`, ... hand out).
    pub const ALL: u32 = 15;
    /// Memory: may be mapped (READ is needed for any mapping, WRITE for a writable one).
    pub const MAP: u32 = 16;
    /// Memory: may be mapped executable. Not handed out by any syscall yet.
    pub const EXEC: u32 = 32;
    /// Memory: the physical address may be read (`mem_phys`). Only for DMA regions.
    pub const PHYS: u32 = 64;
    /// Every defined bit.
    pub const VALID: u32 = 127;
}
use rights::*;

/// Protection requested by `mem_map`.
pub mod prot {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const EXEC: u32 = 4;
}

/// Kinds of `Resource` objects (bit flags).
pub mod resource {
    /// May create physically contiguous regions with a known physical address.
    pub const DMA: u32 = 1;
}

/// Largest anonymous region (`mem_create`).
pub const MEM_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Largest physically contiguous region (`mem_create_contig`).
pub const MEM_CONTIG_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// IRQ lines a driver may own. The rest belong to kernel drivers (timer, keyboard,
/// cascade, debug serial COM1, NIC/audio lines 5/7/9-11, mouse, ATA).
const IRQ_ASSIGNABLE: [u8; 3] = [3, 6, 8];

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
    MemoryRegion = 6,
    MmioRegion = 7,
    Interrupt = 8,
    IoPortRange = 9,
    Resource = 10,
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

enum Backing {
    /// Anonymous memory: one zeroed frame per page, owned by the object.
    Pages(Vec<u64>),
    /// Physically contiguous frames starting here, owned by the object.
    Contig(u64),
    /// Device memory starting here: mapped uncached, never freed.
    Device(u64),
}

struct MemRegion {
    pages: u64,
    backing: Backing,
}

impl MemRegion {
    fn frame(&self, i: u64) -> u64 {
        match &self.backing {
            Backing::Pages(v) => v[i as usize],
            Backing::Contig(b) | Backing::Device(b) => b + i * crate::mm::physical::FRAME_SIZE,
        }
    }
}

struct Interrupt {
    line: u8,
    /// Notification signalled on each interrupt, and the bits ORed into it.
    target: Option<(ObjId, u32)>,
    /// Interrupts delivered so far (diagnostics).
    count: u64,
}

enum Kind {
    Process(u32),
    Thread(u32),
    Channel(Channel),
    Notification(Notification),
    Reply(Reply),
    Memory(MemRegion),
    Interrupt(Interrupt),
    IoPorts { base: u16, count: u32 },
    Resource(u32),
}

struct Object {
    /// Handles + in-flight messages referring to this object.
    refs: u32,
    kind: Kind,
}

/// All kernel-object state, behind the OBJ lock (rank OBJ, the outermost lock).
/// Every public function of this module takes the lock; the helpers below run under it.
struct ObjState {
    objects: Vec<Option<Object>>,
    live: usize,
    /// (waiter pid, pid being waited for)
    proc_waiters: Vec<(u32, u32)>,
    /// IRQ line -> owning Interrupt object + 1 (0 = not owned by a driver).
    irq_owner: [u32; 16],
}

static OBJ: IrqSpinLock<ObjState> = IrqSpinLock::new("OBJ", crate::core::sync::rank::OBJ, ObjState {
    objects: Vec::new(),
    live: 0,
    proc_waiters: Vec::new(),
    irq_owner: [0; 16],
});

/// Lines currently owned by an Interrupt object (bit n = line n): lets the IRQ path skip
/// the lock for every other interrupt.
static IRQ_OWNED_MASK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The protected state. The reference must not outlive the guard of OBJ held further up the
/// call chain (the compiler cannot check that). Panics if the lock is not held.
fn st() -> &'static mut ObjState {
    assert!(OBJ.is_locked(), "object state used without the OBJ lock");
    // SAFETY: the lock is held by this CPU's current call chain.
    unsafe { &mut *OBJ.data_ptr() }
}

type ObjGuard = IrqSpinLockGuard<'static, ObjState>;

/// Sleep until woken or `deadline`, with OBJ released while asleep. Callers re-check their
/// condition afterwards.
fn park_unlocked(g: ObjGuard, deadline: u64) -> ObjGuard {
    let (lock, flags) = g.unlock_keep_irq_off();
    scheduler::park(deadline);
    lock.relock_with(flags)
}

/// Run `f` under the OBJ lock.
fn locked<R>(f: impl FnOnce() -> R) -> R {
    let _g = OBJ.lock();
    f()
}

fn objects() -> &'static mut Vec<Option<Object>> {
    &mut st().objects
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
        Kind::Memory(MemRegion { backing: Backing::Device(_), .. }) => ObjType::MmioRegion,
        Kind::Memory(_) => ObjType::MemoryRegion,
        Kind::Interrupt(_) => ObjType::Interrupt,
        Kind::IoPorts { .. } => ObjType::IoPortRange,
        Kind::Resource(_) => ObjType::Resource,
    }
}

/// Number of live kernel objects (for leak checks).
pub fn live_objects() -> usize {
    OBJ.lock().live
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
    st().live += 1;
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

/// Free an object nobody refers to any more, and whatever it owned.
fn free_object(id: ObjId) {
    let mut work: Vec<(ObjId, u32)> = Vec::new();
    take_object(id, &mut work);
    for (o, r) in work {
        unref(o, r);
    }
}

fn irq_owner() -> &'static mut [u32; 16] {
    &mut st().irq_owner
}

/// Record that `line` is (not) owned; keeps the lock-free mask in step.
fn set_irq_owner(line: u8, owner_plus_1: u32) {
    st().irq_owner[line as usize] = owner_plus_1;
    if owner_plus_1 != 0 {
        IRQ_OWNED_MASK.fetch_or(1 << line, Ordering::Relaxed);
    } else {
        IRQ_OWNED_MASK.fetch_and(!(1 << line), Ordering::Relaxed);
    }
}

/// Remove object `id` from the table and release what it owns. References it held on
/// other objects are pushed to `work` for the caller to drop.
fn take_object(id: ObjId, work: &mut Vec<(ObjId, u32)>) {
    let old = objects()[id as usize].take();
    st().live -= 1;
    let kind = match old {
        Some(o) => o.kind,
        None => return,
    };
    match kind {
        // An unconsumed reply still owns the handles it carries.
        Kind::Reply(Reply { state: ReplyState::Done(p), .. }) => {
            for i in 0..p.nh {
                work.push(p.handles[i]);
            }
        }
        Kind::Memory(m) => match m.backing {
            Backing::Pages(frames) => {
                for f in frames {
                    crate::mm::physical::free_frame(f);
                }
            }
            Backing::Contig(base) => crate::mm::physical::free_frames(base, m.pages),
            Backing::Device(_) => {}
        },
        Kind::Interrupt(i) => {
            crate::arch::x86_64::pic::disable_irq(i.line);
            set_irq_owner(i.line, 0);
            if let Some((n, _)) = i.target {
                work.push((n, 0));
            }
        }
        _ => {}
    }
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
            take_object(id, &mut work);
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

/// A memory object mapped into the process: `pages` pages at `va`. Holds one reference.
#[derive(Clone, Copy, Debug)]
struct Mapping {
    va: u64,
    pages: u64,
    obj: ObjId,
}

/// Everything a process holds through kernel objects: its handles, the memory objects it
/// has mapped, and the I/O port ranges it has enabled (each of the last two holds a
/// reference, so they outlive the handle that created them, like mmap).
#[derive(Clone, Debug, Default)]
pub struct HandleTable {
    slots: Vec<Entry>,
    maps: Vec<Mapping>,
    io: Vec<ObjId>,
}

impl HandleTable {
    pub const fn new() -> HandleTable {
        HandleTable { slots: Vec::new(), maps: Vec::new(), io: Vec::new() }
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

    /// Close everything (process exit). The address space is already gone, so mappings
    /// only drop their reference here.
    fn close_all(&mut self) {
        let slots = core::mem::take(&mut self.slots);
        for e in slots {
            if e.used {
                unref(e.obj, e.rights);
            }
        }
        for m in core::mem::take(&mut self.maps) {
            unref(m.obj, 0);
        }
        for o in core::mem::take(&mut self.io) {
            unref(o, 0);
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
    let _g = OBJ.lock();
    let e = cur_table().take(h)?;
    unref(e.obj, e.rights);
    Ok(())
}

pub fn handle_dup(h: Handle, new_rights: u32) -> Res<Handle> {
    let _g = OBJ.lock();
    let e = cur_table().get(h)?;
    if e.rights & DUP == 0 {
        return Err(E::PermissionDenied as i64);
    }
    // A duplicate can only lose rights.
    if new_rights & !e.rights != 0 || new_rights & !VALID != 0 {
        return Err(E::PermissionDenied as i64);
    }
    let nh = cur_table().alloc(e.obj, new_rights)?;
    ref_add(e.obj, new_rights);
    Ok(nh)
}

/// (object type, rights) of a handle.
pub fn handle_info(h: Handle) -> Res<(ObjType, u32)> {
    let _g = OBJ.lock();
    let e = cur_table().get(h)?;
    Ok((obj_type(obj(e.obj)), e.rights))
}

pub fn channel_create() -> Res<Handle> {
    let _g = OBJ.lock();
    let id = new_channel_obj()?;
    install_current(id, READ | WRITE | DUP | TRANSFER)
}

pub fn notification_create() -> Res<Handle> {
    let _g = OBJ.lock();
    let id = new_notification_obj()?;
    install_current(id, READ | WRITE | DUP | TRANSFER)
}

pub fn process_self() -> Res<Handle> {
    let _g = OBJ.lock();
    let id = new_object(Kind::Process(scheduler::current_pid()))?;
    install_current(id, READ | WRITE | DUP | TRANSFER)
}

pub fn thread_self() -> Res<Handle> {
    let _g = OBJ.lock();
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
    let _g = OBJ.lock();
    let (chan, _) = lookup(ch, ObjType::Channel, WRITE)?;
    check_sendable(chan)?;
    let p = pack(um)?;
    enqueue(chan, p, None);
    Ok(())
}

/// Synchronous call: send a request, sleep until the receiver replies, return the reply.
pub fn ipc_call(ch: Handle, um: &UserMessage) -> Res<UserMessage> {
    let mut g = OBJ.lock();
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
        g = park_unlocked(g, 0);
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
    let mut g = OBJ.lock();
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
        g = park_unlocked(g, deadline);
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
    let _g = OBJ.lock();
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
    let _g = OBJ.lock();
    let (id, _) = lookup(h, ObjType::Notification, WRITE)?;
    signal_obj(id, bits);
    Ok(())
}

/// OR `bits` into a notification and wake its waiters. No allocation: also used from
/// interrupt context.
fn signal_obj(id: ObjId, bits: u32) {
    if let Kind::Notification(n) = &mut obj(id).kind {
        n.bits |= bits;
        if n.bits != 0 {
            wake_all(&mut n.waiters);
        }
    }
}

/// Wait until any bit is set, then return and clear them all.
pub fn notify_wait(h: Handle, timeout_ticks: u64) -> Res<u32> {
    let mut g = OBJ.lock();
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
        g = park_unlocked(g, deadline);
    }
}

// ─── Memory objects ──────────────────────────────────────────────────────────────────

const PAGE: u64 = crate::mm::physical::FRAME_SIZE;

fn pages_for(size: u64, max: u64) -> Res<u64> {
    if size == 0 || size > max {
        return Err(E::InvalidArgument as i64);
    }
    Ok((size + PAGE - 1) / PAGE)
}

/// A new anonymous region of `pages` zeroed frames (not yet referenced).
fn new_anon_region(pages: u64) -> Res<ObjId> {
    let mut frames = Vec::new();
    if frames.try_reserve_exact(pages as usize).is_err() {
        return Err(E::OutOfMemory as i64);
    }
    // Create the object first, then fill it: on failure free_object returns every frame.
    let id = new_object(Kind::Memory(MemRegion { pages: 0, backing: Backing::Pages(frames) }))?;
    for _ in 0..pages {
        let f = match crate::mm::physical::alloc_frame() {
            Some(f) => f,
            None => {
                free_object(id);
                return Err(E::OutOfMemory as i64);
            }
        };
        if let Kind::Memory(MemRegion { pages: n, backing: Backing::Pages(v) }) = &mut obj(id).kind {
            v.push(f); // capacity reserved above
            *n += 1;
        }
    }
    Ok(id)
}

/// mem_create(size): a shareable anonymous region, rounded up to whole pages.
pub fn mem_create(size: u64) -> Res<Handle> {
    let _g = OBJ.lock();
    let pages = pages_for(size, MEM_MAX_BYTES)?;
    let id = new_anon_region(pages)?;
    install_current(id, READ | WRITE | MAP | DUP | TRANSFER)
}

/// mem_create_contig(resource, size): physically contiguous region for DMA. Needs a
/// Resource handle of kind DMA with WRITE; the new handle also carries PHYS.
pub fn mem_create_contig(res: Handle, size: u64) -> Res<Handle> {
    let _g = OBJ.lock();
    let (rid, _) = lookup(res, ObjType::Resource, WRITE)?;
    if !matches!(obj(rid).kind, Kind::Resource(k) if k & resource::DMA != 0) {
        return Err(E::PermissionDenied as i64);
    }
    let pages = pages_for(size, MEM_CONTIG_MAX_BYTES)?;
    let base = crate::mm::physical::alloc_frames(pages).ok_or(E::OutOfMemory as i64)?;
    let id = match new_object(Kind::Memory(MemRegion { pages, backing: Backing::Contig(base) })) {
        Ok(id) => id,
        Err(e) => {
            crate::mm::physical::free_frames(base, pages);
            return Err(e);
        }
    };
    install_current(id, READ | WRITE | MAP | DUP | TRANSFER | PHYS)
}

/// A MemoryRegion or MmioRegion handle with the rights `need`.
fn lookup_mem(h: Handle, need: u32) -> Res<(ObjId, u32)> {
    let e = cur_table().get(h)?;
    if !matches!(obj(e.obj).kind, Kind::Memory(_)) {
        return Err(E::WrongType as i64);
    }
    if e.rights & need != need {
        return Err(E::PermissionDenied as i64);
    }
    Ok((e.obj, e.rights))
}

fn mem_of(id: ObjId) -> &'static MemRegion {
    match &obj(id).kind {
        Kind::Memory(m) => m,
        _ => unreachable!(),
    }
}

/// mem_size(h): size in bytes (any rights).
pub fn mem_size(h: Handle) -> Res<u64> {
    let _g = OBJ.lock();
    let (id, _) = lookup_mem(h, 0)?;
    Ok(mem_of(id).pages * PAGE)
}

/// mem_phys(h): physical address of a contiguous or device region. Needs PHYS.
pub fn mem_phys(h: Handle) -> Res<u64> {
    let _g = OBJ.lock();
    let (id, _) = lookup_mem(h, PHYS)?;
    match mem_of(id).backing {
        Backing::Contig(b) | Backing::Device(b) => Ok(b),
        Backing::Pages(_) => Err(E::NotSupported as i64),
    }
}

/// mem_map(h, hint, prot): map the whole object into the caller's address space.
/// Needs MAP + READ, plus WRITE for prot WRITE and EXEC for prot EXEC. Writable and
/// executable at once is refused (W^X); without EXEC the pages are no-execute. Device
/// regions are mapped uncached. `hint` is reserved (pass 0): the kernel picks the address.
pub fn mem_map(h: Handle, _hint: u64, p: u32) -> Res<u64> {
    let _g = OBJ.lock();
    use crate::mm::r#virtual as vmm;
    if p & !(prot::READ | prot::WRITE | prot::EXEC) != 0
        || p & prot::READ == 0
        || p & (prot::WRITE | prot::EXEC) == (prot::WRITE | prot::EXEC)
    {
        return Err(E::InvalidArgument as i64);
    }
    let mut need = MAP | READ;
    if p & prot::WRITE != 0 {
        need |= WRITE;
    }
    if p & prot::EXEC != 0 {
        need |= EXEC;
    }
    let (id, _) = lookup_mem(h, need)?;
    let cr3 = scheduler::current_user_cr3().ok_or(E::NotSupported as i64)?;
    let m = mem_of(id);
    let pages = m.pages;
    let device = matches!(m.backing, Backing::Device(_));
    let va = scheduler::reserve_user_range(pages).ok_or(E::OutOfMemory as i64)?;
    cur_table().maps.try_reserve(1).map_err(|_| E::OutOfMemory as i64)?;

    // Not FLAG_OWNED: the frames belong to the object, not to the address space.
    let mut flags = vmm::FLAG_USER;
    if p & prot::WRITE != 0 {
        flags |= vmm::FLAG_WRITABLE;
    }
    if p & prot::EXEC == 0 {
        flags |= vmm::nx_flag();
    }
    if device {
        flags |= vmm::FLAG_PCD | vmm::FLAG_PWT;
    }
    for i in 0..pages {
        if !vmm::map_page(cr3, va + i * PAGE, m.frame(i), flags) {
            for k in 0..i {
                vmm::unmap_page_entry(cr3, va + k * PAGE);
                vmm::invlpg(va + k * PAGE);
            }
            return Err(E::OutOfMemory as i64);
        }
    }
    cur_table().maps.push(Mapping { va, pages, obj: id });
    ref_add(id, 0);
    if !device {
        scheduler::add_memory_usage(scheduler::current_pid(), pages * PAGE);
    }
    Ok(va)
}

/// mem_unmap(addr): remove a mapping made by mem_map; `addr` is the address it returned.
pub fn mem_unmap(addr: u64) -> Res<()> {
    let _g = OBJ.lock();
    use crate::mm::r#virtual as vmm;
    let t = cur_table();
    let i = t.maps.iter().position(|m| m.va == addr).ok_or(E::InvalidArgument as i64)?;
    let m = t.maps.remove(i);
    if let Some(cr3) = scheduler::current_user_cr3() {
        for k in 0..m.pages {
            let va = m.va + k * PAGE;
            if vmm::unmap_page_entry(cr3, va).is_some() {
                vmm::invlpg(va);
            }
        }
    }
    if !matches!(mem_of(m.obj).backing, Backing::Device(_)) {
        scheduler::sub_memory_usage(scheduler::current_pid(), m.pages * PAGE);
    }
    unref(m.obj, 0);
    Ok(())
}

// ─── Interrupts ──────────────────────────────────────────────────────────────────────

/// irq_bind(irq, notification, bits): deliver this line's interrupts as `bits` on the
/// notification. Needs READ on the Interrupt and WRITE on the Notification. Replaces an
/// earlier binding. The line stays masked until irq_ack.
pub fn irq_bind(irq: Handle, notif: Handle, bits: u32) -> Res<()> {
    let _g = OBJ.lock();
    let (iid, _) = lookup(irq, ObjType::Interrupt, READ)?;
    let (nid, _) = lookup(notif, ObjType::Notification, WRITE)?;
    if bits == 0 {
        return Err(E::InvalidArgument as i64);
    }
    ref_add(nid, 0);
    let old = match &mut obj(iid).kind {
        Kind::Interrupt(i) => i.target.replace((nid, bits)),
        _ => unreachable!(),
    };
    if let Some((o, _)) = old {
        unref(o, 0);
    }
    Ok(())
}

/// irq_ack(irq): the driver has handled the device; unmask the line. Needs WRITE.
pub fn irq_ack(irq: Handle) -> Res<()> {
    let _g = OBJ.lock();
    let (iid, _) = lookup(irq, ObjType::Interrupt, WRITE)?;
    if let Kind::Interrupt(i) = &obj(iid).kind {
        crate::arch::x86_64::pic::enable_irq(i.line);
    }
    Ok(())
}

/// Called from the IRQ dispatcher (interrupts disabled) before any kernel driver.
/// If a driver owns the line: mask it, signal the bound notification, return true
/// (the caller sends EOI). No allocation here.
pub fn irq_fire(line: u8) -> bool {
    if line >= 16 || IRQ_OWNED_MASK.load(Ordering::Relaxed) & (1 << line) == 0 {
        return false;
    }
    let _g = OBJ.lock();
    let owner = match irq_owner().get(line as usize) {
        Some(&o) if o != 0 => o - 1,
        _ => return false,
    };
    crate::arch::x86_64::pic::disable_irq(line);
    let target = match &mut obj(owner).kind {
        Kind::Interrupt(i) => {
            i.count += 1;
            i.target
        }
        _ => None,
    };
    if let Some((n, bits)) = target {
        signal_obj(n, bits);
    }
    true
}

// ─── I/O ports ───────────────────────────────────────────────────────────────────────

/// I/O permission bitmap (hardware layout: bit set = access denied) covering every
/// range the process enabled. Empty when it has none.
fn io_bitmap(t: &HandleTable) -> Vec<u8> {
    let mut end = 0u32;
    for &o in &t.io {
        if let Kind::IoPorts { base, count } = obj(o).kind {
            end = end.max(base as u32 + count);
        }
    }
    let mut bm = alloc::vec![0xFFu8; ((end + 7) / 8) as usize];
    for &o in &t.io {
        if let Kind::IoPorts { base, count } = obj(o).kind {
            for p in base as u32..base as u32 + count {
                bm[(p / 8) as usize] &= !(1 << (p % 8));
            }
        }
    }
    bm
}

/// ioport_enable(h): allow the caller's IN/OUT on the range. Needs READ and WRITE (the
/// hardware bitmap cannot split them). Lasts until ioport_disable or exit.
pub fn ioport_enable(h: Handle) -> Res<()> {
    let _g = OBJ.lock();
    let (id, _) = lookup(h, ObjType::IoPortRange, READ | WRITE)?;
    let t = cur_table();
    if !t.io.contains(&id) {
        t.io.try_reserve(1).map_err(|_| E::OutOfMemory as i64)?;
        t.io.push(id);
        ref_add(id, 0);
    }
    scheduler::set_current_io_bitmap(io_bitmap(t));
    Ok(())
}

/// ioport_disable(h): withdraw the access ioport_enable granted.
pub fn ioport_disable(h: Handle) -> Res<()> {
    let _g = OBJ.lock();
    let (id, _) = lookup(h, ObjType::IoPortRange, 0)?;
    let t = cur_table();
    let i = t.io.iter().position(|&o| o == id).ok_or(E::InvalidArgument as i64)?;
    t.io.remove(i);
    scheduler::set_current_io_bitmap(io_bitmap(t));
    unref(id, 0);
    Ok(())
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
    let mut g = OBJ.lock();
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
        let w = &mut st().proc_waiters;
        if !w.contains(&(me, pid)) {
            w.push((me, pid));
        }
        g = park_unlocked(g, deadline);
    }
}

pub fn process_kill(h: Handle) -> Res<()> {
    let _g = OBJ.lock();
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
    let _g = OBJ.lock();
    if ipc_wait != 0 {
        let rid = ipc_wait - 1;
        if let Kind::Reply(rp) = &mut obj(rid).kind {
            rp.caller = None;
        }
        if obj(rid).refs == 0 {
            // The receiver side is gone already; nobody else will free it.
            let old = objects()[rid as usize].take();
            if let Some(Object { kind: Kind::Reply(Reply { state: ReplyState::Done(p), .. }), .. }) = old {
                drop_parcel(&p);
            }
            st().live -= 1;
        }
    }
    handles.close_all();
    let w = &mut st().proc_waiters;
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
    locked(|| new_channel_obj().ok())
}

pub fn kernel_new_notification() -> Option<ObjId> {
    locked(|| new_notification_obj().ok())
}

/// An anonymous memory region of `size` bytes (rounded up to pages).
pub fn kernel_new_memory(size: u64) -> Option<ObjId> {
    locked(|| new_anon_region(pages_for(size, MEM_MAX_BYTES).ok()?).ok())
}

/// HHDM address of page `page` of a memory region (kernel-side access for tests and
/// servers set up by the kernel). None for device regions or out-of-range pages.
pub fn kernel_memory_page(id: ObjId, page: u64) -> Option<*mut u8> {
    locked(|| {
        if !exists(id) {
            return None;
        }
        match &obj(id).kind {
            Kind::Memory(m) if page < m.pages && !matches!(m.backing, Backing::Device(_)) => {
                Some(crate::mm::r#virtual::phys_to_virt(m.frame(page)) as *mut u8)
            }
            _ => None,
        }
    })
}

/// A device memory range (MMIO, e.g. a PCI BAR) at physical `phys`, `size` bytes. Both
/// must be page aligned. The range must not be RAM the frame allocator manages.
pub fn kernel_new_mmio(phys: u64, size: u64) -> Option<ObjId> {
    if phys % PAGE != 0 || size == 0 || size % PAGE != 0 {
        return None;
    }
    let pages = size / PAGE;
    let in_ram = crate::mm::physical::get_usable_regions()
        .iter()
        .any(|r| phys < r.base + r.length && r.base < phys + size);
    if in_ram {
        return None;
    }
    locked(|| {
        new_object(Kind::Memory(MemRegion { pages, backing: Backing::Device(phys) })).ok()
    })
}

/// An Interrupt object for legacy IRQ line `line`. Only lines no kernel driver uses can
/// be handed out, and each line to one object at a time. The line starts masked.
pub fn kernel_new_interrupt(line: u8) -> Option<ObjId> {
    if !IRQ_ASSIGNABLE.contains(&line) || crate::acpi::is_sci_irq(line) {
        return None;
    }
    locked(|| {
        if irq_owner()[line as usize] != 0 {
            return None;
        }
        let id = new_object(Kind::Interrupt(Interrupt { line, target: None, count: 0 })).ok()?;
        crate::arch::x86_64::pic::disable_irq(line);
        set_irq_owner(line, id + 1);
        Some(id)
    })
}

/// Interrupts delivered so far through the Interrupt object `id` (diagnostics).
pub fn kernel_interrupt_count(id: ObjId) -> Option<u64> {
    locked(|| match objects().get(id as usize) {
        Some(Some(Object { kind: Kind::Interrupt(i), .. })) => Some(i.count),
        _ => None,
    })
}

/// An I/O port range [base, base + count).
pub fn kernel_new_ioports(base: u16, count: u32) -> Option<ObjId> {
    if count == 0 || base as u32 + count > 0x1_0000 {
        return None;
    }
    locked(|| new_object(Kind::IoPorts { base, count }).ok())
}

/// A Resource object of the given kinds (`resource::DMA`, ...).
pub fn kernel_new_resource(kinds: u32) -> Option<ObjId> {
    locked(|| new_object(Kind::Resource(kinds)).ok())
}

/// A Process object for `pid`.
pub fn kernel_new_process(pid: u32) -> Option<ObjId> {
    locked(|| new_object(Kind::Process(pid)).ok())
}

/// Give process `pid` a handle to `id`. Handles installed before a program starts get the
/// values 1, 2, 3... in the order of installation.
pub fn kernel_install(pid: u32, id: ObjId, r: u32) -> Option<Handle> {
    locked(|| {
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
    locked(|| {
        if exists(id) {
            release_unused(id)
        }
    });
}

fn exists(id: ObjId) -> bool {
    objects().get(id as usize).map_or(false, |o| o.is_some())
}
