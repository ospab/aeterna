# liboos reference

`liboos` (`user/liboos`) is the runtime of ring 3 programs: the entry point, system call wrappers,
the heap, `print!` and the panic handler. It is a `no_std` crate with the target
`x86_64-unknown-oos`. Programs get `core` and `alloc`, not `std`.

Every example on this page was compiled against the current sources. Raw system call numbers and
registers are in [System call ABI](../syscall-abi.md).

## Overview

```rust
#![no_std]
#![no_main]
extern crate alloc;           // only if you use Vec, String, Box, format!

liboos::entry!(main);

fn main(args: liboos::Args) -> i32 {
    liboos::println!("hello");
    0                          // exit status
}
```

| Item | Where |
|---|---|
| `entry!`, `print!`, `println!` | crate root (macros) |
| `Args` | `liboos::Args` |
| `write`, `open`, `read`, `close`, `seek` | crate root, files and standard streams |
| `exit`, `getpid`, `yield_now`, `uptime_ticks` | crate root, process |
| `mmap`, `munmap` | crate root, memory |
| `screen` | framebuffer, raw keyboard, `clock_ns`, `sleep_ms` |
| `audio` | sound output |
| `ipc` | handles, rights, channels, notifications, processes |
| `mem` | shared memory regions |
| `hw` | interrupts, I/O ports, DMA (drivers only) |
| `sys` | raw `syscall0`..`syscall3`, call numbers (`sys::nr`), error codes (`sys::err`) |

Names to be aware of: `sleep_ms` and `clock_ns` are in `liboos::screen`, not at the crate root,
and there is no `std::thread`, `std::time` or `std::env`.

## Error handling

The API has two styles.

- **Plain calls** (crate root, `screen`, `audio`) return the kernel's `i64` result. A negative
  value is an error, a non-negative one is the result (a descriptor, a byte count, an offset).
  `screen::acquire` and `mmap` return `Result<_, i64>` with the negative code.
- **Object calls** (`ipc`, `mem`, `hw`) return `liboos::ipc::Result<T>`, with `ipc::Error`.

Error codes (the kernel negates them):

| Code | Kernel name | `sys::err` | `ipc::Error` | Typical cause |
|---|---|---|---|---|
| -1 | InvalidSyscall | `INVALID_SYSCALL` | `Other(-1)` | No such call. File calls also use -1 for any failure (no such file, bad descriptor, table full). |
| -2 | PermissionDenied | `PERMISSION_DENIED` | `PermissionDenied` | Missing capability, or a handle without the needed right. |
| -3 | InvalidArgument | `INVALID_ARGUMENT` | `InvalidArgument` | Bad flag, size or format. Also `seek` to a negative offset. |
| -4 | NotFound | `NOT_FOUND` | `Other(-4)` | Defined by the kernel; the current calls rarely return it. |
| -5 | Busy | `BUSY` | `Busy` | Channel queue full; screen or raw keyboard already owned. |
| -6 | OutOfMemory | `OUT_OF_MEMORY` | `OutOfMemory` | No frames, no free address range. |
| -7 | NotSupported | `NOT_SUPPORTED` | `NotSupported` | No framebuffer, no sound device, or the object cannot do this (`phys` of anonymous memory). |
| -8 | IoError | none | `Other(-8)` | Defined by the kernel. |
| -9 | NoSuchProcess | none | `Other(-9)` | Defined by the kernel. |
| -10 | BadAddress | `BAD_ADDRESS` | `BadAddress` | Pointer outside the process. |
| -11 | BadHandle | `BAD_HANDLE` | `BadHandle` | Closed, stale or never issued handle; unknown stream id. |
| -12 | WrongType | `WRONG_TYPE` | `WrongType` | Handle of another object kind. |
| -13 | PeerClosed | `PEER_CLOSED` | `PeerClosed` | The other side is gone. |
| -14 | TableFull | `TABLE_FULL` | `TableFull` | Handle table (256) or sound streams (4) full. |
| -15 | Timeout | `TIMEOUT` | `Timeout` | A timed wait expired. |

## Process

```rust
pub struct Args { /* argc, argv */ }
impl Args {
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn get(&self, i: usize) -> Option<&'static str>;
    pub fn iter(&self) -> impl Iterator<Item = &'static str> + '_;
}

pub fn exit(code: i32) -> !;
pub fn getpid() -> u32;
pub fn yield_now();
pub fn uptime_ticks() -> u64;
```

- `args.get(0)` is the name as typed in the shell. `args.len()` counts it.
- `get` returns `None` for a missing argument and for one that is not valid UTF-8. `iter` skips
  the invalid ones, so its positions can shift. Use `get` when positions matter.
- Returning from `main` is the same as `exit(code)`. The shell shows the low 8 bits as `$?`.
  Panics print `panic: <message>` on stdout and exit with 101.
- The kernel frees memory, descriptors, handles, the screen, the raw keyboard and sound streams
  when the process ends, however it ends.
- `yield_now` gives up the rest of the time slice. It does not sleep: a loop around it uses a
  full CPU. Use `screen::sleep_ms` to wait.
- `uptime_ticks` counts 100 Hz ticks since boot (10 ms resolution). For finer time use
  `screen::clock_ns`.

Not available: environment variables (the kernel passes an empty `envp`), a working directory,
starting other programs (no `spawn`, `exec`, `fork`; `sys::nr::WAITPID` exists but has no
wrapper and nothing to wait for), threads, signals. A program started from the shell gets the
capabilities Serial, FsRead, FsWrite and Framebuf. It has no Net, so there are no sockets.

## Console output and input

```rust
macro_rules! print   { ($($arg:tt)*) => ... }
macro_rules! println { () => ...; ($($arg:tt)*) => ... }
pub fn write(fd: u64, bytes: &[u8]) -> i64;
pub fn read(fd: u64, buf: &mut [u8]) -> i64;
```

- `print!` and `println!` write to fd 1. There is no `eprint!`; for stderr call
  `liboos::write(2, b"message\n")`.
- Output goes to the serial port always, and to the shell's current stdout once the console runs:
  the screen, a pipe or a redirect (`prog > file`). Standard error goes to the shell's stderr.
- One `write` call moves at most 64 KiB and returns how many bytes it took. `print!` does not
  loop. If you write large blocks, loop on the return value.
- `read(0, buf)` reads standard input. When the shell gave the program a pipe or a redirect
  (`echo hi | prog`, `prog < file`) the data comes from there and 0 means end of input.
  On the console the kernel runs a line discipline: the call sleeps until a line is complete and
  returns at most `buf.len()` bytes of it. The rest stays for the next call, so reading one byte
  at a time works. Editing keys: Enter ends the line (the newline is in the data), Backspace
  removes a character, Ctrl+U the whole line, Ctrl+D on an empty line is end of input (0 bytes).
  Only printable ASCII is accepted, at most 1024 bytes per line. Typed characters are echoed by
  the kernel. Ctrl+C makes the shell kill the program (status 130).
  Details: [Kernel internals](../kernel.md), "Console input".
- While a program owns the raw keyboard (`screen::kbd_raw(true)`), `read(0)` is not used.

```rust
fn read_line() -> Option<String> {
    let mut line = alloc::vec::Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = liboos::read(0, &mut b);
        if n <= 0 {
            return if line.is_empty() { None } else { Some(String::from_utf8_lossy(&line).into_owned()) };
        }
        if b[0] == b'\n' {
            return Some(String::from_utf8_lossy(&line).into_owned());
        }
        line.push(b[0]);
    }
}
```

## Files

```rust
pub fn open(path: &str, flags: u64) -> i64;
pub fn read(fd: u64, buf: &mut [u8]) -> i64;
pub fn write(fd: u64, bytes: &[u8]) -> i64;
pub fn seek(fd: u64, offset: i64, whence: u64) -> i64;
pub fn close(fd: u64) -> i64;
```

`open` returns a descriptor of 3 or more, or a negative value. The calls work on the same virtual
filesystem the shell uses (`/`, `/tmp`, `/home`, the saved upper layer, mounted disks).

| `flags` | Meaning |
|---|---|
| 0 | read |
| 1 | write; creates the file if it does not exist. Does not truncate an existing file: writing starts at offset 0 and overwrites. |
| 2 | meant as read and write. **Today the descriptor is read-only** (see below). |

Any other value is refused with -3. Flag 2 needs both FsRead and FsWrite. This is a bug in the
kernel: `sys_open` in `vfs/mod.rs` tests the bits 1 and 2 separately, so flag 2 yields a
descriptor that can read but not write. Until it is fixed, use flag 1 for writing and flag 0
for reading, with separate descriptors.

- `whence` for `seek`: 0 from the start, 1 from the current offset, 2 from the end. It returns
  the new offset, or -3. There are no named constants.
- Paths are absolute. A process has no working directory, and relative paths are not resolved
  against the shell's directory.
- At most 64 descriptors per process, three of them (0, 1, 2) taken by the standard streams,
  and 0, 1, 2 cannot be closed. The table is private to the process and freed at exit.
- `read` and `write` move at most 64 KiB per call. `read` returns 0 at end of file. Both return -1
  on a bad or wrong-mode descriptor.
- Each descriptor has its own offset.
- Files written to the RAM layer reach the disk after a short delay (about 10 seconds) or at
  `sync`. A program cannot force it.
- There is no way to list a directory, get a file's size without `seek(fd, 0, 2)`, create a
  directory, rename or delete from ring 3. These calls do not exist yet.

```rust
fn write_all(fd: u64, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let n = liboos::write(fd, data);
        if n <= 0 { return false; }
        data = &data[n as usize..];
    }
    true
}

let fd = liboos::open("/tmp/demo.txt", 1);       // create / overwrite
write_all(fd as u64, b"first line\nsecond line\n");
liboos::close(fd as u64);

let fd = liboos::open("/tmp/demo.txt", 0) as u64;
let size = liboos::seek(fd, 0, 2);                // size in bytes
liboos::seek(fd, 6, 0);                           // back to offset 6
let mut word = [0u8; 4];
liboos::read(fd, &mut word);
liboos::close(fd);
```

## Memory

```rust
pub fn mmap(size: usize) -> Result<*mut u8, i64>;
pub fn munmap(ptr: *mut u8, size: usize) -> i64;
```

- `mmap` maps `size` bytes of fresh, zeroed, read/write, non-executable memory, rounded up to
  whole pages. `size` is at most 64 MiB per call. The kernel chooses the address.
- `munmap` takes a page-aligned address and a size, and frees those pages. Pages that are not
  mapped are skipped.
- Memory is limited by the free RAM of the machine.

### The heap

`alloc` works as usual (`Vec`, `String`, `Box`). The allocator is in `user/liboos/src/heap.rs`:

- Before `main`, one region of 4 MiB is mapped.
- When an allocation does not fit, a new region is mapped: at least 8 MiB, or the size of the
  request plus some overhead if that is larger. Regions are searched first-fit, in order.
- There are 16 regions at most. One allocation can be up to 64 MiB minus a few KiB (the limit of
  one `mmap`). The sum is limited by 16 regions and by RAM.
- Regions are never unmapped, so memory freed by `drop` stays in the process (it is reused for
  later allocations) and is returned only at exit.
- When mapping fails, the allocation returns null and the program aborts with the usual
  allocation error. To find out beforehand, reserve: `Vec::try_reserve_exact(n)` returns an
  error instead of aborting. `drift` uses it to pick a screen size that fits.
- The allocator is protected by a spin lock that guards only against re-entry. Programs have one
  thread.

## Time

```rust
pub fn liboos::uptime_ticks() -> u64;     // 100 Hz ticks since boot
pub fn liboos::screen::clock_ns() -> u64;  // monotonic nanoseconds since boot
pub fn liboos::screen::sleep_ms(ms: u64);
```

- `clock_ns` is monotonic. It comes from the TSC when it is calibrated, otherwise from the
  100 Hz tick. It is not wall-clock time: a ring 3 program cannot read the date.
- `sleep_ms` really sleeps: other tasks and the shell run. It wakes on the 100 Hz tick, so
  it is at least `ms` and up to 10 ms late, and a request is capped at 60 000 ms per call.
  For a delay under 12 ms, spin on `clock_ns` with `core::hint::spin_loop()`.
- `sleep_ms` also checks for Ctrl+C if the program owns the screen or the raw keyboard.

```rust
let t0 = liboos::screen::clock_ns();
liboos::screen::sleep_ms(250);
let elapsed_ms = (liboos::screen::clock_ns() - t0) / 1_000_000;
```

The frame pacing loop is in [Writing a game](games.md).

## Screen

```rust
pub struct Framebuffer {
    pub addr: *mut u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,       // bytes per line
    pub bpp: u32,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}
impl Framebuffer {
    pub fn stride(&self) -> usize;                       // pixels per line (pitch / 4)
    pub unsafe fn pixels(&self) -> &'static mut [u32];   // stride() * height pixels
    pub fn rgb(&self, r: u8, g: u8, b: u8) -> u32;       // pack 8-bit channels
}

pub fn acquire() -> Result<Framebuffer, i64>;
pub fn release() -> i64;
pub fn flush() -> i64;
```

- `acquire` maps the boot framebuffer into the program and stops the kernel console from drawing.
  The console keeps its text, so `release` (or exit) repaints it. Only one process can own the
  screen. Errors: -2 no Framebuf capability, -5 someone else owns it, -7 no framebuffer.
- Pixels are 32 bits. The channel positions are in `red_shift`, `green_shift`, `blue_shift`; on
  the usual BGRA layout they are 16, 8 and 0, which gives `0x00RRGGBB`. Do not assume it:
  use `rgb()`, or convert.
- `pitch` can be larger than `width * 4`. Index with `y * stride() + x`.
- `pixels()` is `unsafe` because it hands out a `&'static mut` slice. Take it once and keep it.
- The mapping is uncached device memory. Writing is fine, but reading from it is slow. Draw into
  a buffer in ordinary memory and copy it to the screen with `copy_from_slice`, row by row.
- The resolution is whatever the boot mode is (the `display` command changes it). Read
  `width` and `height`; do not hard-code them.
- `flush` tells the display that pixels changed. It is required on VMware SVGA II, harmless
  elsewhere. Call it once per frame. It returns -2 if the caller does not own the screen.
- After `release`, do not touch the pixels any more: the mapping stays until exit but the console
  draws there.

```rust
let fb = liboos::screen::acquire()?;            // Err(i64) if refused
let px = unsafe { fb.pixels() };
px.fill(fb.rgb(0, 0, 0));
px[10 * fb.stride() + 20] = fb.rgb(255, 160, 0);
liboos::screen::flush();
// ...
liboos::screen::release();
```

## Raw keyboard

```rust
pub fn kbd_raw(on: bool) -> i64;
pub fn key_event() -> Option<KeyEvent>;

pub struct KeyEvent {
    pub code: u8,        // scancode without the release bit, 1..=0x7F
    pub extended: bool,  // the key sent the 0xE0 prefix
    pub pressed: bool,   // false = released
}
```

- `kbd_raw(true)` switches from the console line discipline to raw press and release events.
  It returns 0, or -5 if another process is in raw mode, or -2 without the capability.
  `kbd_raw(false)` switches back. The kernel also switches back when the program ends and
  drops any queued keys, so they do not reach the shell.
- `key_event()` returns the next event, or `None` if the queue is empty. Call it in a loop each
  frame until it returns `None`. The queue is a ring of 256 bytes shared with the shell input,
  so poll at least every few frames. Calling it without raw mode returns `None`.
- Codes are PC set 1 scancodes. Keys of the extended block (arrows, Home, End, Insert, Delete,
  PgUp, PgDn, right Ctrl and Alt, keypad Enter and `/`) have `extended = true`. The same codes
  without the flag are the keypad digits and the left-hand keys.

  | Key | Code | Key | Code | Key | Code |
  |---|---|---|---|---|---|
  | Esc | 01 | A..L | 1E..26 | F1..F10 | 3B..44 |
  | 1..9, 0 | 02..0B | Z..M | 2C..32 | F11, F12 | 57, 58 |
  | Backspace | 0E | Enter | 1C | Up (ext) | 48 |
  | Tab | 0F | Left Ctrl | 1D | Left (ext) | 4B |
  | Q..P | 10..19 | Left Shift | 2A | Right (ext) | 4D |
  | Space | 39 | Right Shift | 36 | Down (ext) | 50 |
  | Left Alt | 38 | Caps Lock | 3A | Home, End (ext) | 47, 4F |
  | PgUp, PgDn (ext) | 49, 51 | Insert, Delete (ext) | 52, 53 | | |

- The events give key positions of a US layout, not characters. There is no repeat handling:
  keep your own table of held keys, and do not count on auto-repeat events.
- Pasted text (Ctrl+V) and serial input do not arrive in raw mode.
- **Ctrl+C still works.** The keyboard interrupt raises the interrupt flag before the key is
  queued. A program that owns the screen or the raw keyboard is ended by the kernel at its next
  `key_event`, `flush` or `sleep_ms` call, with status 130. You cannot catch this, and you
  cannot use Ctrl+C as a game key. The screen, keyboard and sound are released for you.
- A program that never calls `key_event`, `flush` or `sleep_ms` cannot be stopped by Ctrl+C.
  Call at least one of them in the main loop.

```rust
liboos::screen::kbd_raw(true);
let mut quit = false;
while !quit {
    while let Some(ev) = liboos::screen::key_event() {
        if ev.pressed && ev.code == 0x01 { quit = true; }   // Esc
    }
    // ... update and draw ...
    liboos::screen::sleep_ms(16);
}
liboos::screen::kbd_raw(false);
```

## Audio

```rust
impl Audio {
    pub fn open(rate: u32, channels: u32) -> Result<Audio, i64>;
    pub fn write(&self, samples: &[i16]) -> usize;
    pub fn queued(&self) -> usize;
    pub fn set_volume(&self, percent: u32) -> i64;
    pub fn rate(&self) -> u32;
    pub fn channels(&self) -> u32;
    pub fn drain(&self);
}
```

`Audio` closes its stream when dropped. The kernel also closes streams when the program ends.

- Format: signed 16-bit samples, interleaved, little endian. `rate` is 48000, 44100 or 22050;
  `channels` is 1 or 2. The kernel resamples (linear interpolation) to the device rate and turns
  mono into stereo.
- `open` errors: -7 no sound device (carry on silently), -14 all 4 streams, shared by all
  processes, are in use, -3 bad format, -2 no Framebuf capability.
- `write(samples)` copies as many whole frames as fit and returns the number of `i16` values
  accepted, a multiple of `channels`. It never blocks. 0 means the buffer is full; offer the rest
  again later.
- Each stream has a 200 ms buffer (`rate / 5` frames). `queued()` returns the frames still in it,
  at the stream's own rate.
- The device holds up to about 60 ms more after a frame leaves the stream, and the kernel feeds
  it from the 100 Hz tick, so the delay from `write` to sound is the queued time plus about
  60 ms.
- Keep `queued()` above about 50 ms (`rate / 20`) or there will be gaps. A good target is 60 to
  100 ms: each frame, if `queued()` is below it, mix the missing frames and write them. Keep the
  samples that were not accepted and send them first next time. `drift` and `beeb` do this.
- `set_volume(0..=100)` is a per-stream gain with a squared curve. The master volume of the
  system (`vol`, `mute` in the shell) applies on top.
- `drain()` sleeps until the stream is empty and the tail has played. Use it before exit,
  otherwise the end is cut off.
- Several streams are summed by the kernel with a soft limiter. They do not mix with DOOM or the
  shell's `soundtest`: if one of those keeps the device queue full, ring 3 streams wait.

```rust
let Ok(a) = liboos::audio::Audio::open(48000, 1) else { return 0; };   // no card: stay silent
let tone: Vec<i16> = (0..48000).map(|i| if (i / 50) % 2 == 0 { 6000 } else { -6000 }).collect();
let mut sent = 0;
while sent < tone.len() {
    let n = a.write(&tone[sent..]);
    sent += n;
    if n == 0 { liboos::screen::sleep_ms(20); }
}
a.drain();
```

## Handles, rights and objects (`ipc`)

A handle is a number that refers to a kernel object. Having the handle is the permission to use
the object; rights say how. [Architecture](../architecture.md) and [System call ABI](../syscall-abi.md)
describe the model.

```rust
pub struct Handle(/* u32 */);
impl Handle {
    pub const fn from_raw(raw: u32) -> Handle;
    pub const fn raw(&self) -> u32;
    pub fn into_raw(self) -> u32;                  // give up ownership without closing
    pub const fn bootstrap(n: u32) -> Handle;      // handle n given before the program started
    pub fn duplicate(&self, rights: Rights) -> Result<Handle>;   // needs DUP, rights can only shrink
    pub fn info(&self) -> Result<(ObjectType, Rights)>;
    pub fn close(self) -> Result<()>;
}

pub struct Rights(pub u32);
// READ=1 WRITE=2 DUP=4 TRANSFER=8 ALL=15, memory: MAP=16 EXEC=32 PHYS=64
impl Rights { pub fn contains(self, other: Rights) -> bool; }   // and `|`

pub enum ObjectType { Process, Thread, Channel, Notification, Reply, MemoryRegion,
                      MmioRegion, Interrupt, IoPortRange, Resource, Unknown(u8) }
```

A `Handle` closes itself when dropped.

Channels and messages:

```rust
pub const MSG_DATA_MAX: usize = 128;
pub const MSG_HANDLES_MAX: usize = 4;

// struct Message has a public field `tag: u64`
impl Message {
    pub const fn new(tag: u64) -> Message;
    pub fn with_data(tag: u64, data: &[u8]) -> Message;        // data cut to 128 bytes
    pub fn set_data(&mut self, data: &[u8]);
    pub fn data(&self) -> &[u8];
    pub fn push_handle(&mut self, h: Handle) -> core::result::Result<(), Handle>;
    pub fn handle_count(&self) -> usize;
    pub fn take_handle(&mut self, i: usize) -> Option<Handle>;
}

impl Channel {
    pub fn create() -> Result<Channel>;
    pub fn duplicate(&self, rights: Rights) -> Result<Channel>;
    pub fn call(&self, msg: &mut Message) -> Result<Message>;  // send, sleep until the reply
    pub fn send(&self, msg: &mut Message) -> Result<()>;       // one way, never blocks; Busy if full
    pub fn recv(&self, timeout_ticks: u64) -> Result<(Message, Option<Reply>)>;
}
impl Reply { pub fn reply(self, msg: Message) -> Result<()>; }
```

- Handles in a message are moved, not copied, and need TRANSFER.
- Servers hold the channel with READ (`recv`), clients with WRITE (`call`, `send`).
- A `Reply` dropped without use makes the caller's `call` fail with `PeerClosed`.
- Timeouts are in 10 ms ticks; 0 waits forever. A `recv`, `Notification::wait` or `Process::wait`
  that times out returns `Timeout`. `Channel::call` has no timeout.

Notifications and processes:

```rust
impl Notification {
    pub fn create() -> Result<Notification>;
    pub fn duplicate(&self, rights: Rights) -> Result<Notification>;
    pub fn signal(&self, bits: u32) -> Result<()>;             // OR bits in; needs WRITE
    pub fn wait(&self, timeout_ticks: u64) -> Result<u32>;     // returns and clears the bits; needs READ
}
impl Process {
    pub fn current() -> Result<Process>;
    pub fn current_thread() -> Result<Process>;
    pub fn wait(&self, timeout_ticks: u64) -> Result<i64>;     // exit code; needs READ
    pub fn kill(&self) -> Result<()>;                          // needs WRITE; not on yourself
}
```

**What you can use today.** A program started from the shell has no bootstrap handles, and it
cannot start another process or pass a handle to one. There is also no name service. So channels
between two programs cannot be set up yet. These APIs run today inside one process (the example
below), in the kernel's boot self-tests (`user/ipcsrv`, `user/ipcclient`, `user/memtest`,
`user/uartdrv`, started with `selftest=ipc` or `selftest=mem`) and in whatever `seed` will start
in stage 3 of the [ROADMAP](../../../ROADMAP.md).

## Shared memory (`mem`)

```rust
pub const PAGE: usize = 4096;

pub struct Prot(pub u32);   // READ=1 WRITE=2 EXEC=4 RW=3, combine with |; WRITE|EXEC is refused

impl MemoryRegion {
    pub fn create(size: usize) -> Result<MemoryRegion>;                  // zeroed, <= 64 MiB
    pub fn create_contig(dma: &hw::Resource, size: usize) -> Result<MemoryRegion>;   // <= 4 MiB, DMA
    pub fn duplicate(&self, rights: Rights) -> Result<MemoryRegion>;
    pub fn size(&self) -> Result<usize>;
    pub fn phys(&self) -> Result<u64>;                                   // needs PHYS
    pub fn map(&self, prot: Prot) -> Result<Mapping>;                    // maps the whole region
}

impl Mapping {
    pub fn addr(&self) -> usize;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn writable(&self) -> bool;
    pub fn read<T: Copy>(&self, off: usize) -> T;                // volatile, aligned, bounds checked
    pub fn write<T: Copy>(&self, off: usize, v: T);              // volatile; panics if read-only
    pub fn read_bytes(&self, off: usize, dst: &mut [u8]);
    pub fn write_bytes(&self, off: usize, src: &[u8]);
    pub fn as_ptr(&self) -> *mut u8;
    pub fn unmap(self) -> Result<()>;                            // dropping unmaps too
}
pub fn unmap_raw(addr: usize) -> Result<()>;
pub fn map_raw(h: &Handle, prot: u32) -> core::result::Result<usize, Error>;   // for tests of the rights checks
```

Pages are no-execute: no call hands out EXEC. A mapping stays valid after its handle is closed;
the pages are freed when the last handle and the last mapping are gone.

```rust
use liboos::ipc::{Channel, Message, Notification, Rights};
use liboos::mem::{MemoryRegion, Prot};

let ch = Channel::create().unwrap();
let mut m = Message::with_data(7, b"ping");
ch.send(&mut m).unwrap();
let (got, reply) = ch.recv(0).unwrap();          // reply is None for a one-way send

let n = Notification::create().unwrap();
n.signal(0b101).unwrap();
let bits = n.wait(0).unwrap();                   // 0b101

let region = MemoryRegion::create(8192).unwrap();
let map = region.map(Prot::RW).unwrap();
map.write::<u32>(0, 0xC0FFEE);
let ro = region.duplicate(Rights::READ | Rights::MAP).unwrap();   // what you would send away
let ro_map = ro.map(Prot::READ).unwrap();
assert_eq!(ro_map.read::<u32>(0), 0xC0FFEE);
```

## Hardware handles (`hw`)

For drivers started by a privileged parent. A program cannot create these objects.

```rust
impl Interrupt {                       // an IRQ line (legacy 8259 lines 3, 6, 8 only today)
    pub fn bind(&self, notif: &Notification, bits: u32) -> Result<()>;
    pub fn ack(&self) -> Result<()>;   // unmask after servicing
}
impl IoPorts {
    pub fn new(handle: Handle, base: u16, count: u16) -> IoPorts;
    pub fn enable(&self) -> Result<()>;
    pub fn disable(&self) -> Result<()>;
    pub fn inb(&self, off: u16) -> u8;
    pub fn outb(&self, off: u16, v: u8);
}
pub unsafe fn inb(port: u16) -> u8;
pub unsafe fn outb(port: u16, v: u8);
pub struct Resource(pub Handle);       // DMA authority for MemoryRegion::create_contig
```

An MMIO range arrives as a `MemoryRegion` handle of kind `MmioRegion` and is mapped uncached with
the same `map` call. `user/uartdrv` is a complete ring 3 driver for COM2 and the best example.

## Raw system calls (`sys`)

`sys::syscall0` to `sys::syscall3` issue `SYSCALL` with up to three arguments, `sys::nr` has
the numbers and `sys::err` the error codes. Four and five argument forms do not exist in
liboos. The kernel's dispatch table (`core/syscall/mod.rs`) is the reference. Some numbers in
`sys::nr` have no wrapper, for example `WAITPID`, and the kernel has calls that `sys::nr` does not
list (`spawn` 23, `sysinfo` 50, `cap_delegate` 70). A program started from the shell lacks the
capabilities for most of them. To add a call, see [Kernel hacking](kernel-hacking.md).

## What does not exist yet

- Environment variables and a working directory.
- Directory listing, `stat`, `mkdir`, `unlink`, `rename` from ring 3.
- Sockets and any network access.
- `spawn`, `exec`, `wait` for other programs; threads; signals.
- Wall-clock time and time zones.
- `std`, `eprintln!`, floating point math functions such as `sin` and `sqrt` (arithmetic on
  `f32` and `f64` works, with SSE2; write the functions or use a `no_std` crate such as `libm`).
- Mouse input. Only the keyboard has a ring 3 interface.
- A way to pass handles to a new process from ring 3.
