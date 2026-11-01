# Kernel hacking

How the repository is laid out and how to add the three most common things to the kernel: a
shell command, a system call and a driver. Code in these places runs in ring 0. Read
[Architecture](../architecture.md) and [Kernel internals](../kernel.md) first.

## Code map

The kernel is one crate, `ospab_os`. `src/lib.rs` is the library root and pulls in the
top-level directories with `#[path = "../arch/mod.rs"]` and similar lines; `src/main.rs` is the
binary with the boot sequence. There is no `[[bin]]` or `[lib]` section in `Cargo.toml`.

| Path | What is there |
|---|---|
| `src/main.rs` | `_start`, the boot sequence, `boot_log!` and the boot self-tests |
| `src/lib.rs` | module list of the library crate |
| `src/terminal.rs` | the console: input, `help`, commands that are not coreutils, command dispatch |
| `src/userspace/plum/` | the shell: parser, expansion, builtins (`builtins.rs`), program start (`exec.rs`), stdout and stdin plumbing (`io.rs`), accounts |
| `src/userspace/axon/` | coreutils and tools: `ls`, `grep`, `ping`, `curl`, `ps`, disk tools, the desktop (`desktop/`) |
| `src/userspace/mod.rs` | includes `net/`, `drivers/`, `vfs/` and `userland/*` by `#[path]` |
| `src/installer.rs`, `src/installer/` | the disk installer |
| `src/pci.rs`, `src/acpi/`, `src/xhci/` | PCI access and enumeration, ACPI, USB (xHCI, HID) |
| `src/time.rs`, `src/klog.rs`, `src/esp.rs`, `src/doom.rs` | clock, kernel event log, ESP access for system updates, DOOM glue |
| `arch/x86_64/` | GDT/TSS, IDT and interrupt dispatch, PIC/APIC, TSC, keyboard, mouse, serial, framebuffer and console, panic screen. `boot/` holds the `BootInfo` contract with the loader |
| `core/` | `scheduler/`, `syscall/` (`mod.rs` table, `objects.rs`, `screen.rs`, `audio.rs`), `object.rs` (handles and objects), `elf.rs`, `fd.rs`, `stdin.rs`, `sync.rs`, `selftest.rs`. `capability/` and `ipc/` are older code |
| `mm/` | `physical/` (frames), `virtual/` (page tables), `heap.rs`, `numa/`, `usercopy.rs` |
| `vfs/` | `mod.rs` (mounts, descriptor calls), `ramfs.rs`, `cow.rs`, `procfs.rs`, `aeternafs.rs`, `disk_sync.rs`, `persist.rs` |
| `drivers/` | storage (`ata`, `ahci`, `nvme`, `virtio_blk`, `gpt`, `block`), `audio/`, `gpu/` (VMware SVGA, VMMouse, host clipboard), `registry.rs` |
| `net/` | NIC drivers, Ethernet, ARP, IPv4, ICMP, UDP, TCP, DHCP, DNS, SNTP, `tls/`, `ostp/` |
| `userland/` | `grape` (editor), `tomato` (packages), `seed` (service table); compiled into the kernel |
| `fs/aeternafs/` | AeternaFS v2 as a standalone `no_std` crate with host tests |
| `gui/` | `oos-ui`, the widget toolkit and desktop session |
| `user/` | separate workspace for ring 3: `liboos` and the boot-time test programs |
| `apps/` | separate workspace for ring 3 programs and packages; the SDK |
| `boot/` | ospab-boot: `common/` (shared), `uefi/`, `bios/`, `ospab.cfg` |
| `tools/` | host tools: `tmt/`, `oosfs/`, `mkimage.rs` |
| `scripts/` | `mkiso.sh`, `bios-image.sh`, `run-qemu.*`, `smoke-test.ps1` |
| `doom_engine/` | doomgeneric C sources and a small libc; built by `doom_engine/build_doom.sh` |
| `build.rs`, `linker.ld`, `x86_64-ospab.json` | build identity, kernel link script, kernel target |

Not every `.rs` file under `src/` is compiled. `src/main.rs` declares `terminal`, `version` and
`installer`; the library declares the rest. Files such as `src/shell.rs`, `src/ui.rs`,
`src/console.rs` and `src/logger.rs` are not part of any module tree. If a file does nothing
when you edit it, check that some `mod` line includes it.

## Add a module or file

- A new file in an existing directory: create it, then add `pub mod name;` to that directory's
  `mod.rs` (or `mod name;` for private).
- A new top-level directory: add `#[path = "../dir/mod.rs"] pub mod dir;` to `src/lib.rs`, as for
  `arch`, `mm` and `core`.
- A new external crate: add it to `Cargo.toml`. It must be `no_std`. Use `default-features =
  false`.
- A new C source file for DOOM: `doom_engine/build_doom.sh` and `build.rs`.
- Every source file starts with the license header. See [Contributing](../../../CONTRIBUTIONS.md).
- Build with `./build.sh kernel`: it is the fast compile check. See [Testing](testing.md).

## Add a shell command

Where it goes depends on whether it must work in pipes and redirects.

**A coreutils-style command (preferred).** It reads arguments, writes to the shell's output and
works in pipelines and with `>`.

1. In `src/userspace/axon/mod.rs` write `fn cmd_foo(args: &[String])`. Print with the helpers at
   the top of the file: `out(&str)`, `err(&str)`, `outc(&str, color)`. They go through
   `plum::io`, which is what makes redirects and pipes work. `cmd_basename` is a short model.
   A larger command can live in its own file (`src/userspace/axon/foo.rs` with `pub mod foo;`
   and `pub fn run(args: &str)`, like `ping.rs` or `clip.rs`).
2. Add `"foo" => cmd_foo(args),` to the `match name` in `axon::run`. For the `pub fn run(&str)`
   form, call it with `&joined()`.
3. Add `"foo"` to `command_list()` in the same file. Tab completion and `type` use it.
4. Add a row to the `HELP` table in `src/terminal.rs` and, if you want `help foo` to say more, a
   case in `help_detail`.
5. Add the command to the list in [Shell and tools](../shell.md) and its Russian version.

**A console command.** Commands that draw full-screen interfaces, use the framebuffer console
directly or talk to the machine (`grape`, `reboot`, `date`, `tomato`) live in
`src/terminal.rs`. They cannot be piped or redirected.

1. Write `fn cmd_foo(args: &str)` in `src/terminal.rs`.
2. Add the name to `TERMINAL_COMMANDS` and a match arm to `dispatch_console`.
3. If the command takes over the screen or waits for keys, add it to `NO_PAGER` so the pager does
   not interfere.
4. Add the name to `CONSOLE_COMMANDS` in `src/userspace/plum/mod.rs`, so that the shell finds it
   when it appears in a script. The shell then prints a note if you pipe it.
5. `HELP` and `help_detail` as above.

**A shell builtin** (changes the shell's own state, such as `cd` or `export`): add it to
`src/userspace/plum/builtins.rs` (`builtins::run`).

Before you add a command to the kernel, ask whether it can be a ring 3 program instead
([Your first program](first-program.md)). Only commands that need kernel internals have to be
here.

## Add a system call

Read [System call ABI](../syscall-abi.md) first. The dispatch table in `core/syscall/mod.rs`
(`DISPATCH_TABLE`) is the only thing that matters for dispatch. The `SyscallNumber` enum above it
is a list of names and is not used for dispatch (it still lists calls that are not in the table,
such as `IpcSend = 10` and `Fork = 30`).

Numbers in use:

| Range | Calls |
|---|---|
| 0 to 5 | exit, write, read, open, close, seek |
| 20 to 24 | yield, sleep_ms, getpid, spawn, preempt_control |
| 32 | waitpid |
| 40, 41 | mmap, munmap |
| 50 to 52 | sysinfo, uptime, get_tasks |
| 70, 80, 110 | cap_delegate, med_assign, dev_detach |
| 200 to 253 | handles, channels, notifications, processes, memory regions, interrupts, ports |
| 260 to 264, 270 | screen, raw keyboard, clock |
| 271 to 275 | audio |

Steps:

1. **Pick a number.** Continue a family (276 for audio or clock, for example), or start a new
   block of ten at 280. Record it in `docs/en/syscall-abi.md`.
2. **Write the handler.** Put it in a file under `core/syscall/` (add `pub mod foo;` to
   `core/syscall/mod.rs`) or next to similar calls. Model it on `core/syscall/audio.rs`.
   The signature is `pub fn name(a1: u64, a2: u64, ...) -> i64`. The result is a value >= 0 or a
   negative `SyscallError`, for example `E::InvalidArgument as i64`.
3. **Check the capability first.** The process has a list of `Capability` values
   (`core/scheduler/mod.rs`: FsRead, FsWrite, Framebuf, Serial, Net, Spawn, System, Device, ...).
   Use `scheduler::has_capability(Capability::X)`; a process with `System` passes every check.
   Programs started from the shell get Serial, FsRead, FsWrite and Framebuf
   (`run_elf` in `src/userspace/plum/exec.rs`). Screen, raw keyboard and audio check Framebuf.
   Do not hand out a new power to every program without a reason. If it is a new kind of power,
   add a `Capability` value and give it in `run_elf` only when it is meant to be general.
   Calls on kernel objects need no capability: the handle and its rights are the permission
   (`core/object.rs`).
4. **Never trust a pointer.** Use `crate::mm::usercopy`: `range_ok(addr, len)`,
   `copy_from_user(dst, src)`, `copy_to_user(dst, src)`, `read_user_bytes(src, len, max)`,
   `read_user_str(src, len, max)`. `SyscallError::from(UserCopyError)` converts the error. Clamp
   sizes (`MAX_IO_CHUNK` is 64 KiB) and do not allocate based on an unchecked length.
5. **Blocking.** A call may sleep: every task has its own kernel stack. Use `scheduler::park
   (deadline)` in a loop, like `screen::sleep_ms`. Never block while holding a lock. If the call
   is used by programs that own the screen or keyboard, call `check_interrupt()` so Ctrl+C works.
6. **Cleanup.** If the call hands out something that must go back when the process dies, release
   it in the teardown path. `screen::process_gone` is called from the scheduler and shows the
   pattern (audio streams, the screen, the raw keyboard).
7. **Register it.** Add `(NNN, |a| foo::name(a.arg1, a.arg2, a.arg3)),` to `DISPATCH_TABLE`. The
   table is searched linearly. A number that is missing returns -1.
8. **liboos.** Add `pub const NAME: u64 = NNN;` to `sys::nr` in `user/liboos/src/sys.rs` (the file
   says the numbers must match the kernel) and a safe wrapper in the module where it belongs,
   using `sys::syscall0`..`syscall3`. There is no four or five argument form yet; add one to
   `sys.rs` if you need it. Return `Result<_, ipc::Error>` for object-style APIs, like `mem`
   does, or the raw `i64` like `screen`. Keep to one style per module.
9. **Document.** Add a row and a paragraph to `docs/en/syscall-abi.md`, the wrapper to
   [liboos reference](liboos.md), and translate both into `docs/ru`.
10. **Test.** Write a small ring 3 program. Either put it in `apps/` (like `gfxtest` or `tone`,
    a package that anyone can run), or in `user/` and call it from the boot self-test in
    `src/main.rs`, so that regressions show up in the boot log. Test the error paths: bad
    pointer, wrong handle, no capability.

## Add a driver

Drivers run in ring 0 today. A driver for hardware that exists in VMware or QEMU is the best
kind to start with: you can test it.

1. **File.** Create `drivers/<name>.rs` (or in `drivers/audio/`, `drivers/gpu/`; a NIC goes in
   `net/`) and declare it in the parent `mod.rs`.
2. **Find the device.** `ospab_os::pci` (`src/pci.rs`) has the PCI table, filled at boot:

   ```rust
   crate::pci::find_by_vendor_device(vid, did)        // Option<&PciDevice>
   crate::pci::find_by_class(class, subclass, progif)
   crate::pci::read_bar(bus, dev, func, bar_index)    // BarType::Io { .. } or a memory BAR
   crate::pci::enable_bus_master(bus, dev, func)
   crate::pci::config_read32(bus, dev, func, offset)  // and 8, 16 bit and write forms
   crate::pci::find_capability(bus, dev, func, cap_id)
   ```

   `probe` must be cheap: read PCI config space only.
3. **Initialise.** Provide `pub fn init() -> bool` (or `probe_and_init`). Return `false` when
   the device is not there or does not work. Do not panic on missing hardware. Map MMIO through
   the HHDM or the page table helpers in `mm/virtual`; enable bus mastering before DMA; DMA
   buffers must be physically contiguous and below the limit your device supports.
4. **Log with a tag.** Write detail lines to the serial port with a bracketed tag and `\r\n`:

   ```rust
   serial::write_str("[FOO] Found 1234:5678 at 00:03.0\r\n");
   ```

   The existing drivers use `[ES1371]`, `[AUDIO]`, `[NET]`, `[e1000]` and so on. Write why a
   device was refused. A line that starts with `[ FAIL ]` makes the smoke test fail, so do not
   begin a debug line that way.
5. **Hook it into boot.** In `src/main.rs`, call `boot_step("Foo")` and wrap the init in
   `ospab_os::drivers::registry::try_init_driver("Foo", || { ... })`, which logs `[DRV] Foo:
   probing / active / not available` and records the result. Then print exactly one status line:

   ```rust
   boot_log!(Status::Ok, "Foo", "{} at {}", model, detail);       // [  OK  ]
   boot_log!(Status::Absent, "Foo", "no controller");             // [  --  ] optional hardware missing
   boot_log!(Status::Warn, "Foo", "...");                         // [ WARN ]
   boot_log!(Status::Fail, "Foo", "...");                         // [ FAIL ] only for real errors
   ```

   `Absent` is the right status for a device that may not exist. `Fail` is for a device that is
   there and does not work; it also fails the smoke test and is written to the kernel event log.
   `Status::Info` is for facts. Lines are at most 160 bytes. `GPU`, `Audio` and `USB` in
   `src/main.rs` are short models.
6. **Interrupts.** Legacy PIC lines are dispatched by a `match irq` in `irq_dispatch`
   (`arch/x86_64/idt.rs`). The NIC lines 9, 10 and 11 call `userspace::net::handle_net_irq`.
   An interrupt handler may only take locks that are safe in interrupt context
   (`IrqSpinLock`). Many drivers poll instead; that is acceptable if the driver says so.
   Follow the [locking rules](../kernel.md#locks).
7. **A network card** has more places to touch in `net/mod.rs`: a `NIC_*` constant, the probe
   chain in `init`, and the matches that read the MAC, send, receive, link state, IRQ and names.
   Search for `NIC_PCNET` to see all of them.
8. **A disk** must end up in the table in `drivers/mod.rs` (`DiskKind`, `init`). Everything is
   addressed in 512-byte sectors.
9. **Hardware list and docs.** Add the device to [Hardware](../hardware.md) and its Russian
   version.
10. **Test** in QEMU with the matching `-device` (see [Testing](testing.md)) and, for anything a
    VMware guest can have, in VMware. Watch the serial log.

`drivers/registry.rs` and `drivers/driver_trait.rs` say that a panicking driver is caught. It is
not: the kernel is built with `panic = "abort"`, so a panic in `init` stops the machine. The
registry only records whether `init` returned true.

## Locking

Use the primitives in `core/sync.rs` and follow the ranks in [Kernel internals](../kernel.md).
In short: `IrqSpinLock` for data shared with interrupt handlers, `Mutex` for long sections in
task context, no I/O, waiting or `park` while a spinlock is held, locks in increasing rank
order, HEAP last. If you add a lock, choose its rank by what it calls while held, and add the
row to the table in `docs/en/kernel.md`. New code should not use `static mut` for shared state.

## Where to look when something breaks

- The serial log first. `[CRITICAL] Process N name at 0x...` is a ring 3 fault; `[FATAL] CPU
  Exception` with `Fault RIP` is a kernel fault. Match the address with an
  `objdump -d` (or `nm`) of `target/x86_64-ospab/release/ospab_os`. `build.sh` strips debug
  info but keeps the symbols.
- `dmesg` in the shell shows the kernel event log.
- Boot with the loader entry "ospab.os (debug)": `debug=1` puts detail lines on the screen,
  `selftest=ipc` runs the IPC tests, `persist=ro` stops the saved layer being written.
  Parameters: `debug=1`, `persist=ro`, `selftest=ipc|mem|sched|all`, `session=desktop`, `mode=`.
- `testmode` shows the panic and fault screens without crashing.
