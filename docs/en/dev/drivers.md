# Drivers in ring 3

A driver can be a package. It runs as an ordinary ring 3 process, gets exactly one PCI
function, and is started by the device manager when the package is installed. Adding a driver
does not need a kernel rebuild.

State today: the mechanism works and the first driver, `drv-e1000`, is ported. The other
drivers are still in the kernel. The network stack also stays in the kernel; a ring 3 NIC driver
feeds it through a shared packet ring.

## The parts

```
tomato install drv-e1000        puts /usr/lib/drivers/e1000/{drv-e1000,driver.conf} in the filesystem
devmgr (ring 3, started at boot)   scans PCI, reads driver.conf files, claims a matching function,
                                   starts the driver, restarts it if it dies
drv-e1000 (ring 3)                 maps BAR 0, builds DMA rings, talks to the kernel network stack
kernel                             claim table, PCI objects, DMA memory, interrupts, packet ring
```

- `devmgr` (`user/devmgr`) is the only process that holds the PCI resource. The kernel starts it
  after the boot self-test (kernel parameter `devmgr=off` skips it) and installs the same program
  as `/usr/bin/devctl`.
- `libdriver` (`user/libdriver`) is the library a driver links, on top of `liboos`.
- A driver package is a normal `.tmt` package with a `[driver]` table in the manifest.

## Driver manifest

```toml
name = "drv-e1000"
version = "0.1.0"
description = "Intel e1000 network driver for ring 3"
arch = "x86_64"
depends = []

[[files]]
src = "../target/x86_64-unknown-oos/release/drv-e1000"
dest = "/usr/lib/drivers/e1000/drv-e1000"

[driver]
match = ["pci:8086:100e", "pci:8086:100f", "pci-class:02:00"]
exec = "/usr/lib/drivers/e1000/drv-e1000"      # optional: default is the first file
```

- `match` entries are `pci:VVVV:DDDD` (vendor and device, hex) or `pci-class:CC:SS` (class and
  subclass, hex). A function matches if any entry matches.
- The driver name is the package name without `drv-` (`e1000`). All files must be installed
  under `/usr/lib/drivers/<name>/`.
- `tmt pack` adds `/usr/lib/drivers/<name>/driver.conf` to the package:

  ```
  name=e1000
  exec=/usr/lib/drivers/e1000/drv-e1000
  match=pci:8086:100e,pci:8086:100f
  ```

  and the metadata line `driver_match=...`. `tomato` needs no knowledge of drivers: it installs
  the files, and `devmgr` finds `driver.conf`. Old packages and old `tomato` stay compatible.
  `tomato remove` removes the files. A running driver keeps running until it exits.
- `devmgr` looks at `/usr/lib/drivers` once a second, so a driver starts a moment after
  `tomato install`.

## devctl

```
devctl list                list PCI functions: owner (kernel, ring3, free), driver, state, pid, restarts
devctl start <driver>      start a stopped driver
devctl stop <driver>       kill it and do not restart it
devctl restart <driver>    kill and start again
```

`devctl` talks to `devmgr` through two files: `devmgr` writes `/run/devmgr.status`, and `devctl`
appends commands to `/run/devmgr.cmd`. Driver log lines are in `dmesg` (and on the serial port),
tagged with the driver name.

A driver that exits is started again after 1 s; the delay doubles up to 30 s. A driver that ran
for 15 s or more starts over with 1 s. A device the kernel drives itself (the NIC in use) is
taken from the kernel only when a matching driver package is installed: `devmgr` claims it with
the force flag, the kernel resets the device and its own driver stops. The kernel keeps the IP
configuration, so the new driver continues with the same lease. Without the package nothing
changes: the in-kernel driver is used.

## Kernel side

Objects and calls are in [System call ABI](../syscall-abi.md), "Drivers in ring 3". In short:

- `Resource(PCI)` lets a process list PCI functions (`pci_enum`) and claim one (`pci_claim`).
  Only `devmgr` has it.
- A claim returns a `PciDevice` handle. The claim table keeps one owner per function: kernel or
  ring 3. When the last handle goes away the function is idle again (bus master off).
- From the `PciDevice` handle a driver derives everything it may touch: `pci_open` gives a BAR as
  an `MmioRegion` or `IoPortRange`, or the legacy interrupt; `irq_alloc_msi` gives MSI/MSI-X
  vectors; `pci_cfg_read` and `pci_cfg_write` access config space of this function only (not the
  ID, BARs, ROM base); `mem_create_contig` on this handle gives DMA memory with its physical
  address, optionally uncached.
- A legacy interrupt line is refused when an in-kernel driver of another function shares it.
- There is no IOMMU yet. A driver that is given bus mastering can DMA anywhere. Rings, rights
  and the claim table protect against mistakes and not against a hostile driver.

## libdriver

```rust
let d = Driver::new("mydrv");          // sets the log tag, takes handle 1 (device) and 2 (devmgr)
let pci = d.pci();
pci.enable_bus_master()?;              // memory space, I/O space, bus master on; INTx disable off
let regs = pci.bar_map(0)?;            // Mapping, uncached: regs.read::<u32>(off), regs.write(off, v)
let ports = pci.bar_io(1)?;            // IoPorts; call .enable() first
let irq = pci.irq()?;                  // MSI if the device has it, else INTx; Irq { wait, ack, unmask }
let dma = pci.dma_alloc(64 * 1024, false)?;   // Dma { virt(), phys(), len(), as_ptr(), map, region }
pci.config_read(0x3C, 1)?; pci.config_write(0x04, 2, v)?;
libdriver::log!("link {}", up);        // serial + kernel event log (dmesg), tagged [mydrv]
d.ready("status text");                // tells devmgr the driver is up
```

- `Irq::wait(ticks)` returns the notification bits, 0 on timeout. Bit 1 (`IRQ_BIT`) is the
  device interrupt. After servicing it call `ack()`, which unmasks the line.
  `Driver::run(&irq, ticks, f)` is a loop around this.
- `Irq::notification()` is the notification; other parties may signal other bits (the kernel
  network stack uses bit 2).
- Use `liboos::mem::Mapping::read` and `write` (volatile) for device memory and for memory
  shared with another process.
- Write `libdriver::driver_entry!("name", main)` instead of `liboos::entry!`. A driver must not
  use `println!`: standard output of a ring 3 process also reaches the shell. Use `log!`.

## Write your first driver: the e1000 example

The code is `apps/drivers/e1000/src/main.rs`. Steps it takes:

1. `Driver::new("e1000")`, `pci.info()`, `enable_bus_master()`.
2. `pci.bar_map(0)`: the register window (BAR 0 of the 8254x is memory).
3. `pci.dma_alloc(...)`: one contiguous region holds the descriptor rings and the packet
   buffers. The card gets physical addresses from `dma.phys()`.
4. Reset (`CTRL.RST`, wait), set link up, read the MAC from the EEPROM, program the RX and TX
   rings, enable `RCTL` and `TCTL`.
5. `pci.irq()`. If it fails the driver polls every tick.
6. Fill the ring header and call `netring::attach(...)`, then `d.ready(...)`.
7. Loop: `irq.wait(1)`, read `ICR`, publish finished RX descriptors, hand freed slots back
   (`RDT`), post new TX frames (`TDT`), reap finished ones, watch the link bit.

To make a package:

```
cd apps
cargo +nightly build --release -p drv-e1000        # on Windows: +nightly-x86_64-pc-windows-gnu
..\tools\tmt\bin\tmt pack pkg\drv-e1000.toml -o dist
```

or `apps\build.ps1 -Only drv-e1000`. To add a new crate, put it in `apps/drivers/<name>`, add
it to `members` in `apps/Cargo.toml`, depend on `liboos` and `libdriver`, and write
`apps/pkg/drv-<name>.toml`.

## Network drivers

The kernel network stack is not a server yet, so a NIC driver does not implement sockets. It
fills one DMA region that is also the packet memory (`net/ext.rs`, `libdriver::netring`):

```
page 0     header: magic, version, MAC, flags (bit 0 link, bit 1 running), nslots, slot_size,
           rx_off, tx_off, rx_prod, rx_cons, tx_prod, tx_cons, rx_len[], tx_len[]
rx_off     nslots receive slots: the card writes frames here, the stack reads them in place
tx_off     nslots transmit slots: the stack copies a frame in, the card sends from here
```

Indices are free-running `u32` counters (slot = index % nslots). The driver owns `rx_prod` and
`tx_cons`, the kernel owns `rx_cons` and `tx_prod`. `netring::attach` registers the region and
a notification; the kernel sets bit 2 of it when a frame waits to be sent (it also signals the
driver only when no lock is held, so the driver must also wake by timeout). After publishing
frames the driver calls `netring::poll()`, and the stack processes them in that call. The
receive path has no copy; the transmit path has one (stack buffer to slot).

If the driver process dies, the stack notices at its next send or receive and reports no link
until a driver attaches again.

Limits: the kernel network stack must already be up (an in-kernel NIC driver brought it up), so
a NIC that has no kernel driver cannot be used yet. One external NIC at a time.

## Test

QEMU with `-device e1000`, the ISO built with `scripts/mkiso.sh` (see [Testing](testing.md)):

```
curl -o /run/drv.tmt http://10.0.2.2:8000/drv-e1000-0.1.0.tmt     # served by python -m http.server
tomato install /run/drv.tmt
ping 10.0.2.2                    # now goes through the ring 3 driver
devctl list                      # 00:03.0 8086:100e 02:00 ring3 e1000 running
kill <pid of drv-e1000>          # devmgr starts it again, ping works again
dmesg                            # [e1000] ... [devmgr] ... lines
```

The serial log shows `[NET] external NIC driver attached (ring 3)`.

## Not done yet

- Other drivers (storage, audio, USB, other NICs) are still in the kernel.
- No IOMMU: a ring 3 driver with bus mastering is trusted not to program DMA badly.
- A `devctl stop` leaves the device idle; there is no way to give it back to the kernel driver
  without a reboot.
- The network stack is in the kernel; sockets over IPC are future work.
