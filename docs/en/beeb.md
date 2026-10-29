# beeb: BBC Micro emulator

`beeb` emulates a BBC Micro Model B (32 KB, MOS 1.20). It is written from scratch for ospab.os.
It is a ring-3 program: the CPU, video, VIA and disc code is the `beeb-core` crate
(`apps/beeb-core`), the front end is `apps/beeb`.

## Legal note

ospab.os does **not** contain any BBC ROM or any game. The MOS ROM and the disc images are
copyrighted by their owners. You must supply your own copies, for example dumped from a machine
you own. Nothing of this kind is in the repository, in the ISO or in the package repository.
The `.gitignore` of the project excludes `*.rom` and `*.ssd` so they are not committed by
accident.

## What you need

| File | Size | Where |
|---|---|---|
| BBC MOS 1.20 ROM, usually called `os12.rom` | 16384 bytes exactly | `/usr/share/beeb/os12.rom`, or any path given with `-mos` |
| BBC BASIC ROM (optional, needed by many discs) | 16384 bytes | any path, given with `-basic` or `-rom` |
| a single-sided DFS disc image, `.ssd` | up to 200 KB (80 tracks) | any path, given on the command line |

Get the files into the system with `curl` from a web server on your PC (QEMU user networking:
`http://10.0.2.2:8000/...`) or copy them to the installed disk.

## Run

```
# tomato install beeb.tmt
# curl -o /usr/share/beeb/os12.rom http://10.0.2.2:8000/os12.rom
# curl -o /tmp/disc.ssd http://10.0.2.2:8000/disc.ssd
# beeb -mos /usr/share/beeb/os12.rom /tmp/disc.ssd
```

```
beeb [-mos os12.rom] [-basic basic.rom] [-rom SLOT file.rom] [-scale N] [-nosound] [disc.ssd]
```

- `-mos PATH`: the MOS ROM. If the file is missing the program says so and exits.
- `-basic PATH`: a BBC BASIC ROM in sideways slot 15. Without a language ROM the MOS stops at
  `Language?`. Discs whose loader is a BASIC program (Elite is one) need it.
- `-rom N PATH`: any other sideways ROM in slot N (0 to 13; slot 14 holds the built-in disc
  system).
- `-scale N`: horizontal pixel scale. Default: the largest integer scale that fits. The vertical
  scale is twice that when it fits (a BBC pixel is about twice as tall as wide on a 4:3
  monitor); otherwise 1.
- `-nosound`: do not open the sound device.
- `disc.ssd`: put in drive 0 and booted as with SHIFT+BREAK (the `!BOOT` file runs by the disc's
  `*OPT 4` option).

Defaults can be put in `/etc/beeb.conf`, one `key=value` per line, `#` for comments:

```
mos=/usr/share/beeb/os12.rom
disc=/home/games/elite.ssd
basic=/usr/share/beeb/basic2.rom
rom3=/usr/share/beeb/other.rom
scale=1
```

The picture is 640x256, centred on the screen with black borders, at 50 frames per second.
While `beeb` runs it owns the screen and the keyboard (see
[System call ABI](syscall-abi.md), "Screen, keyboard, clock"). The console comes back when it
exits.

## Keys

| PC key | Action |
|---|---|
| Esc | BBC ESCAPE |
| F12 | quit the emulator |
| F11 | reset (the machine restarts and boots the disc again) |
| Ctrl+C | kill the program (the kernel gives the screen back) |

The rest is positional: the PC key at the place of the BBC key.

| PC | BBC |
|---|---|
| letters, digits, `-`, `;`, `,`, `.`, `/`, `[`, `]`, `\`, Space, Tab, Enter | the same key |
| `=` | `^` |
| `'` | `:` |
| `` ` `` | `@` |
| Backspace, Delete | DELETE |
| End | COPY |
| Arrow keys | cursor keys |
| Caps Lock | CAPS LOCK |
| Scroll Lock | SHIFT LOCK |
| left and right Shift, left and right Ctrl | SHIFT, CTRL |
| F1 to F10 | f0 to f9 |

Symbols you get with Shift are those of the BBC keyboard, not the PC one (Shift+2 is `"`).
The BBC has no key for the PC `Alt`, `Home`, `Insert`, `PgUp`, `PgDn` or the keypad; they do nothing.

Insert is the pound/underscore key. Keys used by Elite: S and X (pitch), `<` and `>` (roll; PC `,` and `.` with Shift), Space
(speed up), `?` (slow down; PC `/` with Shift), A (fire), TAB (hyperspace), and the function
keys f0 to f9 for the views and menus (PC F1 to F10).

## What is emulated

- 6502 CPU with the documented opcodes and the commonly used undocumented ones, cycle counts,
  decimal mode, IRQ and NMI. 2 MHz clock.
- Memory map of the Model B: 32 KB RAM, 16 paged ROM slots at `&8000`, MOS at `&C000`, the I/O
  page `&FE00`.
- 6845 CRTC and the Video ULA, evaluated per scanline, so changes in the middle of the frame
  (the split screen of Elite: mode 4 on top, mode 5 for the dashboard) show correctly. Modes 0
  to 6 and a simple teletext mode 7.
- System VIA (timers, interrupts, keyboard matrix, addressable latch) and User VIA timers.
- Disc: `.ssd` images read through a high-level DFS: the kernel-side filing system calls
  (OSFILE, OSFIND, OSARGS, OSBGET, OSBPUT, OSGBPB, `*RUN`, `*LOAD`, `*EXEC`) are handled by the
  emulator, so no DFS ROM and no 8271 are needed. Files written by the program stay in memory
  and are lost at exit; the image on disk is never changed.

- Sound: the SN76489 as wired in the Model B. Bytes written to System VIA port A are latched into
  the chip when addressable latch bit 0 (sound write enable, active low) goes low. Three
  square-wave tone channels (10-bit period, counters at 250 kHz), one noise channel (periodic or
  white, 15-bit shift register, shift rate /512, /1024, /2048 or tone channel 3) and 2 dB
  attenuation steps. The output is averaged over each output sample and passed through a
  DC-blocking high-pass; the front end plays it as 48 kHz mono, about 960 samples per frame.
  If the machine has no sound card, or with `-nosound` (or `sound=0` in `/etc/beeb.conf`),
  `beeb` runs silently. It keeps 60 to 100 ms queued and drops a frame's audio if more is waiting.

Not emulated: the 8271 disc controller, the second processor, Econet, ADC and
joystick, tape, speech, the printer port.

## Limits

- With only the MOS ROM the machine starts and prints `BBC Computer 32K` and `Language?`: there is
  no language to run. Give it a BASIC ROM with `-basic` to get the `>` prompt and to start discs
  with a BASIC loader.
- Speed depends on the host. In QEMU without KVM the emulator may fall behind 50 Hz; it then
  drops time instead of trying to catch up.
- Display mode changes made by changing the screen start address in the middle of a frame work;
  interlaced video and the 6845 cursor are not drawn.

## Source

- `apps/beeb-core/src/cpu.rs`: 6502.
- `apps/beeb-core/src/machine.rs`: memory map, SHEILA, glue.
- `apps/beeb-core/src/video.rs`, `via.rs`, `keyboard.rs`, `disc.rs`, `sound.rs`: the parts of the machine.
- `apps/beeb/src/main.rs`: front end (arguments, files, keys, framebuffer, 50 Hz pacing).
- `apps/gfxtest`: test program for the screen, raw keyboard and clock calls.
