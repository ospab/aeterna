# Writing a game

A game or an emulator for ospab.os is a normal ring 3 program that takes over the whole screen.
It draws pixels into the framebuffer, reads raw key events, pushes sound samples into the kernel
and keeps its own time. This page shows how, using the two shipped examples. Read
[Your first program](first-program.md) and the [liboos reference](liboos.md) first.

The examples:

- `apps/drift` and `apps/drift-core`: a space trading and combat game with a software 3D renderer.
  [Description](../drift.md).
- `apps/beeb` and `apps/beeb-core`: a BBC Micro emulator. [Description](../beeb.md).
- `apps/gfxtest`: the smallest test of screen, keyboard and clock. `apps/tone`: the smallest
  test of sound.

## Split the game from the front end

Both big examples have two crates:

- `<name>-core` is a `no_std` library with the simulation, the renderer and the menus. It draws
  into a plain pixel buffer (`0x00RRGGBB`), takes abstract actions as input and fills a sample
  buffer for sound. It does not use system calls.
- `<name>` is a thin ring 3 program: arguments, files, the framebuffer, the keyboard, the clock,
  the audio stream.

The core builds and is tested on your PC, with screenshots written as files, so most bugs are
found without a VM. See [Testing](testing.md). Add both crates to `members` in `apps/Cargo.toml`.
Only the front end needs a package manifest.

## The shape of the program

```
acquire screen  ->  raw keyboard on  ->  open audio (optional)
loop:
    read key events
    run the simulation (fixed step)
    mix audio
    draw into a back buffer in RAM
    copy the back buffer to the screen, flush
    wait for the next frame
raw keyboard off  ->  release screen
```

Always undo what you did on the way out, also on error paths. If the program ends in any way,
the kernel releases the screen, the keyboard and the sound streams for you, but a clean exit lets
the console repaint at once and prints your message in the right place.

A complete skeleton follows. It moves a square with the arrow keys, beeps at the walls and quits
on Esc. It builds as is against the current liboos.

```rust
// SPDX-License-Identifier: AGPL-3.0-only
//! Skeleton of a full-screen game: fixed 60 Hz simulation, back buffer, raw keyboard, sound.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use liboos::audio::Audio;
use liboos::println;
use liboos::screen::{self, Framebuffer};

liboos::entry!(main);

const STEP_NS: u64 = 16_666_667; // simulation step: 60 Hz
const MAX_FRAME_NS: u64 = 250_000_000; // never simulate more than 250 ms at once
const W: usize = 320; // internal resolution
const H: usize = 200;

struct State {
    x: i32,
    dx: i32,
    left: bool,
    right: bool,
    beep: bool,
    quit: bool,
}

impl State {
    fn update(&mut self) {
        let want = (self.right as i32) - (self.left as i32);
        self.x = (self.x + want * 3 + self.dx).clamp(0, W as i32 - 16);
        if self.x == 0 || self.x == W as i32 - 16 {
            self.beep = true;
        }
    }

    fn render(&self, back: &mut [u32]) {
        back.fill(0x00101830);
        for y in 90..106 {
            for x in self.x as usize..self.x as usize + 16 {
                back[y * W + x] = 0x00FFA000;
            }
        }
    }
}

/// Copy the back buffer to the screen, scaled by an integer factor and centred.
fn present(fb: &Framebuffer, px: &mut [u32], back: &[u32], scale: usize) {
    let stride = fb.stride();
    let x0 = (fb.width as usize - W * scale) / 2;
    let y0 = (fb.height as usize - H * scale) / 2;
    for y in 0..H {
        for k in 0..scale {
            let row = &mut px[(y0 + y * scale + k) * stride + x0..][..W * scale];
            for (i, d) in row.iter_mut().enumerate() {
                let c = back[y * W + i / scale];
                *d = fb.rgb((c >> 16) as u8, (c >> 8) as u8, c as u8);
            }
        }
    }
}

/// Keep about 90 ms of sound queued. Samples the kernel did not take stay in `pending`.
fn feed_audio(a: &Audio, state: &mut State, phase: &mut u32, pending: &mut Vec<i16>) {
    if !pending.is_empty() {
        let n = a.write(pending);
        pending.drain(..n);
        if !pending.is_empty() {
            return;
        }
    }
    let target = a.rate() as usize * 90 / 1000;
    let queued = a.queued();
    if queued >= target {
        return;
    }
    let frames = target - queued;
    let mut buf = vec![0i16; frames];
    for s in buf.iter_mut() {
        if state.beep {
            *s = if (*phase / 55) % 2 == 0 { 5000 } else { -5000 };
            *phase += 1;
            if *phase > 4800 {
                *phase = 0;
                state.beep = false;
            }
        }
    }
    let n = a.write(&buf);
    pending.extend_from_slice(&buf[n..]);
}

fn main(_args: liboos::Args) -> i32 {
    let fb = match screen::acquire() {
        Ok(f) => f,
        Err(e) => {
            println!("cannot get the screen (error {})", e);
            return 1;
        }
    };
    if screen::kbd_raw(true) < 0 {
        screen::release();
        println!("the keyboard is in use");
        return 1;
    }
    let scale = (fb.width as usize / W).min(fb.height as usize / H).max(1);
    let px = unsafe { fb.pixels() };
    px.fill(fb.rgb(0, 0, 0));
    let mut back = vec![0u32; W * H];
    let audio = Audio::open(48000, 1).ok();
    let mut pending: Vec<i16> = Vec::new();
    let mut phase = 0u32;

    let mut st = State { x: 100, dx: 0, left: false, right: false, beep: false, quit: false };
    let mut last = screen::clock_ns();
    let mut acc = 0u64;
    while !st.quit {
        let now = screen::clock_ns();
        acc += (now - last).min(MAX_FRAME_NS);
        last = now;

        while let Some(ev) = screen::key_event() {
            match (ev.code, ev.extended) {
                (0x01, _) => st.quit = true,
                (0x4B, true) => st.left = ev.pressed,
                (0x4D, true) => st.right = ev.pressed,
                _ => {}
            }
        }
        while acc >= STEP_NS {
            st.update();
            acc -= STEP_NS;
        }
        if let Some(a) = &audio {
            feed_audio(a, &mut st, &mut phase, &mut pending);
        }
        st.render(&mut back);
        present(&fb, px, &back, scale);
        screen::flush();

        // wait for the next frame: sleep while there is time, spin the last milliseconds
        let target = now + STEP_NS;
        loop {
            let t = screen::clock_ns();
            if t >= target {
                break;
            }
            if target - t > 12_000_000 {
                screen::sleep_ms((target - t) / 1_000_000 - 10);
            } else {
                core::hint::spin_loop();
            }
        }
    }
    screen::kbd_raw(false);
    screen::release();
    0
}
```

## Time: a fixed step

Run the simulation at a fixed rate and draw as often as you can. This makes the game behave the
same on a fast and on a slow machine, and makes it testable.

- Read `screen::clock_ns()` once per frame, add the elapsed time to an accumulator and run
  `update()` once for every full step in it.
- Clamp the elapsed time (250 ms in the skeleton) so that a stall does not cause hundreds of
  steps in a row.
- `drift-core` steps at 30 Hz and takes the frame time only for drawing effects. `beeb-core`
  runs exactly one emulated 20 ms frame for each real frame.
- Do not use `uptime_ticks` for game time: it has 10 ms resolution.

## Waiting for the next frame

There is no vertical sync and no flip. You wait yourself.

- `sleep_ms` lets the shell and other tasks run, but the kernel wakes you on its 100 Hz tick, so
  you can be up to 10 ms late. Sleep only for the part of the wait that is more than about
  12 ms, minus 10 ms, and spin on `clock_ns` for the rest. The skeleton and `beeb` do this.
- `drift` calls `liboos::yield_now()` in its wait loop. That keeps the CPU busy but never
  sleeps past the deadline.
- Schedule frames from a running target (`next += FRAME_NS`) and not from "now plus a frame",
  or the frame rate drifts. If you fall far behind (`beeb` allows 5 frames), reset the target
  to now. Do not try to catch up: drop time instead.
- `sleep_ms`, `key_event` and `flush` also check for Ctrl+C. One of them must be in the loop.
- Under QEMU without hardware acceleration the guest is slow. A game that runs at 60 Hz on
  VMware may run at 15 Hz in TCG. Test in both, and measure.

## The screen

- `screen::acquire()` can fail. Print the error and return a non-zero status. See
  [liboos reference](liboos.md#screen).
- Use the real `fb.width` and `fb.height`. The mode depends on the VM and on the `display`
  command. Choose your internal resolution, then scale by an integer factor (`scale = min(fb.width
  / W, fb.height / H)`) and centre. `drift` takes the resolution from `-r N` (1/N of the screen);
  `beeb` has `-scale`.
- Draw into a buffer in ordinary memory (the back buffer), and copy it to `fb.pixels()` once per
  frame, row by row. The framebuffer is uncached device memory: writing a row with
  `copy_from_slice` is fast, reading it back and drawing into it pixel by pixel is slow.
  `drift` and `beeb` repeat scanlines with `copy_within` on the screen; that reads from it. If
  the screen blit is your bottleneck, build the scaled rows in RAM first.
- Check the pixel layout once. If `red_shift == 16 && green_shift == 8 && blue_shift == 0`, your
  `0x00RRGGBB` values can be copied unchanged (`drift` has this fast path). Otherwise convert
  with `fb.rgb`.
- There is only one buffer on the screen. There is no page flipping, so tearing is possible. Keep
  the copy short (one pass over the rows) and call `flush()` right after it. `flush` matters on
  VMware SVGA II: without it the window does not update.
- `beeb` compares each source line with the previous frame and skips unchanged lines. That helps
  for 2D content that changes little.
- Fill the whole screen with black after `acquire`, so the console text does not show around
  your image.

## Input

- Call `kbd_raw(true)` after you got the screen, `kbd_raw(false)` before you give it back.
- Read all pending events every frame with `while let Some(ev) = key_event()`.
- Keep a table of keys that are down, updated from `pressed`, and let the simulation read the
  table. Do not move things only when an event arrives.
- Map scancodes to your own action enum in one function (`map_key` in `apps/drift/src/main.rs`,
  `apps/beeb/src/keymap.rs`). The scancode table is in the liboos reference.
- Arrow keys arrive with `extended = true`. The same codes with `extended = false` are the keypad.
- Offer a quit key (Esc or F12). Ctrl+C always works, but it does not let you save or clean up.
- There is no mouse interface for ring 3. Games are keyboard only.

## Sound

- Open the stream after the screen, ignore an error and continue silently.
- Pick 48000 Hz stereo if you synthesize (`drift`), or mono if the source is mono (`beeb`).
  22050 Hz halves the work for simple effects; the kernel resamples.
- Each frame, look at `queued()`. If it is below your target (60 to 100 ms), generate the missing
  frames. Never generate "one frame's worth of time" unconditionally, or the buffer grows or
  drains when the frame rate varies. This is the whole pacing rule.
- `write` never blocks and may take fewer samples than you offer. Keep the rest for the next
  frame, as `feed_audio` does.
- If the game is far behind and the queue is already long (`beeb`: more than 100 ms), drop that
  frame's samples instead of growing the delay.
- A game that is paused should write silence or stop writing: the stream plays silence when it
  runs empty, and nothing else is needed.
- Latency from game event to sound is the queue plus about 60 ms in the device. Keep the queue
  small if the timing of effects matters.
- Call `drain()` before exit if the last sound should be heard.

## Memory

- The heap starts at 4 MiB and grows by whole regions of at least 8 MiB. A single allocation
  can be at most about 64 MiB. See [liboos reference](liboos.md#the-heap).
- Allocate big buffers once at start (`vec![0u32; W * H]`, textures, meshes) and reuse them. Do
  not allocate in the frame loop. Memory that you free stays in the process, and first-fit
  allocation of mixed sizes fragments the regions.
- Check that the memory exists before you commit to a size. `Vec::try_reserve_exact(n)` returns
  an error instead of aborting. `drift` does this to choose the interface size: it needs
  about 12 MiB plus `w * h * 4` bytes, tries the native size and falls back to 1/2, 1/3, 1/4.
- The VM needs the RAM for it. [drift](../drift.md) quotes about 32 MiB of heap for its 1080p
  default.
- The stack is 64 KiB. Large arrays belong on the heap.

## Performance of a software renderer

There is no GPU interface and no SIMD beyond SSE2 in generated code (the target is built with
`+sse,+sse2`). The following helped in `drift` and `beeb`:

- Render at a lower internal resolution and scale up. The cost of the screen copy is
  `fb.width * fb.height * 4` bytes per frame at 1:1 (8 MiB at 1080p).
- Measure each frame with `clock_ns`, keep a moving average, and lower the quality when it is
  too slow (`drift` drops one quality step when the average is above 38 ms). Do not change
  the saved setting for this.
- Use `f32` and integer math. Arithmetic works with SSE2, but `sin`, `cos`, `sqrt` and `powf` are
  not in `core`: write small approximations or tables (`drift-core` has its own).
- Keep inner loops free of bounds checks and function calls that cannot be inlined. Iterate over
  slices with `iter_mut().zip(...)`, work on whole rows, and use `fill` and `copy_from_slice`.
- The workspace builds with `opt-level = "s"` and LTO. If a core crate is slower than you want,
  try `[profile.release.package.<core-crate>] opt-level = 3` in `apps/Cargo.toml` and measure the
  size and the speed.
- Skip work that did not change: unchanged lines (`beeb`), a sky or a texture that is rendered
  once, a bloom pass at half size.
- Test the slow path: run in QEMU with `-accel tcg`. If it is playable there, it is fine
  everywhere.

## Saving and configuration

Files work as described in the liboos reference: absolute paths, no directory listing. `drift`
writes `drift-slotN.sav` and `drift.cfg` to `/home` and, if that fails, to `/tmp`, and tries the
same directories to read them. Use a fixed size for save files, because opening an existing file
for writing does not truncate it. Files reach the disk after about ten seconds. The program
should write when something important changes, not only at exit.
`beeb` reads `/etc/beeb.conf` for defaults.

Never put third-party game data in the repository. `beeb` asks the user for the MOS ROM and the
disc images; `drift` makes everything itself. See [Contributing](../../../CONTRIBUTIONS.md).
