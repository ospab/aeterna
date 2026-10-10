# Graphical session: architecture

The GUI is the crate `gui/` (`oos-ui`, `no_std` + `alloc`). Everything is drawn in software
into ARGB8888 surfaces. There is no GPU path. The kernel only copies finished pixels to the
framebuffer.

Start it with the `desktop` command, or boot with the kernel parameter `session=desktop`.
Log out (launcher menu) returns to the console.

## Layers

| Layer | Modules | Job |
|---|---|---|
| Pixels | `surface`, `canvas`, `blend`, `shadow`, `damage` | Surfaces, clipping, anti-aliased shapes, soft shadows, damage lists |
| Text | `text`, `fonts` | fontdue rasteriser, glyph cache, kerning, Inter + JetBrains Mono (bundled) |
| Design | `theme`, `icons` | Tokens (colours, radii, spacing, type scale, motion), vector icons |
| Widgets | `ui`, `menu` | Retained widget tree, layout, input, focus, per-widget damage |
| Application API | `app` | `Application`, `Ctx`, `WindowSpec`, dialogs, timers, clipboard, `Platform` |
| Window | `window` | Client-side window: surface, title bar, chrome buttons, protocol glue |
| Protocol | `proto` | Messages between apps and the window manager |
| Window manager | `desktop`, `session` | Compositor, stacking, focus, top bar, dock, launcher, Alt+Tab |

The split that matters: **apps use only `app` (plus the widget types it re-exports)**.
The window manager (`desktop`) and the session loop never appear in app code.

## Processes today

One kernel thread runs everything (`src/userspace/axon/desktop/`):

```
keyboard / mouse ──> Session::input ──> Desktop (WM) ──ToClient──> Bus
                                                                    │
                          AppHost (one per app) <───────────────────┘
                          Application::event / tick
                                   │ ToServer (Create, Damage, ...)
                                   v
                              Bus ──> Desktop::apply ──> composite ──> framebuffer
```

Per frame (`Session::frame`):

1. Device input goes to the window manager. It handles chrome, focus and shortcuts itself;
   everything else becomes `ToClient::Input` for the window under the pointer or the focused window.
2. Each `AppHost` takes the messages for its windows, lets the widget tree handle them and calls
   `Application::event` for what the tree did not consume.
3. Timers and `Application::tick` run; every window repaints its damaged rectangles and sends
   `ToServer::Damage`.
4. The window manager applies the requests, composites only the damaged screen rectangles and
   returns them; the kernel copies those rectangles to the framebuffer.

If nothing changed, the frame costs almost nothing and the loop executes `hlt`.

## Window-manager protocol (`gui/src/proto.rs`)

Client to server (`ToServer`):

| Message | Meaning |
|---|---|
| `Create { id, title, icon, size, min, resizable, surface }` | Map a window. The client allocates the surface and is its only writer |
| `SetTitle { id, title }` | New title |
| `Damage { id, rects }` | These rectangles (window coordinates) changed |
| `BeginMove { id }` | Start an interactive move (title-bar press) |
| `Minimize { id }`, `ToggleMaximize { id }` | Ask for a state change |
| `SetCursor { id, shape }` | Pointer shape over the client area |
| `Activate { id }` | Raise and focus |
| `Destroy { id }` | The window is gone |

Server to client (`ToClient`):

| Message | Meaning |
|---|---|
| `Configure { id, w, h }` | The server chose a new size. The client resizes its surface, lays out, sends a full `Damage` |
| `Input { id, ev }` | Pointer and key events in window coordinates (`Event`) |
| `Focus { id, focused }` | Keyboard focus changed |
| `CloseRequested { id }` | Close button, Alt+F4 or the dock asked to close |

Rules that hold for every transport:

* The client owns pixels. The server only reads them, and only the rectangles of the last
  `Damage` are guaranteed up to date.
* The server owns geometry: position, stacking, size, focus. A client may only ask.
* The title bar is drawn by the client (`window.rs`), so the look of a window never depends on
  the server. The server draws the shadow, the border-less compositing and the shell chrome.

The in-kernel transport is `proto::Bus` (two queues) and `SharedSurface` is
`Rc<RefCell<Surface>>`.

## Window manager

Implemented in `gui/src/desktop.rs`.

| Feature | Behaviour |
|---|---|
| Move | Drag the title bar. Double click zooms |
| Resize | Drag any edge or corner (cursor changes); minimum size from `WindowSpec` |
| Minimize / zoom / close | The three round controls on the left of the title bar |
| Focus and raise | Click, dock icon, or `Activate` |
| Alt+Tab | Switcher overlay; hold Alt, press Tab to cycle (Shift reverses), release to switch, Esc cancels |
| Alt+F4 | Sends `CloseRequested` to the focused window |
| Meta (Windows key) | Opens the launcher menu |
| Top bar | Launcher button, focused app name, network and OSTP state, volume, clock |
| Dock | One icon per pinned app; a dot marks a running app; click raises or launches |
| Redraw | Damage rectangles only: window moves and repaints add the old and new areas |

The clock uses the time zone from `/etc/timezone` (`UTC+3`, `UTC-5`, `UTC+5:30`).

## Frame cost

Software rendering with damage tracking. The session prints its timings on logout (and to the
serial port). Measured in QEMU TCG without KVM (a slow emulated CPU), 1280x800, five windows:

| Measure | Value |
|---|---|
| Session init (fonts, theme, compositor) | 209 ms |
| First frame | 97 ms |
| Full-screen recomposite | 28 ms |
| Average frame while using the desktop (487 frames) | 10.9 ms |
| Average repainted area | 127k px (12% of the screen) |

On the host (native, `gui/examples/mockups.rs`) the first frame takes 3.2 ms and a full
recomposite 1.7 ms. Expect real hardware to be close to the host numbers.

## Moving the compositor to ring 3

Nothing in `oos-ui` needs the kernel. The pieces that change:

| Today | In ring 3 |
|---|---|
| `Bus` queues | One IPC channel per client plus the server's listening channel (`user/liboos/src/ipc.rs`). Messages are serialised: they are small enums plus a rectangle list |
| `SharedSurface = Rc<RefCell<Surface>>` | A shared-memory region handle (`user/liboos/src/mem.rs`). The client maps it read-write, the server maps a read-only duplicate. `Create` carries the handle |
| `Session::pump` calls `AppHost` in turn | The server waits on its channels; each client process runs its own `AppHost` loop and blocks on its channel |
| `Platform` forwards to the VFS | `Platform` is implemented with liboos system calls (file I/O, spawn) |
| Keyboard and mouse read in the kernel loop | A ring-3 input driver (I/O ports and IRQ handles already exist) forwards events to the server |
| Framebuffer copy in `Fb::present` | The server maps the framebuffer as a memory region with the MMIO resource |

The client side is already separate: `AppHost` produces only `ToServer` messages and consumes
only `ToClient` messages. A ring-3 `AppHost` replaces the in-process `Bus` with a channel, and
nothing else in the app changes. `apps/hello-gui` builds for `x86_64-unknown-oos` today and runs
its app against an in-process session; it is the template for this move.

Open work: message encoding, the surface handle in `Create`, an input driver, and a client
library entry (`oos_ui::run(app)`) that connects to the server.

## Build and test

| Task | Command |
|---|---|
| Host check of the toolkit | `cargo check --manifest-path gui/Cargo.toml --features std --examples` (run from outside the repository root, or the kernel's `.cargo/config.toml` forces `build-std`) |
| Refresh PNG mockups | `cargo run --manifest-path gui/Cargo.toml --features std --example mockups` (writes `gui/mockups/*.png`) |
| Build for ring 3 | `cd apps && cargo +nightly build --release -p hello-gui` |
| Kernel with desktop | `./build.sh kernel` |

Mockups are rendered by the same session, window manager and widgets as the kernel desktop.
