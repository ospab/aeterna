# Writing a GUI application

An app depends on one crate, `oos-ui`, and uses its module `oos_ui::app`. It never touches the
window manager. The same code runs inside the kernel desktop today and as a ring-3 process
later (see [gui.md](gui.md)).

The template is `apps/hello-gui`. Copy it.

## Hello world

`apps/<name>/Cargo.toml`:

```toml
[package]
name = "myapp"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "myapp"
path = "src/lib.rs"

[[bin]]
name = "myapp"
path = "src/main.rs"
required-features = ["ring3"]

[features]
default = ["ring3"]
ring3 = ["dep:liboos"]        # the kernel desktop uses the library only

[dependencies]
oos-ui = { path = "../../gui" }
liboos = { path = "../../user/liboos", optional = true }
```

`src/lib.rs`:

```rust
#![no_std]
extern crate alloc;
use oos_ui::app::prelude::*;

#[derive(Default)]
pub struct Hello { label: NodeId, button: NodeId, clicks: u32 }

impl Application for Hello {
    fn info(&self) -> AppInfo { AppInfo::new("org.example.hello", "Hello", Icon::Info) }

    fn start(&mut self, cx: &mut Ctx, _arg: Option<&str>) {
        let mut ui = Ui::new(Axis::Column, cx.theme().color.bg1);
        let root = ui.root();
        ui.padding(root, Insets::new(24, 20, 24, 20));
        ui.gap(root, 12);
        self.label = ui.label(root, "Hello, ospab.os", TextRole::Headline);
        self.button = ui.button(root, "Click me", ButtonKind::Primary);
        cx.open_window(WindowSpec::new("Hello", 360, 200), ui);
    }

    fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent) {
        match ev {
            AppEvent::Action(Action::Clicked(n)) if *n == self.button => {
                self.clicks += 1;
                let text = alloc::format!("Clicked {} times", self.clicks);
                if let Some(ui) = cx.ui(win) { ui.set_text(self.label, &text); }
            }
            AppEvent::CloseRequested => cx.close_window(win),
            _ => {}
        }
    }
}
```

`src/main.rs` (ring-3 program): copy `apps/hello-gui/src/main.rs` and change the app type.

## Application lifecycle

| Call | When |
|---|---|
| `info()` | Once, before anything else. Returns `AppInfo { id, name, icon, version }` |
| `start(cx, arg)` | Once. Open the first window. `arg` is the launch argument (a path, for example) |
| `event(cx, win, ev)` | For every `AppEvent` of any window of the app. `win` is 0 for timers |
| `tick(cx)` | Once per frame, before painting. Keep it cheap; use timers for periodic work |

The app ends when its last window is closed or when it calls `cx.quit()`. The app should
close its windows on `AppEvent::CloseRequested`. If it does not, the close button does nothing,
which is how an app asks the user "discard changes?" first.

`AppInfo::id` is a unique reverse-DNS string. The launcher, the dock and `Platform::launch` use it.

## Windows

```rust
let win = cx.open_window(
    WindowSpec::new("Title", 640, 400)   // client size including the title bar
        .min_size(320, 200)              // default minimum is 240 x 160
        .icon(Icon::Folder),             // default: the app icon
    ui);
```

| Method | Purpose |
|---|---|
| `WindowSpec::fixed()` | Not resizable (minimum = size) |
| `cx.set_title(win, "...")` | Change the title |
| `cx.window_size(win)` | Current size |
| `cx.activate(win)` | Raise and focus |
| `cx.close_window(win)` | Close it |
| `cx.ui(win)` | The widget tree of the window, `None` once closed |

A window has a 38 px title bar drawn by the toolkit; your widget tree fills the rest.
When the user resizes the window you receive `AppEvent::Resized(w, h)`; the tree is laid out again
automatically.

## Widgets and layout

Build the tree with a `Ui`. Every builder method takes the parent `NodeId` and returns the new
`NodeId`. Keep the ids you need later in your struct.

| Builder | Widget |
|---|---|
| `row`, `column`, `stack`, `grid(cols)`, `container(parent, axis, BoxStyle)` | Layout containers. `stack` overlaps children; `grid` has equal columns |
| `label`, `label_colored`, `paragraph` | Text. `paragraph` wraps |
| `button(label, ButtonKind)`, `icon_button(icon)` | Buttons. Kinds: `Primary`, `Secondary`, `Danger`, `Ghost` |
| `text_field(text, placeholder)` | Single line input with selection and clipboard |
| `checkbox`, `toggle`, `slider(0..=1000)` | Boolean and value inputs |
| `list(columns, header, items, row_h)` | Table with selection, scrolling and optional header |
| `tabs(&labels, selected)` | Segmented tab bar |
| `editor(text)` | Multi-line monospace editor with line numbers |
| `terminal(lines)` | Coloured monospace screen with scrollback |
| `progress(value)`, `icon`, `separator`, `spacer` | Misc |

Layout properties (set on any node):

| Method | Meaning |
|---|---|
| `width(id, Length)`, `height`, `size(id, w, h)` | `Length::Hug` (content), `Px(n)`, `Fill(weight)` (share of free space) |
| `padding(id, Insets)` | Inside space. `Insets::new(l, t, r, b)`, `Insets::xy(x, y)` |
| `gap(id, px)` | Space between children |
| `align(id, main, cross)` | `Align::Start`, `Center`, `End`, `Stretch`, `SpaceBetween` (main axis only) |

Example: a toolbar with a field that takes the free width.

```rust
let bar = ui.row(root);
ui.padding(bar, Insets::xy(10, 8));
ui.gap(bar, 8);
ui.align(bar, Align::Start, Align::Center);
let field = ui.text_field(bar, "", "Search");
ui.width(field, Length::Fill(1));
ui.button(bar, "Go", ButtonKind::Primary);
```

Read and change state with `ui.text(id)`, `set_text`, `checked`, `set_checked`, `selected`,
`set_selected`, `list_items_mut`, `slider_value`, `set_slider`, `set_enabled`, `set_visible`,
`set_focus`, `editor_text`, `terminal_mut`. The tree repaints only what changed.

## Events

`AppEvent` variants:

| Variant | Meaning |
|---|---|
| `Action(Action)` | A widget did something (below) |
| `Key(Event)` | A key press no widget consumed: shortcuts, terminals |
| `CloseRequested` | Close button, Alt+F4 or the dock |
| `Resized(w, h)` | The window changed size |
| `Focus(bool)` | The window gained or lost keyboard focus |
| `Timer(id)` | A timer fired |
| `Dialog(id, DialogResult)` | A dialog opened by this app closed |

`Action` variants: `Clicked(node)`, `Toggled(node, on)`, `TextChanged(node)`, `Submitted(node)`
(Enter in a text field), `Selected(node, row_or_tab)`, `Activated(node, row)` (double click or
Enter on a list row), `MenuChosen(owner, index)`, `ValueChanged(node, 0..=1000)`.

Match on the node id you stored: `Action::Clicked(n) if *n == self.button`.

Keyboard shortcuts: handle `AppEvent::Key(Event::KeyDown { key, mods, .. })`:

```rust
AppEvent::Key(Event::KeyDown { key: Key::Char('s'), mods, .. }) if mods.ctrl => self.save(cx),
```

Ctrl+letter arrives as the lowercase letter with `mods.ctrl` set.

## Timers, dialogs, menus, clipboard

```rust
let t = cx.set_timer(1000, true);   // every second; AppEvent::Timer(t)
cx.cancel_timer(t);
```

Dialogs are modal-looking windows owned by a parent window. Each call returns a `DialogId`; the
result arrives as `AppEvent::Dialog(id, result)` with `DialogResult::Ok`, `Cancel` or `Path(p)`.

| Call | Result |
|---|---|
| `cx.alert(win, title, message)` | `Ok` |
| `cx.confirm(win, title, message, "Delete", destructive)` | `Ok` or `Cancel` |
| `cx.open_file(win, start_dir)` | `Path(..)` or `Cancel`; needs `Platform::list_dir` |

Popup menu: `cx.open_menu(win, owner_node, anchor_rect, vec![MenuItem::new("Copy").shortcut("Ctrl+C")])`;
the choice arrives as `Action::MenuChosen(owner, index)`.

Clipboard: `oos_ui::app::clipboard_get()` and `clipboard_set(&str)`, or `cx.clipboard()` /
`cx.set_clipboard()`. Text fields and the editor use it for Ctrl+C, Ctrl+X, Ctrl+V.

## Theme

Never hard-code colours. `cx.theme()` returns the design tokens:

| Token group | Examples |
|---|---|
| `theme.color` | `bg0`, `bg1`, `surface`, `elevated`, `field`, `hairline`, `text`, `text_secondary`, `text_disabled`, `accent`, `accent_text`, `danger`, `success`, `warning` |
| `theme.radius` | `sm`, `md`, `lg`, `window` |
| `theme.spacing` | `xxs` ... `xxl` |
| `theme.text` | type scale: `caption`, `body`, `body_strong`, `title`, `headline`, `mono` |

Style: near-black surfaces separated by small lightness steps and 1 px hairlines, one blue
accent, no gradients. Use `TextRole` for text instead of picking fonts.

## System services: `Platform`

`cx.platform()` gives file and launcher access. The host implements it (the kernel VFS now,
liboos system calls in ring 3). Every method has a safe default (`None` / `false`).

| Method | Purpose |
|---|---|
| `list_dir(path) -> Option<Vec<DirItem>>` | Directory listing |
| `read_file(path)`, `write_file(path, data)` | Whole-file I/O |
| `mkdir`, `remove`, `rename` | Namespace changes |
| `launch(app_id, arg)` | Start another app by id (for example `"org.ospab.editor"`) |
| `uptime_ms()` | Milliseconds since boot |

## Run it

In the kernel desktop (built-in apps): add the app crate as a dependency in the root `Cargo.toml`
(`default-features = false`), add a case to `AppKind` in `src/userspace/axon/desktop/mod.rs`,
and rebuild. Hello GUI is already in the launcher.

As a ring-3 package:

```
bash apps/build.sh                 # builds apps/target/x86_64-unknown-oos/release/myapp
```

Add `apps/pkg/myapp.toml`:

```toml
name = "myapp"
version = "0.1.0"
description = "What it does"
arch = "x86_64"
depends = []

[[files]]
src = "../target/x86_64-unknown-oos/release/myapp"
dest = "/usr/bin/myapp"
```

`apps/build.sh` packs it into `apps/dist/myapp.tmt`; install it with `tomato -U dist/myapp.tmt`.
Limit today: a ring-3 GUI program runs against an in-process session (it renders into memory)
because the compositor has no IPC front end yet. The app code is the same; only the host changes.
See [gui.md](gui.md#moving-the-compositor-to-ring-3).

## Checklist

* `#![no_std]`, `extern crate alloc;`, no kernel types.
* Every window handles `CloseRequested`.
* Store `NodeId`s; do not rebuild the tree to change text.
* Use theme tokens and `TextRole`.
* Keep `tick` cheap; use timers.
* Use `Platform` for files; handle `None` and `false`.
