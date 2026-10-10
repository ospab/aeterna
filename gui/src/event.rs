// SPDX-License-Identifier: AGPL-3.0-only
//! Input events delivered to a window (coordinates are window-local).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// A printable key; the typed text arrives in `Event::KeyDown::text`.
    Char(char),
    Enter,
    Escape,
    Backspace,
    Delete,
    Tab,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    F(u8),
    /// Modifier keys themselves (also reflected in `Modifiers`).
    Shift,
    Ctrl,
    Alt,
    Meta,
    Other,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub meta: bool,
}

impl Modifiers {
    pub const NONE: Modifiers = Modifiers { shift: false, ctrl: false, alt: false, meta: false };
    pub const SHIFT: Modifiers = Modifiers { shift: true, ctrl: false, alt: false, meta: false };
    pub const CTRL: Modifiers = Modifiers { shift: false, ctrl: true, alt: false, meta: false };
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event {
    PointerMove { x: i32, y: i32 },
    PointerDown { x: i32, y: i32, button: MouseButton },
    PointerUp { x: i32, y: i32, button: MouseButton },
    /// Pointer left the window (hover state must be cleared).
    PointerLeave,
    /// Wheel: positive `dy` scrolls content up (towards the start).
    Wheel { x: i32, y: i32, dy: i32 },
    KeyDown { key: Key, mods: Modifiers, text: Option<char> },
    KeyUp { key: Key, mods: Modifiers },
    /// Window gained/lost keyboard focus.
    FocusIn,
    FocusOut,
}

impl Event {
    pub fn pos(&self) -> Option<(i32, i32)> {
        match *self {
            Event::PointerMove { x, y } | Event::PointerDown { x, y, .. } | Event::PointerUp { x, y, .. } | Event::Wheel { x, y, .. } => Some((x, y)),
            _ => None,
        }
    }

    /// The same event shifted by (dx, dy) (pointer events only).
    pub fn translated(&self, dx: i32, dy: i32) -> Event {
        match *self {
            Event::PointerMove { x, y } => Event::PointerMove { x: x + dx, y: y + dy },
            Event::PointerDown { x, y, button } => Event::PointerDown { x: x + dx, y: y + dy, button },
            Event::PointerUp { x, y, button } => Event::PointerUp { x: x + dx, y: y + dy, button },
            Event::Wheel { x, y, dy: w } => Event::Wheel { x: x + dx, y: y + dy, dy: w },
            e => e,
        }
    }
}

/// Pointer shape requested by the widget under the pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorShape {
    Arrow,
    Text,
    Hand,
    ResizeH,
    ResizeV,
    ResizeNwse,
    ResizeNesw,
    Move,
}
