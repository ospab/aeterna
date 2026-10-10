// SPDX-License-Identifier: AGPL-3.0-only
//! Window-system protocol: messages between applications (clients) and the
//! compositor / window manager (server).
//!
//! Today both sides run in the kernel and exchange messages through the
//! in-memory [`Bus`]; surfaces are shared as reference-counted buffers.  When
//! the compositor moves to ring 3, the same enums are serialised over IPC
//! channels and [`SharedSurface`] becomes a shared-memory capability mapped
//! into both address spaces — the client and server logic does not change.
//!
//! Ownership rules (they hold for the IPC version too):
//! * the client allocates its surface and is the only writer;
//! * the server only reads a surface, and only the rectangles announced by
//!   the last `Damage` message are guaranteed to be up to date;
//! * the server owns window geometry: position, stacking, size changes
//!   (`Configure`) and focus.  A client may *ask* to move/resize/maximise.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::event::{CursorShape, Event};
use crate::geom::Rect;
use crate::icons::Icon;
use crate::surface::Surface;

/// Window id, unique per boot (see [`alloc_id`]).
pub type WinId = u32;

static NEXT_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// Allocate a window id. (Ring-3 future: the server assigns ids on Create.)
pub fn alloc_id() -> WinId { NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed) }

/// A client surface the server may read.  In-kernel: a shared heap buffer.
/// Ring-3 future: a shared-memory object handle.
pub type SharedSurface = Rc<RefCell<Surface>>;

pub fn new_surface(w: i32, h: i32) -> SharedSurface { Rc::new(RefCell::new(Surface::new(w, h))) }

/// Client -> server.
#[derive(Clone)]
pub enum ToServer {
    /// Map a new window. `size` is the requested size, `min` the minimum.
    Create { id: WinId, title: String, icon: Icon, size: (i32, i32), min: (i32, i32), resizable: bool, surface: SharedSurface },
    SetTitle { id: WinId, title: String },
    /// These rectangles (window coordinates) of the surface changed.
    Damage { id: WinId, rects: Vec<Rect> },
    /// Start an interactive move with the pointer (title bar press).
    BeginMove { id: WinId },
    Minimize { id: WinId },
    ToggleMaximize { id: WinId },
    /// Pointer shape while over this window's client area.
    SetCursor { id: WinId, shape: CursorShape },
    /// The window is gone (after a close request or on its own).
    Destroy { id: WinId },
    /// Ask to be raised and focused.
    Activate { id: WinId },
}

/// Server -> client.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ToClient {
    /// New size chosen by the server; the client must resize its surface,
    /// re-layout and send a full `Damage`.
    Configure { id: WinId, w: i32, h: i32 },
    /// Input in window coordinates.
    Input { id: WinId, ev: Event },
    Focus { id: WinId, focused: bool },
    /// The user asked to close the window (dock menu, Alt+F4).
    CloseRequested { id: WinId },
}

impl ToServer {
    pub fn id(&self) -> WinId {
        match self {
            ToServer::Create { id, .. } | ToServer::SetTitle { id, .. } | ToServer::Damage { id, .. }
            | ToServer::BeginMove { id } | ToServer::Minimize { id } | ToServer::ToggleMaximize { id }
            | ToServer::SetCursor { id, .. } | ToServer::Destroy { id } | ToServer::Activate { id } => *id,
        }
    }
}

impl ToClient {
    pub fn id(&self) -> WinId {
        match self {
            ToClient::Configure { id, .. } | ToClient::Input { id, .. } | ToClient::Focus { id, .. } | ToClient::CloseRequested { id } => *id,
        }
    }
}

/// In-kernel transport: two queues.  The IPC version replaces this with a
/// channel per client plus notifications.
#[derive(Default)]
pub struct Bus {
    pub to_server: VecDeque<ToServer>,
    pub to_client: VecDeque<ToClient>,
}

impl Bus {
    pub fn new() -> Bus { Bus { to_server: VecDeque::new(), to_client: VecDeque::new() } }

    /// Take all client-bound messages for window `id`, keeping the rest.
    pub fn take_for(&mut self, id: WinId) -> Vec<ToClient> {
        let mut out = Vec::new();
        let mut keep = VecDeque::with_capacity(self.to_client.len());
        while let Some(m) = self.to_client.pop_front() {
            if m.id() == id { out.push(m); } else { keep.push_back(m); }
        }
        self.to_client = keep;
        out
    }
}
