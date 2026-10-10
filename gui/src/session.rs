// SPDX-License-Identifier: AGPL-3.0-only
//! The session loop: compositor + message bus + applications.
//!
//! Every frame: device input goes to the compositor, which turns it into
//! `ToClient` messages; each application drains the messages for its windows,
//! updates, ticks and renders, which produces `ToServer` messages (Damage,
//! Create, Destroy...); the compositor applies them and composites.
//!
//! Applications here are plain Rust objects called in turn (cooperative,
//! single thread).  With ring-3 clients the loop body stays the same on the
//! server side; the "call the app" step becomes "deliver over its channel".

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::desktop::Desktop;
use crate::event::Event;
use crate::geom::Rect;
use crate::proto::{Bus, ToServer};
use crate::text::TextEngine;
use crate::theme::Theme;
use crate::window::{Client, Cx};

pub struct Session {
    pub desktop: Desktop,
    pub bus: Bus,
    pub apps: Vec<Box<dyn Client>>,
}

impl Session {
    pub fn new(width: i32, height: i32) -> Session {
        Session { desktop: Desktop::new(width, height), bus: Bus::new(), apps: Vec::new() }
    }

    /// Queue the requests an app produced while being constructed.
    pub fn add_app(&mut self, app: Box<dyn Client>, created: VecDeque<ToServer>) {
        self.bus.to_server.extend(created);
        self.apps.push(app);
    }

    pub fn input(&mut self, ev: &Event, text: &mut TextEngine, theme: &Theme) {
        self.desktop.handle(ev, &mut self.bus, text, theme);
    }

    /// Deliver messages, update, tick and render every application.
    pub fn pump(&mut self, now: u64, text: &mut TextEngine, theme: &Theme) {
        for _round in 0..3 {
            self.desktop.apply(&mut self.bus, theme);
            let mut out = VecDeque::new();
            let mut any = false;
            for app in self.apps.iter_mut() {
                for id in app.window_ids() {
                    let msgs = self.bus.take_for(id);
                    if msgs.is_empty() { continue; }
                    any = true;
                    let mut cx = Cx { text, theme, out: &mut out, now };
                    let mut evs = Vec::new();
                    if let Some(w) = app.window_mut(id) {
                        for m in &msgs { evs.extend(w.handle(m, &mut cx)); }
                    }
                    if !evs.is_empty() { app.update(id, &evs, &mut cx); }
                }
            }
            self.bus.to_server.extend(out);
            if !any && self.bus.to_server.is_empty() { break; }
        }
        // Messages for windows nobody owns any more.
        self.bus.to_client.clear();
        let mut out = VecDeque::new();
        for app in self.apps.iter_mut() {
            let mut cx = Cx { text, theme, out: &mut out, now };
            app.tick(&mut cx);
            for id in app.window_ids() {
                if let Some(w) = app.window_mut(id) {
                    w.tick(now, theme);
                    w.render(cx.text, theme, cx.out);
                }
            }
        }
        self.bus.to_server.extend(out);
        self.desktop.apply(&mut self.bus, theme);
        self.apps.retain(|a| a.alive());
    }

    /// Pump and composite. Returns the screen rectangles to present.
    pub fn frame(&mut self, now: u64, text: &mut TextEngine, theme: &Theme) -> Vec<Rect> {
        self.pump(now, text, theme);
        self.desktop.render(text, theme)
    }
}
