// SPDX-License-Identifier: AGPL-3.0-only
//! hello-gui — the template for ospab.os GUI applications.
//!
//! Everything here uses only the public application API of `oos-ui`
//! (`oos_ui::app`).  The same `HelloGui` runs inside the kernel desktop
//! session today and as a ring-3 process once the compositor is a server.
#![no_std]

extern crate alloc;

use alloc::format;

use oos_ui::app::{Action, AppEvent, AppInfo, Application, Ctx, DialogResult, WindowSpec};
use oos_ui::geom::Insets;
use oos_ui::icons::Icon;
use oos_ui::proto::WinId;
use oos_ui::ui::{Align, Axis, ButtonKind, Length, NodeId, TextRole, Ui};

pub struct HelloGui {
    count: u32,
    counter: NodeId,
    name: NodeId,
    greeting: NodeId,
    inc: NodeId,
    reset: NodeId,
    tick_label: NodeId,
    win: WinId,
    seconds: u32,
}

impl Default for HelloGui {
    fn default() -> Self {
        HelloGui { count: 0, counter: 0, name: 0, greeting: 0, inc: 0, reset: 0, tick_label: 0, win: 0, seconds: 0 }
    }
}

impl Application for HelloGui {
    fn info(&self) -> AppInfo { AppInfo::new("org.ospab.hello-gui", "Hello GUI", Icon::Info) }

    fn start(&mut self, cx: &mut Ctx, _arg: Option<&str>) {
        // 1. Build the widget tree: a column with padding and a gap.
        let mut ui = Ui::new(Axis::Column, cx.theme().color.bg1);
        let root = ui.root();
        ui.padding(root, Insets::new(24, 20, 24, 20));
        ui.gap(root, 12);

        ui.label(root, "Hello, ospab.os", TextRole::Headline);
        self.greeting = ui.label(root, "Type a name below.", TextRole::Secondary);

        // 2. A row: text field (takes the free width) + button.
        let row = ui.row(root);
        ui.gap(row, 8);
        ui.align(row, Align::Start, Align::Center);
        self.name = ui.text_field(row, "", "Your name");
        ui.width(self.name, Length::Fill(1));
        self.inc = ui.button(row, "Count", ButtonKind::Primary);

        self.counter = ui.label(root, "Clicks: 0", TextRole::Title);
        self.tick_label = ui.label(root, "Running for 0 s", TextRole::Caption);

        ui.spacer(root);
        let bottom = ui.row(root);
        ui.align(bottom, Align::End, Align::Center);
        ui.gap(bottom, 8);
        self.reset = ui.button(bottom, "Reset…", ButtonKind::Secondary);

        ui.set_focus(Some(self.name));

        // 3. Open the window; keep its id to address it later.
        self.win = cx.open_window(WindowSpec::new("Hello GUI", 420, 300).min_size(320, 240), ui);

        // 4. A repeating timer: AppEvent::Timer arrives once a second.
        cx.set_timer(1000, true);
    }

    fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent) {
        match ev {
            AppEvent::Action(Action::Clicked(n)) if *n == self.inc => {
                self.count += 1;
                let text = format!("Clicks: {}", self.count);
                if let Some(ui) = cx.ui(win) { ui.set_text(self.counter, &text); }
            }
            AppEvent::Action(Action::Clicked(n)) if *n == self.reset => {
                cx.confirm(win, "Reset counter?", "The click counter goes back to zero.", "Reset", true);
            }
            AppEvent::Action(Action::TextChanged(n)) if *n == self.name => {
                if let Some(ui) = cx.ui(win) {
                    let name = ui.text(self.name).trim();
                    let msg = if name.is_empty() { format!("Type a name below.") } else { format!("Nice to meet you, {}.", name) };
                    ui.set_text(self.greeting, &msg);
                }
            }
            AppEvent::Dialog(_, DialogResult::Ok) => {
                self.count = 0;
                if let Some(ui) = cx.ui(self.win) { ui.set_text(self.counter, "Clicks: 0"); }
            }
            AppEvent::Timer(_) => {
                self.seconds += 1;
                let text = format!("Running for {} s", self.seconds);
                if let Some(ui) = cx.ui(self.win) { ui.set_text(self.tick_label, &text); }
            }
            AppEvent::CloseRequested => cx.close_window(win),
            _ => {}
        }
    }
}
