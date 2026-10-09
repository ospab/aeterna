/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Scheduler trait definitions for AETERNA.
*/

/// Trait for pluggable scheduler implementations (future use)
pub trait SchedulerPolicy {
    /// Select next task to run
    fn select_next(&self) -> Option<u64>;
    /// Called on timer tick
    fn on_tick(&mut self);
}