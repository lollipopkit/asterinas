// SPDX-License-Identifier: MPL-2.0

use core::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use spin::Once;

use super::TIMER_FREQ;
use crate::arch::{read_tsc, tsc_freq};

/// Jiffies is a term used to denote the units of time measurement by the kernel.
///
/// A jiffy represents one tick of the system timer, whose frequency is equal to [`TIMER_FREQ`] Hz.
#[derive(Clone, Copy, Debug)]
pub struct Jiffies(u64);

static ELAPSED: AtomicU64 = AtomicU64::new(0);

/// The TSC value at the first timer interrupt, from which [`ELAPSED`] is counted.
static BASE_TSC: Once<u64> = Once::new();

/// Brings [`ELAPSED`] up to date from the TSC.
///
/// Timer interrupts can be delayed or lost (e.g., when a vCPU is not scheduled by the host), so
/// counting interrupts falls behind the real time. Like Linux, this derives the jiffies from the
/// clock source instead, which also catches up the missed ticks.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/time/tick-sched.c#L57-L150>
pub(super) fn update_elapsed() {
    let now = read_tsc();
    let base = *BASE_TSC.call_once(|| now);
    let freq = tsc_freq();
    if freq == 0 {
        return;
    }

    let elapsed = u128::from(now.saturating_sub(base)) * u128::from(TIMER_FREQ) / u128::from(freq);
    ELAPSED.fetch_max(elapsed as u64, Ordering::Relaxed);
}

impl Jiffies {
    /// The maximum value of [`Jiffies`].
    pub const MAX: Self = Self(u64::MAX);

    /// Creates a new instance.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the elapsed time since the system boots up.
    pub fn elapsed() -> Self {
        Self::new(ELAPSED.load(Ordering::Relaxed))
    }

    /// Gets the number of jiffies.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Adds the given number of jiffies, saturating at [`Jiffies::MAX`] on overflow.
    pub fn add(&mut self, jiffies: u64) {
        self.0 = self.0.saturating_add(jiffies);
    }

    /// Gets the [`Duration`] calculated from the jiffies counts.
    pub fn as_duration(self) -> Duration {
        let secs = self.0 / TIMER_FREQ;
        let nanos = ((self.0 % TIMER_FREQ) * 1_000_000_000) / TIMER_FREQ;
        Duration::new(secs, nanos as u32)
    }
}

impl From<Jiffies> for Duration {
    fn from(value: Jiffies) -> Self {
        value.as_duration()
    }
}
