// SPDX-License-Identifier: MPL-2.0

//! Device-model tests, grouped by the behavior they verify.
//!
//! - `registry`: initialization.
//! - `registration`: device registration.
//! - `attributes`: device attributes and attribute groups.
//! - `observers`: class observers.
//! - `names`: device name validation.
//! - `system`: system buses and their root devices.
//!
//! `toy` and `utils` provide shared test helpers.

mod attributes;
mod names;
mod observers;
mod registration;
mod registry;
mod system;
mod toy;
mod utils;
