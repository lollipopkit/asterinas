// SPDX-License-Identifier: MPL-2.0

//! Agent VM support.
//!
//! This component implements tool-call transactions (TCTs): `/dev/agent_ctl` lets an agent
//! shim inside the VM mark the boundaries of tool calls, and the effects of each tool call
//! are recorded through the audit hooks of the kernel.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[macro_use]
extern crate ostd_pod;

use component::{ComponentInitError, init_component};

mod device;
mod tct;

#[init_component(process)]
fn init() -> Result<(), ComponentInitError> {
    aster_core::security::audit::register_hooks(&tct::TctAuditHooks)
        .map_err(|_| ComponentInitError::Unknown)?;
    device::init().map_err(|_| ComponentInitError::Unknown)
}
