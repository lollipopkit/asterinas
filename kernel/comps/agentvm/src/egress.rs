// SPDX-License-Identifier: MPL-2.0

//! Egress control based on the read sets of TCTs.
//!
//! The agent shim sets an [`EgressPolicy`] with protected paths and allowed targets. A TCT
//! becomes tainted when one of its processes reads (opens for reading or executes) a protected
//! file, or opens for reading a file that a tainted TCT has opened for writing. The processes of
//! a tainted TCT cannot connect or send to targets that are not allowed.
//!
//! Files written by tainted TCTs are tracked by their [`FileId`], so the taint follows renames
//! and links. The tracking is kept in memory, so it does not survive a reboot.

use alloc::{collections::BTreeSet, string::String, vec::Vec};

use aster_core::{prelude::*, security::audit::FileId};
use ostd::sync::Mutex;

/// The maximum number of files written by tainted TCTs that are tracked.
///
/// Further files make every file read taint the reading TCT, so a tool cannot exhaust kernel
/// memory or evade the tracking.
const MAX_NR_TAINTED_FILES: usize = 1 << 20;

/// The maximum length of an encoded policy.
pub(crate) const MAX_POLICY_LEN: usize = 1 << 20;

/// An egress policy.
#[derive(Debug)]
pub(crate) struct EgressPolicy {
    /// The absolute paths of the protected files and directories.
    protected: Vec<String>,
    /// The allowed targets, in the format of [`AuditEvent::Connect`] targets.
    ///
    /// An entry that ends with `*` allows the targets that start with the rest of it.
    ///
    /// [`AuditEvent::Connect`]: aster_core::security::audit::AuditEvent::Connect
    allowed: Vec<String>,
}

impl EgressPolicy {
    /// Parses a policy from entries that each end with a NUL byte. An entry is `p` followed by
    /// a protected absolute path, or `a` followed by an allowed target.
    pub(crate) fn parse(buf: &[u8]) -> Result<Self> {
        let invalid = || Error::with_message(Errno::EINVAL, "the egress policy is invalid");
        let Some(entries) = buf.strip_suffix(&[0]) else {
            return Err(invalid());
        };

        let mut policy = Self {
            protected: Vec::new(),
            allowed: Vec::new(),
        };
        for entry in entries.split(|&byte| byte == 0) {
            let (&tag, value) = entry.split_first().ok_or_else(invalid)?;
            let value = core::str::from_utf8(value).map_err(|_| invalid())?;
            match tag {
                b'p' if value.starts_with('/') => {
                    let path = value.trim_end_matches('/');
                    policy.protected.push(String::from(path));
                }
                b'a' if !value.is_empty() => policy.allowed.push(String::from(value)),
                _ => return Err(invalid()),
            }
        }
        Ok(policy)
    }

    fn protects(&self, path: &str) -> bool {
        self.protected.iter().any(|protected| {
            path.strip_prefix(protected.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    }

    fn allows(&self, target: &str) -> bool {
        self.allowed
            .iter()
            .any(|allowed| match allowed.strip_suffix('*') {
                Some(prefix) => target.starts_with(prefix),
                None => target == allowed,
            })
    }
}

#[derive(Debug, Default)]
struct EgressState {
    policy: Option<EgressPolicy>,
    /// The files that tainted TCTs have opened for writing.
    tainted_files: BTreeSet<FileId>,
    /// Whether more files have been opened for writing by tainted TCTs than are tracked.
    is_saturated: bool,
}

static EGRESS: Mutex<EgressState> = Mutex::new(EgressState {
    policy: None,
    tainted_files: BTreeSet::new(),
    is_saturated: false,
});

/// Sets the egress policy, or disables egress control if `policy` is `None`.
///
/// The files already tainted stay tainted.
pub(crate) fn set_policy(policy: Option<EgressPolicy>) {
    EGRESS.lock().policy = policy;
}

/// Returns whether reading `path` taints the reader.
pub(super) fn is_protected(path: &str) -> bool {
    EGRESS
        .lock()
        .policy
        .as_ref()
        .is_some_and(|policy| policy.protects(path))
}

/// Returns whether reading `file` taints the reader.
pub(super) fn is_tainted_file(file: FileId) -> bool {
    let state = EGRESS.lock();
    state.policy.is_some() && (state.is_saturated || state.tainted_files.contains(&file))
}

/// Records that a tainted TCT has opened `files` for writing.
pub(super) fn taint_files(files: impl IntoIterator<Item = FileId>, is_incomplete: bool) {
    let mut state = EGRESS.lock();
    if is_incomplete {
        state.is_saturated = true;
    }
    for file in files {
        if state.tainted_files.len() >= MAX_NR_TAINTED_FILES {
            state.is_saturated = true;
            return;
        }
        state.tainted_files.insert(file);
    }
}

/// Returns whether a tainted TCT may connect or send to `target`.
pub(super) fn allows(target: &str) -> bool {
    EGRESS
        .lock()
        .policy
        .as_ref()
        .is_none_or(|policy| policy.allows(target))
}
