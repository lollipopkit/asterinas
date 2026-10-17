// SPDX-License-Identifier: MPL-2.0

//! Devices with neither bus nor class.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use super::{AnyDevice, DevNode, DeviceBase, DeviceInternals, impl_device_node};
use crate::common::{
    Subsystem, SysStr,
    group::{AttrGroup, TyErasedAttrGroup},
    node::Dir,
    registry,
};

/// A device with neither bus nor class, such as a host bridge or a firmware root.
///
/// It is listed in no index; it exists to be the parent of other devices.
/// It has no attributes, except for the root device of a system bus,
/// which carries the bus-wide attributes.
pub struct BareDevice {
    base: DeviceBase,
    groups: &'static [AttrGroup<BareDevice>],
}

impl BareDevice {
    /// Creates a bare device at the top of `/sys/devices`.
    ///
    /// It is not registered until [`add_device`] is called.
    ///
    /// # Panics
    ///
    /// Panics if `name` is not a valid `SysTree` node name.
    ///
    /// [`add_device`]: crate::add_device
    pub fn new_root(name: impl Into<SysStr>) -> Arc<Self> {
        Self::new(name.into(), None, &[], None)
    }

    /// Same as [`Self::new_root`], except the device is created under `parent`.
    pub fn with_parent(name: impl Into<SysStr>, parent: Arc<dyn AnyDevice>) -> Arc<Self> {
        Self::new(name.into(), Some(parent), &[], None)
    }

    /// Creates the root device of a system bus, `/sys/devices/system/<name>`,
    /// carrying the bus-wide attribute groups.
    ///
    /// # Panics
    ///
    /// Panics if the device model is not initialized or `name` is not a valid `SysTree` node name.
    pub(crate) fn new_system_root(
        name: &'static str,
        groups: &'static [AttrGroup<BareDevice>],
    ) -> Arc<Self> {
        let system_root = registry::get().system_root().clone();
        Self::new(SysStr::from(name), None, groups, Some(system_root))
    }

    fn new(
        name: SysStr,
        parent: Option<Arc<dyn AnyDevice>>,
        groups: &'static [AttrGroup<BareDevice>],
        root_dir: Option<Arc<Dir>>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak: &Weak<BareDevice>| {
            let weak_self: Weak<dyn AnyDevice> = weak.clone();
            let mut base = DeviceBase::new(name, parent, None, weak_self);
            if let Some(dir) = root_dir {
                base = base.with_root_dir(dir);
            }
            BareDevice { base, groups }
        })
    }
}

impl AnyDevice for BareDevice {
    fn subsystem(&self) -> Subsystem {
        Subsystem::bare()
    }
}

impl DeviceInternals for BareDevice {
    fn base(&self) -> &DeviceBase {
        &self.base
    }

    fn type_name(&self) -> Option<&'static str> {
        None
    }

    fn attr_groups(&self) -> Vec<TyErasedAttrGroup> {
        self.groups
            .iter()
            .map(TyErasedAttrGroup::from_typed)
            .collect()
    }

    fn devnode_override(&self) -> Option<DevNode> {
        None
    }
}

impl core::fmt::Debug for BareDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BareDevice")
            .field("base", &self.base)
            .finish()
    }
}

impl_device_node!(BareDevice);
