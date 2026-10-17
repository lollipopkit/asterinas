// SPDX-License-Identifier: MPL-2.0

//! System bus tests.

use ostd::prelude::ktest;

use super::utils;
use crate::{
    bus::{self, Bus, BusDevice},
    common::{Attr, AttrGroup, BareDevice, Error},
};

/// A system bus whose devices carry an index.
struct ToySysBus;

impl Bus for ToySysBus {
    const NAME: &'static str = "toysys";
    type Device = u32;
    type MatchData = ();

    fn matches(&self, _dev: &u32, _data: &()) -> bool {
        false
    }

    fn dev_attrs(&self) -> &'static [Attr<BusDevice<Self>>] {
        &[]
    }
}

const ROOT_GROUPS: &[AttrGroup<BareDevice>] =
    &[AttrGroup::unnamed(&[Attr::ro("kind", |_dev, w| {
        writeln!(w, "toy")?;
        Ok(())
    })])];

#[ktest]
fn system_bus_has_a_root_device() {
    crate::init_for_ktest();

    // 1. Register the bus and check its root device.
    let bus = bus::register_system(ToySysBus, ROOT_GROUPS).unwrap();
    let root = bus.dev_root().unwrap().clone();
    assert_eq!(utils::read_attr("/devices/system/toysys", "kind"), "toy\n");
    assert!(utils::lookup("/bus/toysys/devices").is_some());
    // The root belongs to no subsystem, as in Linux.
    assert!(utils::lookup("/devices/system/toysys/subsystem").is_none());
    assert!(utils::lookup("/bus/toysys/devices/toysys").is_none());

    // 2. A device without a parent goes under the root device.
    let dev = BusDevice::builder(&bus, "toysys0", 0).build();
    crate::add_device(&dev).unwrap();
    assert_eq!(
        utils::link_target("/devices/system/toysys/toysys0/subsystem").unwrap(),
        "../../../../bus/toysys"
    );
    assert_eq!(
        utils::link_target("/bus/toysys/devices/toysys0").unwrap(),
        "../../../devices/system/toysys/toysys0"
    );
    assert!(matches!(
        crate::remove_device(&root),
        Err(Error::HasChildren)
    ));

    // 3. Remove the device; the root can then go too.
    crate::remove_device(&dev).unwrap();
    assert!(utils::lookup("/bus/toysys/devices/toysys0").is_none());
    crate::remove_device(&root).unwrap();
    assert!(utils::lookup("/devices/system/toysys").is_none());
}

/// Two buses with the same name; the second is registered as a system bus.
struct ClashBus;
struct ClashSysBus;

impl Bus for ClashBus {
    const NAME: &'static str = "toyclash";
    type Device = ();
    type MatchData = ();

    fn matches(&self, _dev: &(), _data: &()) -> bool {
        false
    }

    fn dev_attrs(&self) -> &'static [Attr<BusDevice<Self>>] {
        &[]
    }
}

impl Bus for ClashSysBus {
    const NAME: &'static str = "toyclash";
    type Device = ();
    type MatchData = ();

    fn matches(&self, _dev: &(), _data: &()) -> bool {
        false
    }

    fn dev_attrs(&self) -> &'static [Attr<BusDevice<Self>>] {
        &[]
    }
}

#[ktest]
fn failed_system_bus_drops_its_root() {
    crate::init_for_ktest();

    bus::register(ClashBus).unwrap();
    assert!(matches!(
        bus::register_system(ClashSysBus, &[]),
        Err(Error::NameConflict)
    ));
    assert!(utils::lookup("/devices/system/toyclash").is_none());
}
