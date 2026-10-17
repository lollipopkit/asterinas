// SPDX-License-Identifier: MPL-2.0

//! Device attribute tests.

use alloc::sync::Arc;

use device_id::{DeviceId, MajorId, MinorId};
use ostd::prelude::ktest;

use super::{
    toy::{self, ToyBlock, ToyBus, ToyDev, ToyDisk, ToyDiskDriver, ToyMatch},
    utils,
};
use crate::{
    bus::BusDevice,
    class::ClassDevice,
    common::{Attr, AttrGroup, DevNum, Error},
};

/// A driver's attributes come and go, and the published attribute set is rebuilt each time.
/// The attributes that survive must keep their IDs,
/// because sysfs derives an inode number from `(node id, attribute id)`:
/// renumbering them would give every file in a device's directory a new inode
/// whenever a driver bound beside it.
#[ktest]
fn attribute_ids_survive_bind_and_unbind() {
    let (class, bus) = toy::register_toy_subsystems();

    // 1. Add an unbound device and record its attribute IDs.
    // Vendor 9 matches no driver registered by another test.
    let dev = BusDevice::builder(
        &bus,
        "ids0",
        ToyDev {
            vendor: 9,
            model: 91,
        },
    )
    .build();
    crate::add_device(&dev).unwrap();
    let path = "/devices/ids0";
    let before = utils::attr_ids(path);
    assert!(!before.is_empty());
    assert!(before.iter().all(|(name, _)| name != "bound_by"));

    // 2. Register a matching driver and check that binding preserves existing IDs.
    let driver = bus
        .register_driver(Arc::new(ToyDiskDriver {
            match_data: ToyMatch { vendor: 9 },
            class: class.clone(),
        }))
        .unwrap();
    assert!(dev.driver().is_some());

    let bound = utils::attr_ids(path);
    for (name, id) in &before {
        assert_eq!(
            bound.iter().find(|(n, _)| n == name).map(|(_, i)| *i),
            Some(*id),
            "attribute `{}` was renumbered by a bind",
            name
        );
    }
    let bound_by_id = bound
        .iter()
        .find(|(n, _)| n == "bound_by")
        .map(|(_, i)| *i)
        .expect("the driver's attribute is present while it is bound");
    assert!(before.iter().all(|(_, id)| *id != bound_by_id));

    // 3. Unbind and check that the original attributes and IDs remain.
    bus.unbind(&dev).unwrap();
    assert_eq!(utils::attr_ids(path), before);

    // 4. Rebind and check that the driver attribute reuses its ID.
    bus.bind(&dev, &driver).unwrap();
    assert_eq!(
        utils::attr_ids(path)
            .iter()
            .find(|(n, _)| n == "bound_by")
            .map(|(_, i)| *i),
        Some(bound_by_id)
    );

    // 5. Unbind, remove the device, and unregister the driver.
    bus.unbind(&dev).unwrap();
    crate::remove_device(&dev).unwrap();
    bus.unregister_driver(&driver).unwrap();
}

/// Registration hands the core, subsystem, device type, and own attributes over as one batch,
/// so a layer that reuses a name the core already took must be rejected there.
/// Otherwise its callback would quietly replace the core's while sysfs went on showing the core's
/// entry.
#[ktest]
fn an_attribute_may_not_shadow_a_core_one() {
    // 1. Define an attribute that conflicts with the core device-number attribute.
    const SHADOWING: &[Attr<BusDevice<ToyBus>>] = &[Attr::ro("dev", |_dev, w| {
        writeln!(w, "not the core's device number")?;
        Ok(())
    })];

    // 2. Build a device that supplies both a device number and this attribute.
    let (_, bus) = toy::register_toy_subsystems();
    let dev = BusDevice::builder(
        &bus,
        "shadow0",
        ToyDev {
            vendor: 8,
            model: 1,
        },
    )
    .devnum(DevNum::char(DeviceId::new(
        MajorId::new(200),
        MinorId::new(1),
    )))
    .attrs(SHADOWING)
    .build();

    // 3. Check that registration fails and leaves no device directory behind.
    assert!(matches!(crate::add_device(&dev), Err(Error::NameConflict)));
    assert!(utils::lookup("/devices/shadow0").is_none());
}

#[ktest]
fn invalid_attribute_names_are_rejected() {
    // 1. Define one attribute for each invalid name.
    const INVALID_ATTRS: &[[Attr<ClassDevice<ToyBlock>>; 1]] = &[
        [Attr::ro("", |_dev, _w| Ok(()))],
        [Attr::ro(".", |_dev, _w| Ok(()))],
        [Attr::ro("..", |_dev, _w| Ok(()))],
        [Attr::ro("bad/name", |_dev, _w| Ok(()))],
        [Attr::ro("bad\0name", |_dev, _w| Ok(()))],
    ];
    let (class, _) = toy::register_toy_subsystems();

    // 2. Check that registration rejects each attribute and removes the directory.
    for attrs in INVALID_ATTRS {
        let dev = ClassDevice::builder(&class, "invalid-attr", ToyDisk { sectors: 8 })
            .attrs(attrs)
            .build();
        assert!(matches!(
            crate::add_device(&dev),
            Err(Error::SysTree(aster_systree::Error::InvalidName))
        ));
        assert!(utils::lookup("/devices/virtual/toyblk/invalid-attr").is_none());
        assert!(utils::lookup("/class/toyblk/invalid-attr").is_none());
    }
}

/// A named group is a subdirectory whose files reach the device,
/// and it dies with the device even while someone still holds the directory.
#[ktest]
fn named_groups_are_subdirectories() {
    // 1. Add a device with an unnamed and a named group.
    const GROUPS: &[AttrGroup<BusDevice<ToyBus>>] = &[
        AttrGroup::unnamed(&[Attr::ro("flat", |_dev, w| {
            writeln!(w, "flat")?;
            Ok(())
        })]),
        AttrGroup::named(
            "grp",
            &[Attr::ro("model_in_grp", |dev, w| {
                writeln!(w, "{}", dev.model)?;
                Ok(())
            })],
        ),
    ];
    let (_, bus) = toy::register_toy_subsystems();
    let dev = BusDevice::builder(
        &bus,
        "grp0",
        ToyDev {
            vendor: 10,
            model: 42,
        },
    )
    .groups(GROUPS)
    .build();
    crate::add_device(&dev).unwrap();

    // 2. Check where the files are and what they show.
    assert!(
        utils::attr_names("/devices/grp0")
            .iter()
            .any(|n| n == "flat")
    );
    assert!(
        !utils::attr_names("/devices/grp0")
            .iter()
            .any(|n| n == "model_in_grp")
    );
    assert_eq!(
        utils::read_attr("/devices/grp0/grp", "model_in_grp"),
        "42\n"
    );

    // 3. Remove the device and check that the held directory reports it as dead.
    let grp = utils::lookup("/devices/grp0/grp")
        .unwrap()
        .cast_to_node()
        .unwrap();
    crate::remove_device(&dev).unwrap();
    assert!(utils::lookup("/devices/grp0").is_none());
    assert!(matches!(
        grp.show_attr("model_in_grp"),
        Err(aster_systree::Error::IsDead)
    ));
}

/// A named group must have a valid name not already used in the device's directory,
/// and a failed registration leaves nothing behind.
#[ktest]
fn a_named_group_may_not_clash() {
    const CLASH_ATTR: &[AttrGroup<BusDevice<ToyBus>>] = &[AttrGroup::named("vendor", &[])];
    const CLASH_GROUP: &[AttrGroup<BusDevice<ToyBus>>] =
        &[AttrGroup::named("twin", &[]), AttrGroup::named("twin", &[])];
    const CLASH_LINK: &[AttrGroup<BusDevice<ToyBus>>] = &[AttrGroup::named("subsystem", &[])];
    const CLASH_IN_GROUP: &[AttrGroup<BusDevice<ToyBus>>] = &[AttrGroup::named(
        "dup",
        &[
            Attr::ro("same", |_dev, _w| Ok(())),
            Attr::ro("same", |_dev, _w| Ok(())),
        ],
    )];
    let (_, bus) = toy::register_toy_subsystems();

    for groups in [CLASH_ATTR, CLASH_GROUP, CLASH_LINK, CLASH_IN_GROUP] {
        let dev = BusDevice::builder(
            &bus,
            "clash0",
            ToyDev {
                vendor: 10,
                model: 1,
            },
        )
        .groups(groups)
        .build();
        assert!(matches!(crate::add_device(&dev), Err(Error::NameConflict)));
        assert!(utils::lookup("/devices/clash0").is_none());
        assert!(utils::lookup("/bus/toy/devices/clash0").is_none());
    }

    const INVALID_NAME: &[AttrGroup<BusDevice<ToyBus>>] = &[AttrGroup::named("bad/name", &[])];
    let dev = BusDevice::builder(
        &bus,
        "clash0",
        ToyDev {
            vendor: 10,
            model: 1,
        },
    )
    .groups(INVALID_NAME)
    .build();
    assert!(matches!(crate::add_device(&dev), Err(Error::InvalidName)));
    assert!(utils::lookup("/devices/clash0").is_none());
}
