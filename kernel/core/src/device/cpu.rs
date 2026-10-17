// SPDX-License-Identifier: MPL-2.0

//! CPU devices: `/sys/devices/system/cpu`.
//!
//! The `cpu` system bus has a root device carrying the system-wide CPU sets,
//! such as `online` and `possible`, and one device `cpuN` per CPU
//! with a `topology` group describing where the CPU sits.
//!
//! OSTD brings up every CPU before the kernel starts, and CPUs cannot go offline,
//! so every CPU is possible, present, enabled, and online.
//!
//! Reference: <https://elixir.bootlin.com/linux/v7.2/source/drivers/base/cpu.c>
//! and <https://elixir.bootlin.com/linux/v7.2/source/drivers/base/topology.c>.

use core::fmt::Write;

use aster_device::{
    bus::{self, Bus, BusDevice},
    common::{Attr, AttrGroup, BareDevice, Result},
};
use ostd::{
    cpu::{CpuId, CpuSet, all_cpus, num_cpus},
    util::id_set::Id,
};

use crate::cpu::{
    cpumask::{write_cpu_list, write_cpu_mask},
    topology,
};

pub(super) fn init_in_first_kthread() {
    topology::wait_all();

    let bus = bus::register_system(CpuBus, ROOT_GROUPS).unwrap();
    for cpu in all_cpus() {
        let name = alloc::format!("cpu{}", cpu.as_usize());
        let dev = BusDevice::builder(&bus, name, cpu)
            .groups(CPU_GROUPS)
            .build();
        // The bus keeps the device alive.
        aster_device::add_device(&dev).unwrap();
    }
}

/// The `cpu` bus, whose devices are the CPUs.
struct CpuBus;

impl Bus for CpuBus {
    const NAME: &'static str = "cpu";
    type Device = CpuId;
    type MatchData = ();

    fn matches(&self, _dev: &CpuId, _data: &()) -> bool {
        // No driver binds to a CPU.
        false
    }

    fn dev_attrs(&self) -> &'static [Attr<BusDevice<Self>>] {
        &[]
    }
}

type CpuDevice = BusDevice<CpuBus>;

// Reference: <https://elixir.bootlin.com/linux/v7.2/source/drivers/base/cpu.c#L208-L314>.
const ROOT_GROUPS: &[AttrGroup<BareDevice>] = &[AttrGroup::unnamed(&[
    Attr::ro("online", show_all_cpus),
    Attr::ro("possible", show_all_cpus),
    Attr::ro("present", show_all_cpus),
    Attr::ro("kernel_max", |_, w| {
        // Asterinas has no compile-time CPU limit, so the highest CPU ID is the limit.
        writeln!(w, "{}", num_cpus() - 1)?;
        Ok(())
    }),
    // No CPU is offline.
    Attr::ro("offline", show_no_cpus),
    Attr::ro("enabled", show_all_cpus),
    // No CPU is isolated from the scheduler.
    Attr::ro("isolated", show_no_cpus),
    // CPU isolation (`nohz_full=` and `isolcpus=`) is not supported, so housekeeping is disabled.
    Attr::ro("housekeeping", show_no_cpus),
])];

fn show_all_cpus(_root: &BareDevice, w: &mut dyn Write) -> Result<()> {
    write_cpu_list(w, all_cpus().map(u32::from))?;
    writeln!(w)?;
    Ok(())
}

fn show_no_cpus(_root: &BareDevice, w: &mut dyn Write) -> Result<()> {
    writeln!(w)?;
    Ok(())
}

const CPU_GROUPS: &[AttrGroup<CpuDevice>] = &[AttrGroup::named("topology", TOPOLOGY_ATTRS)];

/// The `topology` group.
///
/// The files depend on the architecture, as in Linux:
/// only x86 has dies, and LoongArch has no clusters.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2/source/drivers/base/topology.c#L59-L185>
/// and <https://elixir.bootlin.com/linux/v7.2/source/include/linux/topology.h#L180-L230>.
const TOPOLOGY_ATTRS: &[Attr<CpuDevice>] = &[
    Attr::ro("physical_package_id", |dev, w| {
        show_id(w, topology::get(cpu_of(dev)).package_id)
    }),
    #[cfg(target_arch = "x86_64")]
    Attr::ro("die_id", |dev, w| {
        show_id(w, topology::get(cpu_of(dev)).die_id)
    }),
    #[cfg(not(target_arch = "loongarch64"))]
    Attr::ro("cluster_id", show_cluster_id),
    Attr::ro("core_id", |dev, w| {
        show_id(w, topology::get(cpu_of(dev)).core_id)
    }),
    Attr::ro("core_cpus", |dev, w| {
        show_mask(w, topology::thread_siblings(cpu_of(dev)))
    }),
    Attr::ro("core_cpus_list", |dev, w| {
        show_list(w, topology::thread_siblings(cpu_of(dev)))
    }),
    Attr::ro("thread_siblings", |dev, w| {
        show_mask(w, topology::thread_siblings(cpu_of(dev)))
    }),
    Attr::ro("thread_siblings_list", |dev, w| {
        show_list(w, topology::thread_siblings(cpu_of(dev)))
    }),
    Attr::ro("core_siblings", |dev, w| {
        show_mask(w, topology::package_cpus(cpu_of(dev)))
    }),
    Attr::ro("core_siblings_list", |dev, w| {
        show_list(w, topology::package_cpus(cpu_of(dev)))
    }),
    #[cfg(not(target_arch = "loongarch64"))]
    Attr::ro("cluster_cpus", |dev, w| {
        show_mask(w, topology::cluster_cpus(cpu_of(dev)))
    }),
    #[cfg(not(target_arch = "loongarch64"))]
    Attr::ro("cluster_cpus_list", |dev, w| {
        show_list(w, topology::cluster_cpus(cpu_of(dev)))
    }),
    #[cfg(target_arch = "x86_64")]
    Attr::ro("die_cpus", |dev, w| {
        show_mask(w, topology::die_cpus(cpu_of(dev)))
    }),
    #[cfg(target_arch = "x86_64")]
    Attr::ro("die_cpus_list", |dev, w| {
        show_list(w, topology::die_cpus(cpu_of(dev)))
    }),
    Attr::ro("package_cpus", |dev, w| {
        show_mask(w, topology::package_cpus(cpu_of(dev)))
    }),
    Attr::ro("package_cpus_list", |dev, w| {
        show_list(w, topology::package_cpus(cpu_of(dev)))
    }),
];

fn cpu_of(dev: &CpuDevice) -> CpuId {
    *dev.payload()
}

fn show_id(w: &mut dyn Write, id: u32) -> Result<()> {
    // Linux prints IDs with `%d`.
    writeln!(w, "{}", id as i32)?;
    Ok(())
}

#[cfg(not(target_arch = "loongarch64"))]
fn show_cluster_id(dev: &CpuDevice, w: &mut dyn Write) -> Result<()> {
    // An unknown cluster is `BAD_APICID` on x86 and -1 elsewhere.
    const UNKNOWN: i32 = if cfg!(target_arch = "x86_64") {
        0xffff
    } else {
        -1
    };
    let id = topology::get(cpu_of(dev))
        .cluster_id
        .map_or(UNKNOWN, |id| id as i32);
    writeln!(w, "{}", id)?;
    Ok(())
}

fn show_mask(w: &mut dyn Write, cpus: CpuSet) -> Result<()> {
    write_cpu_mask(w, cpus.iter().map(u32::from), num_cpus())?;
    writeln!(w)?;
    Ok(())
}

fn show_list(w: &mut dyn Write, cpus: CpuSet) -> Result<()> {
    write_cpu_list(w, cpus.iter().map(u32::from))?;
    writeln!(w)?;
    Ok(())
}
