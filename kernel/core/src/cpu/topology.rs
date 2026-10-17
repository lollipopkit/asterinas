// SPDX-License-Identifier: MPL-2.0

//! The CPU topology: the package, die, cluster, and core of each CPU.
//!
//! Each CPU probes its own place in the topology through the architecture while it initializes.
//! Every relation between CPUs, such as being thread siblings, is derived from these IDs,
//! so `/proc/cpuinfo` and `/sys/devices/system/cpu` always agree.

use alloc::{collections::BTreeSet, vec::Vec};

use ostd::{
    cpu::{CpuId, CpuSet, PinCurrentCpu, all_cpus},
    cpu_local,
    task::disable_preempt,
    util::id_set::Id,
};
use spin::Once;

/// Where a CPU sits in the topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CpuTopology {
    /// The physical package (socket) ID.
    pub(crate) package_id: u32,
    /// The die ID.
    pub(crate) die_id: u32,
    /// The cluster ID, if known; on x86, the ID of the L2 cache.
    pub(crate) cluster_id: Option<u32>,
    /// The core ID, unique within the package.
    pub(crate) core_id: u32,
}

impl CpuTopology {
    /// Returns the topology of a CPU that the architecture cannot describe:
    /// a core of its own in package 0.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/drivers/base/arch_topology.c#L961-L978>.
    #[cfg(not(target_arch = "x86_64"))]
    pub(crate) fn of_lone_core(cpu: CpuId) -> Self {
        Self {
            package_id: 0,
            die_id: 0,
            cluster_id: None,
            core_id: cpu.as_usize() as u32,
        }
    }

    fn same_package(&self, other: &Self) -> bool {
        self.package_id == other.package_id
    }

    fn same_die(&self, other: &Self) -> bool {
        self.same_package(other) && self.die_id == other.die_id
    }

    fn same_core(&self, other: &Self) -> bool {
        self.same_die(other) && self.core_id == other.core_id
    }

    fn same_cluster(&self, other: &Self) -> bool {
        match (self.cluster_id, other.cluster_id) {
            (Some(a), Some(b)) => self.same_package(other) && a == b,
            // Without cluster information, a cluster is a core, as in Linux.
            (None, None) => self.same_core(other),
            _ => false,
        }
    }
}

cpu_local! {
    static TOPOLOGY: Once<CpuTopology> = Once::new();
}

/// Probes the topology of the current CPU.
///
/// Must be called on every CPU.
pub(crate) fn init_on_each_cpu() {
    let guard = disable_preempt();
    TOPOLOGY
        .get_on_cpu(guard.current_cpu())
        .call_once(|| crate::arch::cpu::probe_topology(&guard));
}

/// Waits until every CPU has probed its topology.
///
/// The APs initialize concurrently with the BSP's first kernel thread,
/// so the topology is complete only after this returns.
pub(crate) fn wait_all() {
    for cpu in all_cpus() {
        TOPOLOGY.get_on_cpu(cpu).wait();
    }
}

/// Returns the topology of `cpu`.
///
/// # Panics
///
/// Panics if `cpu` has not probed its topology; see [`wait_all`].
pub(crate) fn get(cpu: CpuId) -> CpuTopology {
    *TOPOLOGY
        .get_on_cpu(cpu)
        .get()
        .expect("the CPU has not probed its topology")
}

/// Returns the CPUs in the same core as `cpu`, including `cpu`.
pub(crate) fn thread_siblings(cpu: CpuId) -> CpuSet {
    related_set(cpu, CpuTopology::same_core)
}

/// Returns the CPUs in the same cluster as `cpu`, including `cpu`.
///
/// Without cluster information, these are the thread siblings.
#[cfg_attr(target_arch = "loongarch64", expect(dead_code))]
pub(crate) fn cluster_cpus(cpu: CpuId) -> CpuSet {
    related_set(cpu, CpuTopology::same_cluster)
}

/// Returns the CPUs on the same die as `cpu`, including `cpu`.
#[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
pub(crate) fn die_cpus(cpu: CpuId) -> CpuSet {
    related_set(cpu, CpuTopology::same_die)
}

/// Returns the CPUs in the same package as `cpu`, including `cpu`.
pub(crate) fn package_cpus(cpu: CpuId) -> CpuSet {
    related_set(cpu, CpuTopology::same_package)
}

/// Returns the number of cores in the package of `cpu`.
#[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
pub(crate) fn num_cores_in_package(cpu: CpuId) -> usize {
    count_cores_in_package(&snapshot(), cpu.as_usize())
}

type Relation = fn(&CpuTopology, &CpuTopology) -> bool;

fn snapshot() -> Vec<CpuTopology> {
    all_cpus().map(get).collect()
}

fn related_set(cpu: CpuId, relation: Relation) -> CpuSet {
    let topologies = snapshot();
    let mut set = CpuSet::new_empty();
    for id in related(&topologies, cpu.as_usize(), relation) {
        set.add(CpuId::try_from(id).unwrap());
    }
    set
}

/// Returns the indexes of the CPUs related to CPU `cpu`, where `topologies` is indexed by CPU ID.
fn related(
    topologies: &[CpuTopology],
    cpu: usize,
    relation: Relation,
) -> impl Iterator<Item = usize> + '_ {
    let this = topologies[cpu];
    topologies
        .iter()
        .enumerate()
        .filter(move |(_, other)| relation(&this, other))
        .map(|(id, _)| id)
}

fn count_cores_in_package(topologies: &[CpuTopology], cpu: usize) -> usize {
    related(topologies, cpu, CpuTopology::same_package)
        .map(|id| (topologies[id].die_id, topologies[id].core_id))
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(ktest)]
mod test {
    use alloc::vec;

    use ostd::prelude::ktest;

    use super::*;

    fn topo(package_id: u32, die_id: u32, cluster_id: Option<u32>, core_id: u32) -> CpuTopology {
        CpuTopology {
            package_id,
            die_id,
            cluster_id,
            core_id,
        }
    }

    fn ids(topologies: &[CpuTopology], cpu: usize, relation: Relation) -> Vec<usize> {
        related(topologies, cpu, relation).collect()
    }

    /// Two packages of two cores with two threads each;
    /// the cores of a package share no L2 cache.
    #[ktest]
    fn two_packages_with_smt() {
        let t = [
            topo(0, 0, Some(0), 0),
            topo(0, 0, Some(0), 0),
            topo(0, 0, Some(2), 1),
            topo(0, 0, Some(2), 1),
            topo(1, 1, Some(4), 0),
            topo(1, 1, Some(4), 0),
            topo(1, 1, Some(6), 1),
            topo(1, 1, Some(6), 1),
        ];
        assert_eq!(ids(&t, 0, CpuTopology::same_core), vec![0, 1]);
        assert_eq!(ids(&t, 6, CpuTopology::same_core), vec![6, 7]);
        assert_eq!(ids(&t, 2, CpuTopology::same_cluster), vec![2, 3]);
        assert_eq!(ids(&t, 5, CpuTopology::same_die), vec![4, 5, 6, 7]);
        assert_eq!(ids(&t, 3, CpuTopology::same_package), vec![0, 1, 2, 3]);
        assert_eq!(count_cores_in_package(&t, 0), 2);
        assert_eq!(count_cores_in_package(&t, 7), 2);
    }

    /// Core IDs are relative to the package, so equal IDs in different packages are different
    /// cores.
    #[ktest]
    fn core_ids_are_package_relative() {
        let t = [topo(0, 0, None, 0), topo(1, 1, None, 0)];
        assert_eq!(ids(&t, 0, CpuTopology::same_core), vec![0]);
        assert_eq!(ids(&t, 1, CpuTopology::same_package), vec![1]);
        assert_eq!(count_cores_in_package(&t, 1), 1);
    }

    /// Without cluster information, a cluster is a core.
    #[ktest]
    fn unknown_clusters_are_cores() {
        let t = [
            topo(0, 0, None, 0),
            topo(0, 0, None, 0),
            topo(0, 0, None, 1),
        ];
        assert_eq!(ids(&t, 0, CpuTopology::same_cluster), vec![0, 1]);
        assert_eq!(ids(&t, 2, CpuTopology::same_cluster), vec![2]);
        assert_eq!(count_cores_in_package(&t, 2), 2);
    }

    /// One core per CPU in one package, the fallback topology.
    #[ktest]
    fn lone_cores() {
        let t: Vec<_> = (0..4).map(|cpu| topo(0, 0, None, cpu)).collect();
        for cpu in 0..4 {
            assert_eq!(ids(&t, cpu, CpuTopology::same_core), vec![cpu]);
            assert_eq!(ids(&t, cpu, CpuTopology::same_cluster), vec![cpu]);
            assert_eq!(ids(&t, cpu, CpuTopology::same_package), vec![0, 1, 2, 3]);
        }
        assert_eq!(count_cores_in_package(&t, 0), 4);
    }
}
