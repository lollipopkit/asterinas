// SPDX-License-Identifier: MPL-2.0

//! Completely Fair Scheduler (CFS).

#![warn(unused)]

use alloc::{boxed::Box, sync::Arc};
use core::{fmt, ops::Bound, sync::atomic::Ordering};

use ostd::{
    arch::read_tsc as sched_clock,
    cpu::{CpuId, CpuSet, PinCurrentCpu, all_cpus, num_cpus},
    irq::disable_local,
    sync::{LocalIrqDisabled, SpinLock, SpinLockGuard},
    task::{
        AtomicCpuId, Task,
        scheduler::{
            EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags, enable_preemption_on_cpu,
            info::CommonSchedInfo, inject_scheduler,
        },
    },
    timer::{self, Jiffies},
    util::id_set::Id,
};
use spin::Once;

use super::{
    nice::Nice,
    stats::{SchedulerStats, set_stats_from_scheduler},
};
use crate::thread::{AsThread, Thread};

mod policy;
mod time;

mod fair;
mod idle;
mod real_time;
mod stop;

use self::policy::{SchedPolicyKind, SchedPolicyState};
pub(crate) use self::{
    policy::{LinuxSchedPolicy, SchedPolicy},
    real_time::{RealTimePolicy, RealTimePriority},
};

type SchedEntity = (Arc<Task>, Arc<Thread>);

static SCHEDULER: Once<&'static ClassScheduler> = Once::new();

pub(crate) fn init() {
    let scheduler: &'static ClassScheduler = Box::leak(Box::new(ClassScheduler::new()));
    SCHEDULER.call_once(|| scheduler);

    // Inject the scheduler into the ostd for actual scheduling work.
    inject_scheduler(scheduler);

    // Set the scheduler into the system for statistics.
    // We set this after injecting the scheduler into ostd,
    // so that the loadavg statistics are updated after the scheduler is used.
    set_stats_from_scheduler(scheduler);
}

pub(crate) fn init_on_each_cpu() {
    // Balance before the preemption tick, so that the tick can switch to a pulled thread.
    timer::register_callback_on_cpu(|| SCHEDULER.get().unwrap().balance());
    enable_preemption_on_cpu();
}

/// Represents the middle layer between scheduling classes and generic scheduler
/// traits. It consists of all the sets of run queues for CPU cores. Other global
/// information may also be stored here.
pub(crate) struct ClassScheduler {
    /// The per-CPU runqueues.
    ///
    /// We use the `LocalIrqDisabled` marker for this spinlock to ensure local IRQs are always disabled,
    /// preventing potential deadlocks due to the fact that
    /// the runqueues may be accessed in both the task and interrupt context (L1 and L2).
    rqs: Box<[SpinLock<PerCpuClassRqSet, LocalIrqDisabled>]>,
    last_chosen_cpu: AtomicCpuId,
}

/// Represents the run queue for each CPU core. It stores a list of run queues for
/// scheduling classes in its corresponding CPU core. The current task of this CPU
/// core is also stored in this structure.
struct PerCpuClassRqSet {
    stop: stop::StopClassRq,
    real_time: real_time::RealTimeClassRq,
    fair: fair::FairClassRq,
    idle: idle::IdleClassRq,
    current: Option<(SchedEntity, CurrentRuntime)>,
    /// The jiffies when this CPU checks the load balance next time.
    next_balance: u64,
}

/// Stores the runtime information of the current task.
///
/// This is used to calculate the time slice of the current task.
///
/// This struct is independent of the current `Arc<Task>` instead encapsulating the
/// task, because the scheduling class implementations use `CurrentRuntime` and
/// `SchedAttr` only.
struct CurrentRuntime {
    start: u64,
    delta: u64,
    period_delta: u64,
}

impl CurrentRuntime {
    fn new() -> Self {
        CurrentRuntime {
            start: sched_clock(),
            delta: 0,
            period_delta: 0,
        }
    }

    fn update(&mut self) {
        let now = sched_clock();
        self.delta = now - core::mem::replace(&mut self.start, now);
        self.period_delta += self.delta;
    }
}

/// The run queue for scheduling classes (the main trait). Scheduling classes
/// should implement this trait to function as expected.
trait SchedClassRq: Send + fmt::Debug {
    /// Enqueues a task into the run queue.
    fn enqueue(&mut self, task: Arc<Task>, flags: Option<EnqueueFlags>);

    /// Returns the number of threads in the run queue.
    fn len(&self) -> usize;

    /// Checks if the run queue is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Picks the next task for running.
    fn pick_next(&mut self) -> Option<Arc<Task>>;

    /// Update the information of the current task.
    ///
    /// The return value of this method indicates whether there is another task
    /// **in this run queue** to replace the current one.
    fn update_current(&mut self, rt: &CurrentRuntime, attr: &SchedAttr, flags: UpdateFlags)
    -> bool;
}

/// The scheduling attribute for a thread.
///
/// This is used to store the scheduling policy and runtime parameters for each
/// scheduling class.
#[derive(Debug)]
pub(crate) struct SchedAttr {
    policy: SchedPolicyState,
    last_cpu: AtomicCpuId,
    real_time: real_time::RealTimeAttr,
    fair: fair::FairAttr,
}

impl SchedAttr {
    /// Constructs a new `SchedAttr` with the given scheduling policy.
    pub(crate) fn new(policy: SchedPolicy) -> Self {
        Self {
            policy: SchedPolicyState::new(policy),
            last_cpu: AtomicCpuId::default(),
            real_time: {
                let (prio, policy) = match policy {
                    SchedPolicy::RealTime { rt_prio, rt_policy } => (rt_prio.get(), rt_policy),
                    _ => (RealTimePriority::MAX.get(), Default::default()),
                };
                real_time::RealTimeAttr::new(prio, policy)
            },
            fair: fair::FairAttr::new(match policy {
                SchedPolicy::Fair(nice) => nice,
                _ => Nice::default(),
            }),
        }
    }

    /// Retrieves the current scheduling policy of the thread.
    pub(crate) fn policy(&self) -> SchedPolicy {
        self.policy.get()
    }

    fn policy_kind(&self) -> SchedPolicyKind {
        self.policy.kind()
    }

    /// Updates the scheduling policy of the thread.
    ///
    /// Specifically for real-time policies, if the new policy doesn't
    /// specify a base slice factor for RR, the old one will be kept.
    pub(crate) fn set_policy(&self, policy: SchedPolicy) {
        self.policy.set(policy, |policy| match policy {
            SchedPolicy::RealTime { rt_prio, rt_policy } => {
                self.real_time.update(rt_prio.get(), rt_policy);
            }
            SchedPolicy::Fair(nice) => self.fair.update(nice),
            _ => {}
        });
    }

    pub(crate) fn update_policy<T>(&self, f: impl FnOnce(&mut SchedPolicy) -> T) -> T {
        self.policy.update(|policy| {
            let ret = f(policy);
            match *policy {
                SchedPolicy::RealTime { rt_prio, rt_policy } => {
                    self.real_time.update(rt_prio.get(), rt_policy);
                }
                SchedPolicy::Fair(nice) => self.fair.update(nice),
                _ => {}
            }
            ret
        })
    }

    pub(crate) fn last_cpu(&self) -> Option<CpuId> {
        self.last_cpu.get()
    }

    fn set_last_cpu(&self, cpu_id: CpuId) {
        self.last_cpu.set_anyway(cpu_id);
    }
}

impl Scheduler for ClassScheduler {
    fn enqueue(&self, task: Arc<Task>, flags: EnqueueFlags) -> Option<CpuId> {
        let thread = task.as_thread()?.clone();

        let (still_in_rq, cpu) = {
            let selected_cpu_id = self.select_cpu(&thread, flags);

            if let Err(task_cpu_id) = task.cpu().set_if_is_none(selected_cpu_id) {
                debug_assert!(flags != EnqueueFlags::Spawn);
                (true, task_cpu_id)
            } else {
                (false, selected_cpu_id)
            }
        };

        let mut rq = self.rqs[cpu.as_usize()].lock();

        // Note: call set_if_is_none again to prevent a race condition.
        if still_in_rq && task.cpu().set_if_is_none(cpu).is_err() {
            return None;
        }

        // Preempt if the new task has a higher priority.
        let should_preempt = rq
            .current
            .as_ref()
            .is_none_or(|((_, rq_current_thread), _)| {
                thread.sched_attr().policy() < rq_current_thread.sched_attr().policy()
            });

        thread.sched_attr().set_last_cpu(cpu);
        rq.enqueue_entity((task, thread), Some(flags));

        should_preempt.then_some(cpu)
    }

    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue)) {
        let guard = disable_local();
        let mut lock = self.rqs[guard.current_cpu().as_usize()].lock();
        f(&mut *lock)
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue)) {
        let guard = disable_local();
        f(&*self.rqs[guard.current_cpu().as_usize()].lock())
    }
}

impl ClassScheduler {
    pub(crate) fn new() -> Self {
        let class_rq = |cpu| {
            SpinLock::new(PerCpuClassRqSet {
                stop: stop::StopClassRq::new(),
                real_time: real_time::RealTimeClassRq::new(cpu),
                fair: fair::FairClassRq::new(cpu),
                idle: idle::IdleClassRq::new(),
                current: None,
                next_balance: 0,
            })
        };
        ClassScheduler {
            rqs: all_cpus().map(class_rq).collect(),
            last_chosen_cpu: AtomicCpuId::default(),
        }
    }

    /// Selects the CPU to enqueue `thread` on.
    ///
    /// A woken thread stays on its last CPU if that CPU is idle. Otherwise, it moves to an idle
    /// CPU if there is one, like `select_idle_sibling` in Linux, so that runnable threads do not
    /// wait behind each other while a CPU idles. A spawned thread goes to the least loaded CPU.
    /// Threads that keep running without sleeping are moved by [`Self::balance`].
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/sched/fair.c#L9027>
    fn select_cpu(&self, thread: &Thread, flags: EnqueueFlags) -> CpuId {
        let guard = disable_local();
        let affinity = thread.atomic_cpu_affinity().load(Ordering::Relaxed);

        if let Some(last_cpu) = thread.sched_attr().last_cpu()
            && affinity.contains(last_cpu)
        {
            if self.rqs[last_cpu.as_usize()].lock().load_stats().is_idle {
                return last_cpu;
            }
            return Self::cycle_after(last_cpu, &affinity)
                .find(|&cpu| self.rqs[cpu.as_usize()].lock().load_stats().is_idle)
                .unwrap_or(last_cpu);
        }
        debug_assert!(flags == EnqueueFlags::Spawn || thread.sched_attr().last_cpu().is_some());

        let mut selected = guard.current_cpu();
        let mut minimum_load = u32::MAX;

        // Set `selected` as `candidate` if the candidate's load is smaller. The load counts the
        // running thread, so that a busy CPU with an empty queue is not taken for an idle one.
        let test_candidate = |candidate: CpuId| {
            let load = self.rqs[candidate.as_usize()]
                .lock()
                .load_stats()
                .nr_running();
            if load < minimum_load {
                minimum_load = load;
                selected = candidate;
            }
        };

        match self.last_chosen_cpu.get() {
            Some(cpu) => {
                // Perform a round-robin selection starting after the last chosen CPU.
                //
                // It still checks every CPU in the affinity set to find the one with the
                // minimum load, but avoids selecting the same CPU again in case of a tie.
                Self::cycle_after(cpu, &affinity).for_each(test_candidate)
            }
            None => affinity.iter().for_each(test_candidate),
        }

        self.last_chosen_cpu.set_anyway(selected);
        selected
    }

    /// Pulls a queued fair thread to the current CPU from the busiest CPU if that CPU runs at
    /// least two more threads, like the periodic load balancing in Linux.
    ///
    /// This runs on every tick and checks the load every `num_cpus` ticks on an idle CPU, and
    /// `BUSY_FACTOR` times less often on a busy CPU, like the CPU-level scheduling domain in
    /// Linux.
    ///
    /// TODO: Balance real-time threads, which Linux pushes to and pulls from CPUs running
    /// lower-priority threads.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/sched/fair.c#L14080>
    fn balance(&self) {
        /// The factor by which a busy CPU balances less often, like `busy_factor` in Linux.
        const BUSY_FACTOR: u64 = 16;

        let guard = disable_local();
        let this_cpu = guard.current_cpu();
        let now = Jiffies::elapsed().as_u64();

        let this_nr_running = {
            let mut rq = self.rqs[this_cpu.as_usize()].lock();
            if now < rq.next_balance {
                return;
            }
            let stats = rq.load_stats();
            let interval = num_cpus() as u64 * if stats.is_idle { 1 } else { BUSY_FACTOR };
            rq.next_balance = now + interval;
            stats.nr_running()
        };

        let Some(busiest_cpu) = all_cpus()
            .filter(|&cpu| cpu != this_cpu)
            .map(|cpu| {
                (
                    cpu,
                    self.rqs[cpu.as_usize()].lock().load_stats().nr_running(),
                )
            })
            .filter(|&(_, nr_running)| nr_running >= this_nr_running + 2)
            .max_by_key(|&(_, nr_running)| nr_running)
            .map(|(cpu, _)| cpu)
        else {
            return;
        };

        let (mut busiest_rq, mut this_rq) = self.lock_pair(busiest_cpu, this_cpu);
        if busiest_rq.load_stats().nr_running() < this_rq.load_stats().nr_running() + 2 {
            return;
        }
        let Some((task, relative_vruntime)) = busiest_rq.fair.steal(|task| {
            task.as_thread().is_some_and(|thread| {
                thread
                    .atomic_cpu_affinity()
                    .load(Ordering::Relaxed)
                    .contains(this_cpu)
            })
        }) else {
            return;
        };

        // Both run queues are locked, so `Scheduler::enqueue` cannot observe the change halfway.
        task.cpu().set_anyway(this_cpu);
        task.as_thread()
            .unwrap()
            .sched_attr()
            .set_last_cpu(this_cpu);
        this_rq.fair.enqueue_migrated(task, relative_vruntime);
    }

    /// Locks the run queues of two different CPUs in the order of their IDs, returning the
    /// guards in the order of the arguments.
    fn lock_pair(
        &self,
        a: CpuId,
        b: CpuId,
    ) -> (
        SpinLockGuard<'_, PerCpuClassRqSet, LocalIrqDisabled>,
        SpinLockGuard<'_, PerCpuClassRqSet, LocalIrqDisabled>,
    ) {
        debug_assert_ne!(a, b);
        if a.as_usize() < b.as_usize() {
            let a_rq = self.rqs[a.as_usize()].lock();
            (a_rq, self.rqs[b.as_usize()].lock())
        } else {
            let b_rq = self.rqs[b.as_usize()].lock();
            (self.rqs[a.as_usize()].lock(), b_rq)
        }
    }

    /// Returns a cycling iterator over the CPUs in the [`CpuSet`], starting *after*
    /// the given [`CpuId`].
    ///
    /// The iteration order is ascending up to the wrapping point, after which it
    /// continues from the first CPU in the set in ascending order again.
    ///
    /// If the given [`CpuId`] is in the set, it will be the last element yielded.
    fn cycle_after(cpu: CpuId, cpu_set: &CpuSet) -> impl Iterator<Item = CpuId> + '_ {
        cpu_set
            .iter_in((Bound::Excluded(cpu), Bound::Unbounded))
            .chain(cpu_set.iter_in(..=cpu))
    }
}

impl PerCpuClassRqSet {
    fn pick_next_entity(&mut self) -> Option<SchedEntity> {
        (self.stop.pick_next())
            .or_else(|| self.real_time.pick_next())
            .or_else(|| self.fair.pick_next())
            .or_else(|| self.idle.pick_next())
            .and_then(|task| {
                let thread = task.as_thread()?.clone();
                Some((task, thread))
            })
    }

    fn enqueue_entity(&mut self, (task, thread): SchedEntity, flags: Option<EnqueueFlags>) {
        match thread.sched_attr().policy_kind() {
            SchedPolicyKind::Stop => self.stop.enqueue(task, flags),
            SchedPolicyKind::RealTime => self.real_time.enqueue(task, flags),
            SchedPolicyKind::Fair => self.fair.enqueue(task, flags),
            SchedPolicyKind::Idle => self.idle.enqueue(task, flags),
        }
    }

    fn load_stats(&self) -> PerCpuLoadStats {
        let queue_len = (self.stop.len() + self.real_time.len() + self.fair.len()) as u32;
        let is_idle = match &self.current {
            Some(((_, thread), _)) => thread.sched_attr().policy_kind() == SchedPolicyKind::Idle,
            None => true,
        };
        PerCpuLoadStats { queue_len, is_idle }
    }
}

impl LocalRunQueue for PerCpuClassRqSet {
    fn current(&self) -> Option<&Arc<Task>> {
        self.current.as_ref().map(|((task, _), _)| task)
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        self.pick_next_entity().and_then(|next| {
            // We guarantee that a task can appear at once in a `PerCpuClassRqSet`. So, the `next` cannot be the same
            // as the current task here.
            if let Some((old, _)) = self.current.replace((next, CurrentRuntime::new())) {
                self.enqueue_entity(old, None);
            }
            self.current.as_ref().map(|((task, _), _)| task)
        })
    }

    fn update_current(&mut self, flags: UpdateFlags) -> bool {
        let (should_preempt, mut lookahead) = if let Some(((_, cur), rt)) = &mut self.current {
            rt.update();
            let attr = &cur.sched_attr();

            match attr.policy_kind() {
                SchedPolicyKind::Stop => (self.stop.update_current(rt, attr, flags), 0),
                SchedPolicyKind::RealTime => (self.real_time.update_current(rt, attr, flags), 1),
                SchedPolicyKind::Fair => (self.fair.update_current(rt, attr, flags), 2),
                SchedPolicyKind::Idle => (self.idle.update_current(rt, attr, flags), 3),
            }
        } else {
            (false, 4)
        };

        if matches!(flags, UpdateFlags::Wait | UpdateFlags::Exit) {
            lookahead = 4;
        }

        should_preempt
            || (lookahead >= 1 && !self.stop.is_empty())
            || (lookahead >= 2 && !self.real_time.is_empty())
            || (lookahead >= 3 && !self.fair.is_empty())
            || (lookahead >= 4 && !self.idle.is_empty())
    }

    fn dequeue_current(&mut self) -> Option<Arc<Task>> {
        self.current.take().map(|((cur_task, _), _)| {
            cur_task.schedule_info().cpu.set_to_none();
            cur_task
        })
    }
}

/// Holds per-CPU load information.
struct PerCpuLoadStats {
    /// The length of the run queue (excluding the idle task).
    queue_len: u32,
    /// If the CPU is currently idle.
    ///
    /// A CPU is said to be idle when it is running the idle task, or it is not
    /// running any task at all. The latter case is very unlikely to happen
    /// (almost a bug if it happens) as the idle task should always be runnable.
    is_idle: bool,
}

impl PerCpuLoadStats {
    /// Returns the number of runnable threads, including the running one.
    fn nr_running(&self) -> u32 {
        self.queue_len + u32::from(!self.is_idle)
    }
}

impl SchedulerStats for ClassScheduler {
    fn nr_queued_and_running(&self) -> (u32, u32) {
        self.rqs.iter().fold((0, 0), |(queued, running), rq| {
            let PerCpuLoadStats { queue_len, is_idle } = rq.lock().load_stats();
            (queued + queue_len, running + u32::from(!is_idle))
        })
    }
}

impl Default for ClassScheduler {
    fn default() -> Self {
        Self::new()
    }
}
