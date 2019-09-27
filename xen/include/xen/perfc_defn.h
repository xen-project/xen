/* This file is legitimately included multiple times. */
/*#ifndef __XEN_PERFC_DEFN_H__*/
/*#define __XEN_PERFC_DEFN_H__*/

#include <asm/perfc_defn.h>

PERFCOUNTER_ARRAY(hypercalls,           "hypercalls", NR_hypercalls)

PERFCOUNTER(calls_to_multicall,         "calls to multicall")
PERFCOUNTER(calls_from_multicall,       "calls from multicall")

PERFCOUNTER(irqs,                   "#interrupts")
PERFCOUNTER(ipis,                   "#IPIs")

PERFCOUNTER(rcu_idle_timer,         "RCU: idle_timer")

/* Generic scheduler counters (applicable to all schedulers) */
PERFCOUNTER(sched_irq,              "sched: timer")
PERFCOUNTER(sched_run,              "sched: runs through scheduler")
PERFCOUNTER(sched_ctx,              "sched: context switches")
PERFCOUNTER(schedule,               "sched: specific scheduler")
PERFCOUNTER(dom_init,               "sched: dom_init")
PERFCOUNTER(dom_destroy,            "sched: dom_destroy")
PERFCOUNTER(vcpu_yield,             "sched: vcpu_yield")
PERFCOUNTER(unit_alloc,             "sched: unit_alloc")
PERFCOUNTER(unit_insert,            "sched: unit_insert")
PERFCOUNTER(unit_remove,            "sched: unit_remove")
PERFCOUNTER(unit_sleep,             "sched: unit_sleep")
PERFCOUNTER(unit_wake_running,      "sched: unit_wake_running")
PERFCOUNTER(unit_wake_onrunq,       "sched: unit_wake_onrunq")
PERFCOUNTER(unit_wake_runnable,     "sched: unit_wake_runnable")
PERFCOUNTER(unit_wake_not_runnable, "sched: unit_wake_not_runnable")
PERFCOUNTER(tickled_no_cpu,         "sched: tickled_no_cpu")
PERFCOUNTER(tickled_idle_cpu,       "sched: tickled_idle_cpu")
PERFCOUNTER(tickled_idle_cpu_excl,  "sched: tickled_idle_cpu_exclusive")
PERFCOUNTER(tickled_busy_cpu,       "sched: tickled_busy_cpu")
PERFCOUNTER(unit_check,             "sched: unit_check")

/* credit specific counters */
PERFCOUNTER(delay_ms,               "csched: delay")
PERFCOUNTER(acct_run,               "csched: acct_run")
PERFCOUNTER(acct_no_work,           "csched: acct_no_work")
PERFCOUNTER(acct_balance,           "csched: acct_balance")
PERFCOUNTER(acct_reorder,           "csched: acct_reorder")
PERFCOUNTER(acct_min_credit,        "csched: acct_min_credit")
PERFCOUNTER(acct_unit_active,       "csched: acct_unit_active")
PERFCOUNTER(acct_unit_idle,         "csched: acct_unit_idle")
PERFCOUNTER(unit_boost,             "csched: unit_boost")
PERFCOUNTER(unit_park,              "csched: unit_park")
PERFCOUNTER(unit_unpark,            "csched: unit_unpark")
PERFCOUNTER(load_balance_idle,      "csched: load_balance_idle")
PERFCOUNTER(load_balance_over,      "csched: load_balance_over")
PERFCOUNTER(load_balance_other,     "csched: load_balance_other")
PERFCOUNTER(steal_trylock,          "csched: steal_trylock")
PERFCOUNTER(steal_trylock_failed,   "csched: steal_trylock_failed")
PERFCOUNTER(steal_peer_idle,        "csched: steal_peer_idle")
PERFCOUNTER(migrate_queued,         "csched: migrate_queued")
PERFCOUNTER(migrate_running,        "csched: migrate_running")
PERFCOUNTER(migrate_kicked_away,    "csched: migrate_kicked_away")
PERFCOUNTER(unit_hot,               "csched: unit_hot")

/* credit2 specific counters */
PERFCOUNTER(burn_credits_t2c,       "csched2: burn_credits_t2c")
PERFCOUNTER(acct_load_balance,      "csched2: acct_load_balance")
PERFCOUNTER(upd_max_weight_quick,   "csched2: update_max_weight_quick")
PERFCOUNTER(upd_max_weight_full,    "csched2: update_max_weight_full")
PERFCOUNTER(migrate_requested,      "csched2: migrate_requested")
PERFCOUNTER(migrate_on_runq,        "csched2: migrate_on_runq")
PERFCOUNTER(migrate_no_runq,        "csched2: migrate_no_runq")
PERFCOUNTER(runtime_min_timer,      "csched2: runtime_min_timer")
PERFCOUNTER(runtime_max_timer,      "csched2: runtime_max_timer")
PERFCOUNTER(pick_resource,          "csched2: pick_resource")
PERFCOUNTER(need_fallback_cpu,      "csched2: need_fallback_cpu")
PERFCOUNTER(migrated,               "csched2: migrated")
PERFCOUNTER(migrate_resisted,       "csched2: migrate_resisted")
PERFCOUNTER(credit_reset,           "csched2: credit_reset")
PERFCOUNTER(deferred_to_tickled_cpu,"csched2: deferred_to_tickled_cpu")
PERFCOUNTER(tickled_cpu_overwritten,"csched2: tickled_cpu_overwritten")
PERFCOUNTER(tickled_cpu_overridden, "csched2: tickled_cpu_overridden")

PERFCOUNTER(need_flush_tlb_flush,   "PG_need_flush tlb flushes")

/*#endif*/ /* __XEN_PERFC_DEFN_H__ */
