/* This file is legitimately included multiple times. */
/*#ifndef __XEN_PERFC_DEFN_H__*/
/*#define __XEN_PERFC_DEFN_H__*/

#include <asm/perfc_defn.h>

PERFCOUNTER_ARRAY(hypercalls,           "hypercalls", NR_hypercalls)

PERFCOUNTER(calls_to_multicall,         "calls to multicall")
PERFCOUNTER(calls_from_multicall,       "calls from multicall")

PERFCOUNTER(irqs,                   "#interrupts")
PERFCOUNTER(ipis,                   "#IPIs")

/* Generic scheduler counters (applicable to all schedulers) */
PERFCOUNTER(sched_irq,              "sched: timer")
PERFCOUNTER(sched_run,              "sched: runs through scheduler")
PERFCOUNTER(sched_ctx,              "sched: context switches")
PERFCOUNTER(schedule,               "sched: specific scheduler")
PERFCOUNTER(dom_init,               "sched: dom_init")
PERFCOUNTER(dom_destroy,            "sched: dom_destroy")
PERFCOUNTER(vcpu_init,              "sched: vcpu_init")
PERFCOUNTER(vcpu_destroy,           "sched: vcpu_destroy")
PERFCOUNTER(vcpu_sleep,             "sched: vcpu_sleep")
PERFCOUNTER(vcpu_wake_running,      "sched: vcpu_wake_running")
PERFCOUNTER(vcpu_wake_onrunq,       "sched: vcpu_wake_onrunq")
PERFCOUNTER(vcpu_wake_runnable,     "sched: vcpu_wake_runnable")
PERFCOUNTER(vcpu_wake_not_runnable, "sched: vcpu_wake_not_runnable")
PERFCOUNTER(tickle_idlers_none,     "sched: tickle_idlers_none")
PERFCOUNTER(tickle_idlers_some,     "sched: tickle_idlers_some")
PERFCOUNTER(vcpu_check,             "sched: vcpu_check")

/* credit specific counters */
PERFCOUNTER(delay_ms,               "csched: delay")
PERFCOUNTER(acct_run,               "csched: acct_run")
PERFCOUNTER(acct_no_work,           "csched: acct_no_work")
PERFCOUNTER(acct_balance,           "csched: acct_balance")
PERFCOUNTER(acct_reorder,           "csched: acct_reorder")
PERFCOUNTER(acct_min_credit,        "csched: acct_min_credit")
PERFCOUNTER(acct_vcpu_active,       "csched: acct_vcpu_active")
PERFCOUNTER(acct_vcpu_idle,         "csched: acct_vcpu_idle")
PERFCOUNTER(vcpu_park,              "csched: vcpu_park")
PERFCOUNTER(vcpu_unpark,            "csched: vcpu_unpark")
PERFCOUNTER(load_balance_idle,      "csched: load_balance_idle")
PERFCOUNTER(load_balance_over,      "csched: load_balance_over")
PERFCOUNTER(load_balance_other,     "csched: load_balance_other")
PERFCOUNTER(steal_trylock_failed,   "csched: steal_trylock_failed")
PERFCOUNTER(steal_peer_idle,        "csched: steal_peer_idle")
PERFCOUNTER(migrate_queued,         "csched: migrate_queued")
PERFCOUNTER(migrate_running,        "csched: migrate_running")
PERFCOUNTER(migrate_kicked_away,    "csched: migrate_kicked_away")
PERFCOUNTER(vcpu_hot,               "csched: vcpu_hot")

/* credit2 specific counters */
PERFCOUNTER(burn_credits_t2c,       "csched2: burn_credits_t2c")
PERFCOUNTER(upd_max_weight_quick,   "csched2: update_max_weight_quick")
PERFCOUNTER(upd_max_weight_full,    "csched2: update_max_weight_full")
PERFCOUNTER(migrate_requested,      "csched2: migrate_requested")
PERFCOUNTER(migrate_on_runq,        "csched2: migrate_on_runq")
PERFCOUNTER(migrate_no_runq,        "csched2: migrate_no_runq")
PERFCOUNTER(runtime_min_timer,      "csched2: runtime_min_timer")
PERFCOUNTER(runtime_max_timer,      "csched2: runtime_max_timer")
PERFCOUNTER(migrated,               "csched2: migrated")
PERFCOUNTER(migrate_resisted,       "csched2: migrate_resisted")
PERFCOUNTER(credit_reset,           "csched2: credit_reset")

PERFCOUNTER(need_flush_tlb_flush,   "PG_need_flush tlb flushes")

/*#endif*/ /* __XEN_PERFC_DEFN_H__ */
