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

/* credit specific counters */
PERFCOUNTER(delay_ms,               "csched: delay")
PERFCOUNTER(vcpu_check,             "csched: vcpu_check")
PERFCOUNTER(acct_run,               "csched: acct_run")
PERFCOUNTER(acct_no_work,           "csched: acct_no_work")
PERFCOUNTER(acct_balance,           "csched: acct_balance")
PERFCOUNTER(acct_reorder,           "csched: acct_reorder")
PERFCOUNTER(acct_min_credit,        "csched: acct_min_credit")
PERFCOUNTER(acct_vcpu_active,       "csched: acct_vcpu_active")
PERFCOUNTER(acct_vcpu_idle,         "csched: acct_vcpu_idle")
PERFCOUNTER(vcpu_sleep,             "csched: vcpu_sleep")
PERFCOUNTER(vcpu_wake_running,      "csched: vcpu_wake_running")
PERFCOUNTER(vcpu_wake_onrunq,       "csched: vcpu_wake_onrunq")
PERFCOUNTER(vcpu_wake_runnable,     "csched: vcpu_wake_runnable")
PERFCOUNTER(vcpu_wake_not_runnable, "csched: vcpu_wake_not_runnable")
PERFCOUNTER(vcpu_park,              "csched: vcpu_park")
PERFCOUNTER(vcpu_unpark,            "csched: vcpu_unpark")
PERFCOUNTER(tickle_idlers_none,     "csched: tickle_idlers_none")
PERFCOUNTER(tickle_idlers_some,     "csched: tickle_idlers_some")
PERFCOUNTER(load_balance_idle,      "csched: load_balance_idle")
PERFCOUNTER(load_balance_over,      "csched: load_balance_over")
PERFCOUNTER(load_balance_other,     "csched: load_balance_other")
PERFCOUNTER(steal_trylock_failed,   "csched: steal_trylock_failed")
PERFCOUNTER(steal_peer_idle,        "csched: steal_peer_idle")
PERFCOUNTER(migrate_queued,         "csched: migrate_queued")
PERFCOUNTER(migrate_running,        "csched: migrate_running")
PERFCOUNTER(migrate_kicked_away,    "csched: migrate_kicked_away")
PERFCOUNTER(vcpu_hot,               "csched: vcpu_hot")

PERFCOUNTER(need_flush_tlb_flush,   "PG_need_flush tlb flushes")

/*#endif*/ /* __XEN_PERFC_DEFN_H__ */
