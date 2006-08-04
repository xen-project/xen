/* This file is legitimately included multiple times. */

PERFCOUNTER_CPU(dtlb_translate,		"dtlb hit")

PERFCOUNTER_CPU(tr_translate,		"TR hit")

PERFCOUNTER_CPU(vhpt_translate,		"virtual vhpt translation")
PERFCOUNTER_CPU(fast_vhpt_translate,	"virtual vhpt fast translation")

PERFCOUNTER(recover_to_page_fault,	"recoveries to page fault")
PERFCOUNTER(recover_to_break_fault,	"recoveries to break fault")

PERFCOUNTER_CPU(phys_translate,		"metaphysical translation")

PERFCOUNTER_CPU(idle_when_pending,	"vcpu idle at event")

PERFCOUNTER_CPU(pal_halt_light,		"calls to pal_halt_light")

PERFCOUNTER_CPU(context_switch,		"context switch")

PERFCOUNTER_CPU(lazy_cover,		"lazy cover")
