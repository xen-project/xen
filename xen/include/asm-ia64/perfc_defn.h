/* This file is legitimately included multiple times. */

PERFCOUNTER_CPU(dtlb_translate,       "dtlb hit")

PERFCOUNTER_CPU(tr_translate,         "TR hit")

PERFCOUNTER_CPU(vhpt_translate,       "virtual vhpt translation")
PERFCOUNTER_CPU(fast_vhpt_translate,  "virtual vhpt fast translation")

PERFCOUNTER(recover_to_page_fault,    "recoveries to page fault")
PERFCOUNTER(recover_to_break_fault,   "recoveries to break fault")

PERFCOUNTER_CPU(phys_translate,       "metaphysical translation")

PERFCOUNTER_CPU(idle_when_pending,    "vcpu idle at event")

PERFCOUNTER_CPU(pal_halt_light,       "calls to pal_halt_light")

PERFCOUNTER_CPU(lazy_cover,           "lazy cover")

PERFCOUNTER_CPU(mov_to_ar_imm,        "privop mov_to_ar_imm")
PERFCOUNTER_CPU(mov_to_ar_reg,        "privop mov_to_ar_reg")
PERFCOUNTER_CPU(mov_from_ar,          "privop privified-mov_from_ar")
PERFCOUNTER_CPU(ssm,                  "privop ssm")
PERFCOUNTER_CPU(rsm,                  "privop rsm")
PERFCOUNTER_CPU(rfi,                  "privop rfi")
PERFCOUNTER_CPU(bsw0,                 "privop bsw0")
PERFCOUNTER_CPU(bsw1,                 "privop bsw1")
PERFCOUNTER_CPU(cover,                "privop cover")
PERFCOUNTER_CPU(fc,                   "privop privified-fc")
PERFCOUNTER_CPU(cpuid,                "privop privified-cpuid")

PERFCOUNTER_ARRAY(mov_to_cr,          "privop mov to cr", 128)
PERFCOUNTER_ARRAY(mov_from_cr,        "privop mov from cr", 128)

PERFCOUNTER_ARRAY(misc_privop,        "privop misc", 64)

PERFCOUNTER_ARRAY(slow_hyperprivop,   "slow hyperprivops", HYPERPRIVOP_MAX + 1)
PERFCOUNTER_ARRAY(fast_hyperprivop,   "fast hyperprivops", HYPERPRIVOP_MAX + 1)

PERFCOUNTER_ARRAY(slow_reflect,       "slow reflection", 0x80)
PERFCOUNTER_ARRAY(fast_reflect,       "fast reflection", 0x80)
