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

// privileged instructions to fall into vmx_entry
PERFCOUNTER_CPU(vmx_rsm,              "vmx privop rsm")
PERFCOUNTER_CPU(vmx_ssm,              "vmx privop ssm")
PERFCOUNTER_CPU(vmx_mov_to_psr,       "vmx privop mov_to_psr")
PERFCOUNTER_CPU(vmx_mov_from_psr,     "vmx privop mov_from_psr")
PERFCOUNTER_CPU(vmx_mov_from_cr,      "vmx privop mov_from_cr")
PERFCOUNTER_CPU(vmx_mov_to_cr,        "vmx privop mov_to_cr")
PERFCOUNTER_CPU(vmx_bsw0,             "vmx privop bsw0")
PERFCOUNTER_CPU(vmx_bsw1,             "vmx privop bsw1")
PERFCOUNTER_CPU(vmx_cover,            "vmx privop cover")
PERFCOUNTER_CPU(vmx_rfi,              "vmx privop rfi")
PERFCOUNTER_CPU(vmx_itr_d,            "vmx privop itr_d")
PERFCOUNTER_CPU(vmx_itr_i,            "vmx privop itr_i")
PERFCOUNTER_CPU(vmx_ptr_d,            "vmx privop ptr_d")
PERFCOUNTER_CPU(vmx_ptr_i,            "vmx privop ptr_i")
PERFCOUNTER_CPU(vmx_itc_d,            "vmx privop itc_d")
PERFCOUNTER_CPU(vmx_itc_i,            "vmx privop itc_i")
PERFCOUNTER_CPU(vmx_ptc_l,            "vmx privop ptc_l")
PERFCOUNTER_CPU(vmx_ptc_g,            "vmx privop ptc_g")
PERFCOUNTER_CPU(vmx_ptc_ga,           "vmx privop ptc_ga")
PERFCOUNTER_CPU(vmx_ptc_e,            "vmx privop ptc_e")
PERFCOUNTER_CPU(vmx_mov_to_rr,        "vmx privop mov_to_rr")
PERFCOUNTER_CPU(vmx_mov_from_rr,      "vmx privop mov_from_rr")
PERFCOUNTER_CPU(vmx_thash,            "vmx privop thash")
PERFCOUNTER_CPU(vmx_ttag,             "vmx privop ttag")
PERFCOUNTER_CPU(vmx_tpa,              "vmx privop tpa")
PERFCOUNTER_CPU(vmx_tak,              "vmx privop tak")
PERFCOUNTER_CPU(vmx_mov_to_ar_imm,    "vmx privop mov_to_ar_imm")
PERFCOUNTER_CPU(vmx_mov_to_ar_reg,    "vmx privop mov_to_ar_reg")
PERFCOUNTER_CPU(vmx_mov_from_ar_reg,  "vmx privop mov_from_ar_reg")
PERFCOUNTER_CPU(vmx_mov_to_dbr,       "vmx privop mov_to_dbr")
PERFCOUNTER_CPU(vmx_mov_to_ibr,       "vmx privop mov_to_ibr")
PERFCOUNTER_CPU(vmx_mov_to_pmc,       "vmx privop mov_to_pmc")
PERFCOUNTER_CPU(vmx_mov_to_pmd,       "vmx privop mov_to_pmd")
PERFCOUNTER_CPU(vmx_mov_to_pkr,       "vmx privop mov_to_pkr")
PERFCOUNTER_CPU(vmx_mov_from_dbr,     "vmx privop mov_from_dbr")
PERFCOUNTER_CPU(vmx_mov_from_ibr,     "vmx privop mov_from_ibr")
PERFCOUNTER_CPU(vmx_mov_from_pmc,     "vmx privop mov_from_pmc")
PERFCOUNTER_CPU(vmx_mov_from_pkr,     "vmx privop mov_from_pkr")
PERFCOUNTER_CPU(vmx_mov_from_cpuid,   "vmx privop mov_from_cpuid")


PERFCOUNTER_ARRAY(slow_hyperprivop,   "slow hyperprivops", HYPERPRIVOP_MAX + 1)
PERFCOUNTER_ARRAY(fast_hyperprivop,   "fast hyperprivops", HYPERPRIVOP_MAX + 1)

PERFCOUNTER_ARRAY(slow_reflect,       "slow reflection", 0x80)
PERFCOUNTER_ARRAY(fast_reflect,       "fast reflection", 0x80)

PERFSTATUS(vhpt_nbr_entries,          "nbr of entries per VHPT")
PERFSTATUS_CPU(vhpt_valid_entries,    "nbr of valid entries in VHPT")

PERFCOUNTER_ARRAY(vmx_mmio_access,    "vmx_mmio_access", 8)
PERFCOUNTER_CPU(vmx_pal_emul,         "vmx_pal_emul")
PERFCOUNTER_ARRAY(vmx_switch_mm_mode, "vmx_switch_mm_mode", 8)
PERFCOUNTER_CPU(vmx_ia64_handle_break,"vmx_ia64_handle_break")
PERFCOUNTER_ARRAY(vmx_inject_guest_interruption,
                                      "vmx_inject_guest_interruption", 0x80)
PERFCOUNTER_ARRAY(fw_hypercall,       "fw_hypercall", 0x20)

#ifdef CONFIG_PRIVOP_ADDRS
#ifndef PERFPRIVOPADDR
#define PERFPRIVOPADDR(name) \
PERFSTATUS_ARRAY(privop_addr_##name##_addr, "privop-addrs addr " #name, \
                 PRIVOP_COUNT_NADDRS) \
PERFSTATUS_ARRAY(privop_addr_##name##_count, "privop-addrs count " #name, \
                 PRIVOP_COUNT_NADDRS) \
PERFSTATUS(privop_addr_##name##_overflow, "privop-addrs overflow " #name)
#endif

PERFPRIVOPADDR(get_ifa)
PERFPRIVOPADDR(thash)
#endif
