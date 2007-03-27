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
PERFSTATUS(vhpt_valid_entries,        "nbr of valid entries in VHPT")

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

#undef PERFPRIVOPADDR
#endif

// vhpt.c
PERFCOUNTER_CPU(local_vhpt_flush,               "local_vhpt_flush")
PERFCOUNTER_CPU(vcpu_vhpt_flush,                "vcpu_vhpt_flush")
PERFCOUNTER_CPU(vcpu_flush_vtlb_all,            "vcpu_flush_vtlb_all")
PERFCOUNTER_CPU(domain_flush_vtlb_all,          "domain_flush_vtlb_all")
PERFCOUNTER_CPU(vcpu_flush_tlb_vhpt_range,      "vcpu_flush_tlb_vhpt_range")
PERFCOUNTER_CPU(domain_flush_vtlb_track_entry,  "domain_flush_vtlb_track_entry")
PERFCOUNTER_CPU(domain_flush_vtlb_local,        "domain_flush_vtlb_local")
PERFCOUNTER_CPU(domain_flush_vtlb_global,       "domain_flush_vtlb_global")
PERFCOUNTER_CPU(domain_flush_vtlb_range,        "domain_flush_vtlb_range")

// domain.c
PERFCOUNTER_CPU(flush_vtlb_for_context_switch,  "flush_vtlb_for_context_switch")

// mm.c
PERFCOUNTER_CPU(assign_domain_page_replace,     "assign_domain_page_replace")
PERFCOUNTER_CPU(assign_domain_pge_cmpxchg_rel,  "assign_domain_pge_cmpxchg_rel")
PERFCOUNTER_CPU(zap_dcomain_page_one,           "zap_dcomain_page_one")
PERFCOUNTER_CPU(dom0vp_zap_physmap,             "dom0vp_zap_physmap")
PERFCOUNTER_CPU(dom0vp_add_physmap,             "dom0vp_add_physmap")
PERFCOUNTER_CPU(create_grant_host_mapping,      "create_grant_host_mapping")
PERFCOUNTER_CPU(destroy_grant_host_mapping,     "destroy_grant_host_mapping")
PERFCOUNTER_CPU(steal_page_refcount,            "steal_page_refcount")
PERFCOUNTER_CPU(steal_page,                     "steal_page")
PERFCOUNTER_CPU(guest_physmap_add_page,         "guest_physmap_add_page")
PERFCOUNTER_CPU(guest_physmap_remove_page,      "guest_physmap_remove_page")
PERFCOUNTER_CPU(domain_page_flush_and_put,      "domain_page_flush_and_put")

// dom0vp
PERFCOUNTER_CPU(dom0vp_phystomach,              "dom0vp_phystomach")
PERFCOUNTER_CPU(dom0vp_machtophys,              "dom0vp_machtophys")

#ifdef CONFIG_XEN_IA64_TLB_TRACK
// insert or dirty
PERFCOUNTER_CPU(tlb_track_iod,                  "tlb_track_iod")
PERFCOUNTER_CPU(tlb_track_iod_again,            "tlb_track_iod_again")
PERFCOUNTER_CPU(tlb_track_iod_not_tracked,      "tlb_track_iod_not_tracked")
PERFCOUNTER_CPU(tlb_track_iod_force_many,       "tlb_track_iod_force_many")
PERFCOUNTER_CPU(tlb_track_iod_tracked_many,     "tlb_track_iod_tracked_many")
PERFCOUNTER_CPU(tlb_track_iod_tracked_many_del, "tlb_track_iod_tracked_many_del")
PERFCOUNTER_CPU(tlb_track_iod_found,            "tlb_track_iod_found")
PERFCOUNTER_CPU(tlb_track_iod_new_entry,        "tlb_track_iod_new_entry")
PERFCOUNTER_CPU(tlb_track_iod_new_failed,       "tlb_track_iod_new_failed")
PERFCOUNTER_CPU(tlb_track_iod_new_many,         "tlb_track_iod_new_many")
PERFCOUNTER_CPU(tlb_track_iod_insert,           "tlb_track_iod_insert")
PERFCOUNTER_CPU(tlb_track_iod_dirtied,          "tlb_track_iod_dirtied")

// search and remove
PERFCOUNTER_CPU(tlb_track_sar,                  "tlb_track_sar")
PERFCOUNTER_CPU(tlb_track_sar_not_tracked,      "tlb_track_sar_not_tracked")
PERFCOUNTER_CPU(tlb_track_sar_not_found,        "tlb_track_sar_not_found")
PERFCOUNTER_CPU(tlb_track_sar_found,            "tlb_track_sar_found")
PERFCOUNTER_CPU(tlb_track_sar_many,             "tlb_track_sar_many")

// flush
PERFCOUNTER_CPU(tlb_track_use_rr7,              "tlb_track_use_rr7")
PERFCOUNTER_CPU(tlb_track_swap_rr0,             "tlb_track_swap_rr0")
#endif

// tlb flush clock
#ifdef CONFIG_XEN_IA64_TLBFLUSH_CLOCK
PERFCOUNTER_CPU(tlbflush_clock_cswitch_purge,  "tlbflush_clock_cswitch_purge")
PERFCOUNTER_CPU(tlbflush_clock_cswitch_skip,   "tlbflush_clock_cswitch_skip")
#endif
