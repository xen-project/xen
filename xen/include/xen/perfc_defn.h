/* This file is legitimately included multiple times. */
/*#ifndef __XEN_PERFC_DEFN_H__*/
/*#define __XEN_PERFC_DEFN_H__*/

#define PERFC_MAX_PT_UPDATES 64
#define PERFC_PT_UPDATES_BUCKET_SIZE 3
PERFCOUNTER_ARRAY(wpt_updates,          "writable pt updates",
                  PERFC_MAX_PT_UPDATES)
PERFCOUNTER_ARRAY(bpt_updates,          "batched pt updates",
                  PERFC_MAX_PT_UPDATES)
PERFCOUNTER_ARRAY(l1_entries_checked,   "l1 entries checked",
                  PERFC_MAX_PT_UPDATES)
PERFCOUNTER_ARRAY(shm_l2_updates,       "shadow mode L2 pt updates",
                  PERFC_MAX_PT_UPDATES)
PERFCOUNTER_ARRAY(shm_hl2_updates,      "shadow mode HL2 pt updates",
                  PERFC_MAX_PT_UPDATES)
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
PERFCOUNTER_ARRAY(shm_l3_updates,       "shadow mode L3 pt updates",
                  PERFC_MAX_PT_UPDATES)
PERFCOUNTER_ARRAY(shm_l4_updates,       "shadow mode L4 pt updates",
                  PERFC_MAX_PT_UPDATES)
#endif
PERFCOUNTER_ARRAY(snapshot_copies,      "entries copied per snapshot",
                  PERFC_MAX_PT_UPDATES)

PERFCOUNTER_ARRAY(hypercalls,           "hypercalls", NR_hypercalls)
PERFCOUNTER_ARRAY(exceptions,           "exceptions", 32)

#define VMX_PERF_EXIT_REASON_SIZE 37
#define VMX_PERF_VECTOR_SIZE 0x20
PERFCOUNTER_ARRAY(vmexits,              "vmexits", VMX_PERF_EXIT_REASON_SIZE)
PERFCOUNTER_ARRAY(cause_vector,         "cause vector", VMX_PERF_VECTOR_SIZE)

PERFCOUNTER_CPU(seg_fixups,             "segmentation fixups")

PERFCOUNTER_CPU(irqs,                   "#interrupts")
PERFCOUNTER_CPU(ipis,                   "#IPIs")
PERFCOUNTER_CPU(irq_time,               "cycles spent in irq handler")

PERFCOUNTER_CPU(apic_timer,             "apic timer interrupts")
PERFCOUNTER_CPU(timer_max,           "timer max error (ns)")
PERFCOUNTER_CPU(sched_irq,              "sched: timer")
PERFCOUNTER_CPU(sched_run,              "sched: runs through scheduler")
PERFCOUNTER_CPU(sched_ctx,              "sched: context switches")

PERFCOUNTER_CPU(domain_page_tlb_flush,  "domain page tlb flushes")
PERFCOUNTER_CPU(need_flush_tlb_flush,   "PG_need_flush tlb flushes")

PERFCOUNTER_CPU(calls_to_mmu_update,    "calls_to_mmu_update")
PERFCOUNTER_CPU(num_page_updates,       "num_page_updates")
PERFCOUNTER_CPU(calls_to_update_va,     "calls_to_update_va_map")
PERFCOUNTER_CPU(page_faults,            "page faults")
PERFCOUNTER_CPU(copy_user_faults,       "copy_user faults")

PERFCOUNTER_CPU(shadow_fault_calls,     "calls to shadow_fault")
PERFCOUNTER_CPU(shadow_fault_bail_pde_not_present,
                "sf bailed due to pde not present")
PERFCOUNTER_CPU(shadow_fault_bail_pte_not_present,
                "sf bailed due to pte not present")
PERFCOUNTER_CPU(shadow_fault_bail_ro_mapping,
                "sf bailed due to a ro mapping")
PERFCOUNTER_CPU(shadow_fault_fixed,     "sf fixed the pgfault")
PERFCOUNTER_CPU(write_fault_bail,       "sf bailed due to write_fault")
PERFCOUNTER_CPU(read_fault_bail,        "sf bailed due to read_fault")

PERFCOUNTER_CPU(map_domain_page_count,  "map_domain_page count")
PERFCOUNTER_CPU(ptwr_emulations,        "writable pt emulations")

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
PERFCOUNTER_CPU(shadow_l4_table_count,  "shadow_l4_table count")
PERFCOUNTER_CPU(shadow_l3_table_count,  "shadow_l3_table count")
#endif
PERFCOUNTER_CPU(shadow_l2_table_count,  "shadow_l2_table count")
PERFCOUNTER_CPU(shadow_l1_table_count,  "shadow_l1_table count")
PERFCOUNTER_CPU(unshadow_table_count,   "unshadow_table count")
PERFCOUNTER_CPU(shadow_fixup_count,     "shadow_fixup count")
PERFCOUNTER_CPU(shadow_update_va_fail1, "shadow_update_va_fail1")
PERFCOUNTER_CPU(shadow_update_va_fail2, "shadow_update_va_fail2")

/* STATUS counters do not reset when 'P' is hit */
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
PERFSTATUS(shadow_l4_pages,             "current # shadow L4 pages")
PERFSTATUS(shadow_l3_pages,             "current # shadow L3 pages")
#endif
PERFSTATUS(shadow_l2_pages,             "current # shadow L2 pages")
PERFSTATUS(shadow_l1_pages,             "current # shadow L1 pages")
PERFSTATUS(hl2_table_pages,             "current # hl2 pages")
PERFSTATUS(snapshot_pages,              "current # fshadow snapshot pages")
PERFSTATUS(writable_pte_predictions,    "# writable pte predictions")
PERFSTATUS(free_l1_pages,               "current # free shadow L1 pages")

PERFCOUNTER_CPU(check_pagetable,        "calls to check_pagetable")
PERFCOUNTER_CPU(check_all_pagetables,   "calls to check_all_pagetables")

PERFCOUNTER_CPU(shadow_hl2_table_count, "shadow_hl2_table count")
PERFCOUNTER_CPU(shadow_set_l1e_force_map, "shadow_set_l1e forced to map l1")
PERFCOUNTER_CPU(shadow_set_l1e_unlinked, "shadow_set_l1e found unlinked l1")
PERFCOUNTER_CPU(shadow_set_l1e_fail,    "shadow_set_l1e failed (no sl1)")
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
PERFCOUNTER_CPU(shadow_set_l2e_force_map, "shadow_set_l2e forced to map l2")
PERFCOUNTER_CPU(shadow_set_l3e_force_map, "shadow_set_l3e forced to map l3")
#endif
PERFCOUNTER_CPU(shadow_invlpg_faults,   "shadow_invlpg's get_user faulted")
PERFCOUNTER_CPU(unshadow_l2_count,      "unpinned L2 count")

PERFCOUNTER_CPU(shadow_status_shortcut, "fastpath miss on shadow cache")
PERFCOUNTER_CPU(shadow_status_calls,    "calls to shadow_status")
PERFCOUNTER_CPU(shadow_status_miss,     "missed shadow cache")
PERFCOUNTER_CPU(shadow_status_hit_head, "hits on head of bucket")
PERFCOUNTER_CPU(shadow_max_type,        "calls to shadow_max_type")

PERFCOUNTER_CPU(shadow_sync_all,        "calls to shadow_sync_all")
PERFCOUNTER_CPU(shadow_sync_va,         "calls to shadow_sync_va")
PERFCOUNTER_CPU(resync_l1,              "resync L1 page")
PERFCOUNTER_CPU(resync_l2,              "resync L2 page")
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
PERFCOUNTER_CPU(resync_l3,              "resync L3 page")
PERFCOUNTER_CPU(resync_l4,              "resync L4 page")
#endif
PERFCOUNTER_CPU(resync_hl2,             "resync HL2 page")
PERFCOUNTER_CPU(shadow_make_snapshot,   "snapshots created")
PERFCOUNTER_CPU(shadow_mark_mfn_out_of_sync_calls,
                "calls to shadow_mk_out_of_sync")
PERFCOUNTER_CPU(shadow_out_of_sync_calls, "calls to shadow_out_of_sync")
PERFCOUNTER_CPU(snapshot_entry_matches_calls, "calls to ss_entry_matches")
PERFCOUNTER_CPU(snapshot_entry_matches_true, "ss_entry_matches returns true")

PERFCOUNTER_CPU(validate_pte_calls,     "calls to validate_pte_change")
PERFCOUNTER_CPU(validate_pte_changes1,  "validate_pte makes changes1")
PERFCOUNTER_CPU(validate_pte_changes2,  "validate_pte makes changes2")
PERFCOUNTER_CPU(validate_pte_changes3,  "validate_pte makes changes3")
PERFCOUNTER_CPU(validate_pte_changes4,  "validate_pte makes changes4")
PERFCOUNTER_CPU(validate_pde_calls,     "calls to validate_pde_change")
PERFCOUNTER_CPU(validate_pde_changes,   "validate_pde makes changes")
PERFCOUNTER_CPU(shadow_get_page_fail,   "shadow_get_page_from_l1e fails")
PERFCOUNTER_CPU(validate_hl2e_calls,    "calls to validate_hl2e_change")
PERFCOUNTER_CPU(validate_hl2e_changes,  "validate_hl2e makes changes")
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
PERFCOUNTER_CPU(validate_entry_changes,  "validate_entry changes")
#endif
PERFCOUNTER_CPU(exception_fixed,        "pre-exception fixed")
PERFCOUNTER_CPU(get_mfn_from_gpfn_foreign, "calls to get_mfn_from_gpfn_foreign")
PERFCOUNTER_CPU(remove_all_access,      "calls to remove_all_access")
PERFCOUNTER_CPU(remove_write_access,    "calls to remove_write_access")
PERFCOUNTER_CPU(remove_write_access_easy, "easy outs of remove_write_access")
PERFCOUNTER_CPU(remove_write_no_work,   "no work in remove_write_access")
PERFCOUNTER_CPU(remove_write_not_writable, "remove_write non-writable page")
PERFCOUNTER_CPU(remove_write_fast_exit, "remove_write hit predicted entry")
PERFCOUNTER_CPU(remove_write_predicted, "remove_write predict hit&exit")
PERFCOUNTER_CPU(remove_write_bad_prediction, "remove_write bad prediction")
PERFCOUNTER_CPU(update_hl2e_invlpg,     "update_hl2e calls invlpg")

/*#endif*/ /* __XEN_PERFC_DEFN_H__ */
