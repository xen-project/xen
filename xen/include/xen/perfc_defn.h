PERFCOUNTER_CPU (seg_fixups,   "segmentation fixups" )

PERFCOUNTER_CPU( irqs,         "#interrupts" )
PERFCOUNTER_CPU( ipis,         "#IPIs" )
PERFCOUNTER_CPU( irq_time,     "cycles spent in irq handler" )

PERFCOUNTER_CPU( apic_timer,   "apic timer interrupts" )
PERFCOUNTER_CPU( ac_timer_max, "ac_timer max error (ns)" )
PERFCOUNTER_CPU( sched_irq,    "sched: timer" )
PERFCOUNTER_CPU( sched_run,    "sched: runs through scheduler" )
PERFCOUNTER_CPU( sched_ctx,    "sched: context switches" )

PERFCOUNTER_CPU( domain_page_tlb_flush, "domain page tlb flushes" )
PERFCOUNTER_CPU( need_flush_tlb_flush, "PG_need_flush tlb flushes" )

PERFCOUNTER_CPU( calls_to_mmu_update, "calls_to_mmu_update" )
PERFCOUNTER_CPU( num_page_updates, "num_page_updates" )
PERFCOUNTER_CPU( calls_to_update_va, "calls_to_update_va_map" )
PERFCOUNTER_CPU( page_faults, "page faults" )
PERFCOUNTER_CPU( copy_user_faults, "copy_user faults" )
PERFCOUNTER_CPU( map_domain_mem_count, "map_domain_mem count" )

PERFCOUNTER_CPU( shadow_l2_table_count, "shadow_l2_table count" )
PERFCOUNTER_CPU( shadow_l1_table_count, "shadow_l1_table count" )
PERFCOUNTER_CPU( unshadow_table_count, "unshadow_table count" )
PERFCOUNTER_CPU( shadow_fixup_count, "shadow_fixup count" )
PERFCOUNTER_CPU( shadow_update_va_fail1, "shadow_update_va_fail1" )
PERFCOUNTER_CPU( shadow_update_va_fail2, "shadow_update_va_fail2" )

/* STATUS counters do not reset when 'P' is hit */
PERFSTATUS( shadow_l2_pages, "current # shadow L2 pages" )
PERFSTATUS( shadow_l1_pages, "current # shadow L1 pages" )
PERFSTATUS( hl2_table_pages, "current # hl2 pages" )

PERFCOUNTER_CPU( check_pagetable, "calls to check_pagetable" )
PERFCOUNTER_CPU( check_all_pagetables, "calls to check_all_pagetables" )

#define PERFC_MAX_PT_UPDATES 64
#define PERFC_PT_UPDATES_BUCKET_SIZE 3
PERFCOUNTER_ARRAY( wpt_updates, "writable pt updates", PERFC_MAX_PT_UPDATES )
PERFCOUNTER_ARRAY( bpt_updates, "batched pt updates", PERFC_MAX_PT_UPDATES )

PERFCOUNTER_ARRAY( hypercalls, "hypercalls", NR_hypercalls )
PERFCOUNTER_ARRAY( exceptions, "exceptions", 32 )

#define VMX_PERF_EXIT_REASON_SIZE 37
#define VMX_PERF_VECTOR_SIZE 0x20
PERFCOUNTER_ARRAY( vmexits, "vmexits", VMX_PERF_EXIT_REASON_SIZE )
PERFCOUNTER_ARRAY( cause_vector, "cause vector", VMX_PERF_VECTOR_SIZE )


PERFCOUNTER_CPU( shadow_hl2_table_count,   "shadow_hl2_table count" )
PERFCOUNTER_CPU( shadow_set_l1e_force_map, "shadow_set_l1e forced to map l1" )
PERFCOUNTER_CPU( shadow_set_l1e_unlinked,  "shadow_set_l1e found unlinked l1" )
PERFCOUNTER_CPU( shadow_set_l1e_fail,      "shadow_set_l1e failed (no sl1)" )
PERFCOUNTER_CPU( shadow_invlpg_faults,     "shadow_invlpg's get_user faulted")
PERFCOUNTER_CPU( unshadow_l2_count,        "unpinned L2 count")


/* STATUS counters do not reset when 'P' is hit */
PERFSTATUS( snapshot_pages,  "current # fshadow snapshot pages" )

PERFCOUNTER_CPU(shadow_status_shortcut, "fastpath miss on shadow cache")
PERFCOUNTER_CPU(shadow_status_calls,    "calls to ___shadow_status" )
PERFCOUNTER_CPU(shadow_status_miss,     "missed shadow cache" )
PERFCOUNTER_CPU(shadow_status_hit_head, "hits on head of bucket" )

PERFCOUNTER_CPU(shadow_sync_all,                   "calls to shadow_sync_all")
PERFCOUNTER_CPU(shadow_make_snapshot,              "snapshots created")
PERFCOUNTER_CPU(shadow_mark_mfn_out_of_sync_calls, "calls to shadow_mk_out_of_sync")
PERFCOUNTER_CPU(shadow_out_of_sync_calls,          "calls to shadow_out_of_sync")
PERFCOUNTER_CPU(extra_va_update_sync,              "extra syncs for bug in chk_pgtb")
PERFCOUNTER_CPU(snapshot_entry_matches_calls,      "calls to ss_entry_matches")
PERFCOUNTER_CPU(snapshot_entry_matches_true,       "ss_entry_matches returns true")

PERFCOUNTER_CPU(shadow_fault_calls,                "calls to shadow_fault")
PERFCOUNTER_CPU(shadow_fault_bail_pde_not_present, "sf bailed due to pde not present")
PERFCOUNTER_CPU(shadow_fault_bail_pte_not_present, "sf bailed due to pte not present")
PERFCOUNTER_CPU(shadow_fault_bail_ro_mapping,      "sf bailed due to a ro mapping")
PERFCOUNTER_CPU(shadow_fault_fixed,                "sf fixed the pgfault")
PERFCOUNTER_CPU(validate_pte_calls,                "calls to validate_pte_change")
PERFCOUNTER_CPU(validate_pte_changes,              "validate_pte makes changes")
PERFCOUNTER_CPU(validate_pde_calls,                "calls to validate_pde_change")
PERFCOUNTER_CPU(validate_pde_changes,              "validate_pde makes changes")
PERFCOUNTER_CPU(shadow_get_page_fail,   "shadow_get_page_from_l1e fails" )
