
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

#define VMX_PERF_EXIT_REASON_SIZE 37
#define VMX_PERF_VECTOR_SIZE 0x20
PERFCOUNTER_ARRAY(vmexits, "vmexits", VMX_PERF_EXIT_REASON_SIZE )
PERFCOUNTER_ARRAY(cause_vector, "cause vector", VMX_PERF_VECTOR_SIZE )
