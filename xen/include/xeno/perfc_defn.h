
PERFCOUNTER_CPU( irqs,         "#interrupts" )
PERFCOUNTER_CPU( irq_time,     "cycles spent in irq handler" )

PERFCOUNTER_CPU( apic_timer,   "apic timer interrupts" )
PERFCOUNTER_CPU( ac_timer_max, "ac_timer max error (ns)" )
PERFCOUNTER_CPU( sched_irq,    "sched: timer" )
PERFCOUNTER_CPU( sched_run,    "sched: runs through scheduler" )
PERFCOUNTER_CPU( sched_ctx,    "sched: context switches" )

PERFCOUNTER( net_hypercalls, "network hypercalls" )
PERFCOUNTER( net_rx_congestion_drop, "net rx congestion drops" )
PERFCOUNTER( net_rx_capacity_drop, "net rx capacity drops" )
PERFCOUNTER( net_rx_delivered, "net rx delivered" )
PERFCOUNTER( net_rx_tlbflush, "net rx tlb flushes" )
PERFCOUNTER( net_tx_transmitted, "net tx transmitted" )

PERFCOUNTER_CPU( domain_page_tlb_flush, "domain page tlb flushes" )
PERFCOUNTER_CPU( need_flush_tlb_flush, "PG_need_flush tlb flushes" )

PERFCOUNTER_CPU( calls_to_mmu_update, "calls_to_mmu_update" )
PERFCOUNTER_CPU( num_page_updates, "num_page_updates" )



