
PERFCOUNTER_CPU( irqs,         "#interrupts" )
PERFCOUNTER_CPU( irq_time,     "cycles spent in irq handler" )

PERFCOUNTER_CPU( apic_timer,   "apic timer interrupts" )
PERFCOUNTER_CPU( ac_timer_max, "ac_timer max error (ns)" )
PERFCOUNTER_CPU( sched_irq,    "sched: timer" )
PERFCOUNTER_CPU( sched_run1,   "sched: calls to schedule" )
PERFCOUNTER_CPU( sched_run2,   "sched: runs through scheduler" )
PERFCOUNTER_CPU( sched_ctx,    "sched: context switches" )

PERFCOUNTER( net_hypercalls, "network hypercalls" )
PERFCOUNTER( net_rx_capacity_drop, "net rx capacity drop" )
PERFCOUNTER( net_rx_delivered, "net rx delivered" )
PERFCOUNTER( net_rx_tlbflush, "net rx tlb flushes" )
PERFCOUNTER( net_tx_transmitted, "net tx transmitted" )

PERFCOUNTER( domain_page_tlb_flush, "domain page tlb flushes" )
