PERFCOUNTER_CPU( irqs,         "#interrupts" )
PERFCOUNTER_CPU( irq_time,     "cycles spent in irq handler" )

PERFCOUNTER( blockio_tx,       "block io: messages received from tx queue" )
PERFCOUNTER( blockio_rx,       "block io: messages sent on rx queue" )

PERFCOUNTER_CPU( apic_timer,   "apic timer interrupts" )
PERFCOUNTER_CPU( ac_timer_max, "ac_timer max error (ns)" )
PERFCOUNTER_CPU( sched_irq,    "sched: timer" )
PERFCOUNTER_CPU( sched_run1,   "sched: calls to schedule" )
PERFCOUNTER_CPU( sched_run2,   "sched: runs through scheduler" )
PERFCOUNTER_CPU( sched_ctx,    "sched: context switches" )

