/******************************************************************************
 * include/xen/trace.h
 *
 * Xen Trace Buffer
 *
 * Copyright (C) 2003 by Intel Research Cambridge
 *
 * Author: Mark Williamson, mark.a.williamson@intel.com
 * Date:   January 2004
 *
 * Copyright (C) 2005 Bin Ren
 *
 * The trace buffer code is designed to allow debugging traces of Xen to be
 * generated on UP / SMP machines.  Each trace entry is timestamped so that
 * it's possible to reconstruct a chronological record of trace events.
 *
 * Access to the trace buffers is via a dom0 hypervisor op and analysis of
 * trace buffer contents can then be performed using a userland tool.
 *
 * See also common/trace.c and the dom0 op in include/public/dom0_ops.h
 */

#ifndef __XEN_TRACE_H__
#define __XEN_TRACE_H__

#include <asm/page.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/atomic.h>
#include <asm/current.h>
#include <asm/msr.h>
#include <public/dom0_ops.h>
#include <public/trace.h>

extern struct t_buf *t_bufs[];
extern int tb_init_done;
extern unsigned long tb_cpu_mask;
extern u32 tb_event_mask;

/* Used to initialise trace buffer functionality */
void init_trace_bufs(void);

/* used to retrieve the physical address of the trace buffers */
int tb_control(dom0_tbufcontrol_t *tbc);

/**
 * trace - Enters a trace tuple into the trace buffer for the current CPU.
 * @event: the event type being logged
 * @d1...d5: the data items for the event being logged
 *
 * Logs a trace record into the appropriate buffer.  Returns nonzero on
 * failure, otherwise 0.  Failure occurs only if the trace buffers are not yet
 * initialised.
 */
static inline int trace(u32 event, unsigned long d1, unsigned long d2,
                        unsigned long d3, unsigned long d4, unsigned long d5)
{
    atomic_t old, new, seen;
    struct t_buf *buf;
    struct t_rec *rec;

    if ( !tb_init_done )
        return -1;

    if ( (tb_event_mask & event) == 0 )
        return 0;

    /* match class */
    if ( ((tb_event_mask >> TRC_CLS_SHIFT) & (event >> TRC_CLS_SHIFT)) == 0 )
        return 0;

    /* then match subclass */
    if ( (((tb_event_mask >> TRC_SUBCLS_SHIFT) & 0xf )
                & ((event >> TRC_SUBCLS_SHIFT) & 0xf )) == 0 )
        return 0;

    if ( (tb_cpu_mask & (1UL << smp_processor_id())) == 0 )
        return 0;

    buf = t_bufs[smp_processor_id()];

    do
    {
        old = buf->rec_idx;
        _atomic_set(new, (_atomic_read(old) + 1) % buf->rec_num);
        seen = atomic_compareandswap(old, new, &buf->rec_idx);
    }
    while ( unlikely(_atomic_read(seen) != _atomic_read(old)) );

    wmb();

    rec = &buf->rec[_atomic_read(old)];
    rdtscll(rec->cycles);
    rec->event   = event;
    rec->data[0] = d1;
    rec->data[1] = d2;
    rec->data[2] = d3;
    rec->data[3] = d4;
    rec->data[4] = d5;

    return 0;
}

/* Avoids troubling the caller with casting their arguments to a trace macro */
#define trace_do_casts(e,d1,d2,d3,d4,d5)  \
                 trace(e,                 \
                       (unsigned long)d1, \
                       (unsigned long)d2, \
                       (unsigned long)d3, \
                       (unsigned long)d4, \
                       (unsigned long)d5)

/* Convenience macros for calling the trace function. */
#define TRACE_0D(event)                trace_do_casts(event,0, 0, 0, 0, 0 )
#define TRACE_1D(event,d)              trace_do_casts(event,d, 0, 0, 0, 0 )
#define TRACE_2D(event,d1,d2)          trace_do_casts(event,d1,d2,0, 0, 0 )
#define TRACE_3D(event,d1,d2,d3)       trace_do_casts(event,d1,d2,d3,0, 0 )
#define TRACE_4D(event,d1,d2,d3,d4)    trace_do_casts(event,d1,d2,d3,d4,0 )
#define TRACE_5D(event,d1,d2,d3,d4,d5) trace_do_casts(event,d1,d2,d3,d4,d5)

#endif /* __XEN_TRACE_H__ */
