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

#include <public/trace.h>

#ifdef TRACE_BUFFER

#include <xen/spinlock.h>
#include <asm/page.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/atomic.h>
#include <asm/current.h>
#include <asm/msr.h>
#include <public/dom0_ops.h>

/* Used to initialise trace buffer functionality */
void init_trace_bufs(void);

/* used to retrieve the physical address of the trace buffers */
int get_tb_info(dom0_gettbufs_t *st);

/**
 * trace - Enters a trace tuple into the trace buffer for the current CPU.
 * @event: the event type being logged
 * @d1...d5: the data items for the event being logged
 *
 * Logs a trace record into the appropriate buffer.  Returns nonzero on
 * failure, otherwise 0.  Failure occurs only if the trace buffers are not yet
 * initialised.
 */
static inline int trace(u32 event, u32 d1, u32 d2, u32 d3, u32 d4, u32 d5)
{
    extern struct t_buf *t_bufs[];      /* global array of pointers to bufs */
    extern int tb_init_done;            /* set when buffers are initialised */
    unsigned long flags;                /* for saving interrupt flags       */
    struct t_buf *buf;                  /* the buffer we're working on      */
    struct t_rec *rec;                  /* next record to fill out          */


    if ( !tb_init_done )
        return -1;


    buf = t_bufs[smp_processor_id()];

    local_irq_save(flags);

    rec = buf->head_ptr;

    rdtscll(rec->cycles);
    rec->event = event;
    rec->d1 = d1;
    rec->d2 = d2;
    rec->d3 = d3;
    rec->d4 = d4;
    rec->d5 = d5;

    wmb(); /* above must be visible before reader sees index updated */

    buf->head_ptr++;
    buf->head++;
    if ( buf->head_ptr == (buf->vdata + buf->size) )
        buf->head_ptr = buf->vdata;

    local_irq_restore(flags);
    
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

#else

#define init_trace_bufs() ((void)0)

#define TRACE_0D(event)                ((void)0)
#define TRACE_1D(event,d)              ((void)0)
#define TRACE_2D(event,d1,d2)          ((void)0)
#define TRACE_3D(event,d1,d2,d3)       ((void)0)
#define TRACE_4D(event,d1,d2,d3,d4)    ((void)0)
#define TRACE_5D(event,d1,d2,d3,d4,d5) ((void)0)

#endif /* TRACE_BUFFER */

#endif /* __XEN_TRACE_H__ */
