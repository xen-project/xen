/******************************************************************************
 * include/xeno/trace.h
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
 * See also common/trace.c and the dom0 op in include/hypervisor-ifs/dom0_ops.h
 */

#ifndef __XENO_TRACE_H__
#define __XENO_TRACE_H__

/*
 * How much space is allowed for a single trace buffer, including data and
 * metadata (and maybe some waste).
 */
#define TB_SIZE PAGE_SIZE

/* This structure represents a single trace buffer record. */
struct t_rec {
    u64 cycles;               /* 64 bit cycle counter timestamp */
    u32 event;                /* 32 bit event ID                */
    u32 d1, d2, d3, d4, d5;   /* event data items               */
};

/*
 * This structure contains the metadata for a single trace buffer.  The head
 * field, indexes into an array of struct t_rec's.
 */
struct t_buf {
    struct t_rec *data;     /* pointer to data area.  physical address
                             * for convenience in user space code            */

    unsigned int size;      /* size of the data area, in t_recs              */
    unsigned int head;      /* array index of the most recent record         */

#ifdef __KERNEL__
    struct t_rec *head_ptr; /* pointer to the head record                    */
    struct t_rec *vdata;    /* virtual address pointer to data               */
    spinlock_t lock;        /* ensure mutually exlusive access (for inserts) */
#endif

    /* never add anything here - the kernel stuff must be the last elements */
};

#ifdef TRACE_BUFFER

#include <xeno/spinlock.h>
#include <asm/page.h>
#include <xeno/types.h>
#include <xeno/sched.h>
#include <asm/atomic.h>
#include <asm/current.h>
#include <asm/msr.h>

/* Used to initialise trace buffer functionality */
void init_trace_bufs(void);

/* used to retrieve the physical address of the trace buffers */
struct t_buf *get_tb_ptr(void);

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
    rec = buf->head_ptr;

    spin_lock_irqsave(&buf->lock, flags);

    rdtscll(rec->cycles);
    rec->event = event;
    rec->d1 = d1;
    rec->d2 = d2;
    rec->d3 = d3;
    rec->d4 = d4;
    rec->d5 = d5;

    wmb(); /* above must be visible before reader sees index updated */

    if ( likely(buf->head_ptr < (buf->vdata + buf->size - 1)) )
    {
        buf->head_ptr++;
        buf->head++;
    }
    else
    {
        buf->head = 0;
        buf->head_ptr = buf->vdata;
    }

    spin_unlock_irqrestore(&buf->lock, flags);
    
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

#endif /* __XENO_TRACE_H__ */
