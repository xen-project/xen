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
 */

#ifndef __XEN_TRACE_H__
#define __XEN_TRACE_H__

#include <xen/config.h>
#include <public/sysctl.h>
#include <public/trace.h>

extern int tb_init_done;

/* Used to initialise trace buffer functionality */
void init_trace_bufs(void);

/* used to retrieve the physical address of the trace buffers */
int tb_control(struct xen_sysctl_tbuf_op *tbc);

void trace(u32 event, unsigned long d1, unsigned long d2,
           unsigned long d3, unsigned long d4, unsigned long d5);

/* Avoids troubling the caller with casting their arguments to a trace macro */
#define trace_do_casts(e,d1,d2,d3,d4,d5) \
    do {                                 \
        if ( unlikely(tb_init_done) )    \
            trace(e,                     \
                  (unsigned long)(d1),   \
                  (unsigned long)(d2),   \
                  (unsigned long)(d3),   \
                  (unsigned long)(d4),   \
                  (unsigned long)(d5));  \
    } while ( 0 )

/* Convenience macros for calling the trace function. */
#define TRACE_0D(event)                trace_do_casts(event,0, 0, 0, 0, 0 )
#define TRACE_1D(event,d)              trace_do_casts(event,d, 0, 0, 0, 0 )
#define TRACE_2D(event,d1,d2)          trace_do_casts(event,d1,d2,0, 0, 0 )
#define TRACE_3D(event,d1,d2,d3)       trace_do_casts(event,d1,d2,d3,0, 0 )
#define TRACE_4D(event,d1,d2,d3,d4)    trace_do_casts(event,d1,d2,d3,d4,0 )
#define TRACE_5D(event,d1,d2,d3,d4,d5) trace_do_casts(event,d1,d2,d3,d4,d5)

#endif /* __XEN_TRACE_H__ */
