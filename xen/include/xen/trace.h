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

#include <xen/types.h>
#include <public/sysctl.h>
#include <public/trace.h>

#ifdef CONFIG_TRACEBUFFER

extern bool tb_init_done;

/* Used to initialise trace buffer functionality */
void init_trace_bufs(void);

/* used to retrieve the physical address of the trace buffers */
int tb_control(struct xen_sysctl_tbuf_op *tbc);

int trace_will_trace_event(u32 event);

/* Create a trace record, with pre-constructed additional parameters. */
void trace(uint32_t event, unsigned int extra, const void *extra_data);

void __trace_hypercall(uint32_t event, unsigned long op,
                       const xen_ulong_t *args);

#else /* CONFIG_TRACEBUFFER */

#include <xen/errno.h>

#define tb_init_done false

static inline void init_trace_bufs(void) {}
static inline int tb_control(struct xen_sysctl_tbuf_op *tbc)
{
    return -ENOSYS;
}

static inline int trace_will_trace_event(uint32_t event)
{
    return 0;
}

static inline void trace(
    uint32_t event, unsigned int extra, const void *extra_data) {}

static inline void __trace_hypercall(uint32_t event, unsigned long op,
                                     const xen_ulong_t *args) {}
#endif /* CONFIG_TRACEBUFFER */

/* Create a trace record with time included. */
static inline void trace_time(
    uint32_t event, unsigned int extra, const void *extra_data)
{
    trace(event | TRC_HD_CYCLE_FLAG, extra, extra_data);
}

/*
 * Create a trace record, packaging up to 7 additional parameters into a
 * uint32_t array.
 */
#define TRACE(_e, ...)                                          \
    do {                                                        \
        if ( unlikely(tb_init_done) )                           \
        {                                                       \
            uint32_t _d[] = { __VA_ARGS__ };                    \
            BUILD_BUG_ON(ARRAY_SIZE(_d) > TRACE_EXTRA_MAX);     \
            trace(_e, sizeof(_d), sizeof(_d) ? _d : NULL);      \
        }                                                       \
    } while ( 0 )

/* Create a trace record with time included. */
#define TRACE_TIME(_e, ...) TRACE((_e) | TRC_HD_CYCLE_FLAG, ## __VA_ARGS__)

#endif /* __XEN_TRACE_H__ */
