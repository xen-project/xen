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

/* Put 'tb_init_done' here because 'asm/trace.h' may use it */
#ifdef CONFIG_TRACEBUFFER
extern int tb_init_done;
#else
#define tb_init_done false
#endif

#include <xen/types.h>
#include <public/sysctl.h>
#include <public/trace.h>
#include <asm/trace.h>

#ifdef CONFIG_TRACEBUFFER
/* Used to initialise trace buffer functionality */
void init_trace_bufs(void);

/* used to retrieve the physical address of the trace buffers */
int tb_control(struct xen_sysctl_tbuf_op *tbc);

int trace_will_trace_event(u32 event);

void __trace_var(uint32_t event, bool cycles, unsigned int extra, const void *);

static inline void trace_var(uint32_t event, bool cycles, unsigned int extra,
                             const void *extra_data)
{
    if ( unlikely(tb_init_done) )
        __trace_var(event, cycles, extra, extra_data);
}

void __trace_hypercall(uint32_t event, unsigned long op,
                       const xen_ulong_t *args);

#else /* CONFIG_TRACEBUFFER */

#include <xen/errno.h>

static inline void init_trace_bufs(void) {}
static inline int tb_control(struct xen_sysctl_tbuf_op *tbc)
{
    return -ENOSYS;
}

static inline int trace_will_trace_event(uint32_t event)
{
    return 0;
}

static inline void trace_var(uint32_t event, bool cycles, unsigned int extra,
                             const void *extra_data) {}
static inline void __trace_var(uint32_t event, bool cycles, unsigned int extra,
                               const void *extra_data) {}
static inline void __trace_hypercall(uint32_t event, unsigned long op,
                                     const xen_ulong_t *args) {}
#endif /* CONFIG_TRACEBUFFER */

/* Convenience macros for calling the trace function. */
#define TRACE_0D(_e)                            \
    do {                                        \
        trace_var(_e, 1, 0, NULL);              \
    } while ( 0 )

/* Common helper for TRACE_{1..6}D() below. */
#define TRACE_varD(_e, ...)                             \
    do {                                                \
        if ( unlikely(tb_init_done) )                   \
        {                                               \
            uint32_t _d[] = { __VA_ARGS__ };            \
            __trace_var(_e, true, sizeof(_d), _d);      \
        }                                               \
    } while ( 0 )

#define TRACE_1D(_e, d1) \
    TRACE_varD(_e, d1)

#define TRACE_2D(_e, d1, d2) \
    TRACE_varD(_e, d1, d2)

#define TRACE_3D(_e, d1, d2, d3) \
    TRACE_varD(_e, d1, d2, d3)

#define TRACE_4D(_e, d1, d2, d3, d4) \
    TRACE_varD(_e, d1, d2, d3, d4)

#define TRACE_5D(_e, d1, d2, d3, d4, d5) \
    TRACE_varD(_e, d1, d2, d3, d4, d5)

#define TRACE_6D(_e, d1, d2, d3, d4, d5, d6) \
    TRACE_varD(_e, d1, d2, d3, d4, d5, d6)

#endif /* __XEN_TRACE_H__ */
