/******************************************************************************
 * common/trace.c
 *
 * Xen Trace Buffer
 *
 * Copyright (C) 2004 by Intel Research Cambridge
 *
 * Author: Mark Williamson, mark.a.williamson@intel.com
 * Date:   January 2004
 *
 * The trace buffer code is designed to allow debugging traces of Xen to be
 * generated on UP / SMP machines.  Each trace entry is timestamped so that
 * it's possible to reconstruct a chronological record of trace events.
 *
 * See also include/xeno/trace.h and the dom0 op in
 * include/hypervisor-ifs/dom0_ops.h
 */

#include <xeno/config.h>

#ifdef TRACE_BUFFER

#include <asm/timex.h>
#include <asm/types.h>
#include <asm/io.h>
#include <xeno/lib.h>
#include <xeno/sched.h>
#include <xeno/slab.h>
#include <xeno/smp.h>
#include <xeno/spinlock.h>
#include <xeno/trace.h>
#include <asm/atomic.h>

/* Pointers to the meta-data objects for all system trace buffers */
struct t_buf *t_bufs[NR_CPUS];

/* a flag recording whether initialisation has been done */
int tb_init_done = 0;

/**
 * init_trace_bufs - performs initialisation of the per-cpu trace buffers.
 *
 * This function is called at start of day in order to initialise the per-cpu
 * trace buffers.  The trace buffers are then available for debugging use, via
 * the %TRACE_xD macros exported in <xeno/trace.h>.
 */
void init_trace_bufs(void)
{
    int           i;
    char         *rawbuf;
    struct t_buf *buf;

    if ( (rawbuf = kmalloc(smp_num_cpus * TB_SIZE, GFP_KERNEL)) == NULL )
    {
        printk("Xen trace buffers: memory allocation failed\n");
        return;
    }
    
    for ( i = 0; i < smp_num_cpus; i++ )
    {
        buf = t_bufs[i] = (struct t_buf *)&rawbuf[i*TB_SIZE];
        
        /* For use in Xen. */
        buf->vdata    = (struct t_rec *)(buf+1);
        buf->head_ptr = buf->vdata;
        spin_lock_init(&buf->lock);
        
        /* For use in user space. */
        buf->data = (struct t_rec *)__pa(buf->vdata);
        buf->head = 0;

        /* For use in both. */
        buf->size = (TB_SIZE - sizeof(struct t_buf)) / sizeof(struct t_rec);
    }

    printk("Xen trace buffers: initialised\n");
 
    wmb(); /* above must be visible before tb_init_done flag set */

    tb_init_done = 1;
}

/**
 * get_tb_ptr - return physical address of the trace buffers.
 *
 * Called by the %DOM0_GETTBUFS dom0 op to fetch the physical address of the
 * trace buffers.
 */
unsigned long get_tb_ptr(void)
{
    /* Return the physical address. */
    return __pa(t_bufs[0]);
}

#endif /* TRACE_BUFFER */
