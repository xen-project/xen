/******************************************************************************
 *
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
 *
 *****************************************************************************/

#include <xeno/config.h>

#ifdef TRACE_BUFFER /* don't compile this stuff in unless explicitly enabled */

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
atomic_t tb_init_done = ATOMIC_INIT(0);


/**
 * init_trace_bufs - performs initialisation of the per-cpu trace buffers.
 *
 * This function is called at start of day in order to initialise the per-cpu
 * trace buffers.  The trace buffers are then available for debugging use, via
 * the %TRACE_xD macros exported in <xeno/trace.h>.
 */
void init_trace_bufs()
{
    int i;
    void *d;     /* trace buffer area pointer */

    d = kmalloc(smp_num_cpus * TB_SIZE, GFP_KERNEL);
    
    if( d == NULL ) {
        printk("Xen trace buffers: memory allocation failed\n");
        return;
    }
    
    for(i = 0; i < smp_num_cpus; i++) {
        struct t_buf *buf = t_bufs[i]
	  = (struct t_buf *)( (unsigned int)d + TB_SIZE * i );
        
        /* for use in Xen */
        buf->vdata = (struct t_rec *)
            ( (unsigned int)buf + sizeof(struct t_buf) );
        buf->head_ptr = buf->vdata;
	spin_lock_init(&buf->lock);
        
        /* for use in user space */
        buf->data = (struct t_rec *)__pa(buf->vdata);
	buf->head = 0;

        /* for use in both */
	buf->size = (TB_SIZE - sizeof(struct t_buf)) / sizeof(struct t_rec);
    }

    printk("Xen trace buffers: initialised\n");
 
    wmb(); /* above must be visible before tb_init_done flag set */

    atomic_set(&tb_init_done, 1);
}

    

/**
 * get_tb_ptr - return physical address of the trace buffers.
 *
 * Called by the %DOM0_GETTBUFS dom0 op to fetch the physical address of the
 * trace buffers.
 */
struct t_buf *get_tb_ptr()
{
    /* a physical address (user space maps this using /dev/mem) */
  return (struct t_buf *)__pa(t_bufs[0]);
}

#endif /* #ifdef TRACE_BUFFER */
