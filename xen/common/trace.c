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
 * See also include/xen/trace.h and the dom0 op in
 * include/public/dom0_ops.h
 */

#include <xen/config.h>
#include <asm/types.h>
#include <asm/io.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/slab.h>
#include <xen/smp.h>
#include <xen/trace.h>
#include <xen/errno.h>
#include <asm/atomic.h>
#include <public/dom0_ops.h>

/* opt_tbuf_size: trace buffer size (in pages) */
static unsigned int opt_tbuf_size = 10;
integer_param("tbuf_size", opt_tbuf_size);

/* Pointers to the meta-data objects for all system trace buffers */
struct t_buf *t_bufs[NR_CPUS];

/* a flag recording whether initialisation has been done */
int tb_init_done = 0;

/**
 * init_trace_bufs - performs initialisation of the per-cpu trace buffers.
 *
 * This function is called at start of day in order to initialise the per-cpu
 * trace buffers.  The trace buffers are then available for debugging use, via
 * the %TRACE_xD macros exported in <xen/trace.h>.
 */
void init_trace_bufs(void)
{
    int           i, order;
    unsigned long nr_pages;
    char         *rawbuf;
    struct t_buf *buf;
    
    if ( opt_tbuf_size == 0 )
    {
        printk("Xen trace buffers: disabled\n");
        return;
    }

    nr_pages = smp_num_cpus * opt_tbuf_size;
    order    = get_order(nr_pages * PAGE_SIZE);
    
    if ( (rawbuf = (char *)alloc_xenheap_pages(order)) == NULL )
    {
        printk("Xen trace buffers: memory allocation failed\n");
        return;
    }

    /* Share pages so that xentrace can map them. */

    for ( i = 0; i < nr_pages; i++ )
        SHARE_PFN_WITH_DOMAIN(virt_to_page(rawbuf+(i*PAGE_SIZE)), dom0);
    
    for ( i = 0; i < smp_num_cpus; i++ )
    {
        buf = t_bufs[i] = (struct t_buf *)&rawbuf[i*opt_tbuf_size*PAGE_SIZE];
        
        /* For use in Xen. */
        buf->vdata    = (struct t_rec *)(buf+1);
        buf->head_ptr = buf->vdata;
        
        /* For use in user space. */
        buf->data = __pa(buf->vdata);
        buf->head = 0;

        /* For use in both. */
        buf->size = (opt_tbuf_size * PAGE_SIZE - sizeof(struct t_buf))
            / sizeof(struct t_rec);
    }

    printk("Xen trace buffers: initialised\n");
    
    wmb(); /* above must be visible before tb_init_done flag set */

    tb_init_done = 1;
}

/**
 * get_tb_info - get trace buffer details
 * @st: a pointer to a dom0_gettbufs_t to be filled out
 *
 * Called by the %DOM0_GETTBUFS dom0 op to fetch the machine address of the
 * trace buffers.
 */
int get_tb_info(dom0_gettbufs_t *st)
{
    if ( tb_init_done )
    {
        st->mach_addr = __pa(t_bufs[0]);
        st->size      = opt_tbuf_size * PAGE_SIZE;
        
        return 0;
    }
    else
    {
        st->mach_addr = 0;
        st->size      = 0;
        return -ENODATA;
    }
}
