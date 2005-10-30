/******************************************************************************
 * common/trace.c
 *
 * Xen Trace Buffer
 *
 * Copyright (C) 2004 by Intel Research Cambridge
 *
 * Authors: Mark Williamson, mark.a.williamson@intel.com
 *          Rob Gardner, rob.gardner@hp.com
 * Date:    October 2005
 *
 * Copyright (C) 2005 Bin Ren
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
#include <xen/smp.h>
#include <xen/trace.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <asm/atomic.h>
#include <public/dom0_ops.h>

/* opt_tbuf_size: trace buffer size (in pages) */
static unsigned int opt_tbuf_size = 0;
integer_param("tbuf_size", opt_tbuf_size);

/* Pointers to the meta-data objects for all system trace buffers */
struct t_buf *t_bufs[NR_CPUS];

/* a flag recording whether initialization has been done */
/* or more properly, if the tbuf subsystem is enabled right now */
int tb_init_done = 0;

/* which CPUs tracing is enabled on */
unsigned long tb_cpu_mask = (~0UL);

/* which tracing events are enabled */
u32 tb_event_mask = TRC_ALL;

/**
 * init_trace_bufs - performs initialization of the per-cpu trace buffers.
 *
 * This function is called at start of day in order to initialize the per-cpu
 * trace buffers.  The trace buffers are then available for debugging use, via
 * the %TRACE_xD macros exported in <xen/trace.h>.
 */
void init_trace_bufs(void)
{
    extern int alloc_trace_bufs(void);
    
    if ( opt_tbuf_size == 0 )
    {
        printk("Xen trace buffers: disabled\n");
        return;
    }

    if (alloc_trace_bufs() == 0) {
        printk("Xen trace buffers: initialised\n");
        wmb(); /* above must be visible before tb_init_done flag set */
        tb_init_done = 1;
    }
}

/**
 * alloc_trace_bufs - performs initialization of the per-cpu trace buffers.
 *
 * This function is called at start of day in order to initialize the per-cpu
 * trace buffers.  The trace buffers are then available for debugging use, via
 * the %TRACE_xD macros exported in <xen/trace.h>.
 *
 * This function may also be called later when enabling trace buffers 
 * via the SET_SIZE hypercall.
 */
int alloc_trace_bufs(void)
{
    int           i, order;
    unsigned long nr_pages;
    char         *rawbuf;
    struct t_buf *buf;

    if ( opt_tbuf_size == 0 )
        return -EINVAL;

    nr_pages = num_online_cpus() * opt_tbuf_size;
    order    = get_order_from_pages(nr_pages);
    
    if ( (rawbuf = alloc_xenheap_pages(order)) == NULL )
    {
        printk("Xen trace buffers: memory allocation failed\n");
        return -EINVAL;
    }

    /* Share pages so that xentrace can map them. */
    for ( i = 0; i < nr_pages; i++ )
        SHARE_PFN_WITH_DOMAIN(virt_to_page(rawbuf + i * PAGE_SIZE), dom0);
    
    for_each_online_cpu ( i )
    {
        buf = t_bufs[i] = (struct t_buf *)&rawbuf[i*opt_tbuf_size*PAGE_SIZE];
        
        _atomic_set(buf->rec_idx, 0);
        buf->rec_num  = (opt_tbuf_size * PAGE_SIZE - sizeof(struct t_buf))
                        / sizeof(struct t_rec);
        buf->rec      = (struct t_rec *)(buf + 1);
        buf->rec_addr = __pa(buf->rec);
    }
    return 0;
}


/**
 * tb_set_size - handle the logic involved with dynamically
 * allocating and deallocating tbufs
 *
 * This function is called when the SET_SIZE hypercall is done.
 */
int tb_set_size(int size)
{
    // There are three cases to handle:
    //  1. Changing from 0 to non-zero ==> simple allocate
    //  2. Changing from non-zero to 0 ==> simple deallocate
    //  3. Changing size ==> deallocate and reallocate? Or disallow?
    //     User can just do a change to 0, then a change to the new size.
    //
    // Tracing must be disabled (tb_init_done==0) before calling this
    
    if (opt_tbuf_size == 0 && size > 0) {
        // What if size is too big? alloc_xenheap will complain.
        opt_tbuf_size = size;
        if (alloc_trace_bufs() != 0)
            return -EINVAL;
        wmb();
        printk("Xen trace buffers: initialized\n");
        return 0;
    }
    else if (opt_tbuf_size > 0 && size == 0) {
        int order = get_order_from_pages(num_online_cpus() * opt_tbuf_size);
        // is there a way to undo SHARE_PFN_WITH_DOMAIN?
        free_xenheap_pages(t_bufs[0], order);
        opt_tbuf_size = 0;
        printk("Xen trace buffers: uninitialized\n");
        return 0;
    }
    else {
        printk("tb_set_size from %d to %d not implemented\n", opt_tbuf_size, size);
        printk("change size from %d to 0, and then to %d\n",  opt_tbuf_size, size);
        return -EINVAL;
    }
}


/**
 * tb_control - DOM0 operations on trace buffers.
 * @tbc: a pointer to a dom0_tbufcontrol_t to be filled out
 */
int tb_control(dom0_tbufcontrol_t *tbc)
{
    static spinlock_t lock = SPIN_LOCK_UNLOCKED;
    int rc = 0;

    // Commenting this out since we have to allow some of these operations
    // in order to enable dynamic control of the trace buffers.
    //    if ( !tb_init_done )
    //        return -EINVAL;

    spin_lock(&lock);

    switch ( tbc->op)
    {
    case DOM0_TBUF_GET_INFO:
        tbc->cpu_mask   = tb_cpu_mask;
        tbc->evt_mask   = tb_event_mask;
        tbc->buffer_mfn = __pa(t_bufs[0]) >> PAGE_SHIFT;
        tbc->size       = opt_tbuf_size * PAGE_SIZE;
        break;
    case DOM0_TBUF_SET_CPU_MASK:
        tb_cpu_mask = tbc->cpu_mask;
        break;
    case DOM0_TBUF_SET_EVT_MASK:
        tb_event_mask = tbc->evt_mask;
        break;
    case DOM0_TBUF_SET_SIZE:
        // Change trace buffer allocation.
        // Trace buffers must be disabled to do this.
        if (tb_init_done) {
            printk("attempt to change size with tbufs enabled\n");
            rc = -EINVAL;
        }
        else
            rc = tb_set_size(tbc->size);
        break;
    case DOM0_TBUF_ENABLE:
        // Enable trace buffers. Size must be non-zero, ie, buffers
        // must already be allocated. 
        if (opt_tbuf_size == 0) 
            rc = -EINVAL;
        else
            tb_init_done = 1;
        break;
    case DOM0_TBUF_DISABLE:
        // Disable trace buffers. Just stops new records from being written,
        // does not deallocate any memory.
        tb_init_done = 0;
        printk("Xen trace buffers: disabled\n");
        break;
    default:
        rc = -EINVAL;
    }

    spin_unlock(&lock);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
