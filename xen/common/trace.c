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
#include <xen/slab.h>
#include <xen/smp.h>
#include <xen/trace.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <asm/atomic.h>
#include <public/dom0_ops.h>

/* opt_tbuf_size: trace buffer size (in pages) */
static unsigned int opt_tbuf_size = 10;
integer_param("tbuf_size", opt_tbuf_size);

/* Pointers to the meta-data objects for all system trace buffers */
struct t_buf *t_bufs[NR_CPUS];

/* a flag recording whether initialisation has been done */
int tb_init_done = 0;

/* which CPUs tracing is enabled on */
unsigned long tb_cpu_mask = (~0UL);

/* which tracing events are enabled */
u32 tb_event_mask = TRC_ALL;
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
        SHARE_PFN_WITH_DOMAIN(virt_to_page(rawbuf + i * PAGE_SIZE), dom0);
    
    for ( i = 0; i < smp_num_cpus; i++ )
    {
        buf = t_bufs[i] = (struct t_buf *)&rawbuf[i*opt_tbuf_size*PAGE_SIZE];
        
        _atomic_set(buf->rec_idx, 0);
        buf->rec_num  = (opt_tbuf_size * PAGE_SIZE - sizeof(struct t_buf))
                        / sizeof(struct t_rec);
        buf->rec      = (struct t_rec *)(buf + 1);
        buf->rec_addr = __pa(buf->rec);
    }

    printk("Xen trace buffers: initialised\n");
    
    wmb(); /* above must be visible before tb_init_done flag set */

    tb_init_done = 1;
}

/**
 * tb_control - DOM0 operations on trace buffers.
 * @tbc: a pointer to a dom0_tbufcontrol_t to be filled out
 */
int tb_control(dom0_tbufcontrol_t *tbc)
{
    static spinlock_t lock = SPIN_LOCK_UNLOCKED;
    int rc = 0;

    if ( !tb_init_done )
        return -EINVAL;

    spin_lock(&lock);

    switch ( tbc->op)
    {
    case DOM0_TBUF_GET_INFO:
        tbc->cpu_mask  = tb_cpu_mask;
        tbc->evt_mask  = tb_event_mask;
        tbc->mach_addr = __pa(t_bufs[0]);
        tbc->size      = opt_tbuf_size * PAGE_SIZE;
        break;
    case DOM0_TBUF_SET_CPU_MASK:
        tb_cpu_mask = tbc->cpu_mask;
        break;
    case DOM0_TBUF_SET_EVT_MASK:
        tb_event_mask = tbc->evt_mask;
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
