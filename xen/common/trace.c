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
static struct t_buf *t_bufs[NR_CPUS];
static struct t_rec *t_recs[NR_CPUS];
static int nr_recs;

/* a flag recording whether initialization has been done */
/* or more properly, if the tbuf subsystem is enabled right now */
int tb_init_done;

/* which CPUs tracing is enabled on */
static unsigned long tb_cpu_mask = (~0UL);

/* which tracing events are enabled */
static u32 tb_event_mask = TRC_ALL;

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
static int alloc_trace_bufs(void)
{
    int           i, order;
    unsigned long nr_pages;
    char         *rawbuf;
    struct t_buf *buf;

    if ( opt_tbuf_size == 0 )
        return -EINVAL;

    nr_pages = num_online_cpus() * opt_tbuf_size;
    order    = get_order_from_pages(nr_pages);
    nr_recs  = (opt_tbuf_size * PAGE_SIZE - sizeof(struct t_buf)) /
        sizeof(struct t_rec);
    
    if ( (rawbuf = alloc_xenheap_pages(order)) == NULL )
    {
        printk("Xen trace buffers: memory allocation failed\n");
        return -EINVAL;
    }

    /* Share pages so that xentrace can map them. */
    for ( i = 0; i < nr_pages; i++ )
        share_xen_page_with_privileged_guests(
            virt_to_page(rawbuf) + i, XENSHARE_writable);

    for_each_online_cpu ( i )
    {
        buf = t_bufs[i] = (struct t_buf *)&rawbuf[i*opt_tbuf_size*PAGE_SIZE];
        buf->cons = buf->prod = 0;
        t_recs[i] = (struct t_rec *)(buf + 1);
    }

    return 0;
}


/**
 * tb_set_size - handle the logic involved with dynamically
 * allocating and deallocating tbufs
 *
 * This function is called when the SET_SIZE hypercall is done.
 */
static int tb_set_size(int size)
{
    /*
     * Setting size is a one-shot operation. It can be done either at
     * boot time or via control tools, but not by both. Once buffers
     * are created they cannot be destroyed.
     */
    if ( (opt_tbuf_size != 0) || (size <= 0) )
    {
        DPRINTK("tb_set_size from %d to %d not implemented\n",
                opt_tbuf_size, size);
        return -EINVAL;
    }

    opt_tbuf_size = size;
    if ( alloc_trace_bufs() != 0 )
    {
        opt_tbuf_size = 0;
        return -EINVAL;
    }

    printk("Xen trace buffers: initialized\n");
    return 0;
}


/**
 * init_trace_bufs - performs initialization of the per-cpu trace buffers.
 *
 * This function is called at start of day in order to initialize the per-cpu
 * trace buffers.  The trace buffers are then available for debugging use, via
 * the %TRACE_xD macros exported in <xen/trace.h>.
 */
void init_trace_bufs(void)
{
    if ( opt_tbuf_size == 0 )
    {
        printk("Xen trace buffers: disabled\n");
        return;
    }

    if ( alloc_trace_bufs() == 0 )
    {
        printk("Xen trace buffers: initialised\n");
        wmb(); /* above must be visible before tb_init_done flag set */
        tb_init_done = 1;
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

    spin_lock(&lock);

    if ( !tb_init_done &&
         (tbc->op != DOM0_TBUF_SET_SIZE) &&
         (tbc->op != DOM0_TBUF_ENABLE) )
    {
        spin_unlock(&lock);
        return -EINVAL;
    }

    switch ( tbc->op )
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
        rc = !tb_init_done ? tb_set_size(tbc->size) : -EINVAL;
        break;
    case DOM0_TBUF_ENABLE:
        /* Enable trace buffers. Check buffers are already allocated. */
        if ( opt_tbuf_size == 0 ) 
            rc = -EINVAL;
        else
            tb_init_done = 1;
        break;
    case DOM0_TBUF_DISABLE:
        /*
         * Disable trace buffers. Just stops new records from being written,
         * does not deallocate any memory.
         */
        tb_init_done = 0;
        break;
    default:
        rc = -EINVAL;
        break;
    }

    spin_unlock(&lock);

    return rc;
}

/**
 * trace - Enters a trace tuple into the trace buffer for the current CPU.
 * @event: the event type being logged
 * @d1...d5: the data items for the event being logged
 *
 * Logs a trace record into the appropriate buffer.  Returns nonzero on
 * failure, otherwise 0.  Failure occurs only if the trace buffers are not yet
 * initialised.
 */
void trace(u32 event, unsigned long d1, unsigned long d2,
           unsigned long d3, unsigned long d4, unsigned long d5)
{
    struct t_buf *buf;
    struct t_rec *rec;
    unsigned long flags;

    BUG_ON(!tb_init_done);

    if ( (tb_event_mask & event) == 0 )
        return;

    /* match class */
    if ( ((tb_event_mask >> TRC_CLS_SHIFT) & (event >> TRC_CLS_SHIFT)) == 0 )
        return;

    /* then match subclass */
    if ( (((tb_event_mask >> TRC_SUBCLS_SHIFT) & 0xf )
                & ((event >> TRC_SUBCLS_SHIFT) & 0xf )) == 0 )
        return;

    if ( (tb_cpu_mask & (1UL << smp_processor_id())) == 0 )
        return;

    /* Read tb_init_done /before/ t_bufs. */
    rmb();

    buf = t_bufs[smp_processor_id()];

    local_irq_save(flags);

    if ( (buf->prod - buf->cons) >= nr_recs )
    {
        local_irq_restore(flags);
        return;
    }

    rec = &t_recs[smp_processor_id()][buf->prod % nr_recs];
    rec->cycles  = (u64)get_cycles();
    rec->event   = event;
    rec->data[0] = d1;
    rec->data[1] = d2;
    rec->data[2] = d3;
    rec->data[3] = d4;
    rec->data[4] = d5;

    wmb();
    buf->prod++;

    local_irq_restore(flags);
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
