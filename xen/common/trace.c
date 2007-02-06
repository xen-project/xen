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
 */

#include <xen/config.h>
#include <asm/types.h>
#include <asm/io.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/trace.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/softirq.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/percpu.h>
#include <asm/atomic.h>
#include <public/sysctl.h>

#ifdef CONFIG_COMPAT
#include <compat/trace.h>
#define xen_t_buf t_buf
CHECK_t_buf;
#undef xen_t_buf
#define TB_COMPAT IS_COMPAT(dom0)
#else
#define compat_t_rec t_rec
#define TB_COMPAT 0
#endif

typedef union {
	struct t_rec *nat;
	struct compat_t_rec *cmp;
} t_rec_u;

/* opt_tbuf_size: trace buffer size (in pages) */
static unsigned int opt_tbuf_size = 0;
integer_param("tbuf_size", opt_tbuf_size);

/* Pointers to the meta-data objects for all system trace buffers */
static DEFINE_PER_CPU(struct t_buf *, t_bufs);
static DEFINE_PER_CPU(t_rec_u, t_recs);
static int nr_recs;

/* High water mark for trace buffers; */
/* Send virtual interrupt when buffer level reaches this point */
static int t_buf_highwater;

/* Number of records lost due to per-CPU trace buffer being full. */
static DEFINE_PER_CPU(unsigned long, lost_records);

/* a flag recording whether initialization has been done */
/* or more properly, if the tbuf subsystem is enabled right now */
int tb_init_done;

/* which CPUs tracing is enabled on */
static cpumask_t tb_cpu_mask = CPU_MASK_ALL;

/* which tracing events are enabled */
static u32 tb_event_mask = TRC_ALL;

static void trace_notify_guest(void)
{
    send_guest_global_virq(dom0, VIRQ_TBUF);
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
        (!TB_COMPAT ? sizeof(struct t_rec) : sizeof(struct compat_t_rec));
    
    if ( (rawbuf = alloc_xenheap_pages(order)) == NULL )
    {
        printk("Xen trace buffers: memory allocation failed\n");
        opt_tbuf_size = 0;
        return -EINVAL;
    }

    /* Share pages so that xentrace can map them. */
    for ( i = 0; i < nr_pages; i++ )
        share_xen_page_with_privileged_guests(
            virt_to_page(rawbuf) + i, XENSHARE_writable);

    for_each_online_cpu ( i )
    {
        buf = per_cpu(t_bufs, i) = (struct t_buf *)
            &rawbuf[i*opt_tbuf_size*PAGE_SIZE];
        buf->cons = buf->prod = 0;
        per_cpu(t_recs, i).nat = (struct t_rec *)(buf + 1);
    }

    t_buf_highwater = nr_recs >> 1; /* 50% high water */
    open_softirq(TRACE_SOFTIRQ, trace_notify_guest);

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
        gdprintk(XENLOG_INFO, "tb_set_size from %d to %d not implemented\n",
                opt_tbuf_size, size);
        return -EINVAL;
    }

    opt_tbuf_size = size;
    if ( alloc_trace_bufs() != 0 )
        return -EINVAL;

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
 * tb_control - sysctl operations on trace buffers.
 * @tbc: a pointer to a xen_sysctl_tbuf_op_t to be filled out
 */
int tb_control(xen_sysctl_tbuf_op_t *tbc)
{
    static DEFINE_SPINLOCK(lock);
    int rc = 0;

    spin_lock(&lock);

    switch ( tbc->cmd )
    {
    case XEN_SYSCTL_TBUFOP_get_info:
        tbc->evt_mask   = tb_event_mask;
        tbc->buffer_mfn = opt_tbuf_size ? virt_to_mfn(per_cpu(t_bufs, 0)) : 0;
        tbc->size       = opt_tbuf_size * PAGE_SIZE;
        break;
    case XEN_SYSCTL_TBUFOP_set_cpu_mask:
        xenctl_cpumap_to_cpumask(&tb_cpu_mask, &tbc->cpu_mask);
        break;
    case XEN_SYSCTL_TBUFOP_set_evt_mask:
        tb_event_mask = tbc->evt_mask;
        break;
    case XEN_SYSCTL_TBUFOP_set_size:
        rc = !tb_init_done ? tb_set_size(tbc->size) : -EINVAL;
        break;
    case XEN_SYSCTL_TBUFOP_enable:
        /* Enable trace buffers. Check buffers are already allocated. */
        if ( opt_tbuf_size == 0 ) 
            rc = -EINVAL;
        else
            tb_init_done = 1;
        break;
    case XEN_SYSCTL_TBUFOP_disable:
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
    t_rec_u rec;
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

    if ( !cpu_isset(smp_processor_id(), tb_cpu_mask) )
        return;

    /* Read tb_init_done /before/ t_bufs. */
    rmb();

    buf = this_cpu(t_bufs);

    local_irq_save(flags);

    /* Check if space for two records (we write two if there are lost recs). */
    if ( (buf->prod - buf->cons) >= (nr_recs - 1) )
    {
        this_cpu(lost_records)++;
        local_irq_restore(flags);
        return;
    }

    if ( unlikely(this_cpu(lost_records) != 0) )
    {
        if ( !TB_COMPAT )
        {
            rec.nat = &this_cpu(t_recs).nat[buf->prod % nr_recs];
            memset(rec.nat, 0, sizeof(*rec.nat));
            rec.nat->cycles  = (u64)get_cycles();
            rec.nat->event   = TRC_LOST_RECORDS;
            rec.nat->data[0] = this_cpu(lost_records);
            this_cpu(lost_records) = 0;
        }
        else
        {
            rec.cmp = &this_cpu(t_recs).cmp[buf->prod % nr_recs];
            memset(rec.cmp, 0, sizeof(*rec.cmp));
            rec.cmp->cycles  = (u64)get_cycles();
            rec.cmp->event   = TRC_LOST_RECORDS;
            rec.cmp->data[0] = this_cpu(lost_records);
            this_cpu(lost_records) = 0;
        }

        wmb();
        buf->prod++;
    }

    if ( !TB_COMPAT )
    {
        rec.nat = &this_cpu(t_recs).nat[buf->prod % nr_recs];
        rec.nat->cycles  = (u64)get_cycles();
        rec.nat->event   = event;
        rec.nat->data[0] = d1;
        rec.nat->data[1] = d2;
        rec.nat->data[2] = d3;
        rec.nat->data[3] = d4;
        rec.nat->data[4] = d5;
    }
    else
    {
        rec.cmp = &this_cpu(t_recs).cmp[buf->prod % nr_recs];
        rec.cmp->cycles  = (u64)get_cycles();
        rec.cmp->event   = event;
        rec.cmp->data[0] = d1;
        rec.cmp->data[1] = d2;
        rec.cmp->data[2] = d3;
        rec.cmp->data[3] = d4;
        rec.cmp->data[4] = d5;
    }

    wmb();
    buf->prod++;

    local_irq_restore(flags);

    /*
     * Notify trace buffer consumer that we've reached the high water mark.
     *
     */
    if ( (buf->prod - buf->cons) == t_buf_highwater )
        raise_softirq(TRACE_SOFTIRQ);
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
