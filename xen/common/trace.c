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

/* opt_tbuf_size: trace buffer size (in pages) */
static unsigned int opt_tbuf_size = 0;
integer_param("tbuf_size", opt_tbuf_size);

/* Pointers to the meta-data objects for all system trace buffers */
static DEFINE_PER_CPU(struct t_buf *, t_bufs);
static DEFINE_PER_CPU(unsigned char *, t_data);
static int data_size;

/* High water mark for trace buffers; */
/* Send virtual interrupt when buffer level reaches this point */
static int t_buf_highwater;

/* Number of records lost due to per-CPU trace buffer being full. */
static DEFINE_PER_CPU(unsigned long, lost_records);

/* a flag recording whether initialization has been done */
/* or more properly, if the tbuf subsystem is enabled right now */
int tb_init_done __read_mostly;

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
    data_size  = (opt_tbuf_size * PAGE_SIZE - sizeof(struct t_buf));
    
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
        per_cpu(t_data, i) = (unsigned char *)(buf + 1);
    }

    t_buf_highwater = data_size >> 1; /* 50% high water */
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
void __init init_trace_bufs(void)
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

static inline int calc_rec_size(int cycles, int extra) 
{
    int rec_size;
    rec_size = 4;
    if ( cycles )
        rec_size += 8;
    rec_size += extra;
    return rec_size;
}

static inline int calc_unconsumed_bytes(struct t_buf *buf)
{
    int x = buf->prod - buf->cons;
    if ( x < 0 )
        x += 2*data_size;

    ASSERT(x >= 0);
    ASSERT(x <= data_size);

    return x;
}

static inline int calc_bytes_to_wrap(struct t_buf *buf)
{
    int x = data_size - buf->prod;
    if ( x <= 0 )
        x += data_size;

    ASSERT(x > 0);
    ASSERT(x <= data_size);

    return x;
}

static inline int calc_bytes_avail(struct t_buf *buf)
{
    return data_size - calc_unconsumed_bytes(buf);
}

static inline struct t_rec *
next_record(struct t_buf *buf)
{
    int x = buf->prod;
    if ( x >= data_size )
        x -= data_size;

    ASSERT(x >= 0);
    ASSERT(x < data_size);

    return (struct t_rec *)&this_cpu(t_data)[x];
}

static inline int __insert_record(struct t_buf *buf,
                                  unsigned long event,
                                  int extra,
                                  int cycles,
                                  int rec_size,
                                  unsigned char *extra_data)
{
    struct t_rec *rec;
    unsigned char *dst;
    unsigned long extra_word = extra/sizeof(u32);
    int local_rec_size = calc_rec_size(cycles, extra);
    uint32_t next;

    BUG_ON(local_rec_size != rec_size);
    BUG_ON(extra & 3);

    /* Double-check once more that we have enough space.
     * Don't bugcheck here, in case the userland tool is doing
     * something stupid. */
    if ( calc_bytes_avail(buf) < rec_size )
    {
        printk("%s: %u bytes left (%u - ((%u - %u) %% %u) recsize %u.\n",
               __func__,
               calc_bytes_avail(buf),
               data_size, buf->prod, buf->cons, data_size, rec_size);
        return 0;
    }
    rmb();

    rec = next_record(buf);
    rec->event = event;
    rec->extra_u32 = extra_word;
    dst = (unsigned char *)rec->u.nocycles.extra_u32;
    if ( (rec->cycles_included = cycles) != 0 )
    {
        u64 tsc = (u64)get_cycles();
        rec->u.cycles.cycles_lo = (uint32_t)tsc;
        rec->u.cycles.cycles_hi = (uint32_t)(tsc >> 32);
        dst = (unsigned char *)rec->u.cycles.extra_u32;
    } 

    if ( extra_data && extra )
        memcpy(dst, extra_data, extra);

    wmb();

    next = buf->prod + rec_size;
    if ( next >= 2*data_size )
        next -= 2*data_size;
    ASSERT(next >= 0);
    ASSERT(next < 2*data_size);
    buf->prod = next;

    return rec_size;
}

static inline int insert_wrap_record(struct t_buf *buf, int size)
{
    int space_left = calc_bytes_to_wrap(buf);
    unsigned long extra_space = space_left - sizeof(u32);
    int cycles = 0;

    BUG_ON(space_left > size);

    /* We may need to add cycles to take up enough space... */
    if ( (extra_space/sizeof(u32)) > TRACE_EXTRA_MAX )
    {
        cycles = 1;
        extra_space -= sizeof(u64);
        ASSERT((extra_space/sizeof(u32)) <= TRACE_EXTRA_MAX);
    }

    return __insert_record(buf,
                    TRC_TRACE_WRAP_BUFFER,
                    extra_space,
                    cycles,
                    space_left,
                    NULL);
}

#define LOST_REC_SIZE 8

static inline int insert_lost_records(struct t_buf *buf)
{
    struct {
        u32 lost_records;
    } ed;

    ed.lost_records = this_cpu(lost_records);

    this_cpu(lost_records) = 0;

    return __insert_record(buf,
                           TRC_LOST_RECORDS,
                           sizeof(ed),
                           0 /* !cycles */,
                           LOST_REC_SIZE,
                           (unsigned char *)&ed);
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
void __trace_var(u32 event, int cycles, int extra, unsigned char *extra_data)
{
    struct t_buf *buf;
    unsigned long flags, bytes_to_tail, bytes_to_wrap;
    int rec_size, total_size;
    int extra_word;
    int started_below_highwater;

    ASSERT(tb_init_done);

    /* Convert byte count into word count, rounding up */
    extra_word = (extra / sizeof(u32));
    if ( (extra % sizeof(u32)) != 0 )
        extra_word++;
    
    ASSERT(extra_word <= TRACE_EXTRA_MAX);
    extra_word = min_t(int, extra_word, TRACE_EXTRA_MAX);

    /* Round size up to nearest word */
    extra = extra_word * sizeof(u32);

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

    started_below_highwater = (calc_unconsumed_bytes(buf) < t_buf_highwater);

    /* Calculate the record size */
    rec_size = calc_rec_size(cycles, extra);
 
    /* How many bytes are available in the buffer? */
    bytes_to_tail = calc_bytes_avail(buf);
    
    /* How many bytes until the next wrap-around? */
    bytes_to_wrap = calc_bytes_to_wrap(buf);
    
    /* 
     * Calculate expected total size to commit this record by
     * doing a dry-run.
     */
    total_size = 0;

    /* First, check to see if we need to include a lost_record.
     */
    if ( this_cpu(lost_records) )
    {
        if ( LOST_REC_SIZE > bytes_to_wrap )
        {
            total_size += bytes_to_wrap;
            bytes_to_wrap = data_size;
        } 
        total_size += LOST_REC_SIZE;
        bytes_to_wrap -= LOST_REC_SIZE;

        /* LOST_REC might line up perfectly with the buffer wrap */
        if ( bytes_to_wrap == 0 )
            bytes_to_wrap = data_size;
    }

    if ( rec_size > bytes_to_wrap )
    {
        total_size += bytes_to_wrap;
    } 
    total_size += rec_size;

    /* Do we have enough space for everything? */
    if ( total_size > bytes_to_tail )
    {
        this_cpu(lost_records)++;
        local_irq_restore(flags);
        return;
    }

    /*
     * Now, actually write information 
     */
    bytes_to_wrap = calc_bytes_to_wrap(buf);

    if ( this_cpu(lost_records) )
    {
        if ( LOST_REC_SIZE > bytes_to_wrap )
        {
            insert_wrap_record(buf, LOST_REC_SIZE);
            bytes_to_wrap = data_size;
        } 
        insert_lost_records(buf);
        bytes_to_wrap -= LOST_REC_SIZE;

        /* LOST_REC might line up perfectly with the buffer wrap */
        if ( bytes_to_wrap == 0 )
            bytes_to_wrap = data_size;
    }

    if ( rec_size > bytes_to_wrap )
        insert_wrap_record(buf, rec_size);

    /* Write the original record */
    __insert_record(buf, event, extra, cycles, rec_size, extra_data);

    local_irq_restore(flags);

    /* Notify trace buffer consumer that we've crossed the high water mark. */
    if ( started_below_highwater &&
         (calc_unconsumed_bytes(buf) >= t_buf_highwater) )
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
