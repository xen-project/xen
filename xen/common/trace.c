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
#include <xen/tasklet.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/percpu.h>
#include <xen/cpu.h>
#include <asm/atomic.h>
#include <public/sysctl.h>

#ifdef CONFIG_COMPAT
#include <compat/trace.h>
#define xen_t_buf t_buf
CHECK_t_buf;
#undef xen_t_buf
#else
#define compat_t_rec t_rec
#endif

/* opt_tbuf_size: trace buffer size (in pages) */
static unsigned int opt_tbuf_size = 0;
integer_param("tbuf_size", opt_tbuf_size);

/* Pointers to the meta-data objects for all system trace buffers */
static struct t_info *t_info;
#define T_INFO_PAGES 2  /* Size fixed at 2 pages for now. */
#define T_INFO_SIZE ((T_INFO_PAGES)*(PAGE_SIZE))
static DEFINE_PER_CPU_READ_MOSTLY(struct t_buf *, t_bufs);
static DEFINE_PER_CPU_READ_MOSTLY(unsigned char *, t_data);
static DEFINE_PER_CPU_READ_MOSTLY(spinlock_t, t_lock);
static u32 data_size;
static u32 t_info_first_offset __read_mostly;

/* High water mark for trace buffers; */
/* Send virtual interrupt when buffer level reaches this point */
static u32 t_buf_highwater;

/* Number of records lost due to per-CPU trace buffer being full. */
static DEFINE_PER_CPU(unsigned long, lost_records);
static DEFINE_PER_CPU(unsigned long, lost_records_first_tsc);

/* a flag recording whether initialization has been done */
/* or more properly, if the tbuf subsystem is enabled right now */
int tb_init_done __read_mostly;

/* which CPUs tracing is enabled on */
static cpumask_t tb_cpu_mask = CPU_MASK_ALL;

/* which tracing events are enabled */
static u32 tb_event_mask = TRC_ALL;

/* Return the number of elements _type necessary to store at least _x bytes of data
 * i.e., sizeof(_type) * ans >= _x. */
#define fit_to_type(_type, _x) (((_x)+sizeof(_type)-1) / sizeof(_type))

static void calc_tinfo_first_offset(void)
{
    int offset_in_bytes;
    
    offset_in_bytes = offsetof(struct t_info, mfn_offset[NR_CPUS]);

    t_info_first_offset = fit_to_type(uint32_t, offset_in_bytes);

    gdprintk(XENLOG_INFO, "%s: NR_CPUs %d, offset_in_bytes %d, t_info_first_offset %u\n",
           __func__, NR_CPUS, offset_in_bytes, (unsigned)t_info_first_offset);
}

/**
 * check_tbuf_size - check to make sure that the proposed size will fit
 * in the currently sized struct t_info and allows prod and cons to
 * reach double the value without overflow.
 */
static int check_tbuf_size(u32 pages)
{
    struct t_buf dummy;
    typeof(dummy.prod) size;
    
    size = ((typeof(dummy.prod))pages)  * PAGE_SIZE;
    
    return (size / PAGE_SIZE != pages)
           || (size + size < size)
           || (num_online_cpus() * pages + t_info_first_offset > T_INFO_SIZE / sizeof(uint32_t));
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
    int           i, cpu, order;
    unsigned long nr_pages;
    /* Start after a fixed-size array of NR_CPUS */
    uint32_t *t_info_mfn_list = (uint32_t *)t_info;
    int offset = t_info_first_offset;

    BUG_ON(check_tbuf_size(opt_tbuf_size));

    if ( opt_tbuf_size == 0 )
        return -EINVAL;

    if ( !t_info )
    {
        printk("%s: t_info not allocated, cannot allocate trace buffers!\n",
               __func__);
        return -EINVAL;
    }

    t_info->tbuf_size = opt_tbuf_size;
    printk(XENLOG_INFO "tbuf_size %d\n", t_info->tbuf_size);

    nr_pages = opt_tbuf_size;
    order = get_order_from_pages(nr_pages);

    /*
     * First, allocate buffers for all of the cpus.  If any
     * fails, deallocate what you have so far and exit. 
     */
    for_each_online_cpu(cpu)
    {
        int flags;
        char         *rawbuf;
        struct t_buf *buf;

        if ( (rawbuf = alloc_xenheap_pages(
                order, MEMF_bits(32 + PAGE_SHIFT))) == NULL )
        {
            printk("Xen trace buffers: memory allocation failed\n");
            opt_tbuf_size = 0;
            goto out_dealloc;
        }

        spin_lock_irqsave(&per_cpu(t_lock, cpu), flags);

        per_cpu(t_bufs, cpu) = buf = (struct t_buf *)rawbuf;
        buf->cons = buf->prod = 0;
        per_cpu(t_data, cpu) = (unsigned char *)(buf + 1);

        spin_unlock_irqrestore(&per_cpu(t_lock, cpu), flags);

    }

    /*
     * Now share the pages to xentrace can map them, and write them in
     * the global t_info structure.
     */
    for_each_online_cpu(cpu)
    {
        /* Share pages so that xentrace can map them. */
        char         *rawbuf;

        if ( (rawbuf = (char *)per_cpu(t_bufs, cpu)) )
        {
            struct page_info *p = virt_to_page(rawbuf);
            uint32_t mfn = virt_to_mfn(rawbuf);

            for ( i = 0; i < nr_pages; i++ )
            {
                share_xen_page_with_privileged_guests(
                    p + i, XENSHARE_writable);
            
                t_info_mfn_list[offset + i]=mfn + i;
            }
            /* Write list first, then write per-cpu offset. */
            wmb();
            t_info->mfn_offset[cpu]=offset;
            printk(XENLOG_INFO "p%d mfn %"PRIx32" offset %d\n",
                   cpu, mfn, offset);
            offset+=i;
        }
    }

    data_size  = (opt_tbuf_size * PAGE_SIZE - sizeof(struct t_buf));
    t_buf_highwater = data_size >> 1; /* 50% high water */

    return 0;
out_dealloc:
    for_each_online_cpu(cpu)
    {
        int flags;
        char * rawbuf;

        spin_lock_irqsave(&per_cpu(t_lock, cpu), flags);
        if ( (rawbuf = (char *)per_cpu(t_bufs, cpu)) )
        {
            per_cpu(t_bufs, cpu) = NULL;
            ASSERT(!(virt_to_page(rawbuf)->count_info & PGC_allocated));
            free_xenheap_pages(rawbuf, order);
        }
        spin_unlock_irqrestore(&per_cpu(t_lock, cpu), flags);
    }
    
    return -ENOMEM;
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
    int ret = 0;

    if ( (opt_tbuf_size != 0) )
    {
        if ( size != opt_tbuf_size )
            gdprintk(XENLOG_INFO, "tb_set_size from %d to %d not implemented\n",
                     opt_tbuf_size, size);
        return -EINVAL;
    }

    if ( size <= 0 )
        return -EINVAL;

    if ( check_tbuf_size(size) )
    {
        gdprintk(XENLOG_INFO, "tb size %d too large\n", size);
        return -EINVAL;
    }

    opt_tbuf_size = size;

    if ( (ret = alloc_trace_bufs()) == 0 )
        printk("Xen trace buffers: initialized\n");
    else
        opt_tbuf_size = 0;

    return ret;
}

int trace_will_trace_event(u32 event)
{
    if ( !tb_init_done )
        return 0;

    /*
     * Copied from __trace_var()
     */
    if ( (tb_event_mask & event) == 0 )
        return 0;

    /* match class */
    if ( ((tb_event_mask >> TRC_CLS_SHIFT) & (event >> TRC_CLS_SHIFT)) == 0 )
        return 0;

    /* then match subclass */
    if ( (((tb_event_mask >> TRC_SUBCLS_SHIFT) & 0xf )
                & ((event >> TRC_SUBCLS_SHIFT) & 0xf )) == 0 )
        return 0;

    if ( !cpu_isset(smp_processor_id(), tb_cpu_mask) )
        return 0;

    return 1;
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    if ( action == CPU_UP_PREPARE )
        spin_lock_init(&per_cpu(t_lock, cpu));

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};
/**
 * init_trace_bufs - performs initialization of the per-cpu trace buffers.
 *
 * This function is called at start of day in order to initialize the per-cpu
 * trace buffers.  The trace buffers are then available for debugging use, via
 * the %TRACE_xD macros exported in <xen/trace.h>.
 */
void __init init_trace_bufs(void)
{
    int i;

    /* Calculate offset in u32 of first mfn */
    calc_tinfo_first_offset();

    /* t_info size is fixed for now. Currently this works great, so there
     * seems to be no need to make it dynamic. */
    t_info = alloc_xenheap_pages(get_order_from_pages(T_INFO_PAGES), 0);

    if ( t_info == NULL )
    {
        printk("Xen trace buffers: t_info allocation failed!  Tracing disabled.\n");
        return;
    }

    for_each_online_cpu ( i )
        spin_lock_init(&per_cpu(t_lock, i));
    register_cpu_notifier(&cpu_nfb);

    for(i=0; i<T_INFO_PAGES; i++)
        share_xen_page_with_privileged_guests(
            virt_to_page(t_info) + i, XENSHARE_readonly);

    if ( opt_tbuf_size == 0 )
    {
        printk("Xen trace buffers: disabled\n");
        return;
    }
    else if ( check_tbuf_size(opt_tbuf_size) )
    {
        gdprintk(XENLOG_INFO, "Xen trace buffers: "
                 "tb size %d too large, disabling\n",
                 opt_tbuf_size);
        opt_tbuf_size = 0;
    }

    if ( alloc_trace_bufs() == 0 )
    {
        printk("Xen trace buffers: initialised\n");
        wmb(); /* above must be visible before tb_init_done flag set */
        tb_init_done = 1;
    }
    else
    {
        gdprintk(XENLOG_INFO, "Xen trace buffers: "
                 "allocation size %d failed, disabling\n",
                 opt_tbuf_size);
        opt_tbuf_size = 0;
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
        tbc->buffer_mfn = t_info ? virt_to_mfn(t_info) : 0;
        tbc->size = T_INFO_PAGES * PAGE_SIZE;
        break;
    case XEN_SYSCTL_TBUFOP_set_cpu_mask:
        rc = xenctl_cpumap_to_cpumask(&tb_cpu_mask, &tbc->cpu_mask);
        break;
    case XEN_SYSCTL_TBUFOP_set_evt_mask:
        tb_event_mask = tbc->evt_mask;
        break;
    case XEN_SYSCTL_TBUFOP_set_size:
        rc = tb_set_size(tbc->size);
        break;
    case XEN_SYSCTL_TBUFOP_enable:
        /* Enable trace buffers. Check buffers are already allocated. */
        if ( opt_tbuf_size == 0 ) 
            rc = -EINVAL;
        else
            tb_init_done = 1;
        break;
    case XEN_SYSCTL_TBUFOP_disable:
    {
        /*
         * Disable trace buffers. Just stops new records from being written,
         * does not deallocate any memory.
         */
        int i;

        tb_init_done = 0;
        wmb();
        /* Clear any lost-record info so we don't get phantom lost records next time we
         * start tracing.  Grab the lock to make sure we're not racing anyone.  After this
         * hypercall returns, no more records should be placed into the buffers. */
        for_each_online_cpu(i)
        {
            int flags;
            spin_lock_irqsave(&per_cpu(t_lock, i), flags);
            per_cpu(lost_records, i)=0;
            spin_unlock_irqrestore(&per_cpu(t_lock, i), flags);
        }
    }
        break;
    default:
        rc = -EINVAL;
        break;
    }

    spin_unlock(&lock);

    return rc;
}

static inline unsigned int calc_rec_size(bool_t cycles, unsigned int extra) 
{
    unsigned int rec_size = 4;

    if ( cycles )
        rec_size += 8;
    rec_size += extra;
    return rec_size;
}

static inline bool_t bogus(u32 prod, u32 cons)
{
    if ( unlikely(prod & 3) || unlikely(prod >= 2 * data_size) ||
         unlikely(cons & 3) || unlikely(cons >= 2 * data_size) )
    {
        tb_init_done = 0;
        printk(XENLOG_WARNING "trc#%u: bogus prod (%08x) and/or cons (%08x)\n",
               smp_processor_id(), prod, cons);
        return 1;
    }
    return 0;
}

static inline u32 calc_unconsumed_bytes(const struct t_buf *buf)
{
    u32 prod = buf->prod, cons = buf->cons;
    s32 x;

    barrier(); /* must read buf->prod and buf->cons only once */
    if ( bogus(prod, cons) )
        return data_size;

    x = prod - cons;
    if ( x < 0 )
        x += 2*data_size;

    ASSERT(x >= 0);
    ASSERT(x <= data_size);

    return x;
}

static inline u32 calc_bytes_to_wrap(const struct t_buf *buf)
{
    u32 prod = buf->prod, cons = buf->cons;
    s32 x;

    barrier(); /* must read buf->prod and buf->cons only once */
    if ( bogus(prod, cons) )
        return 0;

    x = data_size - prod;
    if ( x <= 0 )
        x += data_size;

    ASSERT(x > 0);
    ASSERT(x <= data_size);

    return x;
}

static inline u32 calc_bytes_avail(const struct t_buf *buf)
{
    return data_size - calc_unconsumed_bytes(buf);
}

static inline struct t_rec *next_record(const struct t_buf *buf,
                                        uint32_t *next)
{
    u32 x = buf->prod, cons = buf->cons;

    barrier(); /* must read buf->prod and buf->cons only once */
    *next = x;
    if ( !tb_init_done || bogus(x, cons) )
        return NULL;

    if ( x >= data_size )
        x -= data_size;

    ASSERT(x < data_size);

    return (struct t_rec *)&this_cpu(t_data)[x];
}

static inline void __insert_record(struct t_buf *buf,
                                   unsigned long event,
                                   unsigned int extra,
                                   bool_t cycles,
                                   unsigned int rec_size,
                                   const void *extra_data)
{
    struct t_rec *rec;
    unsigned char *dst;
    unsigned int extra_word = extra / sizeof(u32);
    unsigned int local_rec_size = calc_rec_size(cycles, extra);
    uint32_t next;

    BUG_ON(local_rec_size != rec_size);
    BUG_ON(extra & 3);

    rec = next_record(buf, &next);
    if ( !rec )
        return;
    /* Double-check once more that we have enough space.
     * Don't bugcheck here, in case the userland tool is doing
     * something stupid. */
    if ( (unsigned char *)rec + rec_size > this_cpu(t_data) + data_size )
    {
        if ( printk_ratelimit() )
            printk(XENLOG_WARNING
                   "%s: size=%08x prod=%08x cons=%08x rec=%u\n",
                   __func__, data_size, next, buf->cons, rec_size);
        return;
    }

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

    next += rec_size;
    if ( next >= 2*data_size )
        next -= 2*data_size;
    ASSERT(next < 2*data_size);
    buf->prod = next;
}

static inline void insert_wrap_record(struct t_buf *buf,
                                      unsigned int size)
{
    u32 space_left = calc_bytes_to_wrap(buf);
    unsigned int extra_space = space_left - sizeof(u32);
    bool_t cycles = 0;

    BUG_ON(space_left > size);

    /* We may need to add cycles to take up enough space... */
    if ( (extra_space/sizeof(u32)) > TRACE_EXTRA_MAX )
    {
        cycles = 1;
        extra_space -= sizeof(u64);
        ASSERT((extra_space/sizeof(u32)) <= TRACE_EXTRA_MAX);
    }

    __insert_record(buf, TRC_TRACE_WRAP_BUFFER, extra_space, cycles,
                    space_left, NULL);
}

#define LOST_REC_SIZE (4 + 8 + 16) /* header + tsc + sizeof(struct ed) */

static inline void insert_lost_records(struct t_buf *buf)
{
    struct {
        u32 lost_records;
        u32 did:16, vid:16;
        u64 first_tsc;
    } __attribute__((packed)) ed;

    ed.vid = current->vcpu_id;
    ed.did = current->domain->domain_id;
    ed.lost_records = this_cpu(lost_records);
    ed.first_tsc = this_cpu(lost_records_first_tsc);

    this_cpu(lost_records) = 0;

    __insert_record(buf, TRC_LOST_RECORDS, sizeof(ed), 1 /* cycles */,
                    LOST_REC_SIZE, &ed);
}

/*
 * Notification is performed in qtasklet to avoid deadlocks with contexts
 * which __trace_var() may be called from (e.g., scheduler critical regions).
 */
static void trace_notify_dom0(unsigned long unused)
{
    send_guest_global_virq(dom0, VIRQ_TBUF);
}
static DECLARE_TASKLET(trace_notify_dom0_tasklet, trace_notify_dom0, 0);

/**
 * trace - Enters a trace tuple into the trace buffer for the current CPU.
 * @event: the event type being logged
 * @d1...d5: the data items for the event being logged
 *
 * Logs a trace record into the appropriate buffer.  Returns nonzero on
 * failure, otherwise 0.  Failure occurs only if the trace buffers are not yet
 * initialised.
 */
void __trace_var(u32 event, bool_t cycles, unsigned int extra,
                 const void *extra_data)
{
    struct t_buf *buf;
    unsigned long flags;
    u32 bytes_to_tail, bytes_to_wrap;
    unsigned int rec_size, total_size;
    unsigned int extra_word;
    bool_t started_below_highwater;

    if( !tb_init_done )
        return;

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

    spin_lock_irqsave(&this_cpu(t_lock), flags);

    buf = this_cpu(t_bufs);

    if ( unlikely(!buf) )
    {
        /* Make gcc happy */
        started_below_highwater = 0;
        goto unlock;
    }

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
        if ( ++this_cpu(lost_records) == 1 )
            this_cpu(lost_records_first_tsc)=(u64)get_cycles();
        started_below_highwater = 0;
        goto unlock;
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

unlock:
    spin_unlock_irqrestore(&this_cpu(t_lock), flags);

    /* Notify trace buffer consumer that we've crossed the high water mark. */
    if ( likely(buf!=NULL)
         && started_below_highwater
         && (calc_unconsumed_bytes(buf) >= t_buf_highwater) )
        tasklet_schedule(&trace_notify_dom0_tasklet);
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
