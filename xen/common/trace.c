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
#include <xen/pfn.h>
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

/* opt_tbuf_size: trace buffer size (in pages) for each cpu */
static unsigned int opt_tbuf_size;
static unsigned int opt_tevt_mask;
integer_param("tbuf_size", opt_tbuf_size);
integer_param("tevt_mask", opt_tevt_mask);

/* Pointers to the meta-data objects for all system trace buffers */
static struct t_info *t_info;
static unsigned int t_info_pages;

static DEFINE_PER_CPU_READ_MOSTLY(struct t_buf *, t_bufs);
static DEFINE_PER_CPU_READ_MOSTLY(spinlock_t, t_lock);
static u32 data_size __read_mostly;

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
static cpumask_t tb_cpu_mask;

/* which tracing events are enabled */
static u32 tb_event_mask = TRC_ALL;

/* Return the number of elements _type necessary to store at least _x bytes of data
 * i.e., sizeof(_type) * ans >= _x. */
#define fit_to_type(_type, _x) (((_x)+sizeof(_type)-1) / sizeof(_type))

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

static uint32_t calc_tinfo_first_offset(void)
{
    int offset_in_bytes = offsetof(struct t_info, mfn_offset[NR_CPUS]);
    return fit_to_type(uint32_t, offset_in_bytes);
}

/**
 * calculate_tbuf_size - check to make sure that the proposed size will fit
 * in the currently sized struct t_info and allows prod and cons to
 * reach double the value without overflow.
 * The t_info layout is fixed and cant be changed without breaking xentrace.
 * Initialize t_info_pages based on number of trace pages.
 */
static int calculate_tbuf_size(unsigned int pages, uint16_t t_info_first_offset)
{
    struct t_buf dummy_size;
    typeof(dummy_size.prod) max_size;
    struct t_info dummy_pages;
    typeof(dummy_pages.tbuf_size) max_pages;
    typeof(dummy_pages.mfn_offset[0]) max_mfn_offset;
    unsigned int max_cpus = num_online_cpus();
    unsigned int t_info_words;

    /* force maximum value for an unsigned type */
    max_size = -1;
    max_pages = -1;
    max_mfn_offset = -1;

    /* max size holds up to n pages */
    max_size /= PAGE_SIZE;

    if ( max_size < max_pages )
        max_pages = max_size;

    /*
     * max mfn_offset holds up to n pages per cpu
     * The array of mfns for the highest cpu can start at the maximum value
     * mfn_offset can hold. So reduce the number of cpus and also the mfn_offset.
     */
    max_mfn_offset -= t_info_first_offset;
    max_cpus--;
    if ( max_cpus )
        max_mfn_offset /= max_cpus;
    if ( max_mfn_offset < max_pages )
        max_pages = max_mfn_offset;

    if ( pages > max_pages )
    {
        printk(XENLOG_INFO "xentrace: requested number of %u pages "
               "reduced to %u\n",
               pages, max_pages);
        pages = max_pages;
    }

    /* 
     * NB this calculation is correct, because t_info_first_offset is
     * in words, not bytes, not bytes
     */
    t_info_words = num_online_cpus() * pages + t_info_first_offset;
    t_info_pages = PFN_UP(t_info_words * sizeof(uint32_t));
    printk(XENLOG_INFO "xentrace: requesting %u t_info pages "
           "for %u trace pages on %u cpus\n",
           t_info_pages, pages, num_online_cpus());
    return pages;
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
static int alloc_trace_bufs(unsigned int pages)
{
    int i, cpu;
    /* Start after a fixed-size array of NR_CPUS */
    uint32_t *t_info_mfn_list;
    uint16_t t_info_first_offset;
    uint16_t offset;

    if ( t_info )
        return -EBUSY;

    if ( pages == 0 )
        return -EINVAL;

    /* Calculate offset in units of u32 of first mfn */
    t_info_first_offset = calc_tinfo_first_offset();

    pages = calculate_tbuf_size(pages, t_info_first_offset);

    t_info = alloc_xenheap_pages(get_order_from_pages(t_info_pages), 0);
    if ( t_info == NULL )
        goto out_fail;

    memset(t_info, 0, t_info_pages*PAGE_SIZE);

    t_info_mfn_list = (uint32_t *)t_info;

    t_info->tbuf_size = pages;

    /*
     * Allocate buffers for all of the cpus.
     * If any fails, deallocate what you have so far and exit.
     */
    for_each_online_cpu(cpu)
    {
        offset = t_info_first_offset + (cpu * pages);
        t_info->mfn_offset[cpu] = offset;

        for ( i = 0; i < pages; i++ )
        {
            void *p = alloc_xenheap_pages(0, MEMF_bits(32 + PAGE_SHIFT));
            if ( !p )
            {
                printk(XENLOG_INFO "xentrace: memory allocation failed "
                       "on cpu %d after %d pages\n", cpu, i);
                t_info_mfn_list[offset + i] = 0;
                goto out_dealloc;
            }
            t_info_mfn_list[offset + i] = virt_to_mfn(p);
        }
    }

    /*
     * Initialize buffers for all of the cpus.
     */
    for_each_online_cpu(cpu)
    {
        struct t_buf *buf;
        struct page_info *pg;

        spin_lock_init(&per_cpu(t_lock, cpu));

        offset = t_info->mfn_offset[cpu];

        /* Initialize the buffer metadata */
        per_cpu(t_bufs, cpu) = buf = mfn_to_virt(t_info_mfn_list[offset]);
        buf->cons = buf->prod = 0;

        printk(XENLOG_INFO "xentrace: p%d mfn %x offset %u\n",
                   cpu, t_info_mfn_list[offset], offset);

        /* Now share the trace pages */
        for ( i = 0; i < pages; i++ )
        {
            pg = mfn_to_page(t_info_mfn_list[offset + i]);
            share_xen_page_with_privileged_guests(pg, XENSHARE_writable);
        }
    }

    /* Finally, share the t_info page */
    for(i = 0; i < t_info_pages; i++)
        share_xen_page_with_privileged_guests(
            virt_to_page(t_info) + i, XENSHARE_readonly);

    data_size  = (pages * PAGE_SIZE - sizeof(struct t_buf));
    t_buf_highwater = data_size >> 1; /* 50% high water */
    opt_tbuf_size = pages;

    printk("xentrace: initialised\n");
    smp_wmb(); /* above must be visible before tb_init_done flag set */
    tb_init_done = 1;

    return 0;

out_dealloc:
    for_each_online_cpu(cpu)
    {
        offset = t_info->mfn_offset[cpu];
        if ( !offset )
            continue;
        for ( i = 0; i < pages; i++ )
        {
            uint32_t mfn = t_info_mfn_list[offset + i];
            if ( !mfn )
                break;
            ASSERT(!(mfn_to_page(mfn)->count_info & PGC_allocated));
            free_xenheap_pages(mfn_to_virt(mfn), 0);
        }
    }
    free_xenheap_pages(t_info, get_order_from_pages(t_info_pages));
    t_info = NULL;
out_fail:
    printk(XENLOG_WARNING "xentrace: allocation failed! Tracing disabled.\n");
    return -ENOMEM;
}


/**
 * tb_set_size - handle the logic involved with dynamically allocating tbufs
 *
 * This function is called when the SET_SIZE hypercall is done.
 */
static int tb_set_size(unsigned int pages)
{
    /*
     * Setting size is a one-shot operation. It can be done either at
     * boot time or via control tools, but not by both. Once buffers
     * are created they cannot be destroyed.
     */
    if ( opt_tbuf_size && pages != opt_tbuf_size )
    {
        printk(XENLOG_INFO "xentrace: tb_set_size from %d to %d "
               "not implemented\n",
               opt_tbuf_size, pages);
        return -EINVAL;
    }

    return alloc_trace_bufs(pages);
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

    if ( !cpumask_test_cpu(smp_processor_id(), &tb_cpu_mask) )
        return 0;

    return 1;
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
    cpumask_setall(&tb_cpu_mask);
    register_cpu_notifier(&cpu_nfb);

    if ( opt_tbuf_size )
    {
        if ( alloc_trace_bufs(opt_tbuf_size) )
        {
            printk("xentrace: allocation size %d failed, disabling\n",
                   opt_tbuf_size);
            opt_tbuf_size = 0;
        }
        else if ( opt_tevt_mask )
        {
            printk("xentrace: Starting tracing, enabling mask %x\n",
                   opt_tevt_mask);
            tb_event_mask = opt_tevt_mask;
            tb_init_done=1;
        }
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
        tbc->size = t_info_pages * PAGE_SIZE;
        break;
    case XEN_SYSCTL_TBUFOP_set_cpu_mask:
    {
        cpumask_var_t mask;

        rc = xenctl_bitmap_to_cpumask(&mask, &tbc->cpu_mask);
        if ( !rc )
        {
            cpumask_copy(&tb_cpu_mask, mask);
            free_cpumask_var(mask);
        }
    }
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
        smp_wmb();
        /* Clear any lost-record info so we don't get phantom lost records next time we
         * start tracing.  Grab the lock to make sure we're not racing anyone.  After this
         * hypercall returns, no more records should be placed into the buffers. */
        for_each_online_cpu(i)
        {
            unsigned long flags;
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

static unsigned char *next_record(const struct t_buf *buf, uint32_t *next,
                                 unsigned char **next_page,
                                 uint32_t *offset_in_page)
{
    u32 x = buf->prod, cons = buf->cons;
    uint16_t per_cpu_mfn_offset;
    uint32_t per_cpu_mfn_nr;
    uint32_t *mfn_list;
    uint32_t mfn;
    unsigned char *this_page;

    barrier(); /* must read buf->prod and buf->cons only once */
    *next = x;
    if ( !tb_init_done || bogus(x, cons) )
        return NULL;

    if ( x >= data_size )
        x -= data_size;

    ASSERT(x < data_size);

    /* add leading header to get total offset of next record */
    x += sizeof(struct t_buf);
    *offset_in_page = x & ~PAGE_MASK;

    /* offset into array of mfns */
    per_cpu_mfn_nr = x >> PAGE_SHIFT;
    per_cpu_mfn_offset = t_info->mfn_offset[smp_processor_id()];
    mfn_list = (uint32_t *)t_info;
    mfn = mfn_list[per_cpu_mfn_offset + per_cpu_mfn_nr];
    this_page = mfn_to_virt(mfn);
    if (per_cpu_mfn_nr + 1 >= opt_tbuf_size)
    {
        /* reached end of buffer? */
        *next_page = NULL;
    }
    else
    {
        mfn = mfn_list[per_cpu_mfn_offset + per_cpu_mfn_nr + 1];
        *next_page = mfn_to_virt(mfn);
    }
    return this_page;
}

static inline void __insert_record(struct t_buf *buf,
                                   unsigned long event,
                                   unsigned int extra,
                                   bool_t cycles,
                                   unsigned int rec_size,
                                   const void *extra_data)
{
    struct t_rec split_rec, *rec;
    uint32_t *dst;
    unsigned char *this_page, *next_page;
    unsigned int extra_word = extra / sizeof(u32);
    unsigned int local_rec_size = calc_rec_size(cycles, extra);
    uint32_t next;
    uint32_t offset;
    uint32_t remaining;

    BUG_ON(local_rec_size != rec_size);
    BUG_ON(extra & 3);

    this_page = next_record(buf, &next, &next_page, &offset);
    if ( !this_page )
        return;

    remaining = PAGE_SIZE - offset;

    if ( unlikely(rec_size > remaining) )
    {
        if ( next_page == NULL )
        {
            /* access beyond end of buffer */
            printk(XENLOG_WARNING
                   "%s: size=%08x prod=%08x cons=%08x rec=%u remaining=%u\n",
                   __func__, data_size, next, buf->cons, rec_size, remaining);
            return;
        }
        rec = &split_rec;
    } else {
        rec = (struct t_rec*)(this_page + offset);
    }

    rec->event = event;
    rec->extra_u32 = extra_word;
    dst = rec->u.nocycles.extra_u32;
    if ( (rec->cycles_included = cycles) != 0 )
    {
        u64 tsc = (u64)get_cycles();
        rec->u.cycles.cycles_lo = (uint32_t)tsc;
        rec->u.cycles.cycles_hi = (uint32_t)(tsc >> 32);
        dst = rec->u.cycles.extra_u32;
    } 

    if ( extra_data && extra )
        memcpy(dst, extra_data, extra);

    if ( unlikely(rec_size > remaining) )
    {
        memcpy(this_page + offset, rec, remaining);
        memcpy(next_page, (char *)rec + remaining, rec_size - remaining);
    }

    smp_wmb();

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
    struct __packed {
        u32 lost_records;
        u16 did, vid;
        u64 first_tsc;
    } ed;

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
    send_global_virq(VIRQ_TBUF);
}
static DECLARE_SOFTIRQ_TASKLET(trace_notify_dom0_tasklet,
                               trace_notify_dom0, 0);

/**
 * __trace_var - Enters a trace tuple into the trace buffer for the current CPU.
 * @event: the event type being logged
 * @cycles: include tsc timestamp into trace record
 * @extra: size of additional trace data in bytes
 * @extra_data: pointer to additional trace data
 *
 * Logs a trace record into the appropriate buffer.
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

    if ( !cpumask_test_cpu(smp_processor_id(), &tb_cpu_mask) )
        return;

    /* Read tb_init_done /before/ t_bufs. */
    smp_rmb();

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

void __trace_hypercall(uint32_t event, unsigned long op,
                       const xen_ulong_t *args)
{
    struct __packed {
        uint32_t op;
        uint32_t args[6];
    } d;
    uint32_t *a = d.args;

#define APPEND_ARG32(i)                         \
    do {                                        \
        unsigned i_ = (i);                      \
        *a++ = args[(i_)];                      \
        d.op |= TRC_PV_HYPERCALL_V2_ARG_32(i_); \
    } while( 0 )

    /*
     * This shouldn't happen as @op should be small enough but just in
     * case, warn if the argument bits in the trace record would
     * clobber the hypercall op.
     */
    WARN_ON(op & TRC_PV_HYPERCALL_V2_ARG_MASK);

    d.op = op;

    switch ( op )
    {
    case __HYPERVISOR_mmu_update:
        APPEND_ARG32(1); /* count */
        break;
    case __HYPERVISOR_multicall:
        APPEND_ARG32(1); /* count */
        break;
    case __HYPERVISOR_grant_table_op:
        APPEND_ARG32(0); /* cmd */
        APPEND_ARG32(2); /* count */
        break;
    case __HYPERVISOR_vcpu_op:
        APPEND_ARG32(0); /* cmd */
        APPEND_ARG32(1); /* vcpuid */
        break;
    case __HYPERVISOR_mmuext_op:
        APPEND_ARG32(1); /* count */
        break;
    case __HYPERVISOR_sched_op:
        APPEND_ARG32(0); /* cmd */
        break;
    }

    __trace_var(event, 1, sizeof(uint32_t) * (1 + (a - d.args)), &d);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
