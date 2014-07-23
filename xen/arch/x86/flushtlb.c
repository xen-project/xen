/******************************************************************************
 * flushtlb.c
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2006, K A Fraser
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <asm/flushtlb.h>
#include <asm/page.h>

/* Debug builds: Wrap frequently to stress-test the wrap logic. */
#ifdef NDEBUG
#define WRAP_MASK (0xFFFFFFFFU)
#else
#define WRAP_MASK (0x000003FFU)
#endif

u32 tlbflush_clock = 1U;
DEFINE_PER_CPU(u32, tlbflush_time);

/*
 * pre_flush(): Increment the virtual TLB-flush clock. Returns new clock value.
 * 
 * This must happen *before* we flush the TLB. If we do it after, we race other
 * CPUs invalidating PTEs. For example, a page invalidated after the flush
 * might get the old timestamp, but this CPU can speculatively fetch the
 * mapping into its TLB after the flush but before inc'ing the clock.
 */
static u32 pre_flush(void)
{
    u32 t, t1, t2;

    t = tlbflush_clock;
    do {
        t1 = t2 = t;
        /* Clock wrapped: someone else is leading a global TLB shootdown. */
        if ( unlikely(t1 == 0) )
            goto skip_clocktick;
        t2 = (t + 1) & WRAP_MASK;
    }
    while ( unlikely((t = cmpxchg(&tlbflush_clock, t1, t2)) != t1) );

    /* Clock wrapped: we will lead a global TLB shootdown. */
    if ( unlikely(t2 == 0) )
        raise_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ);

 skip_clocktick:
    return t2;
}

/*
 * post_flush(): Update this CPU's timestamp with specified clock value.
 * 
 * Note that this happens *after* flushing the TLB, as otherwise we can race a 
 * NEED_FLUSH() test on another CPU. (e.g., other CPU sees the updated CPU 
 * stamp and so does not force a synchronous TLB flush, but the flush in this
 * function hasn't yet occurred and so the TLB might be stale). The ordering 
 * would only actually matter if this function were interruptible, and 
 * something that abuses the stale mapping could exist in an interrupt 
 * handler. In fact neither of these is the case, so really we are being ultra 
 * paranoid.
 */
static void post_flush(u32 t)
{
    this_cpu(tlbflush_time) = t;
}

void write_cr3(unsigned long cr3)
{
    unsigned long flags, cr4 = read_cr4();
    u32 t;

    /* This non-reentrant function is sometimes called in interrupt context. */
    local_irq_save(flags);

    t = pre_flush();

    hvm_flush_guest_tlbs();

    write_cr4(cr4 & ~X86_CR4_PGE);
    asm volatile ( "mov %0, %%cr3" : : "r" (cr3) : "memory" );
    write_cr4(cr4);

    post_flush(t);

    local_irq_restore(flags);
}

void flush_area_local(const void *va, unsigned int flags)
{
    const struct cpuinfo_x86 *c = &current_cpu_data;
    unsigned int order = (flags - 1) & FLUSH_ORDER_MASK;
    unsigned long irqfl;

    /* This non-reentrant function is sometimes called in interrupt context. */
    local_irq_save(irqfl);

    if ( flags & (FLUSH_TLB|FLUSH_TLB_GLOBAL) )
    {
        if ( order == 0 )
        {
            /*
             * We don't INVLPG multi-page regions because the 2M/4M/1G
             * region may not have been mapped with a superpage. Also there
             * are various errata surrounding INVLPG usage on superpages, and
             * a full flush is in any case not *that* expensive.
             */
            asm volatile ( "invlpg %0"
                           : : "m" (*(const char *)(va)) : "memory" );
        }
        else
        {
            u32 t = pre_flush();
            unsigned long cr4 = read_cr4();

            hvm_flush_guest_tlbs();

            write_cr4(cr4 & ~X86_CR4_PGE);
            barrier();
            write_cr4(cr4);

            post_flush(t);
        }
    }

    if ( flags & FLUSH_CACHE )
    {
        unsigned long i, sz = 0;

        if ( order < (BITS_PER_LONG - PAGE_SHIFT) )
            sz = 1UL << (order + PAGE_SHIFT);

        if ( !(flags & (FLUSH_TLB|FLUSH_TLB_GLOBAL)) &&
             c->x86_clflush_size && c->x86_cache_size && sz &&
             ((sz >> 10) < c->x86_cache_size) )
        {
            va = (const void *)((unsigned long)va & ~(sz - 1));
            for ( i = 0; i < sz; i += c->x86_clflush_size )
                 asm volatile ( "clflush %0"
                                : : "m" (((const char *)va)[i]) );
        }
        else
        {
            wbinvd();
        }
    }

    local_irq_restore(irqfl);
}
