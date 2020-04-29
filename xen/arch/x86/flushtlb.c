/******************************************************************************
 * flushtlb.c
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2006, K A Fraser
 */

#include <xen/paging.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <asm/flushtlb.h>
#include <asm/invpcid.h>
#include <asm/nops.h>
#include <asm/page.h>
#include <asm/pv/domain.h>
#include <asm/spec_ctrl.h>

/* Debug builds: Wrap frequently to stress-test the wrap logic. */
#ifdef NDEBUG
#define WRAP_MASK (0xFFFFFFFFU)
#else
#define WRAP_MASK (0x000003FFU)
#endif

#ifndef CONFIG_PV
# undef X86_CR4_PCIDE
# define X86_CR4_PCIDE 0
#endif

u32 tlbflush_clock = 1U;
DEFINE_PER_CPU(u32, tlbflush_time);

/* Signals whether the TLB flush clock is in use. */
bool __read_mostly tlb_clk_enabled = true;

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

static void do_tlb_flush(void)
{
    unsigned long flags, cr4;
    u32 t = 0;

    /* This non-reentrant function is sometimes called in interrupt context. */
    local_irq_save(flags);

    if ( tlb_clk_enabled )
        t = pre_flush();

    if ( use_invpcid )
        invpcid_flush_all();
    else if ( (cr4 = read_cr4()) & X86_CR4_PGE )
    {
        write_cr4(cr4 & ~X86_CR4_PGE);
        write_cr4(cr4);
    }
    else
        write_cr3(read_cr3());

    if ( tlb_clk_enabled )
        post_flush(t);

    local_irq_restore(flags);
}

void switch_cr3_cr4(unsigned long cr3, unsigned long cr4)
{
    unsigned long flags, old_cr4;
    u32 t = 0;

    /* Throughout this function we make this assumption: */
    ASSERT(!(cr4 & X86_CR4_PCIDE) || !(cr4 & X86_CR4_PGE));

    /* This non-reentrant function is sometimes called in interrupt context. */
    local_irq_save(flags);

    if ( tlb_clk_enabled )
        t = pre_flush();
    hvm_flush_guest_tlbs();

    old_cr4 = read_cr4();
    ASSERT(!(old_cr4 & X86_CR4_PCIDE) || !(old_cr4 & X86_CR4_PGE));

    /*
     * We need to write CR4 before CR3 if we're about to enable PCIDE, at the
     * very least when the new PCID is non-zero.
     *
     * As we also need to do two CR4 writes in total when PGE is enabled and
     * is to remain enabled, do the one temporarily turning off the bit right
     * here as well.
     *
     * The only TLB flushing effect we depend on here is in case we move from
     * PGE set to PCIDE set, where we want global page entries gone (and none
     * to re-appear) after this write.
     */
    if ( !(old_cr4 & X86_CR4_PCIDE) &&
         ((cr4 & X86_CR4_PCIDE) || (cr4 & old_cr4 & X86_CR4_PGE)) )
    {
        old_cr4 = cr4 & ~X86_CR4_PGE;
        write_cr4(old_cr4);
    }

    /*
     * If the CR4 write is to turn off PCIDE, we don't need the CR3 write to
     * flush anything, as that transition is a full flush itself.
     */
    if ( (old_cr4 & X86_CR4_PCIDE) > (cr4 & X86_CR4_PCIDE) )
        cr3 |= X86_CR3_NOFLUSH;
    write_cr3(cr3);

    if ( old_cr4 != cr4 )
        write_cr4(cr4);

    /*
     *  PGE  | PCIDE | flush at
     * ------+-------+------------------------
     *  0->0 | 0->0  | CR3 write
     *  0->0 | 0->1  | n/a (see 1st CR4 write)
     *  0->x | 1->0  | CR4 write
     *  x->1 | x->1  | n/a
     *  0->0 | 1->1  | INVPCID
     *  0->1 | 0->0  | CR3 and CR4 writes
     *  1->0 | 0->0  | CR4 write
     *  1->0 | 0->1  | n/a (see 1st CR4 write)
     *  1->1 | 0->0  | n/a (see 1st CR4 write)
     *  1->x | 1->x  | n/a
     */
    if ( cr4 & X86_CR4_PCIDE )
        invpcid_flush_all_nonglobals();

    if ( tlb_clk_enabled )
        post_flush(t);

    local_irq_restore(flags);
}

/*
 * The return value of this function is the passed in "flags" argument with
 * bits cleared that have been fully (i.e. system-wide) taken care of, i.e.
 * namely not requiring any further action on remote CPUs.
 */
unsigned int flush_area_local(const void *va, unsigned int flags)
{
    unsigned int order = (flags - 1) & FLUSH_ORDER_MASK;

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
            if ( read_cr4() & X86_CR4_PCIDE )
            {
                unsigned long addr = (unsigned long)va;

                /*
                 * Flush the addresses for all potential address spaces.
                 * We can't check the current domain for being subject to
                 * XPTI as current might be the idle vcpu while we still have
                 * some XPTI domain TLB entries.
                 * Using invpcid is okay here, as with PCID enabled we always
                 * have global pages disabled.
                 */
                invpcid_flush_one(PCID_PV_PRIV, addr);
                invpcid_flush_one(PCID_PV_USER, addr);
                if ( opt_xpti_hwdom || opt_xpti_domu )
                {
                    invpcid_flush_one(PCID_PV_PRIV | PCID_PV_XPTI, addr);
                    invpcid_flush_one(PCID_PV_USER | PCID_PV_XPTI, addr);
                }
            }
            else
                asm volatile ( "invlpg %0"
                               : : "m" (*(const char *)(va)) : "memory" );
        }
        else
            do_tlb_flush();
    }

    if ( flags & FLUSH_HVM_ASID_CORE )
        hvm_flush_guest_tlbs();

    if ( flags & FLUSH_CACHE )
    {
        const struct cpuinfo_x86 *c = &current_cpu_data;
        unsigned long i, sz = 0;

        if ( order < (BITS_PER_LONG - PAGE_SHIFT) )
            sz = 1UL << (order + PAGE_SHIFT);

        if ( (!(flags & (FLUSH_TLB|FLUSH_TLB_GLOBAL)) ||
              (flags & FLUSH_VA_VALID)) &&
             c->x86_clflush_size && c->x86_cache_size && sz &&
             ((sz >> 10) < c->x86_cache_size) )
        {
            alternative("", "sfence", X86_FEATURE_CLFLUSHOPT);
            for ( i = 0; i < sz; i += c->x86_clflush_size )
                alternative_input(".byte " __stringify(NOP_DS_PREFIX) ";"
                                  " clflush %0",
                                  "data16 clflush %0",      /* clflushopt */
                                  X86_FEATURE_CLFLUSHOPT,
                                  "m" (((const char *)va)[i]));
            flags &= ~FLUSH_CACHE;
        }
        else
        {
            wbinvd();
        }
    }

    if ( flags & FLUSH_ROOT_PGTBL )
        get_cpu_info()->root_pgt_changed = true;

    return flags;
}

unsigned int guest_flush_tlb_flags(const struct domain *d)
{
    bool shadow = paging_mode_shadow(d);
    bool asid = is_hvm_domain(d) && (cpu_has_svm || shadow);

    return (shadow ? FLUSH_TLB : 0) | (asid ? FLUSH_HVM_ASID_CORE : 0);
}

void guest_flush_tlb_mask(const struct domain *d, const cpumask_t *mask)
{
    unsigned int flags = guest_flush_tlb_flags(d);

    if ( flags )
        flush_mask(mask, flags);
}
