/******************************************************************************
 * flushtlb.c
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2006, K A Fraser
 */

#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <asm/flushtlb.h>
#include <asm/invpcid.h>
#include <asm/page.h>
#include <asm/pv/domain.h>

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
    hvm_flush_guest_tlbs();

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
    unsigned long cr4;
    u32 t = pre_flush();

    if ( use_invpcid )
        invpcid_flush_all();
    else if ( (cr4 = read_cr4()) & X86_CR4_PGE )
    {
        write_cr4(cr4 & ~X86_CR4_PGE);
        write_cr4(cr4);
    }
    else
        write_cr3(read_cr3());

    post_flush(t);
}

void switch_cr3_cr4(unsigned long cr3, unsigned long cr4)
{
    unsigned long flags, old_cr4, old_pcid;
    u32 t;

    /* This non-reentrant function is sometimes called in interrupt context. */
    local_irq_save(flags);

    t = pre_flush();

    old_cr4 = read_cr4();
    if ( old_cr4 & X86_CR4_PGE )
    {
        /*
         * X86_CR4_PGE set means PCID is inactive.
         * We have to purge the TLB via flipping cr4.pge.
         */
        old_cr4 = cr4 & ~X86_CR4_PGE;
        write_cr4(old_cr4);
    }
    else if ( use_invpcid )
    {
        /*
         * Flushing the TLB via INVPCID is necessary only in case PCIDs are
         * in use, which is true only with INVPCID being available.
         * Without PCID usage the following write_cr3() will purge the TLB
         * (we are in the cr4.pge off path) of all entries.
         * Using invpcid_flush_all_nonglobals() seems to be faster than
         * invpcid_flush_all(), so use that.
         */
        invpcid_flush_all_nonglobals();

        /*
         * CR4.PCIDE needs to be set before the CR3 write below. Otherwise
         * - the CR3 write will fault when CR3.NOFLUSH is set (which is the
         *   case normally),
         * - the subsequent CR4 write will fault if CR3.PCID != 0.
         */
        if ( (old_cr4 & X86_CR4_PCIDE) < (cr4 & X86_CR4_PCIDE) )
        {
            write_cr4(cr4);
            old_cr4 = cr4;
        }
    }

    /*
     * If we don't change PCIDs, the CR3 write below needs to flush this very
     * PCID, even when a full flush was performed above, as we are currently
     * accumulating TLB entries again from the old address space.
     * NB: Clearing the bit when we don't use PCID is benign (as it is clear
     * already in that case), but allows the if() to be more simple.
     */
    old_pcid = cr3_pcid(read_cr3());
    if ( old_pcid == cr3_pcid(cr3) )
        cr3 &= ~X86_CR3_NOFLUSH;

    write_cr3(cr3);

    if ( old_cr4 != cr4 )
        write_cr4(cr4);

    /*
     * Make sure no TLB entries related to the old PCID created between
     * flushing the TLB and writing the new %cr3 value remain in the TLB.
     *
     * The write to CR4 just above has performed a wider flush in certain
     * cases, which therefore get excluded here. Since that write is
     * conditional, note in particular that it won't be skipped if PCIDE
     * transitions from 1 to 0. This is because the CR4 write further up will
     * have been skipped in this case, as PCIDE and PGE won't both be set at
     * the same time.
     *
     * Note also that PGE is always clear in old_cr4.
     */
    if ( old_pcid != cr3_pcid(cr3) &&
         !(cr4 & X86_CR4_PGE) &&
         (old_cr4 & X86_CR4_PCIDE) <= (cr4 & X86_CR4_PCIDE) )
        invpcid_flush_single_context(old_pcid);

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
                if ( !cpu_has_no_xpti )
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
            alternative(ASM_NOP3, "sfence", X86_FEATURE_CLFLUSHOPT);
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

    local_irq_restore(irqfl);

    if ( flags & FLUSH_ROOT_PGTBL )
        get_cpu_info()->root_pgt_changed = true;

    return flags;
}
