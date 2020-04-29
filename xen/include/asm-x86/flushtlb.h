/******************************************************************************
 * flushtlb.h
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2004, K A Fraser
 */

#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

#include <xen/mm.h>
#include <xen/percpu.h>
#include <xen/smp.h>
#include <xen/types.h>

/* The current time as shown by the virtual TLB clock. */
extern u32 tlbflush_clock;

/* Time at which each CPU's TLB was last flushed. */
DECLARE_PER_CPU(u32, tlbflush_time);

/* TLB clock is in use. */
extern bool tlb_clk_enabled;

static inline uint32_t tlbflush_current_time(void)
{
    /* Returning 0 from tlbflush_current_time will always force a flush. */
    return tlb_clk_enabled ? tlbflush_clock : 0;
}

static inline void page_set_tlbflush_timestamp(struct page_info *page)
{
    /* Avoid the write if the TLB clock is disabled. */
    if ( !tlb_clk_enabled )
        return;

    /*
     * Prevent storing a stale time stamp, which could happen if an update
     * to tlbflush_clock plus a subsequent flush IPI happen between the
     * reading of tlbflush_clock and the writing of the struct page_info
     * field.
     */
    ASSERT(local_irq_is_enabled());
    local_irq_disable();
    page->tlbflush_timestamp = tlbflush_current_time();
    local_irq_enable();
}

/*
 * @cpu_stamp is the timestamp at last TLB flush for the CPU we are testing.
 * @lastuse_stamp is a timestamp taken when the PFN we are testing was last 
 * used for a purpose that may have caused the CPU's TLB to become tainted.
 */
static inline bool NEED_FLUSH(u32 cpu_stamp, u32 lastuse_stamp)
{
    u32 curr_time = tlbflush_current_time();
    /*
     * Two cases:
     *  1. During a wrap, the clock ticks over to 0 while CPUs catch up. For
     *     safety during this period, we force a flush if @curr_time == 0.
     *  2. Otherwise, we look to see if @cpu_stamp <= @lastuse_stamp.
     *     To detect false positives because @cpu_stamp has wrapped, we
     *     also check @curr_time. If less than @lastuse_stamp we definitely
     *     wrapped, so there's no need for a flush (one is forced every wrap).
     */
    return ((curr_time == 0) ||
            ((cpu_stamp <= lastuse_stamp) &&
             (lastuse_stamp <= curr_time)));
}

/*
 * Filter the given set of CPUs, removing those that definitely flushed their
 * TLB since @page_timestamp.
 */
static inline void tlbflush_filter(cpumask_t *mask, uint32_t page_timestamp)
{
    unsigned int cpu;

    /* Short-circuit: there's no need to iterate if the clock is disabled. */
    if ( !tlb_clk_enabled )
        return;

    for_each_cpu ( cpu, mask )
        if ( !NEED_FLUSH(per_cpu(tlbflush_time, cpu), page_timestamp) )
            __cpumask_clear_cpu(cpu, mask);
}

void new_tlbflush_clock_period(void);

/* Read pagetable base. */
static inline unsigned long read_cr3(void)
{
    unsigned long cr3;
    __asm__ __volatile__ (
        "mov %%cr3, %0" : "=r" (cr3) : );
    return cr3;
}

/* Write pagetable base and implicitly tick the tlbflush clock. */
void switch_cr3_cr4(unsigned long cr3, unsigned long cr4);

/* flush_* flag fields: */
 /*
  * Area to flush: 2^flush_order pages. Default is flush entire address space.
  * NB. Multi-page areas do not need to have been mapped with a superpage.
  */
#define FLUSH_ORDER_MASK 0xff
#define FLUSH_ORDER(x)   ((x)+1)
 /* Flush TLBs (or parts thereof) */
#define FLUSH_TLB        0x100
 /* Flush TLBs (or parts thereof) including global mappings */
#define FLUSH_TLB_GLOBAL 0x200
 /* Flush data caches */
#define FLUSH_CACHE      0x400
 /* VA for the flush has a valid mapping */
#define FLUSH_VA_VALID   0x800
 /* Flush CPU state */
#define FLUSH_VCPU_STATE 0x1000
 /* Flush the per-cpu root page table */
#define FLUSH_ROOT_PGTBL 0x2000
#if CONFIG_HVM
 /* Flush all HVM guests linear TLB (using ASID/VPID) */
#define FLUSH_HVM_ASID_CORE 0x4000
#else
#define FLUSH_HVM_ASID_CORE 0
#endif

/* Flush local TLBs/caches. */
unsigned int flush_area_local(const void *va, unsigned int flags);
#define flush_local(flags) flush_area_local(NULL, flags)

/* Flush specified CPUs' TLBs/caches */
void flush_area_mask(const cpumask_t *, const void *va, unsigned int flags);
#define flush_mask(mask, flags) flush_area_mask(mask, NULL, flags)

/* Flush all CPUs' TLBs/caches */
#define flush_area_all(va, flags) flush_area_mask(&cpu_online_map, va, flags)
#define flush_all(flags) flush_mask(&cpu_online_map, flags)

/* Flush local TLBs */
#define flush_tlb_local()                       \
    flush_local(FLUSH_TLB)
#define flush_tlb_one_local(v)                  \
    flush_area_local((const void *)(v), FLUSH_TLB|FLUSH_ORDER(0))

/* Flush specified CPUs' TLBs */
#define flush_tlb_mask(mask)                    \
    flush_mask(mask, FLUSH_TLB)
#define flush_tlb_one_mask(mask,v)              \
    flush_area_mask(mask, (const void *)(v), FLUSH_TLB|FLUSH_ORDER(0))

/* Flush all CPUs' TLBs */
#define flush_tlb_all()                         \
    flush_tlb_mask(&cpu_online_map)
#define flush_tlb_one_all(v)                    \
    flush_tlb_one_mask(&cpu_online_map, v)

#define flush_root_pgtbl_domain(d)                                       \
{                                                                        \
    if ( is_pv_domain(d) && (d)->arch.pv.xpti )                          \
        flush_mask((d)->dirty_cpumask, FLUSH_ROOT_PGTBL);                \
}

static inline void flush_page_to_ram(unsigned long mfn, bool sync_icache) {}
static inline int invalidate_dcache_va_range(const void *p,
                                             unsigned long size)
{ return -EOPNOTSUPP; }
static inline int clean_and_invalidate_dcache_va_range(const void *p,
                                                       unsigned long size)
{
    unsigned int order = get_order_from_bytes(size);
    /* sub-page granularity support needs to be added if necessary */
    flush_area_local(p, FLUSH_CACHE|FLUSH_ORDER(order));
    return 0;
}
static inline int clean_dcache_va_range(const void *p, unsigned long size)
{
    return clean_and_invalidate_dcache_va_range(p, size);
}

unsigned int guest_flush_tlb_flags(const struct domain *d);
void guest_flush_tlb_mask(const struct domain *d, const cpumask_t *mask);

#endif /* __FLUSHTLB_H__ */
