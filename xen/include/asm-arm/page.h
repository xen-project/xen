#ifndef __ARM_PAGE_H__
#define __ARM_PAGE_H__

#include <public/xen.h>
#include <asm/processor.h>
#include <asm/lpae.h>

#ifdef CONFIG_ARM_64
#define PADDR_BITS              48
#else
#define PADDR_BITS              40
#endif
#define PADDR_MASK              ((1ULL << PADDR_BITS)-1)

#define VADDR_BITS              32
#define VADDR_MASK              (~0UL)

/* Shareability values for the LPAE entries */
#define LPAE_SH_NON_SHAREABLE 0x0
#define LPAE_SH_UNPREDICTALE  0x1
#define LPAE_SH_OUTER         0x2
#define LPAE_SH_INNER         0x3

/* LPAE Memory region attributes, to match Linux's (non-LPAE) choices.
 * Indexed by the AttrIndex bits of a LPAE entry;
 * the 8-bit fields are packed little-endian into MAIR0 and MAIR1
 *
 *                 ai    encoding
 *   UNCACHED      000   0000 0000  -- Strongly Ordered
 *   BUFFERABLE    001   0100 0100  -- Non-Cacheable
 *   WRITETHROUGH  010   1010 1010  -- Write-through
 *   WRITEBACK     011   1110 1110  -- Write-back
 *   DEV_SHARED    100   0000 0100  -- Device
 *   ??            101
 *   reserved      110
 *   WRITEALLOC    111   1111 1111  -- Write-back write-allocate
 *
 *   DEV_NONSHARED 100   (== DEV_SHARED)
 *   DEV_WC        001   (== BUFFERABLE)
 *   DEV_CACHED    011   (== WRITEBACK)
 */
#define MAIR0VAL 0xeeaa4400
#define MAIR1VAL 0xff000004
#define MAIRVAL (MAIR0VAL|MAIR1VAL<<32)

/*
 * Attribute Indexes.
 *
 * These are valid in the AttrIndx[2:0] field of an LPAE stage 1 page
 * table entry. They are indexes into the bytes of the MAIR*
 * registers, as defined above.
 *
 */
#define UNCACHED      0x0
#define BUFFERABLE    0x1
#define WRITETHROUGH  0x2
#define WRITEBACK     0x3
#define DEV_SHARED    0x4
#define WRITEALLOC    0x7
#define DEV_NONSHARED DEV_SHARED
#define DEV_WC        BUFFERABLE
#define DEV_CACHED    WRITEBACK

#define PAGE_HYPERVISOR         (WRITEALLOC)
#define PAGE_HYPERVISOR_NOCACHE (DEV_SHARED)
#define PAGE_HYPERVISOR_WC      (DEV_WC)

/*
 * Defines for changing the hypervisor PTE .ro and .nx bits. This is only to be
 * used with modify_xen_mappings.
 */
#define _PTE_NX_BIT     0U
#define _PTE_RO_BIT     1U
#define PTE_NX          (1U << _PTE_NX_BIT)
#define PTE_RO          (1U << _PTE_RO_BIT)
#define PTE_NX_MASK(x)  (((x) >> _PTE_NX_BIT) & 0x1U)
#define PTE_RO_MASK(x)  (((x) >> _PTE_RO_BIT) & 0x1U)

/*
 * Stage 2 Memory Type.
 *
 * These are valid in the MemAttr[3:0] field of an LPAE stage 2 page
 * table entry.
 *
 */
#define MATTR_DEV     0x1
#define MATTR_MEM_NC  0x5
#define MATTR_MEM     0xf

/* Flags for get_page_from_gva, gvirt_to_maddr etc */
#define GV2M_READ  (0u<<0)
#define GV2M_WRITE (1u<<0)

#ifndef __ASSEMBLY__

#include <xen/errno.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <asm/system.h>

#if defined(CONFIG_ARM_32)
# include <asm/arm32/page.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/page.h>
#else
# error "unknown ARM variant"
#endif

/* Architectural minimum cacheline size is 4 32-bit words. */
#define MIN_CACHELINE_BYTES 16
/* Actual cacheline size on the boot CPU. */
extern size_t cacheline_bytes;

#define copy_page(dp, sp) memcpy(dp, sp, PAGE_SIZE)

/* Functions for flushing medium-sized areas.
 * if 'range' is large enough we might want to use model-specific
 * full-cache flushes. */

static inline int invalidate_dcache_va_range(const void *p, unsigned long size)
{
    const void *end = p + size;
    size_t cacheline_mask = cacheline_bytes - 1;

    dsb(sy);           /* So the CPU issues all writes to the range */

    if ( (uintptr_t)p & cacheline_mask )
    {
        p = (void *)((uintptr_t)p & ~cacheline_mask);
        asm volatile (__clean_and_invalidate_dcache_one(0) : : "r" (p));
        p += cacheline_bytes;
    }
    if ( (uintptr_t)end & cacheline_mask )
    {
        end = (void *)((uintptr_t)end & ~cacheline_mask);
        asm volatile (__clean_and_invalidate_dcache_one(0) : : "r" (end));
    }

    for ( ; p < end; p += cacheline_bytes )
        asm volatile (__invalidate_dcache_one(0) : : "r" (p));

    dsb(sy);           /* So we know the flushes happen before continuing */

    return 0;
}

static inline int clean_dcache_va_range(const void *p, unsigned long size)
{
    const void *end = p + size;
    dsb(sy);           /* So the CPU issues all writes to the range */
    p = (void *)((uintptr_t)p & ~(cacheline_bytes - 1));
    for ( ; p < end; p += cacheline_bytes )
        asm volatile (__clean_dcache_one(0) : : "r" (p));
    dsb(sy);           /* So we know the flushes happen before continuing */
    /* ARM callers assume that dcache_* functions cannot fail. */
    return 0;
}

static inline int clean_and_invalidate_dcache_va_range
    (const void *p, unsigned long size)
{
    const void *end = p + size;
    dsb(sy);         /* So the CPU issues all writes to the range */
    p = (void *)((uintptr_t)p & ~(cacheline_bytes - 1));
    for ( ; p < end; p += cacheline_bytes )
        asm volatile (__clean_and_invalidate_dcache_one(0) : : "r" (p));
    dsb(sy);         /* So we know the flushes happen before continuing */
    /* ARM callers assume that dcache_* functions cannot fail. */
    return 0;
}

/* Macros for flushing a single small item.  The predicate is always
 * compile-time constant so this will compile down to 3 instructions in
 * the common case. */
#define clean_dcache(x) do {                                            \
    typeof(x) *_p = &(x);                                               \
    if ( sizeof(x) > MIN_CACHELINE_BYTES || sizeof(x) > alignof(x) )    \
        clean_dcache_va_range(_p, sizeof(x));                           \
    else                                                                \
        asm volatile (                                                  \
            "dsb sy;"   /* Finish all earlier writes */                 \
            __clean_dcache_one(0)                                       \
            "dsb sy;"   /* Finish flush before continuing */            \
            : : "r" (_p), "m" (*_p));                                   \
} while (0)

#define clean_and_invalidate_dcache(x) do {                             \
    typeof(x) *_p = &(x);                                               \
    if ( sizeof(x) > MIN_CACHELINE_BYTES || sizeof(x) > alignof(x) )    \
        clean_and_invalidate_dcache_va_range(_p, sizeof(x));            \
    else                                                                \
        asm volatile (                                                  \
            "dsb sy;"   /* Finish all earlier writes */                 \
            __clean_and_invalidate_dcache_one(0)                        \
            "dsb sy;"   /* Finish flush before continuing */            \
            : : "r" (_p), "m" (*_p));                                   \
} while (0)

/*
 * Flush a range of VA's hypervisor mappings from the data TLB of the
 * local processor. This is not sufficient when changing code mappings
 * or for self modifying code.
 */
static inline void flush_xen_data_tlb_range_va_local(unsigned long va,
                                                     unsigned long size)
{
    unsigned long end = va + size;
    dsb(sy); /* Ensure preceding are visible */
    while ( va < end )
    {
        __flush_xen_data_tlb_one_local(va);
        va += PAGE_SIZE;
    }
    dsb(sy); /* Ensure completion of the TLB flush */
    isb();
}

/*
 * Flush a range of VA's hypervisor mappings from the data TLB of all
 * processors in the inner-shareable domain. This is not sufficient
 * when changing code mappings or for self modifying code.
 */
static inline void flush_xen_data_tlb_range_va(unsigned long va,
                                               unsigned long size)
{
    unsigned long end = va + size;
    dsb(sy); /* Ensure preceding are visible */
    while ( va < end )
    {
        __flush_xen_data_tlb_one(va);
        va += PAGE_SIZE;
    }
    dsb(sy); /* Ensure completion of the TLB flush */
    isb();
}

/* Flush the dcache for an entire page. */
void flush_page_to_ram(unsigned long mfn, bool sync_icache);

/*
 * Print a walk of a page table or p2m
 *
 * ttbr is the base address register (TTBR0_EL2 or VTTBR_EL2)
 * addr is the PA or IPA to translate
 * root_level is the starting level of the page table
 *   (e.g. TCR_EL2.SL0 or VTCR_EL2.SL0 )
 * nr_root_tables is the number of concatenated tables at the root.
 *   this can only be != 1 for P2M walks starting at the first or
 *   subsequent level.
 */
void dump_pt_walk(paddr_t ttbr, paddr_t addr,
                  unsigned int root_level,
                  unsigned int nr_root_tables);

/* Print a walk of the hypervisor's page tables for a virtual addr. */
extern void dump_hyp_walk(vaddr_t addr);
/* Print a walk of the p2m for a domain for a physical address. */
extern void dump_p2m_lookup(struct domain *d, paddr_t addr);

static inline uint64_t va_to_par(vaddr_t va)
{
    uint64_t par = __va_to_par(va);
    /* It is not OK to call this with an invalid VA */
    if ( par & PAR_F )
    {
        dump_hyp_walk(va);
        panic_PAR(par);
    }
    return par;
}

static inline int gva_to_ipa(vaddr_t va, paddr_t *paddr, unsigned int flags)
{
    uint64_t par = gva_to_ipa_par(va, flags);
    if ( par & PAR_F )
        return -EFAULT;
    *paddr = (par & PADDR_MASK & PAGE_MASK) | ((unsigned long) va & ~PAGE_MASK);
    return 0;
}

/* Bits in the PAR returned by va_to_par */
#define PAR_FAULT 0x1

#endif /* __ASSEMBLY__ */

#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

#endif /* __ARM_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
