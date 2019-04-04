#ifndef __ARM_PAGE_H__
#define __ARM_PAGE_H__

#include <public/xen.h>
#include <asm/processor.h>
#include <asm/lpae.h>
#include <asm/sysregs.h>

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

/*
 * Attribute Indexes.
 *
 * These are valid in the AttrIndx[2:0] field of an LPAE stage 1 page
 * table entry. They are indexes into the bytes of the MAIR*
 * registers, as defined below.
 *
 */
#define MT_DEVICE_nGnRnE 0x0
#define MT_NORMAL_NC     0x1
#define MT_NORMAL_WT     0x2
#define MT_NORMAL_WB     0x3
#define MT_DEVICE_nGnRE  0x4
#define MT_NORMAL        0x7

/*
 * LPAE Memory region attributes. Indexed by the AttrIndex bits of a
 * LPAE entry; the 8-bit fields are packed little-endian into MAIR0 and MAIR1.
 *
 * See section "Device memory" B2.7.2 in ARM DDI 0487B.a for more
 * details about the meaning of *G*R*E.
 *
 *                    ai    encoding
 *   MT_DEVICE_nGnRnE 000   0000 0000  -- Strongly Ordered/Device nGnRnE
 *   MT_NORMAL_NC     001   0100 0100  -- Non-Cacheable
 *   MT_NORMAL_WT     010   1010 1010  -- Write-through
 *   MT_NORMAL_WB     011   1110 1110  -- Write-back
 *   MT_DEVICE_nGnRE  100   0000 0100  -- Device nGnRE
 *   ??               101
 *   reserved         110
 *   MT_NORMAL        111   1111 1111  -- Write-back write-allocate
 *
 * /!\ It is not possible to combine the definition in MAIRVAL and then
 * split because it would result to a 64-bit value that some assembler
 * doesn't understand.
 */
#define _MAIR0(attr, mt) (_AC(attr, ULL) << ((mt) * 8))
#define _MAIR1(attr, mt) (_AC(attr, ULL) << (((mt) * 8) - 32))

#define MAIR0VAL (_MAIR0(0x00, MT_DEVICE_nGnRnE)| \
                  _MAIR0(0x44, MT_NORMAL_NC)    | \
                  _MAIR0(0xaa, MT_NORMAL_WT)    | \
                  _MAIR0(0xee, MT_NORMAL_WB))

#define MAIR1VAL (_MAIR1(0x04, MT_DEVICE_nGnRE) | \
                  _MAIR1(0xff, MT_NORMAL))

#define MAIRVAL (MAIR1VAL << 32 | MAIR0VAL)

/*
 * Layout of the flags used for updating the hypervisor page tables
 *
 * [0:2] Memory Attribute Index
 * [3:4] Permission flags
 */
#define PAGE_AI_MASK(x) ((x) & 0x7U)

#define _PAGE_XN_BIT    3
#define _PAGE_RO_BIT    4
#define _PAGE_XN    (1U << _PAGE_XN_BIT)
#define _PAGE_RO    (1U << _PAGE_RO_BIT)
#define PAGE_XN_MASK(x) (((x) >> _PAGE_XN_BIT) & 0x1U)
#define PAGE_RO_MASK(x) (((x) >> _PAGE_RO_BIT) & 0x1U)

/*
 * _PAGE_DEVICE and _PAGE_NORMAL are convenience defines. They are not
 * meant to be used outside of this header.
 */
#define _PAGE_DEVICE    _PAGE_XN
#define _PAGE_NORMAL    MT_NORMAL

#define PAGE_HYPERVISOR_RO      (_PAGE_NORMAL|_PAGE_RO|_PAGE_XN)
#define PAGE_HYPERVISOR_RX      (_PAGE_NORMAL|_PAGE_RO)
#define PAGE_HYPERVISOR_RW      (_PAGE_NORMAL|_PAGE_XN)

#define PAGE_HYPERVISOR         PAGE_HYPERVISOR_RW
#define PAGE_HYPERVISOR_NOCACHE (_PAGE_DEVICE|MT_DEVICE_nGnRE)
#define PAGE_HYPERVISOR_WC      (_PAGE_DEVICE|MT_NORMAL_NC)

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
#define GV2M_EXEC  (1u<<1)

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
/* Min dcache line size on the boot CPU. */
extern size_t dcache_line_bytes;

#define copy_page(dp, sp) memcpy(dp, sp, PAGE_SIZE)

static inline size_t read_dcache_line_bytes(void)
{
    uint32_t ctr;

    /* Read CTR */
    ctr = READ_SYSREG32(CTR_EL0);

    /* Bits 16-19 are the log2 number of words in the cacheline. */
    return (size_t) (4 << ((ctr >> 16) & 0xf));
}

/* Functions for flushing medium-sized areas.
 * if 'range' is large enough we might want to use model-specific
 * full-cache flushes. */

static inline int invalidate_dcache_va_range(const void *p, unsigned long size)
{
    const void *end = p + size;
    size_t cacheline_mask = dcache_line_bytes - 1;

    dsb(sy);           /* So the CPU issues all writes to the range */

    if ( (uintptr_t)p & cacheline_mask )
    {
        p = (void *)((uintptr_t)p & ~cacheline_mask);
        asm volatile (__clean_and_invalidate_dcache_one(0) : : "r" (p));
        p += dcache_line_bytes;
    }
    if ( (uintptr_t)end & cacheline_mask )
    {
        end = (void *)((uintptr_t)end & ~cacheline_mask);
        asm volatile (__clean_and_invalidate_dcache_one(0) : : "r" (end));
    }

    for ( ; p < end; p += dcache_line_bytes )
        asm volatile (__invalidate_dcache_one(0) : : "r" (p));

    dsb(sy);           /* So we know the flushes happen before continuing */

    return 0;
}

static inline int clean_dcache_va_range(const void *p, unsigned long size)
{
    const void *end = p + size;
    dsb(sy);           /* So the CPU issues all writes to the range */
    p = (void *)((uintptr_t)p & ~(dcache_line_bytes - 1));
    for ( ; p < end; p += dcache_line_bytes )
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
    p = (void *)((uintptr_t)p & ~(dcache_line_bytes - 1));
    for ( ; p < end; p += dcache_line_bytes )
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
 * Flush a range of VA's hypervisor mappings from the TLB of the local
 * processor.
 */
static inline void flush_xen_tlb_range_va_local(vaddr_t va,
                                                unsigned long size)
{
    vaddr_t end = va + size;

    dsb(sy); /* Ensure preceding are visible */
    while ( va < end )
    {
        __flush_xen_tlb_one_local(va);
        va += PAGE_SIZE;
    }
    dsb(sy); /* Ensure completion of the TLB flush */
    isb();
}

/*
 * Flush a range of VA's hypervisor mappings from the TLB of all
 * processors in the inner-shareable domain.
 */
static inline void flush_xen_tlb_range_va(vaddr_t va,
                                          unsigned long size)
{
    vaddr_t end = va + size;

    dsb(sy); /* Ensure preceding are visible */
    while ( va < end )
    {
        __flush_xen_tlb_one(va);
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
