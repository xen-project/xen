#ifndef __ARM_PAGE_H__
#define __ARM_PAGE_H__

#include <xen/config.h>
#include <public/xen.h>
#include <asm/processor.h>

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

/* WARNING!  Unlike the Intel pagetable code, where l1 is the lowest
 * level and l4 is the root of the trie, the ARM pagetables follow ARM's
 * documentation: the levels are called first, second &c in the order
 * that the MMU walks them (i.e. "first" is the root of the trie). */

/******************************************************************************
 * ARMv7-A LPAE pagetables: 3-level trie, mapping 40-bit input to
 * 40-bit output addresses.  Tables at all levels have 512 64-bit entries
 * (i.e. are 4Kb long).
 *
 * The bit-shuffling that has the permission bits in branch nodes in a
 * different place from those in leaf nodes seems to be to allow linear
 * pagetable tricks.  If we're not doing that then the set of permission
 * bits that's not in use in a given node type can be used as
 * extra software-defined bits. */

typedef struct __packed {
    /* These are used in all kinds of entry. */
    unsigned long valid:1;      /* Valid mapping */
    unsigned long table:1;      /* == 1 in 4k map entries too */

    /* These ten bits are only used in Block entries and are ignored
     * in Table entries. */
    unsigned long ai:3;         /* Attribute Index */
    unsigned long ns:1;         /* Not-Secure */
    unsigned long user:1;       /* User-visible */
    unsigned long ro:1;         /* Read-Only */
    unsigned long sh:2;         /* Shareability */
    unsigned long af:1;         /* Access Flag */
    unsigned long ng:1;         /* Not-Global */

    /* The base address must be appropriately aligned for Block entries */
    unsigned long long base:36; /* Base address of block or next table */
    unsigned long sbz:4;        /* Must be zero */

    /* These seven bits are only used in Block entries and are ignored
     * in Table entries. */
    unsigned long contig:1;     /* In a block of 16 contiguous entries */
    unsigned long pxn:1;        /* Privileged-XN */
    unsigned long xn:1;         /* eXecute-Never */
    unsigned long avail:4;      /* Ignored by hardware */

    /* These 5 bits are only used in Table entries and are ignored in
     * Block entries */
    unsigned long pxnt:1;       /* Privileged-XN */
    unsigned long xnt:1;        /* eXecute-Never */
    unsigned long apt:2;        /* Access Permissions */
    unsigned long nst:1;        /* Not-Secure */
} lpae_pt_t;

/* The p2m tables have almost the same layout, but some of the permission
 * and cache-control bits are laid out differently (or missing) */
typedef struct __packed {
    /* These are used in all kinds of entry. */
    unsigned long valid:1;      /* Valid mapping */
    unsigned long table:1;      /* == 1 in 4k map entries too */

    /* These ten bits are only used in Block entries and are ignored
     * in Table entries. */
    unsigned long mattr:4;      /* Memory Attributes */
    unsigned long read:1;       /* Read access */
    unsigned long write:1;      /* Write access */
    unsigned long sh:2;         /* Shareability */
    unsigned long af:1;         /* Access Flag */
    unsigned long sbz4:1;

    /* The base address must be appropriately aligned for Block entries */
    unsigned long long base:36; /* Base address of block or next table */
    unsigned long sbz3:4;

    /* These seven bits are only used in Block entries and are ignored
     * in Table entries. */
    unsigned long contig:1;     /* In a block of 16 contiguous entries */
    unsigned long sbz2:1;
    unsigned long xn:1;         /* eXecute-Never */
    unsigned long type:4;       /* Ignore by hardware. Used to store p2m types */

    unsigned long sbz1:5;
} lpae_p2m_t;

/* Permission mask: xn, write, read */
#define P2M_PERM_MASK (0x00400000000000C0ULL)
#define P2M_CLEAR_PERM(pte) ((pte).bits & ~P2M_PERM_MASK)

/*
 * Walk is the common bits of p2m and pt entries which are needed to
 * simply walk the table (e.g. for debug).
 */
typedef struct __packed {
    /* These are used in all kinds of entry. */
    unsigned long valid:1;      /* Valid mapping */
    unsigned long table:1;      /* == 1 in 4k map entries too */

    unsigned long pad2:10;

    /* The base address must be appropriately aligned for Block entries */
    unsigned long long base:36; /* Base address of block or next table */

    unsigned long pad1:16;
} lpae_walk_t;

typedef union {
    uint64_t bits;
    lpae_pt_t pt;
    lpae_p2m_t p2m;
    lpae_walk_t walk;
} lpae_t;

/* Standard entry type that we'll use to build Xen's own pagetables.
 * We put the same permissions at every level, because they're ignored
 * by the walker in non-leaf entries. */
static inline lpae_t mfn_to_xen_entry(unsigned long mfn, unsigned attr)
{
    paddr_t pa = ((paddr_t) mfn) << PAGE_SHIFT;
    lpae_t e = (lpae_t) {
        .pt = {
            .valid = 1,           /* Mappings are present */
            .table = 0,           /* Set to 1 for links and 4k maps */
            .ai = attr,
            .ns = 1,              /* Hyp mode is in the non-secure world */
            .user = 1,            /* See below */
            .ro = 0,              /* Assume read-write */
            .af = 1,              /* No need for access tracking */
            .ng = 1,              /* Makes TLB flushes easier */
            .contig = 0,          /* Assume non-contiguous */
            .xn = 1,              /* No need to execute outside .text */
            .avail = 0,           /* Reference count for domheap mapping */
        }};;
    /* Setting the User bit is strange, but the ATS1H[RW] instructions
     * don't seem to work otherwise, and since we never run on Xen
     * pagetables in User mode it's OK.  If this changes, remember
     * to update the hard-coded values in head.S too */

    switch ( attr )
    {
    case BUFFERABLE:
        /*
         * ARM ARM: Overlaying the shareability attribute (DDI
         * 0406C.b B3-1376 to 1377)
         *
         * A memory region with a resultant memory type attribute of Normal,
         * and a resultant cacheability attribute of Inner Non-cacheable,
         * Outer Non-cacheable, must have a resultant shareability attribute
         * of Outer Shareable, otherwise shareability is UNPREDICTABLE.
         *
         * On ARMv8 sharability is ignored and explicitly treated as Outer
         * Shareable for Normal Inner Non_cacheable, Outer Non-cacheable.
         */
        e.pt.sh = LPAE_SH_OUTER;
        break;
    case UNCACHED:
    case DEV_SHARED:
        /* Shareability is ignored for non-Normal memory, Outer is as
         * good as anything.
         *
         * On ARMv8 sharability is ignored and explicitly treated as Outer
         * Shareable for any device memory type.
         */
        e.pt.sh = LPAE_SH_OUTER;
        break;
    default:
        e.pt.sh = LPAE_SH_INNER;  /* Xen mappings are SMP coherent */
        break;
    }

    ASSERT(!(pa & ~PAGE_MASK));
    ASSERT(!(pa & ~PADDR_MASK));

    // XXX shifts
    e.bits |= pa;
    return e;
}

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

/*
 * These numbers add up to a 48-bit input address space.
 *
 * On 32-bit the zeroeth level does not exist, therefore the total is
 * 39-bits. The ARMv7-A architecture actually specifies a 40-bit input
 * address space for the p2m, with an 8K (1024-entry) top-level table.
 * However Xen only supports 16GB of RAM on 32-bit ARM systems and
 * therefore 39-bits are sufficient.
 */

#define LPAE_SHIFT      9
#define LPAE_ENTRIES    (_AC(1,U) << LPAE_SHIFT)
#define LPAE_ENTRY_MASK (LPAE_ENTRIES - 1)

#define THIRD_SHIFT    (PAGE_SHIFT)
#define THIRD_ORDER    (THIRD_SHIFT - PAGE_SHIFT)
#define THIRD_SIZE     ((paddr_t)1 << THIRD_SHIFT)
#define THIRD_MASK     (~(THIRD_SIZE - 1))
#define SECOND_SHIFT   (THIRD_SHIFT + LPAE_SHIFT)
#define SECOND_ORDER   (SECOND_SHIFT - PAGE_SHIFT)
#define SECOND_SIZE    ((paddr_t)1 << SECOND_SHIFT)
#define SECOND_MASK    (~(SECOND_SIZE - 1))
#define FIRST_SHIFT    (SECOND_SHIFT + LPAE_SHIFT)
#define FIRST_ORDER    (FIRST_SHIFT - PAGE_SHIFT)
#define FIRST_SIZE     ((paddr_t)1 << FIRST_SHIFT)
#define FIRST_MASK     (~(FIRST_SIZE - 1))
#define ZEROETH_SHIFT  (FIRST_SHIFT + LPAE_SHIFT)
#define ZEROETH_ORDER  (ZEROETH_SHIFT - PAGE_SHIFT)
#define ZEROETH_SIZE   ((paddr_t)1 << ZEROETH_SHIFT)
#define ZEROETH_MASK   (~(ZEROETH_SIZE - 1))

/* Calculate the offsets into the pagetables for a given VA */
#define zeroeth_linear_offset(va) ((va) >> ZEROETH_SHIFT)
#define first_linear_offset(va) ((va) >> FIRST_SHIFT)
#define second_linear_offset(va) ((va) >> SECOND_SHIFT)
#define third_linear_offset(va) ((va) >> THIRD_SHIFT)

#define TABLE_OFFSET(offs) ((unsigned int)(offs) & LPAE_ENTRY_MASK)
#define first_table_offset(va)  TABLE_OFFSET(first_linear_offset(va))
#define second_table_offset(va) TABLE_OFFSET(second_linear_offset(va))
#define third_table_offset(va)  TABLE_OFFSET(third_linear_offset(va))
#define zeroeth_table_offset(va)  TABLE_OFFSET(zeroeth_linear_offset(va))

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
