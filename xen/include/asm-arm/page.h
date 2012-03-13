#ifndef __ARM_PAGE_H__
#define __ARM_PAGE_H__

#include <xen/config.h>

#define PADDR_BITS              40
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

#define UNCACHED      0x0
#define BUFFERABLE    0x1
#define WRITETHROUGH  0x2
#define WRITEBACK     0x3
#define DEV_SHARED    0x4
#define WRITEALLOC    0x7
#define DEV_NONSHARED DEV_SHARED
#define DEV_WC        BUFFERABLE
#define DEV_CACHED    WRITEBACK


#ifndef __ASSEMBLY__

#include <xen/types.h>
#include <xen/lib.h>

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

typedef struct {
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

    /* The base address must be approprately aligned for Block entries */
    unsigned long base:28;      /* Base address of block or next table */
    unsigned long sbz:12;       /* Must be zero */

    /* These seven bits are only used in Block entries and are ignored
     * in Table entries. */
    unsigned long hint:1;       /* In a block of 16 contiguous entries */
    unsigned long pxn:1;        /* Privileged-XN */
    unsigned long xn:1;         /* eXecute-Never */
    unsigned long avail:4;      /* Ignored by hardware */

    /* These 5 bits are only used in Table entries and are ignored in
     * Block entries */
    unsigned long pxnt:1;       /* Privileged-XN */
    unsigned long xnt:1;        /* eXecute-Never */
    unsigned long apt:2;        /* Access Permissions */
    unsigned long nst:1;        /* Not-Secure */
} __attribute__((__packed__)) lpae_pt_t;

/* The p2m tables have almost the same layout, but some of the permission
 * and cache-control bits are laid out differently (or missing) */
typedef struct {
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

    /* The base address must be approprately aligned for Block entries */
    unsigned long base:28;      /* Base address of block or next table */
    unsigned long sbz3:12;

    /* These seven bits are only used in Block entries and are ignored
     * in Table entries. */
    unsigned long hint:1;       /* In a block of 16 contiguous entries */
    unsigned long sbz2:1;
    unsigned long xn:1;         /* eXecute-Never */
    unsigned long avail:4;      /* Ignored by hardware */

    unsigned long sbz1:5;
} __attribute__((__packed__)) lpae_p2m_t;

typedef union {
    uint64_t bits;
    lpae_pt_t pt;
    lpae_p2m_t p2m;
} lpae_t;

/* Standard entry type that we'll use to build Xen's own pagetables.
 * We put the same permissions at every level, because they're ignored
 * by the walker in non-leaf entries. */
static inline lpae_t mfn_to_xen_entry(unsigned long mfn)
{
    paddr_t pa = ((paddr_t) mfn) << PAGE_SHIFT;
    lpae_t e = (lpae_t) {
        .pt = {
            .xn = 1,              /* No need to execute outside .text */
            .ng = 1,              /* Makes TLB flushes easier */
            .af = 1,              /* No need for access tracking */
            .sh = LPAE_SH_OUTER,  /* Xen mappings are globally coherent */
            .ns = 1,              /* Hyp mode is in the non-secure world */
            .user = 1,            /* See below */
            .ai = WRITEALLOC,
            .table = 0,           /* Set to 1 for links and 4k maps */
            .valid = 1,           /* Mappings are present */
        }};;
    /* Setting the User bit is strange, but the ATS1H[RW] instructions
     * don't seem to work otherwise, and since we never run on Xen
     * pagetables un User mode it's OK.  If this changes, remember
     * to update the hard-coded values in head.S too */

    ASSERT(!(pa & ~PAGE_MASK));
    ASSERT(!(pa & ~PADDR_MASK));

    // XXX shifts
    e.bits |= pa;
    return e;
}

static inline lpae_t mfn_to_p2m_entry(unsigned long mfn)
{
    paddr_t pa = ((paddr_t) mfn) << PAGE_SHIFT;
    lpae_t e = (lpae_t) {
        .p2m.xn = 0,
        .p2m.af = 1,
        .p2m.sh = LPAE_SH_OUTER,
        .p2m.write = 1,
        .p2m.read = 1,
        .p2m.mattr = 0xf,
        .p2m.table = 1,
        .p2m.valid = 1,
    };

    ASSERT(!(pa & ~PAGE_MASK));
    ASSERT(!(pa & ~PADDR_MASK));

    e.bits |= pa;

    return e;
}

/* Write a pagetable entry */
static inline void write_pte(lpae_t *p, lpae_t pte)
{
    asm volatile (
        /* Safely write the entry (STRD is atomic on CPUs that support LPAE) */
        "strd %0, %H0, [%1];"
        /* Push this cacheline to the PoC so the rest of the system sees it. */
        STORE_CP32(1, DCCMVAC)
        : : "r" (pte.bits), "r" (p) : "memory");
}

/*
 * Flush all hypervisor mappings from the TLB and branch predictor.
 * This is needed after changing Xen code mappings. 
 */
static inline void flush_xen_text_tlb(void)
{
    register unsigned long r0 asm ("r0");
    asm volatile (
        "dsb;"                        /* Ensure visibility of PTE writes */
        STORE_CP32(0, TLBIALLH)       /* Flush hypervisor TLB */
        STORE_CP32(0, BPIALL)         /* Flush branch predictor */
        "dsb;"                        /* Ensure completion of TLB+BP flush */
        "isb;"
        : : "r" (r0) /*dummy*/ : "memory");
}

/*
 * Flush all hypervisor mappings from the data TLB. This is not
 * sufficient when changing code mappings or for self modifying code.
 */
static inline void flush_xen_data_tlb(void)
{
    register unsigned long r0 asm ("r0");
    asm volatile("dsb;" /* Ensure preceding are visible */
                 STORE_CP32(0, TLBIALLH)
                 "dsb;" /* Ensure completion of the TLB flush */
                 "isb;"
                 : : "r" (r0) /* dummy */: "memory");
}

/*
 * Flush one VA's hypervisor mappings from the data TLB. This is not
 * sufficient when changing code mappings or for self modifying code.
 */
static inline void flush_xen_data_tlb_va(unsigned long va)
{
    asm volatile("dsb;" /* Ensure preceding are visible */
                 STORE_CP32(0, TLBIMVAH)
                 "dsb;" /* Ensure completion of the TLB flush */
                 "isb;"
                 : : "r" (va) : "memory");
}

/* Flush all non-hypervisor mappings from the TLB */
static inline void flush_guest_tlb(void)
{
    register unsigned long r0 asm ("r0");
    WRITE_CP32(r0 /* dummy */, TLBIALLNSNH);
}

/* Ask the MMU to translate a VA for us */
static inline uint64_t __va_to_par(uint32_t va)
{
    uint64_t par, tmp;
    tmp = READ_CP64(PAR);
    WRITE_CP32(va, ATS1HR);
    isb(); /* Ensure result is available. */
    par = READ_CP64(PAR);
    WRITE_CP64(tmp, PAR);
    return par;
}

static inline uint64_t va_to_par(uint32_t va)
{
    uint64_t par = __va_to_par(va);
    /* It is not OK to call this with an invalid VA */
    if ( par & PAR_F ) panic_PAR(par, "Hypervisor");
    return par;
}

/* Ask the MMU to translate a Guest VA for us */
static inline uint64_t __gva_to_par(uint32_t va)
{
    uint64_t par, tmp;
    tmp = READ_CP64(PAR);
    WRITE_CP32(va, ATS12NSOPR);
    isb(); /* Ensure result is available. */
    par = READ_CP64(PAR);
    WRITE_CP64(tmp, PAR);
    return par;
}
static inline uint64_t gva_to_par(uint32_t va)
{
    uint64_t par = __gva_to_par(va);
    /* It is not OK to call this with an invalid VA */
    /* XXX harsh for a guest address... */
    if ( par & PAR_F ) panic_PAR(par, "Guest");
    return par;
}
static inline uint64_t __gva_to_ipa(uint32_t va)
{
    uint64_t par, tmp;
    tmp = READ_CP64(PAR);
    WRITE_CP32(va, ATS1CPR);
    isb(); /* Ensure result is available. */
    par = READ_CP64(PAR);
    WRITE_CP64(tmp, PAR);
    return par;
}
static inline uint64_t gva_to_ipa(uint32_t va)
{
    uint64_t par = __gva_to_ipa(va);
    /* It is not OK to call this with an invalid VA */
    /* XXX harsh for a guest address... */
    if ( par & PAR_F ) panic_PAR(par, "Guest");
    return (par & PADDR_MASK & PAGE_MASK) | ((unsigned long) va & ~PAGE_MASK);
}
/* Bits in the PAR returned by va_to_par */
#define PAR_FAULT 0x1

#endif /* __ASSEMBLY__ */

/* These numbers add up to a 39-bit input address space.  The  ARMv7-A
 * architecture actually specifies a 40-bit input address space for the p2m,
 * with an 8K (1024-entry) top-level table. */

#define LPAE_SHIFT      9
#define LPAE_ENTRIES    (1u << LPAE_SHIFT)
#define LPAE_ENTRY_MASK (LPAE_ENTRIES - 1)

#define THIRD_SHIFT  PAGE_SHIFT
#define SECOND_SHIFT (THIRD_SHIFT + LPAE_SHIFT)
#define FIRST_SHIFT  (SECOND_SHIFT + LPAE_SHIFT)

/* Calculate the offsets into the pagetables for a given VA */
#define first_linear_offset(va) (va >> FIRST_SHIFT)
#define second_linear_offset(va) (va >> SECOND_SHIFT)
#define third_linear_offset(va) (va >> THIRD_SHIFT)
#define first_table_offset(va) (first_linear_offset(va))
#define second_table_offset(va) (second_linear_offset(va) & LPAE_ENTRY_MASK)
#define third_table_offset(va) (third_linear_offset(va) & LPAE_ENTRY_MASK)

#define clear_page(page)memset((void *)(page), 0, PAGE_SIZE)

#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

#endif /* __ARM_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
