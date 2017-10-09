#ifndef __ARM_LPAE_H__
#define __ARM_LPAE_H__

#ifndef __ASSEMBLY__

#include <xen/page-defs.h>

/*
 * WARNING!  Unlike the x86 pagetable code, where l1 is the lowest level and
 * l4 is the root of the trie, the ARM pagetables follow ARM's documentation:
 * the levels are called first, second &c in the order that the MMU walks them
 * (i.e. "first" is the root of the trie).
 */

/******************************************************************************
 * ARMv7-A LPAE pagetables: 3-level trie, mapping 40-bit input to
 * 40-bit output addresses.  Tables at all levels have 512 64-bit entries
 * (i.e. are 4Kb long).
 *
 * The bit-shuffling that has the permission bits in branch nodes in a
 * different place from those in leaf nodes seems to be to allow linear
 * pagetable tricks.  If we're not doing that then the set of permission
 * bits that's not in use in a given node type can be used as
 * extra software-defined bits.
 */

typedef struct __packed {
    /* These are used in all kinds of entry. */
    unsigned long valid:1;      /* Valid mapping */
    unsigned long table:1;      /* == 1 in 4k map entries too */

    /*
     * These ten bits are only used in Block entries and are ignored
     * in Table entries.
     */
    unsigned long ai:3;         /* Attribute Index */
    unsigned long ns:1;         /* Not-Secure */
    unsigned long up:1;         /* Unpriviledged access */
    unsigned long ro:1;         /* Read-Only */
    unsigned long sh:2;         /* Shareability */
    unsigned long af:1;         /* Access Flag */
    unsigned long ng:1;         /* Not-Global */

    /* The base address must be appropriately aligned for Block entries */
    unsigned long long base:36; /* Base address of block or next table */
    unsigned long sbz:4;        /* Must be zero */

    /*
     * These seven bits are only used in Block entries and are ignored
     * in Table entries.
     */
    unsigned long contig:1;     /* In a block of 16 contiguous entries */
    unsigned long pxn:1;        /* Privileged-XN */
    unsigned long xn:1;         /* eXecute-Never */
    unsigned long avail:4;      /* Ignored by hardware */

    /*
     * These 5 bits are only used in Table entries and are ignored in
     * Block entries.
     */
    unsigned long pxnt:1;       /* Privileged-XN */
    unsigned long xnt:1;        /* eXecute-Never */
    unsigned long apt:2;        /* Access Permissions */
    unsigned long nst:1;        /* Not-Secure */
} lpae_pt_t;

/*
 * The p2m tables have almost the same layout, but some of the permission
 * and cache-control bits are laid out differently (or missing).
 */
typedef struct __packed {
    /* These are used in all kinds of entry. */
    unsigned long valid:1;      /* Valid mapping */
    unsigned long table:1;      /* == 1 in 4k map entries too */

    /*
     * These ten bits are only used in Block entries and are ignored
     * in Table entries.
     */
    unsigned long mattr:4;      /* Memory Attributes */
    unsigned long read:1;       /* Read access */
    unsigned long write:1;      /* Write access */
    unsigned long sh:2;         /* Shareability */
    unsigned long af:1;         /* Access Flag */
    unsigned long sbz4:1;

    /* The base address must be appropriately aligned for Block entries */
    unsigned long long base:36; /* Base address of block or next table */
    unsigned long sbz3:4;

    /*
     * These seven bits are only used in Block entries and are ignored
     * in Table entries.
     */
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

static inline bool lpae_valid(lpae_t pte)
{
    return pte.walk.valid;
}

/*
 * These two can only be used on L0..L2 ptes because L3 mappings set
 * the table bit and therefore these would return the opposite to what
 * you would expect.
 */
static inline bool lpae_table(lpae_t pte)
{
    return lpae_valid(pte) && pte.walk.table;
}

static inline bool lpae_mapping(lpae_t pte)
{
    return lpae_valid(pte) && !pte.walk.table;
}

static inline bool lpae_is_superpage(lpae_t pte, unsigned int level)
{
    return (level < 3) && lpae_mapping(pte);
}

static inline bool lpae_is_page(lpae_t pte, unsigned int level)
{
    return (level == 3) && lpae_valid(pte) && pte.walk.table;
}

/*
 * AArch64 supports pages with different sizes (4K, 16K, and 64K). To enable
 * page table walks for various configurations, the following helpers enable
 * walking the translation table with varying page size granularities.
 */

#define LPAE_SHIFT_4K           (9)
#define LPAE_SHIFT_16K          (11)
#define LPAE_SHIFT_64K          (13)

#define lpae_entries(gran)      (_AC(1,U) << LPAE_SHIFT_##gran)
#define lpae_entry_mask(gran)   (lpae_entries(gran) - 1)

#define third_shift(gran)       (PAGE_SHIFT_##gran)
#define third_size(gran)        ((paddr_t)1 << third_shift(gran))

#define second_shift(gran)      (third_shift(gran) + LPAE_SHIFT_##gran)
#define second_size(gran)       ((paddr_t)1 << second_shift(gran))

#define first_shift(gran)       (second_shift(gran) + LPAE_SHIFT_##gran)
#define first_size(gran)        ((paddr_t)1 << first_shift(gran))

/* Note that there is no zeroeth lookup level with a 64K granule size. */
#define zeroeth_shift(gran)     (first_shift(gran) + LPAE_SHIFT_##gran)
#define zeroeth_size(gran)      ((paddr_t)1 << zeroeth_shift(gran))

#define TABLE_OFFSET(offs, gran)      (offs & lpae_entry_mask(gran))
#define TABLE_OFFSET_HELPERS(gran)                                          \
static inline paddr_t third_table_offset_##gran##K(paddr_t va)              \
{                                                                           \
    return TABLE_OFFSET((va >> third_shift(gran##K)), gran##K);             \
}                                                                           \
                                                                            \
static inline paddr_t second_table_offset_##gran##K(paddr_t va)             \
{                                                                           \
    return TABLE_OFFSET((va >> second_shift(gran##K)), gran##K);            \
}                                                                           \
                                                                            \
static inline paddr_t first_table_offset_##gran##K(paddr_t va)              \
{                                                                           \
    return TABLE_OFFSET((va >> first_shift(gran##K)), gran##K);             \
}                                                                           \
                                                                            \
static inline paddr_t zeroeth_table_offset_##gran##K(paddr_t va)            \
{                                                                           \
    /* Note that there is no zeroeth lookup level with 64K granule sizes. */\
    if ( gran == 64 )                                                       \
        return 0;                                                           \
    else                                                                    \
        return TABLE_OFFSET((va >> zeroeth_shift(gran##K)), gran##K);       \
}                                                                           \

TABLE_OFFSET_HELPERS(4);
TABLE_OFFSET_HELPERS(16);
TABLE_OFFSET_HELPERS(64);

#undef TABLE_OFFSET
#undef TABLE_OFFSET_HELPERS

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

#endif /* __ARM_LPAE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
