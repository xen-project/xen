#ifndef __ARM_LPAE_H__
#define __ARM_LPAE_H__

#ifndef __ASSEMBLY__

#include <xen/page-defs.h>
#include <xen/mm-frame.h>

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

static inline bool lpae_is_valid(lpae_t pte)
{
    return pte.walk.valid;
}

/*
 * lpae_is_* don't check the valid bit. This gives an opportunity for the
 * callers to operate on the entry even if they are not valid. For
 * instance to store information in advance.
 */
static inline bool lpae_is_table(lpae_t pte, unsigned int level)
{
    return (level < 3) && pte.walk.table;
}

static inline bool lpae_is_mapping(lpae_t pte, unsigned int level)
{
    if ( level == 3 )
        return pte.walk.table;
    else
        return !pte.walk.table;
}

static inline bool lpae_is_superpage(lpae_t pte, unsigned int level)
{
    return (level < 3) && lpae_is_mapping(pte, level);
}

#define lpae_get_mfn(pte)    (_mfn((pte).walk.base))
#define lpae_set_mfn(pte, mfn)  ((pte).walk.base = mfn_x(mfn))

/* Generate an array @var containing the offset for each level from @addr */
#define DECLARE_OFFSETS(var, addr)          \
    const unsigned int var[4] = {           \
        zeroeth_table_offset(addr),         \
        first_table_offset(addr),           \
        second_table_offset(addr),          \
        third_table_offset(addr)            \
    }

/*
 * Standard entry type that we'll use to build Xen's own pagetables.
 * We put the same permissions at every level, because they're ignored
 * by the walker in non-leaf entries.
 */
lpae_t mfn_to_xen_entry(mfn_t mfn, unsigned int attr);

#endif /* __ASSEMBLY__ */

/*
 * AArch64 supports pages with different sizes (4K, 16K, and 64K).
 * Provide a set of generic helpers that will compute various
 * information based on the page granularity.
 *
 * Note the parameter 'gs' is the page shift of the granularity used.
 * Some macro will evaluate 'gs' twice rather than storing in a
 * variable. This is to allow using the macros in assembly.
 */

/*
 * Granularity | PAGE_SHIFT | LPAE_SHIFT
 * -------------------------------------
 * 4K          | 12         | 9
 * 16K         | 14         | 11
 * 64K         | 16         | 13
 *
 * This is equivalent to LPAE_SHIFT = PAGE_SHIFT - 3
 */
#define LPAE_SHIFT_GS(gs)         ((gs) - 3)
#define LPAE_ENTRIES_GS(gs)       (_AC(1, U) << LPAE_SHIFT_GS(gs))
#define LPAE_ENTRY_MASK_GS(gs)    (LPAE_ENTRIES_GS(gs) - 1)

#define LEVEL_ORDER_GS(gs, lvl)   ((3 - (lvl)) * LPAE_SHIFT_GS(gs))
#define LEVEL_SHIFT_GS(gs, lvl)   (LEVEL_ORDER_GS(gs, lvl) + (gs))
#define LEVEL_SIZE_GS(gs, lvl)    (_AT(paddr_t, 1) << LEVEL_SHIFT_GS(gs, lvl))

/* Offset in the table at level 'lvl' */
#define LPAE_TABLE_INDEX_GS(gs, lvl, addr)   \
    (((addr) >> LEVEL_SHIFT_GS(gs, lvl)) & LPAE_ENTRY_MASK_GS(gs))

/*
 * These numbers add up to a 48-bit input address space.
 *
 * On 32-bit the zeroeth level does not exist, therefore the total is
 * 39-bits. The ARMv7-A architecture actually specifies a 40-bit input
 * address space for the p2m, with an 8K (1024-entry) top-level table.
 * However Xen only supports 16GB of RAM on 32-bit ARM systems and
 * therefore 39-bits are sufficient.
 */

#define XEN_PT_LPAE_SHIFT         LPAE_SHIFT_GS(PAGE_SHIFT)
#define XEN_PT_LPAE_ENTRIES       LPAE_ENTRIES_GS(PAGE_SHIFT)
#define XEN_PT_LPAE_ENTRY_MASK    LPAE_ENTRY_MASK_GS(PAGE_SHIFT)

#define XEN_PT_LEVEL_SHIFT(lvl)   LEVEL_SHIFT_GS(PAGE_SHIFT, lvl)
#define XEN_PT_LEVEL_ORDER(lvl)   LEVEL_ORDER_GS(PAGE_SHIFT, lvl)
#define XEN_PT_LEVEL_SIZE(lvl)    LEVEL_SIZE_GS(PAGE_SHIFT, lvl)
#define XEN_PT_LEVEL_MASK(lvl)    (~(XEN_PT_LEVEL_SIZE(lvl) - 1))

/* Convenience aliases */
#define THIRD_SHIFT         XEN_PT_LEVEL_SHIFT(3)
#define THIRD_ORDER         XEN_PT_LEVEL_ORDER(3)
#define THIRD_SIZE          XEN_PT_LEVEL_SIZE(3)
#define THIRD_MASK          XEN_PT_LEVEL_MASK(3)

#define SECOND_SHIFT        XEN_PT_LEVEL_SHIFT(2)
#define SECOND_ORDER        XEN_PT_LEVEL_ORDER(2)
#define SECOND_SIZE         XEN_PT_LEVEL_SIZE(2)
#define SECOND_MASK         XEN_PT_LEVEL_MASK(2)

#define FIRST_SHIFT         XEN_PT_LEVEL_SHIFT(1)
#define FIRST_ORDER         XEN_PT_LEVEL_ORDER(1)
#define FIRST_SIZE          XEN_PT_LEVEL_SIZE(1)
#define FIRST_MASK          XEN_PT_LEVEL_MASK(1)

#define ZEROETH_SHIFT       XEN_PT_LEVEL_SHIFT(0)
#define ZEROETH_ORDER       XEN_PT_LEVEL_ORDER(0)
#define ZEROETH_SIZE        XEN_PT_LEVEL_SIZE(0)
#define ZEROETH_MASK        XEN_PT_LEVEL_MASK(0)

/* Calculate the offsets into the pagetables for a given VA */
#define zeroeth_linear_offset(va) ((va) >> ZEROETH_SHIFT)
#define first_linear_offset(va) ((va) >> FIRST_SHIFT)
#define second_linear_offset(va) ((va) >> SECOND_SHIFT)
#define third_linear_offset(va) ((va) >> THIRD_SHIFT)

#define TABLE_OFFSET(offs) (_AT(unsigned int, offs) & XEN_PT_LPAE_ENTRY_MASK)
#define first_table_offset(va)  TABLE_OFFSET(first_linear_offset(va))
#define second_table_offset(va) TABLE_OFFSET(second_linear_offset(va))
#define third_table_offset(va)  TABLE_OFFSET(third_linear_offset(va))
#ifdef CONFIG_PHYS_ADDR_T_32
#define zeroeth_table_offset(va)  0
#else
#define zeroeth_table_offset(va)  TABLE_OFFSET(zeroeth_linear_offset(va))
#endif

/*
 * Macros to define page-tables:
 *  - DEFINE_BOOT_PAGE_TABLE{,S} are used to define one or multiple
 *  page-table that are used in assembly code before BSS is zeroed.
 *  - DEFINE_PAGE_TABLE{,S} are used to define one or multiple
 *  page-tables to be used after BSS is zeroed (typically they are only used
 *  in C).
 */
#define DEFINE_BOOT_PAGE_TABLES(name, nr)                                     \
lpae_t __aligned(PAGE_SIZE) __section(".data.page_aligned")                   \
    name[XEN_PT_LPAE_ENTRIES * (nr)]

#define DEFINE_BOOT_PAGE_TABLE(name) DEFINE_BOOT_PAGE_TABLES(name, 1)

#define DEFINE_PAGE_TABLES(name, nr)                    \
lpae_t __aligned(PAGE_SIZE) name[XEN_PT_LPAE_ENTRIES * (nr)]

#define DEFINE_PAGE_TABLE(name) DEFINE_PAGE_TABLES(name, 1)

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
