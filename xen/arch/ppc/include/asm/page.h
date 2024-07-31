/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_PPC_PAGE_H
#define _ASM_PPC_PAGE_H

#include <xen/bitops.h>
#include <xen/types.h>

#include <asm/byteorder.h>

#define PDE_VALID     PPC_BIT(0)
#define PDE_NLB_MASK  0x1ffffffffffffe0UL
#define PDE_NLS_MASK  0x1f

#define PTE_VALID     PPC_BIT(0)
#define PTE_LEAF      PPC_BIT(1)
#define PTE_REFERENCE PPC_BIT(55)
#define PTE_CHANGE    PPC_BIT(56)

/* PTE Attributes */
#define PTE_ATT_SAO            PPC_BIT(59) /* Strong Access Ordering */
#define PTE_ATT_NON_IDEMPOTENT PPC_BIT(58)
#define PTE_ATT_TOLERANT       (PPC_BIT(58) | PPC_BIT(59))

/* PTE Encoded Access Authority*/
#define PTE_EAA_PRIVILEGED PPC_BIT(60)
#define PTE_EAA_READ       PPC_BIT(61)
#define PTE_EAA_WRITE      PPC_BIT(62)
#define PTE_EAA_EXECUTE    PPC_BIT(63)

/* Field shifts/masks */
#define PTE_RPN_MASK  0x1fffffffffff000UL
#define PTE_ATT_MASK  0x30UL
#define PTE_EAA_MASK  0xfUL

#define PTE_XEN_BASE (PTE_VALID | PTE_EAA_PRIVILEGED | PTE_REFERENCE)
#define PTE_XEN_RW   (PTE_XEN_BASE | PTE_EAA_READ | PTE_EAA_WRITE | PTE_CHANGE)
#define PTE_XEN_RO   (PTE_XEN_BASE | PTE_EAA_READ)
#define PTE_XEN_RX   (PTE_XEN_BASE | PTE_EAA_READ | PTE_EAA_EXECUTE)

/* TODO */
#define PAGE_HYPERVISOR 0

/*
 * Radix Tree layout for 64KB pages:
 *
 * [ L1 (ROOT) PAGE DIRECTORY (8192 * sizeof(pde_t)) ]
 *                     |
 *                     |
 *                     v
 *    [ L2 PAGE DIRECTORY (512 * sizeof(pde_t)) ]
 *                     |
 *                     |
 *                     v
 *    [ L3 PAGE DIRECTORY (512 * sizeof(pde_t)) ]
 *                     |
 *                     |
 *                     v
 *      [ L4 PAGE TABLE (32 * sizeof(pte_t)) ]
 *                     |
 *                     |
 *                     v
 *            [ PAGE TABLE ENTRY ]
 */

#define XEN_PT_ENTRIES_LOG2_LVL_1 13 /* 2**13 entries, maps 2**13 * 512GB = 4PB */
#define XEN_PT_ENTRIES_LOG2_LVL_2 9  /* 2**9  entries, maps 2**9  * 1GB = 512GB */
#define XEN_PT_ENTRIES_LOG2_LVL_3 9  /* 2**9  entries, maps 2**9  * 1GB = 512GB */
#define XEN_PT_ENTRIES_LOG2_LVL_4 5  /* 2**5  entries, maps 2**5  * 64K = 2MB */

#define XEN_PT_SHIFT_LVL_1    (XEN_PT_SHIFT_LVL_2 + XEN_PT_ENTRIES_LOG2_LVL_2)
#define XEN_PT_SHIFT_LVL_2    (XEN_PT_SHIFT_LVL_3 + XEN_PT_ENTRIES_LOG2_LVL_3)
#define XEN_PT_SHIFT_LVL_3    (XEN_PT_SHIFT_LVL_4 + XEN_PT_ENTRIES_LOG2_LVL_4)
#define XEN_PT_SHIFT_LVL_4    PAGE_SHIFT

#define XEN_PT_ENTRIES_LOG2_LVL(lvl) (XEN_PT_ENTRIES_LOG2_LVL_##lvl)
#define XEN_PT_SHIFT_LVL(lvl)        (XEN_PT_SHIFT_LVL_##lvl)
#define XEN_PT_ENTRIES_LVL(lvl)      (1UL << XEN_PT_ENTRIES_LOG2_LVL(lvl))
#define XEN_PT_SIZE_LVL(lvl)         (sizeof(uint64_t) * XEN_PT_ENTRIES_LVL(lvl))
#define XEN_PT_MASK_LVL(lvl)         (XEN_PT_ENTRIES_LVL(lvl) - 1)
#define XEN_PT_INDEX_LVL(lvl, va)    (((va) >> XEN_PT_SHIFT_LVL(lvl)) & XEN_PT_MASK_LVL(lvl))

/*
 * Calculate the index of the provided virtual address in the provided
 * page table struct
 */
#define pt_index(pt, va) _Generic((pt), \
    struct lvl1_pd * : XEN_PT_INDEX_LVL(1, (va)), \
    struct lvl2_pd * : XEN_PT_INDEX_LVL(2, (va)), \
    struct lvl3_pd * : XEN_PT_INDEX_LVL(3, (va)), \
    struct lvl4_pt * : XEN_PT_INDEX_LVL(4, (va)))

#define pt_entry(pt, va) (&((pt)->entries[pt_index((pt), (va))]))

typedef struct
{
    __be64 pde;
} pde_t;

typedef struct
{
    __be64 pte;
} pte_t;

struct lvl1_pd
{
    pde_t entries[XEN_PT_ENTRIES_LVL(1)];
} __aligned(XEN_PT_SIZE_LVL(1));

struct lvl2_pd
{
    pde_t entries[XEN_PT_ENTRIES_LVL(2)];
} __aligned(XEN_PT_SIZE_LVL(2));

struct lvl3_pd
{
    pde_t entries[XEN_PT_ENTRIES_LVL(3)];
} __aligned(XEN_PT_SIZE_LVL(3));

struct lvl4_pt
{
    pte_t entries[XEN_PT_ENTRIES_LVL(4)];
} __aligned(XEN_PT_SIZE_LVL(4));

static inline pte_t paddr_to_pte(paddr_t paddr, unsigned long flags)
{
    paddr_t paddr_aligned = paddr & PTE_RPN_MASK;

    return (pte_t){ .pte = cpu_to_be64(paddr_aligned | flags | PTE_LEAF) };
}

static inline pde_t paddr_to_pde(paddr_t paddr, unsigned long flags,
                                 unsigned long nls)
{
    paddr_t paddr_aligned = paddr & PDE_NLB_MASK;

    return (pde_t){ .pde = cpu_to_be64(paddr_aligned | flags | nls) };
}

static inline paddr_t pte_to_paddr(pte_t pte)
{
    return be64_to_cpu(pte.pte) & PTE_RPN_MASK;
}

static inline paddr_t pde_to_paddr(pde_t pde)
{
    return be64_to_cpu(pde.pde) & PDE_NLB_MASK;
}

static inline bool pte_is_valid(pte_t pte)
{
    return pte.pte & be64_to_cpu(PTE_VALID);
}

static inline bool pde_is_valid(pde_t pde)
{
    return pde.pde & be64_to_cpu(PDE_VALID);
}

/*
 * ISA 3.0 partition and process table entry format
 */
struct patb_entry {
	__be64 patb0;
	__be64 patb1;
};
#define PATB0_HR PPC_BIT(0) /* host uses radix */
#define PATB1_GR PPC_BIT(0) /* guest uses radix; must match HR */

struct prtb_entry {
	__be64 prtb0;
	__be64 reserved;
};

/*
 * We support 52 bits, hence:
 * bits 52 - 31 = 21, 0b10101
 * RTS encoding details
 * bits 0 - 2 of rts -> bits 5 - 7 of unsigned long
 * bits 3 - 4 of rts -> bits 61 - 62 of unsigned long
 */
#define RTS_FIELD ((0x2UL << 61) | (0x5UL << 5))

void tlbie_all(void);

static inline void invalidate_icache(void)
{
    BUG_ON("unimplemented");
}

#define clear_page(page) memset(page, 0, PAGE_SIZE)
#define copy_page(dp, sp) memcpy(dp, sp, PAGE_SIZE)

/* TODO: Flush the dcache for an entire page. */
static inline void flush_page_to_ram(unsigned long mfn, bool sync_icache)
{
    BUG_ON("unimplemented");
}

#endif /* _ASM_PPC_PAGE_H */
