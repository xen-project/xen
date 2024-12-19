/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__PAGE_H
#define ASM__RISCV__PAGE_H

#ifndef __ASSEMBLY__

#include <xen/bug.h>
#include <xen/const.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/types.h>

#include <asm/atomic.h>
#include <asm/mm.h>
#include <asm/page-bits.h>

#define VPN_MASK                    (PAGETABLE_ENTRIES - 1UL)

#define XEN_PT_LEVEL_ORDER(lvl)     ((lvl) * PAGETABLE_ORDER)
#define XEN_PT_LEVEL_SHIFT(lvl)     (XEN_PT_LEVEL_ORDER(lvl) + PAGE_SHIFT)
#define XEN_PT_LEVEL_SIZE(lvl)      (_AT(paddr_t, 1) << XEN_PT_LEVEL_SHIFT(lvl))
#define XEN_PT_LEVEL_MAP_MASK(lvl)  (~(XEN_PT_LEVEL_SIZE(lvl) - 1))
#define XEN_PT_LEVEL_MASK(lvl)      (VPN_MASK << XEN_PT_LEVEL_SHIFT(lvl))

/*
 * PTE format:
 * | XLEN-1  10 | 9             8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0
 *       PFN      reserved for SW   D   A   G   U   X   W   R   V
 */
#define PTE_VALID                   BIT(0, UL)
#define PTE_READABLE                BIT(1, UL)
#define PTE_WRITABLE                BIT(2, UL)
#define PTE_EXECUTABLE              BIT(3, UL)
#define PTE_USER                    BIT(4, UL)
#define PTE_GLOBAL                  BIT(5, UL)
#define PTE_ACCESSED                BIT(6, UL)
#define PTE_DIRTY                   BIT(7, UL)
#define PTE_RSW                     (BIT(8, UL) | BIT(9, UL))

#define PTE_LEAF_DEFAULT            (PTE_VALID | PTE_READABLE | PTE_WRITABLE)
#define PTE_TABLE                   (PTE_VALID)

#define PAGE_HYPERVISOR_RO          (PTE_VALID | PTE_READABLE)
#define PAGE_HYPERVISOR_RW          (PTE_VALID | PTE_READABLE | PTE_WRITABLE)
#define PAGE_HYPERVISOR_RX          (PTE_VALID | PTE_READABLE | PTE_EXECUTABLE)

#define PAGE_HYPERVISOR             PAGE_HYPERVISOR_RW

/*
 * The PTE format does not contain the following bits within itself;
 * they are created artificially to inform the Xen page table
 * handling algorithm. These bits should not be explicitly written
 * to the PTE entry.
 */
#define PTE_SMALL       BIT(10, UL)
#define PTE_POPULATE    BIT(11, UL)

#define PTE_ACCESS_MASK (PTE_READABLE | PTE_WRITABLE | PTE_EXECUTABLE)

/* Calculate the offsets into the pagetables for a given VA */
#define pt_linear_offset(lvl, va)   ((va) >> XEN_PT_LEVEL_SHIFT(lvl))

#define pt_index(lvl, va) (pt_linear_offset((lvl), (va)) & VPN_MASK)

#define PAGETABLE_ORDER_MASK ((_AC(1, U) << PAGETABLE_ORDER) - 1)
#define TABLE_OFFSET(offs) (_AT(unsigned int, offs) & PAGETABLE_ORDER_MASK)

#if RV_STAGE1_MODE > SATP_MODE_SV39
#error "need to to update DECLARE_OFFSETS macros"
#else

#define l0_table_offset(va) TABLE_OFFSET(pt_linear_offset(0, va))
#define l1_table_offset(va) TABLE_OFFSET(pt_linear_offset(1, va))
#define l2_table_offset(va) TABLE_OFFSET(pt_linear_offset(2, va))

/* Generate an array @var containing the offset for each level from @addr */
#define DECLARE_OFFSETS(var, addr)          \
    const unsigned int var[] = {            \
        l0_table_offset(addr),              \
        l1_table_offset(addr),              \
        l2_table_offset(addr),              \
    }

#endif

/* Page Table entry */
typedef struct {
#ifdef CONFIG_RISCV_64
    uint64_t pte;
#else
    uint32_t pte;
#endif
} pte_t;

static inline pte_t paddr_to_pte(paddr_t paddr,
                                 unsigned int permissions)
{
    return (pte_t) { .pte = (paddr_to_pfn(paddr) << PTE_PPN_SHIFT) | permissions };
}

static inline paddr_t pte_to_paddr(pte_t pte)
{
    return pfn_to_paddr(pte.pte >> PTE_PPN_SHIFT);
}

static inline bool pte_is_valid(pte_t p)
{
    return p.pte & PTE_VALID;
}

/*
 * From the RISC-V spec:
 *   The V bit indicates whether the PTE is valid; if it is 0, all other bits
 *   in the PTE are don’t-cares and may be used freely by software.
 *
 *   If V=1 the encoding of PTE R/W/X bits could be find in "the encoding
 *   of the permission bits" table.
 *
 *   The encoding of the permission bits table:
 *      X W R Meaning
 *      0 0 0 Pointer to next level of page table.
 *      0 0 1 Read-only page.
 *      0 1 0 Reserved for future use.
 *      0 1 1 Read-write page.
 *      1 0 0 Execute-only page.
 *      1 0 1 Read-execute page.
 *      1 1 0 Reserved for future use.
 *      1 1 1 Read-write-execute page.
 */
static inline bool pte_is_table(pte_t p)
{
    /*
     * According to the spec if V=1 and W=1 then R also needs to be 1 as
     * R = 0 is reserved for future use ( look at the Table 4.5 ) so check
     * in ASSERT that if (V==1 && W==1) then R isn't 0.
     *
     * PAGE_HYPERVISOR_RW contains PTE_VALID too.
     */
    ASSERT(((p.pte & PAGE_HYPERVISOR_RW) != (PTE_VALID | PTE_WRITABLE)));

    return ((p.pte & (PTE_VALID | PTE_ACCESS_MASK)) == PTE_VALID);
}

static inline bool pte_is_mapping(pte_t p)
{
    /* See pte_is_table() */
    ASSERT(((p.pte & PAGE_HYPERVISOR_RW) != (PTE_VALID | PTE_WRITABLE)));

    return (p.pte & PTE_VALID) && (p.pte & PTE_ACCESS_MASK);
}

static inline int clean_and_invalidate_dcache_va_range(const void *p,
                                                       unsigned long size)
{
#ifndef CONFIG_QEMU_PLATFORM
# error "should clean_and_invalidate_dcache_va_range() be updated?"
#endif

    return 0;
}

static inline int clean_dcache_va_range(const void *p, unsigned long size)
{
#ifndef CONFIG_QEMU_PLATFORM
# error "should clean_dcache_va_range() be updated?"
#endif

    return 0;
}

static inline void invalidate_icache(void)
{
    asm volatile ( "fence.i" ::: "memory" );
}

#define clear_page(page) memset((void *)(page), 0, PAGE_SIZE)
#define copy_page(dp, sp) memcpy(dp, sp, PAGE_SIZE)

static inline void flush_page_to_ram(unsigned long mfn, bool sync_icache)
{
    const void *v = map_domain_page(_mfn(mfn));

    if ( clean_and_invalidate_dcache_va_range(v, PAGE_SIZE) )
        BUG();

    unmap_domain_page(v);

    if ( sync_icache )
        invalidate_icache();
}

/* Write a pagetable entry. */
static inline void write_pte(pte_t *p, pte_t pte)
{
    write_atomic(p, pte);
}

/* Read a pagetable entry. */
static inline pte_t read_pte(const pte_t *p)
{
    return read_atomic(p);
}

static inline pte_t pte_from_mfn(mfn_t mfn, unsigned int flags)
{
    unsigned long pte = (mfn_x(mfn) << PTE_PPN_SHIFT) | flags;
    return (pte_t){ .pte = pte };
}

#endif /* __ASSEMBLY__ */

#endif /* ASM__RISCV__PAGE_H */
