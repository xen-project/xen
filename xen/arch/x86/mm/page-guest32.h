
#ifndef __X86_PAGE_GUEST_H__
#define __X86_PAGE_GUEST_H__

#ifndef __ASSEMBLY__
# include <asm/types.h>
#endif

#define PAGETABLE_ORDER_32         10
#define L1_PAGETABLE_ENTRIES_32    (1<<PAGETABLE_ORDER_32)
#define L2_PAGETABLE_ENTRIES_32    (1<<PAGETABLE_ORDER_32)
#define ROOT_PAGETABLE_ENTRIES_32  L2_PAGETABLE_ENTRIES_32


#define L1_PAGETABLE_SHIFT_32 12
#define L2_PAGETABLE_SHIFT_32 22

/* Extract flags into 12-bit integer, or turn 12-bit flags into a pte mask. */

#ifndef __ASSEMBLY__

typedef u32 intpte_32_t;

typedef struct { intpte_32_t l1; } l1_pgentry_32_t;
typedef struct { intpte_32_t l2; } l2_pgentry_32_t;
typedef l2_pgentry_t root_pgentry_32_t;
#endif

#define get_pte_flags_32(x) ((u32)(x) & 0xFFF)
#define put_pte_flags_32(x) ((intpte_32_t)(x))

/* Get pte access flags (unsigned int). */
#define l1e_get_flags_32(x)           (get_pte_flags_32((x).l1))
#define l2e_get_flags_32(x)           (get_pte_flags_32((x).l2))

#define l1e_get_paddr_32(x)           \
    ((paddr_t)(((x).l1 & (PADDR_MASK&PAGE_MASK))))
#define l2e_get_paddr_32(x)           \
    ((paddr_t)(((x).l2 & (PADDR_MASK&PAGE_MASK))))

/* Construct an empty pte. */
#define l1e_empty_32()                ((l1_pgentry_32_t) { 0 })
#define l2e_empty_32()                ((l2_pgentry_32_t) { 0 })

/* Construct a pte from a pfn and access flags. */
#define l1e_from_pfn_32(pfn, flags)   \
    ((l1_pgentry_32_t) { ((intpte_32_t)(pfn) << PAGE_SHIFT) | put_pte_flags_32(flags) })
#define l2e_from_pfn_32(pfn, flags)   \
    ((l2_pgentry_32_t) { ((intpte_32_t)(pfn) << PAGE_SHIFT) | put_pte_flags_32(flags) })

/* Construct a pte from a physical address and access flags. */
#ifndef __ASSEMBLY__
static inline l1_pgentry_32_t l1e_from_paddr_32(paddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (l1_pgentry_32_t) { pa | put_pte_flags_32(flags) };
}
static inline l2_pgentry_32_t l2e_from_paddr_32(paddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (l2_pgentry_32_t) { pa | put_pte_flags_32(flags) };
}
#endif /* !__ASSEMBLY__ */


/* Construct a pte from a page pointer and access flags. */
#define l1e_from_page_32(page, flags) (l1e_from_pfn_32(page_to_mfn(page),(flags)))
#define l2e_from_page_32(page, flags) (l2e_from_pfn_32(page_to_mfn(page),(flags)))

/* Add extra flags to an existing pte. */
#define l1e_add_flags_32(x, flags)    ((x).l1 |= put_pte_flags_32(flags))
#define l2e_add_flags_32(x, flags)    ((x).l2 |= put_pte_flags_32(flags))

/* Remove flags from an existing pte. */
#define l1e_remove_flags_32(x, flags) ((x).l1 &= ~put_pte_flags_32(flags))
#define l2e_remove_flags_32(x, flags) ((x).l2 &= ~put_pte_flags_32(flags))

/* Check if a pte's page mapping or significant access flags have changed. */
#define l1e_has_changed_32(x,y,flags) \
    ( !!(((x).l1 ^ (y).l1) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags_32(flags))) )
#define l2e_has_changed_32(x,y,flags) \
    ( !!(((x).l2 ^ (y).l2) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags_32(flags))) )

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset_32(a)         \
    (((a) >> L1_PAGETABLE_SHIFT_32) & (L1_PAGETABLE_ENTRIES_32 - 1))
#define l2_table_offset_32(a)         \
    (((a) >> L2_PAGETABLE_SHIFT_32) & (L2_PAGETABLE_ENTRIES_32 - 1))

#endif /* __X86_PAGE_GUEST_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
