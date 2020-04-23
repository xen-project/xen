
#ifndef __X86_64_PAGE_H__
#define __X86_64_PAGE_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define SUPERPAGE_SHIFT         L2_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L4_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L4_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define ROOT_PAGETABLE_ENTRIES  L4_PAGETABLE_ENTRIES
#define SUPERPAGE_ORDER         PAGETABLE_ORDER
#define SUPERPAGE_PAGES         (1<<SUPERPAGE_ORDER)

#define __XEN_VIRT_START        XEN_VIRT_START

/* These are architectural limits. Current CPUs support only 40-bit phys. */
#define PADDR_BITS              52
#define VADDR_BITS              48
#define PADDR_MASK              ((_AC(1,UL) << PADDR_BITS) - 1)
#define VADDR_MASK              ((_AC(1,UL) << VADDR_BITS) - 1)

#define VADDR_TOP_BIT           (1UL << (VADDR_BITS - 1))
#define CANONICAL_MASK          (~0UL & ~VADDR_MASK)

#define is_canonical_address(x) (((long)(x) >> 47) == ((long)(x) >> 63))

#ifndef __ASSEMBLY__

static inline unsigned long canonicalise_addr(unsigned long addr)
{
    if ( addr & VADDR_TOP_BIT )
        return addr | CANONICAL_MASK;
    else
        return addr & ~CANONICAL_MASK;
}

#include <asm/types.h>

#include <xen/pdx.h>

extern unsigned long xen_virt_end;

/*
 * Note: These are solely for the use by page_{get,set}_owner(), and
 *       therefore don't need to handle the XEN_VIRT_{START,END} range.
 */
#define virt_to_pdx(va)  (((unsigned long)(va) - DIRECTMAP_VIRT_START) >> \
                          PAGE_SHIFT)
#define pdx_to_virt(pdx) ((void *)(DIRECTMAP_VIRT_START + \
                                   ((unsigned long)(pdx) << PAGE_SHIFT)))

static inline unsigned long __virt_to_maddr(unsigned long va)
{
    ASSERT(va < DIRECTMAP_VIRT_END);
    if ( va >= DIRECTMAP_VIRT_START )
        va -= DIRECTMAP_VIRT_START;
    else
    {
        BUILD_BUG_ON(XEN_VIRT_END - XEN_VIRT_START != GB(1));
        /* Signed, so ((long)XEN_VIRT_START >> 30) fits in an imm32. */
        ASSERT(((long)va >> (PAGE_ORDER_1G + PAGE_SHIFT)) ==
               ((long)XEN_VIRT_START >> (PAGE_ORDER_1G + PAGE_SHIFT)));

        va += xen_phys_start - XEN_VIRT_START;
    }
    return (va & ma_va_bottom_mask) |
           ((va << pfn_pdx_hole_shift) & ma_top_mask);
}

static inline void *__maddr_to_virt(unsigned long ma)
{
    ASSERT(pfn_to_pdx(ma >> PAGE_SHIFT) < (DIRECTMAP_SIZE >> PAGE_SHIFT));
    return (void *)(DIRECTMAP_VIRT_START +
                    ((ma & ma_va_bottom_mask) |
                     ((ma & ma_top_mask) >> pfn_pdx_hole_shift)));
}

/* read access (should only be used for debug printk's) */
typedef u64 intpte_t;
#define PRIpte "016lx"

typedef struct { intpte_t l1; } l1_pgentry_t;
typedef struct { intpte_t l2; } l2_pgentry_t;
typedef struct { intpte_t l3; } l3_pgentry_t;
typedef struct { intpte_t l4; } l4_pgentry_t;
typedef l4_pgentry_t root_pgentry_t;

#endif /* !__ASSEMBLY__ */

#define pte_read_atomic(ptep)       read_atomic(ptep)
#define pte_write_atomic(ptep, pte) write_atomic(ptep, pte)
#define pte_write(ptep, pte)        write_atomic(ptep, pte)

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) (((_a) & VADDR_MASK) >> L1_PAGETABLE_SHIFT)
#define l2_linear_offset(_a) (((_a) & VADDR_MASK) >> L2_PAGETABLE_SHIFT)
#define l3_linear_offset(_a) (((_a) & VADDR_MASK) >> L3_PAGETABLE_SHIFT)
#define l4_linear_offset(_a) (((_a) & VADDR_MASK) >> L4_PAGETABLE_SHIFT)

#define is_guest_l2_slot(_d, _t, _s)                   \
    ( !is_pv_32bit_domain(_d) ||                       \
      !((_t) & PGT_pae_xen_l2) ||                      \
      ((_s) < COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(_d)) )
#define is_guest_l4_slot(_d, _s)                    \
    ( is_pv_32bit_domain(_d)                        \
      ? ((_s) == 0)                                 \
      : (((_s) < ROOT_PAGETABLE_FIRST_XEN_SLOT) ||  \
         ((_s) > ROOT_PAGETABLE_LAST_XEN_SLOT)))

#define root_table_offset         l4_table_offset
#define root_get_pfn              l4e_get_pfn
#define root_get_flags            l4e_get_flags
#define root_get_intpte           l4e_get_intpte
#define root_empty                l4e_empty
#define root_from_paddr           l4e_from_paddr
#define PGT_root_page_table       PGT_l4_page_table

/*
 * PTE pfn and flags:
 *  40-bit pfn   = (pte[51:12])
 *  24-bit flags = (pte[63:52],pte[11:0])
 */

/* Extract flags into 24-bit integer, or turn 24-bit flags into a pte mask. */
#ifndef __ASSEMBLY__
static inline unsigned int get_pte_flags(intpte_t x)
{
    return ((x >> 40) & ~0xfff) | (x & 0xfff);
}

static inline intpte_t put_pte_flags(unsigned int x)
{
    return (((intpte_t)x & ~0xfff) << 40) | (x & 0xfff);
}
#endif

/*
 * Protection keys define a new 4-bit protection key field
 * (PKEY) in bits 62:59 of leaf entries of the page tables.
 * This corresponds to bit 22:19 of a 24-bit flags.
 *
 * Notice: Bit 22 is used by _PAGE_GNTTAB which is visible to PV guests,
 * so Protection keys must be disabled on PV guests.
 */
#define _PAGE_PKEY_BITS  (0x780000)	 /* Protection Keys, 22:19 */

#define get_pte_pkey(x) (MASK_EXTR(get_pte_flags(x), _PAGE_PKEY_BITS))

/* Bit 23 of a 24-bit flag mask. This corresponds to bit 63 of a pte.*/
#define _PAGE_NX_BIT (1U<<23)

/* Bit 22 of a 24-bit flag mask. This corresponds to bit 62 of a pte.*/
#define _PAGE_GNTTAB (1U<<22)

/*
 * Bit 12 of a 24-bit flag mask. This corresponds to bit 52 of a pte.
 * This is needed to distinguish between user and kernel PTEs since _PAGE_USER
 * is asserted for both.
 */
#define _PAGE_GUEST_KERNEL (1U<<12)

#define PAGE_HYPERVISOR_RO      (__PAGE_HYPERVISOR_RO      | _PAGE_GLOBAL)
#define PAGE_HYPERVISOR_RW      (__PAGE_HYPERVISOR_RW      | _PAGE_GLOBAL)
#define PAGE_HYPERVISOR_RX      (__PAGE_HYPERVISOR_RX      | _PAGE_GLOBAL)
#define PAGE_HYPERVISOR_RWX     (__PAGE_HYPERVISOR         | _PAGE_GLOBAL)
#define PAGE_HYPERVISOR_SHSTK   (__PAGE_HYPERVISOR_SHSTK   | _PAGE_GLOBAL)

#define PAGE_HYPERVISOR         PAGE_HYPERVISOR_RW
#define PAGE_HYPERVISOR_UCMINUS (__PAGE_HYPERVISOR_UCMINUS | \
                                 _PAGE_GLOBAL | _PAGE_NX)
#define PAGE_HYPERVISOR_UC      (__PAGE_HYPERVISOR_UC | \
                                 _PAGE_GLOBAL | _PAGE_NX)

#endif /* __X86_64_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
