
#ifndef __X86_PAGE_H__
#define __X86_PAGE_H__

#if defined(__i386__)
#include <asm/x86_32/page.h>
#elif defined(__x86_64__)
#include <asm/x86_64/page.h>
#endif

/* Convert a pointer to a page-table entry into pagetable slot index. */
#define pgentry_ptr_to_slot(_p) \
    (((unsigned long)(_p) & ~PAGE_MASK) / sizeof(*(_p)))

/* Page-table type. */
#ifndef __ASSEMBLY__
typedef struct { unsigned long pt_lo; } pagetable_t;
#define pagetable_val(_x)   ((_x).pt_lo)
#define mk_pagetable(_x)    ( (pagetable_t) { (_x) } )
#endif

#ifndef __ASSEMBLY__
#define PAGE_SIZE           (1UL << PAGE_SHIFT)
#else
#define PAGE_SIZE           (1 << PAGE_SHIFT)
#endif
#define PAGE_MASK           (~(PAGE_SIZE-1))

#define clear_page(_p)      memset((void *)(_p), 0, PAGE_SIZE)
#define copy_page(_t,_f)    memcpy((void *)(_t), (void *)(_f), PAGE_SIZE)

#define PAGE_OFFSET         ((unsigned long)__PAGE_OFFSET)
#define __pa(x)             ((unsigned long)(x)-PAGE_OFFSET)
#define __va(x)             ((void *)((unsigned long)(x)+PAGE_OFFSET))
#define pfn_to_page(_pfn)   (frame_table + (_pfn))
#define phys_to_page(kaddr) (frame_table + ((kaddr) >> PAGE_SHIFT))
#define virt_to_page(kaddr) (frame_table + (__pa(kaddr) >> PAGE_SHIFT))
#define VALID_PAGE(page)    ((page - frame_table) < max_mapnr)

/*
 * NB. We don't currently track I/O holes in the physical RAM space.
 * For now we guess that I/O devices will be mapped in the first 1MB
 * (e.g., VGA buffers) or beyond the end of physical RAM.
 */
#define pfn_is_ram(_pfn)    (((_pfn) > 0x100) && ((_pfn) < max_page))

/* High table entries are reserved by the hypervisor. */
#define DOMAIN_ENTRIES_PER_L2_PAGETABLE     \
  (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT)
#define HYPERVISOR_ENTRIES_PER_L2_PAGETABLE \
  (L2_PAGETABLE_ENTRIES - DOMAIN_ENTRIES_PER_L2_PAGETABLE)

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/bitops.h>
#include <asm/flushtlb.h>

#define linear_pg_table ((l1_pgentry_t *)LINEAR_PT_VIRT_START)
#define linear_l2_table ((l2_pgentry_t *)(LINEAR_PT_VIRT_START+(LINEAR_PT_VIRT_START>>(L2_PAGETABLE_SHIFT-L1_PAGETABLE_SHIFT))))

#define va_to_l1mfn(_va) (l2_pgentry_val(linear_l2_table[_va>>L2_PAGETABLE_SHIFT]) >> PAGE_SHIFT)

extern root_pgentry_t idle_pg_table[ROOT_PAGETABLE_ENTRIES];

extern void paging_init(void);

/* Flush global pages as well. */

#define __pge_off()                                                     \
    do {                                                                \
        __asm__ __volatile__(                                           \
            "mov %0, %%cr4;  # turn off PGE     "                       \
            : : "r" (mmu_cr4_features & ~X86_CR4_PGE) );                \
        } while ( 0 )

#define __pge_on()                                                      \
    do {                                                                \
        __asm__ __volatile__(                                           \
            "mov %0, %%cr4;  # turn off PGE     "                       \
            : : "r" (mmu_cr4_features) );                               \
    } while ( 0 )


#define __flush_tlb_pge()                                               \
    do {                                                                \
        __pge_off();                                                    \
        __flush_tlb();                                                  \
        __pge_on();                                                     \
    } while ( 0 )

#define __flush_tlb_one(__addr) \
    __asm__ __volatile__("invlpg %0": :"m" (*(char *) (__addr)))

#endif /* !__ASSEMBLY__ */


#define _PAGE_PRESENT  0x001UL
#define _PAGE_RW       0x002UL
#define _PAGE_USER     0x004UL
#define _PAGE_PWT      0x008UL
#define _PAGE_PCD      0x010UL
#define _PAGE_ACCESSED 0x020UL
#define _PAGE_DIRTY    0x040UL
#define _PAGE_PAT      0x080UL
#define _PAGE_PSE      0x080UL
#define _PAGE_GLOBAL   0x100UL

#define __PAGE_HYPERVISOR \
    (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED)
#define __PAGE_HYPERVISOR_NOCACHE \
    (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_PCD | _PAGE_ACCESSED)

#define MAKE_GLOBAL(_x) ((_x) | _PAGE_GLOBAL)

#define PAGE_HYPERVISOR MAKE_GLOBAL(__PAGE_HYPERVISOR)
#define PAGE_HYPERVISOR_NOCACHE MAKE_GLOBAL(__PAGE_HYPERVISOR_NOCACHE)

#ifndef __ASSEMBLY__

static __inline__ int get_order(unsigned long size)
{
    int order;
    
    size = (size-1) >> (PAGE_SHIFT-1);
    order = -1;
    do {
        size >>= 1;
        order++;
    } while (size);
    return order;
}

extern void zap_low_mappings(void);

/* Map physical byte range (@p, @p+@s) at virt address @v in pagetable @pt. */
extern int
map_pages(
    root_pgentry_t *pt,
    unsigned long v,
    unsigned long p,
    unsigned long s,
    unsigned long flags);

#endif /* !__ASSEMBLY__ */

#endif /* __I386_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
