/******************************************************************************
 * asm-x86/page.h
 * 
 * Definitions relating to page tables.
 */

#ifndef __X86_PAGE_H__
#define __X86_PAGE_H__

#if defined(__x86_64__)

#define L1_PAGETABLE_SHIFT       12
#define L2_PAGETABLE_SHIFT       21
#define L3_PAGETABLE_SHIFT       30
#define L4_PAGETABLE_SHIFT       39

#define ENTRIES_PER_L1_PAGETABLE 512
#define ENTRIES_PER_L2_PAGETABLE 512
#define ENTRIES_PER_L3_PAGETABLE 512
#define ENTRIES_PER_L4_PAGETABLE 512

#define __PAGE_OFFSET		(0xFFFF830000000000)

#elif defined(__i386__)

#define L1_PAGETABLE_SHIFT       12
#define L2_PAGETABLE_SHIFT       22

#define ENTRIES_PER_L1_PAGETABLE 1024
#define ENTRIES_PER_L2_PAGETABLE 1024

#define __PAGE_OFFSET		(0xFC400000)

#endif

#define PAGE_SHIFT               L1_PAGETABLE_SHIFT
#define PAGE_SIZE	         (1UL << PAGE_SHIFT)
#define PAGE_MASK	         (~(PAGE_SIZE-1))

#define clear_page(_p)           memset((void *)(_p), 0, PAGE_SIZE)
#define copy_page(_t,_f)         memcpy((void *)(_t), (void *)(_f), PAGE_SIZE)

#ifndef __ASSEMBLY__
#include <xen/config.h>
typedef struct { unsigned long l1_lo; } l1_pgentry_t;
typedef struct { unsigned long l2_lo; } l2_pgentry_t;
typedef struct { unsigned long l3_lo; } l3_pgentry_t;
typedef struct { unsigned long l4_lo; } l4_pgentry_t;
typedef struct { unsigned long pt_lo; } pagetable_t;
#endif /* !__ASSEMBLY__ */

/* Strip type from a table entry. */
#define l1_pgentry_val(_x) ((_x).l1_lo)
#define l2_pgentry_val(_x) ((_x).l2_lo)
#define l3_pgentry_val(_x) ((_x).l3_lo)
#define l4_pgentry_val(_x) ((_x).l4_lo)
#define pagetable_val(_x)  ((_x).pt_lo)

/* Add type to a table entry. */
#define mk_l1_pgentry(_x)  ( (l1_pgentry_t) { (_x) } )
#define mk_l2_pgentry(_x)  ( (l2_pgentry_t) { (_x) } )
#define mk_l3_pgentry(_x)  ( (l3_pgentry_t) { (_x) } )
#define mk_l4_pgentry(_x)  ( (l4_pgentry_t) { (_x) } )
#define mk_pagetable(_x)   ( (pagetable_t) { (_x) } )

/* Turn a typed table entry into a page index. */
#define l1_pgentry_to_pagenr(_x) (l1_pgentry_val(_x) >> PAGE_SHIFT) 
#define l2_pgentry_to_pagenr(_x) (l2_pgentry_val(_x) >> PAGE_SHIFT)
#define l3_pgentry_to_pagenr(_x) (l3_pgentry_val(_x) >> PAGE_SHIFT)
#define l4_pgentry_to_pagenr(_x) (l4_pgentry_val(_x) >> PAGE_SHIFT)

/* Turn a typed table entry into a physical address. */
#define l1_pgentry_to_phys(_x) (l1_pgentry_val(_x) & PAGE_MASK)
#define l2_pgentry_to_phys(_x) (l2_pgentry_val(_x) & PAGE_MASK)
#define l3_pgentry_to_phys(_x) (l3_pgentry_val(_x) & PAGE_MASK)
#define l4_pgentry_to_phys(_x) (l4_pgentry_val(_x) & PAGE_MASK)

/* Pagetable walking. */
#define l2_pgentry_to_l1(_x) \
  ((l1_pgentry_t *)__va(l2_pgentry_val(_x) & PAGE_MASK))
#define l3_pgentry_to_l2(_x) \
  ((l2_pgentry_t *)__va(l3_pgentry_val(_x) & PAGE_MASK))
#define l4_pgentry_to_l3(_x) \
  ((l3_pgentry_t *)__va(l4_pgentry_val(_x) & PAGE_MASK))

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT) & (ENTRIES_PER_L1_PAGETABLE - 1))
#if defined(__i386__)
#define l2_table_offset(_a) \
  ((_a) >> L2_PAGETABLE_SHIFT)
#elif defined(__x86_64__)
#define l2_table_offset(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT) & (ENTRIES_PER_L2_PAGETABLE -1))
#define l3_table_offset(_a) \
  (((_a) >> L3_PAGETABLE_SHIFT) & (ENTRIES_PER_L3_PAGETABLE -1))
#define l4_table_offset(_a) \
  ((_a) >> L4_PAGETABLE_SHIFT)
#endif

#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define __pa(x)			((unsigned long)(x)-PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define page_address(_p)        (__va(((_p) - frame_table) << PAGE_SHIFT))
#define phys_to_page(kaddr)     (frame_table + ((kaddr) >> PAGE_SHIFT))
#define virt_to_page(kaddr)	(frame_table + (__pa(kaddr) >> PAGE_SHIFT))
#define VALID_PAGE(page)	((page - frame_table) < max_mapnr)

/*
 * NB. We don't currently track I/O holes in the physical RAM space.
 * For now we guess that I/O devices will be mapped in the first 1MB
 * (e.g., VGA buffers) or beyond the end of physical RAM.
 */
#define pfn_is_ram(_pfn)        (((_pfn) > 0x100) && ((_pfn) < max_page))

/* High table entries are reserved by the hypervisor. */
#define DOMAIN_ENTRIES_PER_L2_PAGETABLE	    \
  (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT)
#define HYPERVISOR_ENTRIES_PER_L2_PAGETABLE \
  (ENTRIES_PER_L2_PAGETABLE - DOMAIN_ENTRIES_PER_L2_PAGETABLE)

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/bitops.h>
#include <asm/flushtlb.h>

#define linear_pg_table ((l1_pgentry_t *)LINEAR_PT_VIRT_START)
#define linear_l2_table ((l2_pgentry_t *)(LINEAR_PT_VIRT_START+(LINEAR_PT_VIRT_START>>(L2_PAGETABLE_SHIFT-L1_PAGETABLE_SHIFT))))

#define va_to_l1mfn(_va) (l2_pgentry_val(linear_l2_table[_va>>L2_PAGETABLE_SHIFT]) >> PAGE_SHIFT)

#ifdef __i386__
extern l2_pgentry_t idle_pg_table[ENTRIES_PER_L2_PAGETABLE];
#else
extern l4_pgentry_t idle_pg_table[ENTRIES_PER_L4_PAGETABLE];
#endif

extern void paging_init(void);

/* Flush global pages as well. */

#define __pge_off()                                                     \
        do {                                                            \
                __asm__ __volatile__(                                   \
                        "mov %0, %%cr4;  # turn off PGE     "           \
                        :: "r" (mmu_cr4_features & ~X86_CR4_PGE));      \
        } while (0)

#define __pge_on()                                                      \
        do {                                                            \
                __asm__ __volatile__(                                   \
                        "mov %0, %%cr4;  # turn off PGE     "           \
                        :: "r" (mmu_cr4_features));                     \
        } while (0)


#define __flush_tlb_pge()						\
	do {								\
                __pge_off();                                            \
		__flush_tlb();						\
                __pge_on();                                             \
	} while (0)

#define __flush_tlb_one(__addr) \
__asm__ __volatile__("invlpg %0": :"m" (*(char *) (__addr)))

#endif /* !__ASSEMBLY__ */


#define _PAGE_PRESENT	0x001
#define _PAGE_RW	0x002
#define _PAGE_USER	0x004
#define _PAGE_PWT	0x008
#define _PAGE_PCD	0x010
#define _PAGE_ACCESSED	0x020
#define _PAGE_DIRTY	0x040
#define _PAGE_PAT       0x080
#define _PAGE_PSE	0x080
#define _PAGE_GLOBAL	0x100

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
#endif

#endif /* __I386_PAGE_H__ */
