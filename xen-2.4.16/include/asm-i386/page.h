#ifndef _I386_PAGE_H
#define _I386_PAGE_H


#ifndef __ASSEMBLY__
#ifdef CONFIG_DEBUG_BUGVERBOSE
extern void do_BUG(const char *file, int line);
#define BUG() do {					\
	do_BUG(__FILE__, __LINE__);			\
	__asm__ __volatile__("ud2");			\
} while (0)
#else
#include <xeno/lib.h>
#define BUG() (panic("BUG at %s:%d\n", __FILE__, __LINE__))
#endif
#endif /* __ASSEMBLY__ */


#define L1_PAGETABLE_SHIFT       12
#define L2_PAGETABLE_SHIFT       22

#define ENTRIES_PER_L1_PAGETABLE 1024
#define ENTRIES_PER_L2_PAGETABLE 1024

#define PAGE_SHIFT               L1_PAGETABLE_SHIFT
#define PAGE_SIZE	         (1UL << PAGE_SHIFT)
#define PAGE_MASK	         (~(PAGE_SIZE-1))

#define clear_page(_p)           memset((void *)(_p), 0, PAGE_SIZE)
#define copy_page(_t,_f)         memcpy((void *)(_t), (void *)(_f), PAGE_SIZE)

#ifndef __ASSEMBLY__
#include <xeno/config.h>
typedef struct { unsigned long l1_lo; } l1_pgentry_t;
typedef struct { unsigned long l2_lo; } l2_pgentry_t;
typedef l1_pgentry_t *l1_pagetable_t;
typedef l2_pgentry_t *l2_pagetable_t;
typedef struct { unsigned long pt_lo; } pagetable_t;
#endif /* !__ASSEMBLY__ */

/* Strip type from a table entry. */
#define l1_pgentry_val(_x) ((_x).l1_lo)
#define l2_pgentry_val(_x) ((_x).l2_lo)
#define pagetable_val(_x)  ((_x).pt_lo)

#define alloc_l1_pagetable()  ((l1_pgentry_t *)get_free_page(GFP_KERNEL))
#define alloc_l2_pagetable()  ((l2_pgentry_t *)get_free_page(GFP_KERNEL))

/* Add type to a table entry. */
#define mk_l1_pgentry(_x)  ( (l1_pgentry_t) { (_x) } )
#define mk_l2_pgentry(_x)  ( (l2_pgentry_t) { (_x) } )
#define mk_pagetable(_x)   ( (pagetable_t) { (_x) } )

/* Turn a typed table entry into a page index. */
#define l1_pgentry_to_pagenr(_x) (l1_pgentry_val(_x) >> PAGE_SHIFT) 
#define l2_pgentry_to_pagenr(_x) (l2_pgentry_val(_x) >> PAGE_SHIFT)

/* Turn a typed table entry into a physical address. */
#define l1_pgentry_to_phys(_x) (l1_pgentry_val(_x) & PAGE_MASK)
#define l2_pgentry_to_phys(_x) (l2_pgentry_val(_x) & PAGE_MASK)

/* Dereference a typed level-2 entry to yield a typed level-1 table. */
#define l2_pgentry_to_l1(_x)     \
  ((l1_pgentry_t *)__va(l2_pgentry_val(_x) & PAGE_MASK))

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT) & (ENTRIES_PER_L1_PAGETABLE - 1))
#define l2_table_offset(_a) \
  ((_a) >> L2_PAGETABLE_SHIFT)

/* Hypervisor table entries use zero to sugnify 'empty'. */
#define l1_pgentry_empty(_x) (!l1_pgentry_val(_x))
#define l2_pgentry_empty(_x) (!l2_pgentry_val(_x))

#define __PAGE_OFFSET		(0xFC000000)
#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define __pa(x)			((unsigned long)(x)-PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define page_address(_p)        (__va(((_p) - frame_table) << PAGE_SHIFT))
#define virt_to_page(kaddr)	(frame_table + (__pa(kaddr) >> PAGE_SHIFT))
#define VALID_PAGE(page)	((page - frame_table) < max_mapnr)

/* High table entries are reserved by the hypervisor. */
#define DOMAIN_ENTRIES_PER_L2_PAGETABLE	    \
  (PAGE_OFFSET >> L2_PAGETABLE_SHIFT)
#define HYPERVISOR_ENTRIES_PER_L2_PAGETABLE \
  (ENTRIES_PER_L2_PAGETABLE - DOMAIN_ENTRIES_PER_L2_PAGETABLE)

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/bitops.h>

extern l2_pgentry_t idle0_pg_table[ENTRIES_PER_L2_PAGETABLE];
extern l2_pgentry_t *idle_pg_table[NR_CPUS];
extern void paging_init(void);

#define __flush_tlb()							\
	do {								\
		unsigned int tmpreg;					\
									\
		__asm__ __volatile__(					\
			"movl %%cr3, %0;  # flush TLB \n"		\
			"movl %0, %%cr3;              \n"		\
			: "=r" (tmpreg)					\
			:: "memory");					\
	} while (0)

/* Flush global pages as well. */
#define __flush_tlb_all()						\
	do {								\
		unsigned int tmpreg;					\
									\
		__asm__ __volatile__(					\
			"movl %1, %%cr4;  # turn off PGE     \n"	\
			"movl %%cr3, %0;  # flush TLB        \n"	\
			"movl %0, %%cr3;                     \n"	\
			"movl %2, %%cr4;  # turn PGE back on \n"	\
			: "=&r" (tmpreg)				\
			: "r" (mmu_cr4_features & ~X86_CR4_PGE),	\
			  "r" (mmu_cr4_features)			\
			: "memory");					\
	} while (0)

#define __flush_tlb_one(addr) \
__asm__ __volatile__("invlpg %0": :"m" (*(char *) addr))

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
#define __PAGE_HYPERVISOR_RO \
	(_PAGE_PRESENT | _PAGE_DIRTY | _PAGE_ACCESSED)

#define MAKE_GLOBAL(_x) ((_x) | _PAGE_GLOBAL)

#define PAGE_HYPERVISOR MAKE_GLOBAL(__PAGE_HYPERVISOR)
#define PAGE_HYPERVISOR_RO MAKE_GLOBAL(__PAGE_HYPERVISOR_RO)
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
#endif

#endif /* _I386_PAGE_H */
