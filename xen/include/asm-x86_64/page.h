#ifndef _X86_64_PAGE_H
#define _X86_64_PAGE_H

#define BUG() do {					\
	printk("BUG at %s:%d\n", __FILE__, __LINE__);	\
	__asm__ __volatile__("ud2");			\
} while (0)
 
#define __PHYSICAL_MASK       0x0000ffffffffffffUL
#define PHYSICAL_PAGE_MASK    0x0000fffffffff000UL
#define PTE_MASK	PHYSICAL_PAGE_MASK

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT	12
#ifdef __ASSEMBLY__
#define PAGE_SIZE	(0x1 << PAGE_SHIFT)
#else
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK	(~(PAGE_SIZE-1))
#define LARGE_PAGE_MASK (~(LARGE_PAGE_SIZE-1))
#define LARGE_PAGE_SIZE (1UL << PMD_SHIFT)

#define L1_PAGETABLE_SHIFT       12
#define L2_PAGETABLE_SHIFT       21
#define L3_PAGETABLE_SHIFT	 30
#define L4_PAGETABLE_SHIFT	 39
#define LARGE_PFN	(LARGE_PAGE_SIZE / PAGE_SIZE)

#define ENTRIES_PER_L1_PAGETABLE 512 
#define ENTRIES_PER_L2_PAGETABLE 512 
#define ENTRIES_PER_L3_PAGETABLE 512
#define ENTRIES_PER_L4_PAGETABLE 512

#define KERNEL_TEXT_SIZE  (40UL*1024*1024)
#define KERNEL_TEXT_START 0xffffffff80000000UL 

/* Changing the next two defines should be enough to increase the kernel stack */
/* We still hope 8K is enough, but ... */
#define THREAD_ORDER    1
#define THREAD_SIZE    (2*PAGE_SIZE)

#define INIT_TASK_SIZE THREAD_SIZE
#define CURRENT_MASK (~(THREAD_SIZE-1))

#define clear_page(_p)           memset((void *)(_p), 0, PAGE_SIZE)
#define copy_page(_t,_f)         memcpy((void *)(_t), (void *)(_f), PAGE_SIZE)

#ifndef __ASSEMBLY__
#include <xen/config.h>
typedef struct { unsigned long l1_lo; } l1_pgentry_t;
typedef struct { unsigned long l2_lo; } l2_pgentry_t;
typedef struct { unsigned long l3_lo; } l3_pgentry_t;
typedef struct { unsigned long l4_lo; } l4_pgentry_t;
typedef l1_pgentry_t *l1_pagetable_t;
typedef l2_pgentry_t *l2_pagetable_t;
typedef l3_pgentry_t *l3_pagetable_t;
typedef l4_pgentry_t *l4_pagetable_t;
typedef struct { unsigned long pt_lo; } pagetable_t;
typedef struct { unsigned long pgprot; } pgprot_t;
#endif /* !__ASSEMBLY__ */

/* Strip type from a table entry. */
#define l1_pgentry_val(_x) ((_x).l1_lo)
#define l2_pgentry_val(_x) ((_x).l2_lo)
#define l3_pgentry_val(_x) ((_x).l3_lo)
#define l4_pgentry_val(_x) ((_x).l4_lo)
#define pagetable_val(_x)  ((_x).pt_lo)

#define alloc_l1_pagetable()  ((l1_pgentry_t *)get_free_page(GFP_KERNEL))
#define alloc_l2_pagetable()  ((l2_pgentry_t *)get_free_page(GFP_KERNEL))
#define alloc_l3_pagetable()  ((l3_pgentry_t *)get_free_page(GFP_KERNEL))
#define alloc_l4_pagetable()  ((l4_pgentry_t *)get_free_page(GFP_KERNEL))

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

/* Dereference a typed level-2 entry to yield a typed level-1 table. */
#define l2_pgentry_to_l1(_x)     \
  ((l1_pgentry_t *)__va(l2_pgentry_val(_x) & PAGE_MASK))

/* Dereference a typed level-4 entry to yield a typed level-3 table. */
#define l4_pgentry_to_l3(_x)     \
  ((l3_pgentry_t *)__va(l4_pgentry_val(_x) & PAGE_MASK))

/* Dereference a typed level-3 entry to yield a typed level-2 table. */
#define l3_pgentry_to_l2(_x)     \
  ((l2_pgentry_t *)__va(l3_pgentry_val(_x) & PAGE_MASK))

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT) & (ENTRIES_PER_L1_PAGETABLE - 1))
#define l2_table_offset(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT) & (ENTRIES_PER_L2_PAGETABLE - 1))
#define l3_table_offset(_a) \
  (((_a) >> L3_PAGETABLE_SHIFT) & (ENTRIES_PER_L3_PAGETABLE - 1))
#define l4_table_offset(_a) \
  ((_a) >> L4_PAGETABLE_SHIFT)

/* Hypervisor table entries use zero to sugnify 'empty'. */
#define l1_pgentry_empty(_x) (!l1_pgentry_val(_x))
#define l2_pgentry_empty(_x) (!l2_pgentry_val(_x))
#define l3_pgentry_empty(_x) (!l3_pgentry_val(_x))
#define l4_pgentry_empty(_x) (!l4_pgentry_val(_x))


#define pgprot_val(x)	((x).pgprot)
#define __pgprot(x)	((pgprot_t) { (x) } )
 
#define clear_user_page(page, vaddr)	clear_page(page)
#define copy_user_page(to, from, vaddr)	copy_page(to, from)

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK)

/*
 * NB. We don't currently track I/O holes in the physical RAM space.
 * For now we guess that I/O devices will be mapped in the first 1MB
 * (e.g., VGA buffers) or beyond the end of physical RAM.
 */
#define pfn_is_ram(_pfn)        (((_pfn) > 0x100) && ((_pfn) < max_page))

/* High table entries are reserved by the hypervisor. */
#define DOMAIN_ENTRIES_PER_L4_PAGETABLE	    \
  (HYPERVISOR_VIRT_START >> L4_PAGETABLE_SHIFT)
#define HYPERVISOR_ENTRIES_PER_L4_PAGETABLE \
  (ENTRIES_PER_L4_PAGETABLE - DOMAIN_ENTRIES_PER_L4_PAGETABLE)

#define __START_KERNEL		0xffffffff80100000
#define __START_KERNEL_map	0xffffffff80000000
#define __PAGE_OFFSET           0x0000010000000000
#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/bitops.h>
#include <asm/flushtlb.h>

extern unsigned long vm_stack_flags, vm_stack_flags32;
extern unsigned long vm_data_default_flags, vm_data_default_flags32;
extern unsigned long vm_force_exec32;

#define linear_pg_table ((l1_pgentry_t *)LINEAR_PT_VIRT_START)

extern l2_pgentry_t idle_pg_table[ENTRIES_PER_L2_PAGETABLE];
extern void paging_init(void);

#define __flush_tlb() flush_tlb_counted()

/* Flush global pages as well. */

#define __pge_off()                                                     \
        do {                                                            \
                __asm__ __volatile__(                                   \
                        "movl %0, %%cr4;  # turn off PGE     "          \
                        :: "r" (mmu_cr4_features & ~X86_CR4_PGE));      \
        } while (0)

#define __pge_on()                                                      \
        do {                                                            \
                __asm__ __volatile__(                                   \
                        "movl %0, %%cr4;  # turn off PGE     "          \
                        :: "r" (mmu_cr4_features));                     \
        } while (0)


#define __flush_tlb_pge()						\
	do {								\
                __pge_off();                                            \
		flush_tlb_counted();					\
                __pge_on();                                             \
	} while (0)

#define __flush_tlb_one(__addr) \
__asm__ __volatile__("invlpg %0": :"m" (*(char *) (__addr)))

#include <xen/config.h>

/*
 * Tell the user there is some problem.  The exception handler decodes this frame.
 */
struct bug_frame { 
       unsigned char ud2[2];          
       char *filename;    /* should use 32bit offset instead, but the assembler doesn't like it */ 
       unsigned short line; 
} __attribute__((packed)); 
#define HEADER_BUG() asm volatile("ud2 ; .quad %P1 ; .short %P0" :: "i"(__LINE__), \
		"i" (__stringify(__FILE__)))
#define PAGE_BUG(page) BUG()

#endif /* ASSEMBLY */

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

#define mk_l4_writeable(_p) \
    (*(_p) = mk_l4_pgentry(l4_pgentry_val(*(_p)) |  _PAGE_RW))
#define mk_l4_readonly(_p) \
    (*(_p) = mk_l4_pgentry(l4_pgentry_val(*(_p)) & ~_PAGE_RW))
#define mk_l3_writeable(_p) \
    (*(_p) = mk_l3_pgentry(l3_pgentry_val(*(_p)) |  _PAGE_RW))
#define mk_l3_readonly(_p) \
    (*(_p) = mk_l3_pgentry(l3_pgentry_val(*(_p)) & ~_PAGE_RW))
#define mk_l2_writeable(_p) \
    (*(_p) = mk_l2_pgentry(l2_pgentry_val(*(_p)) |  _PAGE_RW))
#define mk_l2_readonly(_p) \
    (*(_p) = mk_l2_pgentry(l2_pgentry_val(*(_p)) & ~_PAGE_RW))
#define mk_l1_writeable(_p) \
    (*(_p) = mk_l1_pgentry(l1_pgentry_val(*(_p)) |  _PAGE_RW))
#define mk_l1_readonly(_p) \
    (*(_p) = mk_l1_pgentry(l1_pgentry_val(*(_p)) & ~_PAGE_RW))

/* Note: __pa(&symbol_visible_to_c) should be always replaced with __pa_symbol.
   Otherwise you risk miscompilation. */ 
#define __pa(x)			(((unsigned long)(x)>=__START_KERNEL_map)?(unsigned long)(x) - (unsigned long)__START_KERNEL_map:(unsigned long)(x) - PAGE_OFFSET)
/* __pa_symbol should use for C visible symbols, but only for them. 
   This seems to be the official gcc blessed way to do such arithmetic. */ 
#define __pa_symbol(x)		\
	({unsigned long v;  \
	  asm("" : "=r" (v) : "0" (x)); \
	 v - __START_KERNEL_map; })
#define __pa_maybe_symbol(x)		\
	({unsigned long v;  \
	  asm("" : "=r" (v) : "0" (x)); \
	  __pa(v); })
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#ifndef CONFIG_DISCONTIGMEM
#define virt_to_page(kaddr)	(frame_table + (__pa(kaddr) >> PAGE_SHIFT))
#define pfn_to_page(pfn)	(frame_table + (pfn)) 
#define page_address(_p)        (__va(((_p) - frame_table) << PAGE_SHIFT))
#define VALID_PAGE(page)	(((page) - frame_table) < max_mapnr)
#endif

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

#define phys_to_pfn(phys)	((phys) >> PAGE_SHIFT)

#define __VM_DATA_DEFAULT_FLAGS	(VM_READ | VM_WRITE | VM_EXEC | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)
#define __VM_STACK_FLAGS 	(VM_GROWSDOWN | VM_READ | VM_WRITE | VM_EXEC | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#define VM_DATA_DEFAULT_FLAGS \
	((current->thread.flags & THREAD_IA32) ? vm_data_default_flags32 : \
	  vm_data_default_flags) 
#define VM_STACK_FLAGS	vm_stack_flags

#endif /* _X86_64_PAGE_H */
