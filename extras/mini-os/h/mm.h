/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: mm.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Aug 2003
 * 
 * Environment: 
 * Description: 
 *
 ****************************************************************************
 * $Id: h-insert.h,v 1.4 2002/11/08 16:03:55 rn Exp $
 ****************************************************************************
 */

#ifndef _MM_H_
#define _MM_H_

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE-1))


#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
#define PFN_PHYS(x)	((x) << PAGE_SHIFT)


/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)


extern unsigned long *phys_to_machine_mapping;
#define pfn_to_mfn(_pfn) (phys_to_machine_mapping[(_pfn)])
#define mfn_to_pfn(_mfn) (machine_to_phys_mapping[(_mfn)])
static inline unsigned long phys_to_machine(unsigned long phys)
{
    unsigned long machine = pfn_to_mfn(phys >> PAGE_SHIFT);
    machine = (machine << PAGE_SHIFT) | (phys & ~PAGE_MASK);
    return machine;
}
static inline unsigned long machine_to_phys(unsigned long machine)
{
    unsigned long phys = mfn_to_pfn(machine >> PAGE_SHIFT);
    phys = (phys << PAGE_SHIFT) | (machine & ~PAGE_MASK);
    return phys;
}

/* VIRT <-> MACHINE conversion */
#define virt_to_machine(_a) (phys_to_machine(__pa(_a)))
#define machine_to_virt(_m) (__va(machine_to_phys(_m)))

/*
 * This handles the memory map.. We could make this a config
 * option, but too many people screw it up, and too few need
 * it.
 *
 * A __PAGE_OFFSET of 0xC0000000 means that the kernel has
 * a virtual address space of one gigabyte, which limits the
 * amount of physical memory you can use to about 950MB. 
 *
 * If you want more physical memory than this then see the CONFIG_HIGHMEM4G
 * and CONFIG_HIGHMEM64G options in the kernel configuration.
 */

#define __PAGE_OFFSET           (0xC0000000)

#define PAGE_OFFSET             ((unsigned long)__PAGE_OFFSET)
#define __pa(x)                 ((unsigned long)(x)-PAGE_OFFSET)
#define __va(x)                 ((void *)((unsigned long)(x)+PAGE_OFFSET))
#define virt_to_page(kaddr)     (mem_map + (__pa(kaddr) >> PAGE_SHIFT))
#define VALID_PAGE(page)        ((page - mem_map) < max_mapnr)

#define VM_DATA_DEFAULT_FLAGS   (VM_READ | VM_WRITE | VM_EXEC | \
                                 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)


/* prototypes */
void init_mm();
void release_bytes_to_allocator(unsigned long min, unsigned long max);
unsigned long __get_free_pages(int order);
void __free_pages(unsigned long p, int order);
#define get_free_pages(_o) (__get_free_pages(_o))
#define get_free_page() (__get_free_pages(0))
#define free_pages(_p,_o) (__free_pages(_p,_o))
#define free_page(_p) (__free_pages(_p,0))

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


#endif /* _MM_H_ */
