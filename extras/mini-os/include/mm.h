/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 *
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 * Copyright (c) 2005, Keir A Fraser
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef _MM_H_
#define _MM_H_

#if defined(__i386__)
#include <xen/arch-x86_32.h>
#elif defined(__x86_64__)
#include <xen/arch-x86_64.h>
#else
#error "Unsupported architecture"
#endif

#include <lib.h>

#define L1_FRAME                1
#define L2_FRAME                2
#define L3_FRAME                3

#define L1_PAGETABLE_SHIFT      12

#if defined(__i386__)

#define L2_PAGETABLE_SHIFT      22

#define L1_PAGETABLE_ENTRIES    1024
#define L2_PAGETABLE_ENTRIES    1024

#define PADDR_BITS              32
#define PADDR_MASK              (~0UL)

#elif defined(__x86_64__)

#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39

#define L1_PAGETABLE_ENTRIES    512
#define L2_PAGETABLE_ENTRIES    512
#define L3_PAGETABLE_ENTRIES    512
#define L4_PAGETABLE_ENTRIES    512

/* These are page-table limitations. Current CPUs support only 40-bit phys. */
#define PADDR_BITS              52
#define VADDR_BITS              48
#define PADDR_MASK              ((1UL << PADDR_BITS)-1)
#define VADDR_MASK              ((1UL << VADDR_BITS)-1)

/* Get physical address of page mapped by pte (paddr_t). */
#define l1e_get_paddr(x)           \
    ((unsigned long)(((x) & (PADDR_MASK&PAGE_MASK))))
#define l2e_get_paddr(x)           \
    ((unsigned long)(((x) & (PADDR_MASK&PAGE_MASK))))
#define l3e_get_paddr(x)           \
    ((unsigned long)(((x) & (PADDR_MASK&PAGE_MASK))))
#define l4e_get_paddr(x)           \
    ((unsigned long)(((x) & (PADDR_MASK&PAGE_MASK))))

#define L2_MASK  ((1UL << L3_PAGETABLE_SHIFT) - 1)
#define L3_MASK  ((1UL << L4_PAGETABLE_SHIFT) - 1)

#endif

#define L1_MASK  ((1UL << L2_PAGETABLE_SHIFT) - 1)

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define l2_table_offset(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1))
#if defined(__x86_64__)
#define l3_table_offset(_a) \
  (((_a) >> L3_PAGETABLE_SHIFT) & (L3_PAGETABLE_ENTRIES - 1))
#define l4_table_offset(_a) \
  (((_a) >> L4_PAGETABLE_SHIFT) & (L4_PAGETABLE_ENTRIES - 1))
#endif

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

#if defined(__i386__)
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY |_PAGE_USER)
#elif defined(__x86_64__)
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L3_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L4_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#endif

#define PAGE_SIZE       (1UL << L1_PAGETABLE_SHIFT)
#define PAGE_SHIFT      L1_PAGETABLE_SHIFT
#define PAGE_MASK       (~(PAGE_SIZE-1))

#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> L1_PAGETABLE_SHIFT)
#define PFN_DOWN(x)	((x) >> L1_PAGETABLE_SHIFT)
#define PFN_PHYS(x)	((x) << L1_PAGETABLE_SHIFT)

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)

extern unsigned long *phys_to_machine_mapping;
#define pfn_to_mfn(_pfn) (phys_to_machine_mapping[(_pfn)])
static __inline__ unsigned long phys_to_machine(unsigned long phys)
{
    unsigned long machine = pfn_to_mfn(phys >> L1_PAGETABLE_SHIFT);
    machine = (machine << L1_PAGETABLE_SHIFT) | (phys & ~PAGE_MASK);
    return machine;
}


#define mfn_to_pfn(_mfn) (machine_to_phys_mapping[(_mfn)])
static __inline__ unsigned long machine_to_phys(unsigned long machine)
{
    unsigned long phys = mfn_to_pfn(machine >> L1_PAGETABLE_SHIFT);
    phys = (phys << L1_PAGETABLE_SHIFT) | (machine & ~PAGE_MASK);
    return phys;
}

#if defined(__x86_64__)
#define VIRT_START              0xFFFFFFFF80000000UL
#elif defined(__i386__)
#define VIRT_START              0xC0000000UL
#endif

#define to_phys(x)                 ((unsigned long)(x)-VIRT_START)
#define to_virt(x)                 ((void *)((unsigned long)(x)+VIRT_START))

#define virt_to_pfn(_virt)         (PFN_DOWN(to_phys(_virt)))
#define mach_to_virt(_mach)        (to_virt(machine_to_phys(_mach)))
#define mfn_to_virt(_mfn)          (mach_to_virt(_mfn << PAGE_SHIFT))
#define pfn_to_virt(_pfn)          (to_virt(_pfn << PAGE_SHIFT))

/* Pagetable walking. */
#define pte_to_mfn(_pte)           (((_pte) & (PADDR_MASK&PAGE_MASK)) >> L1_PAGETABLE_SHIFT)
#define pte_to_virt(_pte)          to_virt(mfn_to_pfn(pte_to_mfn(_pte)) << PAGE_SHIFT)

void init_mm(void);
unsigned long alloc_pages(int order);
#define alloc_page()    alloc_pages(0);
void free_pages(void *pointer, int order);

static __inline__ int get_order(unsigned long size)
{
    int order;
    size = (size-1) >> PAGE_SHIFT;
    for ( order = 0; size; order++ )
        size >>= 1;
    return order;
}


#endif /* _MM_H_ */
