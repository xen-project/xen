/*
 * arch/xen/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 *
 * Modifications for Xenolinux (c) 2003-2004 Keir Fraser
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/mmu.h>

#if defined(CONFIG_XEN_PRIVILEGED_GUEST)

/* These hacky macros avoid phys->machine translations. */
#define __direct_pte(x) ((pte_t) { (x) } )
#define __direct_mk_pte(page_nr,pgprot) \
  __direct_pte(((page_nr) << PAGE_SHIFT) | pgprot_val(pgprot))
#define direct_mk_pte_phys(physpage, pgprot) \
  __direct_mk_pte((physpage) >> PAGE_SHIFT, pgprot)

static inline void direct_remap_area_pte(pte_t *pte, 
                                        unsigned long address, 
                                        unsigned long size,
					mmu_update_t **v)
{
    unsigned long end;

    address &= ~PMD_MASK;
    end = address + size;
    if (end > PMD_SIZE)
        end = PMD_SIZE;
    if (address >= end)
        BUG();

    do {
        (*v)->ptr = virt_to_machine(pte);
        (*v)++;
        address += PAGE_SIZE;
        pte++;
    } while (address && (address < end));
}

static inline int direct_remap_area_pmd(struct mm_struct *mm,
                                        pmd_t *pmd, 
                                        unsigned long address, 
                                        unsigned long size,
					mmu_update_t **v)
{
    unsigned long end;

    address &= ~PGDIR_MASK;
    end = address + size;
    if (end > PGDIR_SIZE)
        end = PGDIR_SIZE;
    if (address >= end)
        BUG();
    do {
        pte_t *pte = pte_alloc(mm, pmd, address);
        if (!pte)
            return -ENOMEM;
        direct_remap_area_pte(pte, address, end - address, v);

        address = (address + PMD_SIZE) & PMD_MASK;
        pmd++;
    } while (address && (address < end));
    return 0;
}
 
int __direct_remap_area_pages(struct mm_struct *mm,
			      unsigned long address, 
			      unsigned long size, 
			      mmu_update_t *v)
{
    pgd_t * dir;
    unsigned long end = address + size;

    dir = pgd_offset(mm, address);
    flush_cache_all();
    if (address >= end)
        BUG();
    spin_lock(&mm->page_table_lock);
    do {
        pmd_t *pmd = pmd_alloc(mm, dir, address);
        if (!pmd)
	    return -ENOMEM;
        direct_remap_area_pmd(mm, pmd, address, end - address, &v);
        address = (address + PGDIR_SIZE) & PGDIR_MASK;
        dir++;

    } while (address && (address < end));
    spin_unlock(&mm->page_table_lock);
    flush_tlb_all();
    return 0;
}


int direct_remap_area_pages(struct mm_struct *mm,
                            unsigned long address, 
                            unsigned long machine_addr,
                            unsigned long size, 
                            pgprot_t prot,
                            domid_t  domid)
{
    int i;
    unsigned long start_address;
#define MAX_DIRECTMAP_MMU_QUEUE 130
    mmu_update_t u[MAX_DIRECTMAP_MMU_QUEUE], *v = u;

    start_address = address;

    for( i = 0; i < size; i += PAGE_SIZE )
    {
	if ( (v - u) == MAX_DIRECTMAP_MMU_QUEUE )
	{
	    /* Fill in the PTE pointers. */
	    __direct_remap_area_pages( mm,
				       start_address, 
				       address-start_address, 
				       u);
	    
	    if ( HYPERVISOR_mmu_update(u, v - u, NULL, domid) < 0 )
		return -EFAULT;	    
	    v = u;
	    start_address = address;
	}

	/*
         * Fill in the machine address: PTE ptr is done later by
         * __direct_remap_area_pages(). 
         */
        v->val = (machine_addr & PAGE_MASK) | pgprot_val(prot);

        machine_addr += PAGE_SIZE;
        address += PAGE_SIZE; 
        v++;
    }

    if ( v != u )
    {
	/* get the ptep's filled in */
	__direct_remap_area_pages(mm,
                                  start_address, 
                                  address-start_address, 
                                  u);	 
	if ( unlikely(HYPERVISOR_mmu_update(u, v - u, NULL, domid) < 0) )
	    return -EFAULT;	    
    }
    
    return 0;
}


#endif /* CONFIG_XEN_PRIVILEGED_GUEST */


/*
 * Remap an arbitrary machine address space into the kernel virtual
 * address space. Needed when a privileged instance of Xenolinux wants
 * to access space outside its world directly.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */
void * __ioremap(unsigned long machine_addr, 
                 unsigned long size, 
                 unsigned long flags)
{
#if defined(CONFIG_XEN_PRIVILEGED_GUEST)
    void * addr;
    struct vm_struct * area;
    unsigned long offset, last_addr;
    pgprot_t prot;

    /* Don't allow wraparound or zero size */
    last_addr = machine_addr + size - 1;
    if (!size || last_addr < machine_addr)
        return NULL;

    /* Mappings have to be page-aligned */
    offset = machine_addr & ~PAGE_MASK;
    machine_addr &= PAGE_MASK;
    size = PAGE_ALIGN(last_addr+1) - machine_addr;

    /* Ok, go for it */
    area = get_vm_area(size, VM_IOREMAP);
    if (!area)
        return NULL;
    addr = area->addr;
    prot = __pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | 
                    _PAGE_ACCESSED | flags);
    if (direct_remap_area_pages(&init_mm, VMALLOC_VMADDR(addr), 
                                machine_addr, size, prot, 0)) {
        vfree(addr);
        return NULL;
    }
    return (void *) (offset + (char *)addr);
#else
    return NULL;
#endif
}

void iounmap(void *addr)
{
    vfree((void *)((unsigned long)addr & PAGE_MASK));
}

/* implementation of boot time ioremap for purpose of provising access
to the vga console for privileged domains. Unlike boot time ioremap on 
other architectures, ours is permanent and not reclaimed when then vmalloc
infrastructure is started */

void __init *bt_ioremap(unsigned long machine_addr, unsigned long size)
{
        unsigned long offset, last_addr;
        unsigned int nrpages;
        enum fixed_addresses idx;

        /* Don't allow wraparound or zero size */
        last_addr = machine_addr + size - 1;
        if (!size || last_addr < machine_addr)
                return NULL;

        /*
         * Mappings have to be page-aligned
         */
        offset = machine_addr & ~PAGE_MASK;
        machine_addr &= PAGE_MASK;
        size = PAGE_ALIGN(last_addr) - machine_addr;

        /*
         * Mappings have to fit in the FIX_BTMAP area.
         */
        nrpages = size >> PAGE_SHIFT;
        if (nrpages > NR_FIX_BTMAPS)
                return NULL;

        /*
         * Ok, go for it..
         */
        idx = FIX_BTMAP_BEGIN;
        while (nrpages > 0) {
                __set_fixmap(idx, machine_addr, PAGE_KERNEL);
                machine_addr += PAGE_SIZE;
                --idx;
                --nrpages;
        }

	flush_tlb_all();

        return (void*) (offset + fix_to_virt(FIX_BTMAP_BEGIN));
}


#if 0 /* We don't support these functions. They shouldn't be required. */
void __init bt_iounmap(void *addr, unsigned long size) {}
#endif
