/*
 * arch/xen/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 *
 * Modifications for Xenolinux (c) 2003 Keir Fraser
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

static inline int direct_remap_area_pte(pte_t *pte, 
                                         unsigned long address, 
                                         unsigned long size,
                                         unsigned long machine_addr, 
                                         pgprot_t prot,
                                         domid_t  domid)
{
    unsigned long end;

    mmu_update_t *u, *v;
    u = v = vmalloc(3*PAGE_SIZE); /* plenty */

    if (!u) 
	return -ENOMEM;

    /* If not I/O mapping then specify General-Purpose Subject Domain (GPS). */
    if ( domid != 0 )
    {
        v[0].val  = (unsigned long)(domid<<16) & ~0xFFFFUL;
        v[0].ptr  = (unsigned long)(domid<< 0) & ~0xFFFFUL;
        v[1].val  = (unsigned long)(domid>>16) & ~0xFFFFUL;
        v[1].ptr  = (unsigned long)(domid>>32) & ~0xFFFFUL;
        v[0].ptr |= MMU_EXTENDED_COMMAND;
        v[0].val |= MMUEXT_SET_SUBJECTDOM_L;
        v[1].ptr |= MMU_EXTENDED_COMMAND;
        v[1].val |= MMUEXT_SET_SUBJECTDOM_H;
        v += 2;
    }

    address &= ~PMD_MASK;
    end = address + size;
    if (end > PMD_SIZE)
        end = PMD_SIZE;
    if (address >= end)
        BUG();
    do {
#if 0  /* thanks to new ioctl mmaping interface this is no longer a bug */
        if (!pte_none(*pte)) {
            printk("direct_remap_area_pte: page already exists\n");
            BUG();
        }
#endif
        v->ptr = virt_to_machine(pte);
        v->val = (machine_addr & PAGE_MASK) | pgprot_val(prot) | _PAGE_IO;
        v++;
        address += PAGE_SIZE;
        machine_addr += PAGE_SIZE;
        pte++;
    } while (address && (address < end));

    if ( ((v-u) > 2) && (HYPERVISOR_mmu_update(u, v-u) < 0) )
    {
        printk(KERN_WARNING "Failed to ioremap %08lx->%08lx (%08lx)\n",
               end-size, end, machine_addr-size);
	return -EINVAL;
    }

    vfree(u);
    return 0;
}

static inline int direct_remap_area_pmd(struct mm_struct *mm,
                                        pmd_t *pmd, 
                                        unsigned long address, 
                                        unsigned long size,
                                        unsigned long machine_addr,
                                        pgprot_t prot,
                                        domid_t  domid)
{
    unsigned long end;
    int rc;

    address &= ~PGDIR_MASK;
    end = address + size;
    if (end > PGDIR_SIZE)
        end = PGDIR_SIZE;
    machine_addr -= address;
    if (address >= end)
        BUG();
    do {
        pte_t * pte = pte_alloc(mm, pmd, address);
        if (!pte)
            return -ENOMEM;

        if ( rc = direct_remap_area_pte(pte, address, end - address, 
                              address + machine_addr, prot, domid) )
	    return rc;

        address = (address + PMD_SIZE) & PMD_MASK;
        pmd++;
    } while (address && (address < end));
    return 0;
}
 
int direct_remap_area_pages(struct mm_struct *mm,
                            unsigned long address, 
                            unsigned long machine_addr,
                            unsigned long size, 
                            pgprot_t prot,
                            domid_t  domid)
{
    int error = 0;
    pgd_t * dir;
    unsigned long end = address + size;

/*printk("direct_remap_area_pages va=%08lx ma=%08lx size=%d\n",
       address, machine_addr, size);*/

    machine_addr -= address;
    dir = pgd_offset(mm, address);
    flush_cache_all();
    if (address >= end)
        BUG();
    spin_lock(&mm->page_table_lock);
    do {
        pmd_t *pmd = pmd_alloc(mm, dir, address);
        error = -ENOMEM;
        if (!pmd)
            break;
        error = direct_remap_area_pmd(mm, pmd, address, end - address,
                                      machine_addr + address, prot, domid);
        if (error)
            break;
        address = (address + PGDIR_SIZE) & PGDIR_MASK;
        dir++;
    } while (address && (address < end));
    spin_unlock(&mm->page_table_lock);
    flush_tlb_all();
    return error;
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

    /* Only privileged Xenolinux can make unchecked pagetable updates. */
    if ( !(start_info.flags & SIF_PRIVILEGED) )
        return NULL;

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
                __set_fixmap(idx, machine_addr, 
                             __pgprot(__PAGE_KERNEL|_PAGE_IO));
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
