/*
 * arch/i386/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */

#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/fixmap.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#ifndef CONFIG_XEN_PHYSDEV_ACCESS

void * __ioremap(unsigned long phys_addr, unsigned long size,
		 unsigned long flags)
{
	return NULL;
}

void *ioremap_nocache (unsigned long phys_addr, unsigned long size)
{
	return NULL;
}

void iounmap(volatile void __iomem *addr)
{
}

void __init *bt_ioremap(unsigned long phys_addr, unsigned long size)
{
	return NULL;
}

void __init bt_iounmap(void *addr, unsigned long size)
{
}

#else

static inline void remap_area_pte(pte_t * pte, unsigned long address, unsigned long size,
	unsigned long phys_addr, unsigned long flags)
{
	unsigned long end;
	unsigned long pfn;

	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	if (address >= end)
		BUG();
	pfn = phys_addr >> PAGE_SHIFT;
	do {
		if (!pte_none(*pte)) {
			printk("remap_area_pte: page already exists\n");
			BUG();
		}
		set_pte(pte, pfn_pte_ma(pfn, __pgprot(_PAGE_PRESENT | _PAGE_RW | 
					_PAGE_DIRTY | _PAGE_ACCESSED | flags)));
		address += PAGE_SIZE;
		pfn++;
		pte++;
	} while (address && (address < end));
}

static inline int remap_area_pmd(pmd_t * pmd, unsigned long address, unsigned long size,
	unsigned long phys_addr, unsigned long flags)
{
	unsigned long end;

	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	phys_addr -= address;
	if (address >= end)
		BUG();
	do {
		pte_t * pte = pte_alloc_kernel(&init_mm, pmd, address);
		if (!pte)
			return -ENOMEM;
		remap_area_pte(pte, address, end - address, address + phys_addr, flags);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address && (address < end));
	return 0;
}

static int remap_area_pages(unsigned long address, unsigned long phys_addr,
				 unsigned long size, unsigned long flags)
{
	int error;
	pgd_t * dir;
	unsigned long end = address + size;

	phys_addr -= address;
	dir = pgd_offset(&init_mm, address);
	flush_cache_all();
	if (address >= end)
		BUG();
	spin_lock(&init_mm.page_table_lock);
	do {
		pmd_t *pmd;
		pmd = pmd_alloc(&init_mm, dir, address);
		error = -ENOMEM;
		if (!pmd)
			break;
		if (remap_area_pmd(pmd, address, end - address,
					 phys_addr + address, flags))
			break;
		error = 0;
		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (address && (address < end));
	spin_unlock(&init_mm.page_table_lock);
	flush_tlb_all();
	return error;
}

/*
 * Generic mapping function (not visible outside):
 */

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. Needed when the kernel wants to access high addresses
 * directly.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */
void __iomem * __ioremap(unsigned long phys_addr, unsigned long size, unsigned long flags)
{
	void __iomem * addr;
	struct vm_struct * area;
	unsigned long offset, last_addr;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	if (phys_addr >= 0x0 && last_addr < 0x100000)
		return isa_bus_to_virt(phys_addr);

	/*
	 * Don't remap the low PCI/ISA area, it's always mapped..
	 */
	if (phys_addr >= 0xA0000 && last_addr < 0x100000)
		return (void __iomem *) phys_to_virt(phys_addr);

	/*
	 * Don't allow anybody to remap normal RAM that we're using..
	 */
	if (machine_to_phys(phys_addr) < virt_to_phys(high_memory)) {
		char *t_addr, *t_end;
		struct page *page;

		t_addr = bus_to_virt(phys_addr);
		t_end = t_addr + (size - 1);
	   
		for(page = virt_to_page(t_addr); page <= virt_to_page(t_end); page++)
			if(!PageReserved(page))
				return NULL;
	}

	/*
	 * Mappings have to be page-aligned
	 */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr+1) - phys_addr;

	/*
	 * Ok, go for it..
	 */
	area = get_vm_area(size, VM_IOREMAP);
	if (!area)
		return NULL;
	area->phys_addr = phys_addr;
	addr = (void __iomem *) area->addr;
	if (remap_area_pages((unsigned long) addr, phys_addr, size, flags)) {
		vunmap((void __force *) addr);
		return NULL;
	}
	return (void __iomem *) (offset + (char __iomem *)addr);
}


/**
 * ioremap_nocache     -   map bus memory into CPU space
 * @offset:    bus address of the memory
 * @size:      size of the resource to map
 *
 * ioremap_nocache performs a platform specific sequence of operations to
 * make bus memory CPU accessible via the readb/readw/readl/writeb/
 * writew/writel functions and the other mmio helpers. The returned
 * address is not guaranteed to be usable directly as a virtual
 * address. 
 *
 * This version of ioremap ensures that the memory is marked uncachable
 * on the CPU as well as honouring existing caching rules from things like
 * the PCI bus. Note that there are other caches and buffers on many 
 * busses. In particular driver authors should read up on PCI writes
 *
 * It's useful if some control registers are in such an area and
 * write combining or read caching is not desirable:
 * 
 * Must be freed with iounmap.
 */

void __iomem *ioremap_nocache (unsigned long phys_addr, unsigned long size)
{
	unsigned long last_addr;
	void __iomem *p = __ioremap(phys_addr, size, _PAGE_PCD);
	if (!p) 
		return p; 

	/* Guaranteed to be > phys_addr, as per __ioremap() */
	last_addr = phys_addr + size - 1;

	if (machine_to_phys(last_addr) < virt_to_phys(high_memory)) { 
		struct page *ppage = virt_to_page(bus_to_virt(phys_addr));
		unsigned long npages;

		phys_addr &= PAGE_MASK;

		/* This might overflow and become zero.. */
		last_addr = PAGE_ALIGN(last_addr);

		/* .. but that's ok, because modulo-2**n arithmetic will make
	 	* the page-aligned "last - first" come out right.
	 	*/
		npages = (last_addr - phys_addr) >> PAGE_SHIFT;

		if (change_page_attr(ppage, npages, PAGE_KERNEL_NOCACHE) < 0) { 
			iounmap(p); 
			p = NULL;
		}
		global_flush_tlb();
	}

	return p;					
}

void iounmap(volatile void __iomem *addr)
{
	struct vm_struct *p;
	if ((unsigned long)addr <= 0x100000)
		return;
	if ((void __force *) addr <= high_memory) 
		return; 
	p = remove_vm_area((void *) (PAGE_MASK & (unsigned long __force) addr));
	if (!p) { 
		printk("__iounmap: bad address %p\n", addr);
		return;
	} 

	if (p->flags && machine_to_phys(p->phys_addr) < virt_to_phys(high_memory)) { 
		change_page_attr(virt_to_page(bus_to_virt(p->phys_addr)),
				 p->size >> PAGE_SHIFT,
				 PAGE_KERNEL); 				 
		global_flush_tlb();
	} 
	kfree(p); 
}

void __init *bt_ioremap(unsigned long phys_addr, unsigned long size)
{
	unsigned long offset, last_addr;
	unsigned int nrpages;
	enum fixed_addresses idx;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	if (phys_addr >= 0x0 && last_addr < 0x100000)
		return isa_bus_to_virt(phys_addr);

	/*
	 * Don't remap the low PCI/ISA area, it's always mapped..
	 */
	if (phys_addr >= 0xA0000 && last_addr < 0x100000)
		return phys_to_virt(phys_addr);

	/*
	 * Mappings have to be page-aligned
	 */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr) - phys_addr;

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
		set_fixmap_ma(idx, phys_addr);
		phys_addr += PAGE_SIZE;
		--idx;
		--nrpages;
	}
	return (void*) (offset + fix_to_virt(FIX_BTMAP_BEGIN));
}

void __init bt_iounmap(void *addr, unsigned long size)
{
	unsigned long virt_addr;
	unsigned long offset;
	unsigned int nrpages;
	enum fixed_addresses idx;

	virt_addr = (unsigned long)addr;
	if (virt_addr < 0x100000)
		return;
	if (virt_addr < fix_to_virt(FIX_BTMAP_BEGIN))
		return;
	offset = virt_addr & ~PAGE_MASK;
	nrpages = PAGE_ALIGN(offset + size - 1) >> PAGE_SHIFT;

	idx = FIX_BTMAP_BEGIN;
	while (nrpages > 0) {
		clear_fixmap(idx);
		--idx;
		--nrpages;
	}
}

#endif /* CONFIG_XEN_PHYSDEV_ACCESS */

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
		pte_t *pte = pte_alloc_map(mm, pmd, address);
		if (!pte)
			return -ENOMEM;
		direct_remap_area_pte(pte, address, end - address, v);
		pte_unmap(pte);
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
	mmu_update_t u[MAX_DIRECTMAP_MMU_QUEUE], *w, *v;

	u[0].ptr  = MMU_EXTENDED_COMMAND;
	u[0].val  = MMUEXT_SET_FOREIGNDOM;
	u[0].val |= (unsigned long)domid << 16;
	v = w = &u[1];

	start_address = address;

	for(i = 0; i < size; i += PAGE_SIZE) {
		if ((v - u) == MAX_DIRECTMAP_MMU_QUEUE) {
			/* Fill in the PTE pointers. */
			__direct_remap_area_pages(mm,
						  start_address, 
						  address-start_address, 
						  w);
	    
			if (HYPERVISOR_mmu_update(u, v - u, NULL) < 0)
				return -EFAULT;	    
			v = w;
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

	if (v != w) {
		/* get the ptep's filled in */
		__direct_remap_area_pages(mm,
					  start_address, 
					  address-start_address, 
					  w);	 
		if (unlikely(HYPERVISOR_mmu_update(u, v - u, NULL) < 0))
			return -EFAULT;	    
	}
    
	return 0;
}
