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
#include <linux/module.h>
#include <asm/io.h>
#include <asm/fixmap.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>

#define ISA_START_ADDRESS	0x0
#define ISA_END_ADDRESS		0x100000

#if 0 /* not PAE safe */
/* These hacky macros avoid phys->machine translations. */
#define __direct_pte(x) ((pte_t) { (x) } )
#define __direct_mk_pte(page_nr,pgprot) \
  __direct_pte(((page_nr) << PAGE_SHIFT) | pgprot_val(pgprot))
#define direct_mk_pte_phys(physpage, pgprot) \
  __direct_mk_pte((physpage) >> PAGE_SHIFT, pgprot)
#endif

static int direct_remap_area_pte_fn(pte_t *pte, 
				    struct page *pmd_page,
				    unsigned long address, 
				    void *data)
{
	mmu_update_t **v = (mmu_update_t **)data;

	(*v)->ptr = ((u64)pfn_to_mfn(page_to_pfn(pmd_page)) <<
		     PAGE_SHIFT) | ((unsigned long)pte & ~PAGE_MASK);
	(*v)++;

	return 0;
}

static int __direct_remap_pfn_range(struct mm_struct *mm,
				    unsigned long address, 
				    unsigned long mfn,
				    unsigned long size, 
				    pgprot_t prot,
				    domid_t  domid)
{
	int rc;
	unsigned long i, start_address;
	mmu_update_t *u, *v, *w;

	u = v = w = (mmu_update_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT);
	if (u == NULL)
		return -ENOMEM;

	start_address = address;

	flush_cache_all();

	for (i = 0; i < size; i += PAGE_SIZE) {
		if ((v - u) == (PAGE_SIZE / sizeof(mmu_update_t))) {
			/* Fill in the PTE pointers. */
			rc = apply_to_page_range(mm, start_address, 
						 address - start_address,
						 direct_remap_area_pte_fn, &w);
			if (rc)
				goto out;
			w = u;
			rc = -EFAULT;
			if (HYPERVISOR_mmu_update(u, v - u, NULL, domid) < 0)
				goto out;
			v = u;
			start_address = address;
		}

		/*
		 * Fill in the machine address: PTE ptr is done later by
		 * __direct_remap_area_pages(). 
		 */
		v->val = pte_val_ma(pfn_pte_ma(mfn, prot));

		mfn++;
		address += PAGE_SIZE; 
		v++;
	}

	if (v != u) {
		/* get the ptep's filled in */
		rc = apply_to_page_range(mm, start_address,
					 address - start_address,
					 direct_remap_area_pte_fn, &w);
		if (rc)
			goto out;
		rc = -EFAULT;
		if (unlikely(HYPERVISOR_mmu_update(u, v - u, NULL, domid) < 0))
			goto out;
	}

	rc = 0;

 out:
	flush_tlb_all();

	free_page((unsigned long)u);

	return rc;
}

int direct_remap_pfn_range(struct vm_area_struct *vma,
			   unsigned long address, 
			   unsigned long mfn,
			   unsigned long size, 
			   pgprot_t prot,
			   domid_t  domid)
{
	/* Same as remap_pfn_range(). */
	vma->vm_flags |= VM_IO | VM_RESERVED;

	if (domid == DOMID_SELF)
		return -EINVAL;

	return __direct_remap_pfn_range(
		vma->vm_mm, address, mfn, size, prot, domid);
}
EXPORT_SYMBOL(direct_remap_pfn_range);

int direct_kernel_remap_pfn_range(unsigned long address, 
				  unsigned long mfn,
				  unsigned long size, 
				  pgprot_t prot,
				  domid_t  domid)
{
	return __direct_remap_pfn_range(
		&init_mm, address, mfn, size, prot, domid);
}
EXPORT_SYMBOL(direct_kernel_remap_pfn_range);

static int lookup_pte_fn(
	pte_t *pte, struct page *pmd_page, unsigned long addr, void *data)
{
	uint64_t *ptep = (uint64_t *)data;
	if (ptep)
		*ptep = ((uint64_t)pfn_to_mfn(page_to_pfn(pmd_page)) <<
			 PAGE_SHIFT) | ((unsigned long)pte & ~PAGE_MASK);
	return 0;
}

int create_lookup_pte_addr(struct mm_struct *mm, 
			   unsigned long address,
			   uint64_t *ptep)
{
	return apply_to_page_range(mm, address, PAGE_SIZE,
				   lookup_pte_fn, ptep);
}

EXPORT_SYMBOL(create_lookup_pte_addr);

static int noop_fn(
	pte_t *pte, struct page *pmd_page, unsigned long addr, void *data)
{
	return 0;
}

int touch_pte_range(struct mm_struct *mm,
		    unsigned long address,
		    unsigned long size)
{
	return apply_to_page_range(mm, address, size, noop_fn, NULL);
} 

EXPORT_SYMBOL(touch_pte_range);

/*
 * Does @address reside within a non-highmem page that is local to this virtual
 * machine (i.e., not an I/O page, nor a memory page belonging to another VM).
 * See the comment that accompanies mfn_to_local_pfn() in page.h to understand
 * why this works.
 */
static inline int is_local_lowmem(unsigned long address)
{
	extern unsigned long max_low_pfn;
	return (mfn_to_local_pfn(address >> PAGE_SHIFT) < max_low_pfn);
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
	domid_t domid = DOMID_IO;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	/*
	 * Don't remap the low PCI/ISA area, it's always mapped..
	 */
	if (xen_start_info->flags & SIF_PRIVILEGED &&
	    phys_addr >= ISA_START_ADDRESS && last_addr < ISA_END_ADDRESS)
		return (void __iomem *) isa_bus_to_virt(phys_addr);

	/*
	 * Don't allow anybody to remap normal RAM that we're using..
	 */
	if (is_local_lowmem(phys_addr)) {
		char *t_addr, *t_end;
		struct page *page;

		t_addr = bus_to_virt(phys_addr);
		t_end = t_addr + (size - 1);
	   
		for(page = virt_to_page(t_addr); page <= virt_to_page(t_end); page++)
			if(!PageReserved(page))
				return NULL;

		domid = DOMID_SELF;
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
	area = get_vm_area(size, VM_IOREMAP | (flags << 20));
	if (!area)
		return NULL;
	area->phys_addr = phys_addr;
	addr = (void __iomem *) area->addr;
	flags |= _PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED;
#ifdef __x86_64__
	flags |= _PAGE_USER;
#endif
	if (__direct_remap_pfn_range(&init_mm, (unsigned long)addr,
				     phys_addr>>PAGE_SHIFT,
				     size, __pgprot(flags), domid)) {
		vunmap((void __force *) addr);
		return NULL;
	}
	return (void __iomem *) (offset + (char __iomem *)addr);
}
EXPORT_SYMBOL(__ioremap);

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

	if (is_local_lowmem(last_addr)) { 
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
EXPORT_SYMBOL(ioremap_nocache);

/**
 * iounmap - Free a IO remapping
 * @addr: virtual address from ioremap_*
 *
 * Caller must ensure there is only one unmapping for the same pointer.
 */
void iounmap(volatile void __iomem *addr)
{
	struct vm_struct *p, *o;

	if ((void __force *)addr <= high_memory)
		return;

	/*
	 * __ioremap special-cases the PCI/ISA range by not instantiating a
	 * vm_area and by simply returning an address into the kernel mapping
	 * of ISA space.   So handle that here.
	 */
	if ((unsigned long) addr >= fix_to_virt(FIX_ISAMAP_BEGIN))
		return;

	addr = (volatile void __iomem *)(PAGE_MASK & (unsigned long __force)addr);

	/* Use the vm area unlocked, assuming the caller
	   ensures there isn't another iounmap for the same address
	   in parallel. Reuse of the virtual address is prevented by
	   leaving it in the global lists until we're done with it.
	   cpa takes care of the direct mappings. */
	read_lock(&vmlist_lock);
	for (p = vmlist; p; p = p->next) {
		if (p->addr == addr)
			break;
	}
	read_unlock(&vmlist_lock);

	if (!p) {
		printk("iounmap: bad address %p\n", addr);
		dump_stack();
		return;
	}

	/* Reset the direct mapping. Can block */
	if ((p->flags >> 20) && is_local_lowmem(p->phys_addr)) {
		/* p->size includes the guard page, but cpa doesn't like that */
		change_page_attr(virt_to_page(bus_to_virt(p->phys_addr)),
				 (p->size - PAGE_SIZE) >> PAGE_SHIFT,
				 PAGE_KERNEL);
		global_flush_tlb();
	} 

	/* Finally remove it */
	o = remove_vm_area((void *)addr);
	BUG_ON(p != o || o == NULL);
	kfree(p); 
}
EXPORT_SYMBOL(iounmap);

#ifdef __i386__

void __init *bt_ioremap(unsigned long phys_addr, unsigned long size)
{
	unsigned long offset, last_addr;
	unsigned int nrpages;
	enum fixed_addresses idx;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	/*
	 * Don't remap the low PCI/ISA area, it's always mapped..
	 */
	if (xen_start_info->flags & SIF_PRIVILEGED &&
	    phys_addr >= ISA_START_ADDRESS && last_addr < ISA_END_ADDRESS)
		return isa_bus_to_virt(phys_addr);

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
		set_fixmap(idx, phys_addr);
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
	if (virt_addr < fix_to_virt(FIX_BTMAP_BEGIN))
		return;
	if (virt_addr >= fix_to_virt(FIX_ISAMAP_BEGIN))
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

#endif /* __i386__ */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
