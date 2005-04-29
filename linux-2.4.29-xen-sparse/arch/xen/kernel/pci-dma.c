/*
 * Dynamic DMA mapping support.
 *
 * On i386 there is no hardware dynamic DMA address translation,
 * so consistent alloc/free are merely page allocation/freeing.
 * The rest of the dynamic DMA mapping interface is implemented
 * in asm/pci.h.
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/version.h>
#include <asm/io.h>
#include <asm-xen/balloon.h>

#define pte_offset_kernel pte_offset

struct dma_coherent_mem {
	void		*virt_base;
	u32		device_base;
	int		size;
	int		flags;
	unsigned long	*bitmap;
};

static void
xen_contig_memory(unsigned long vstart, unsigned int order)
{
	/*
	 * Ensure multi-page extents are contiguous in machine memory.
	 * This code could be cleaned up some, and the number of
	 * hypercalls reduced.
	 */
	pgd_t         *pgd; 
	pmd_t         *pmd;
	pte_t         *pte;
	unsigned long  pfn, i, flags;

	scrub_pages(vstart, 1 << order);

        balloon_lock(flags);

	/* 1. Zap current PTEs, giving away the underlying pages. */
	for (i = 0; i < (1<<order); i++) {
		pgd = pgd_offset_k(   (vstart + (i*PAGE_SIZE)));
		pmd = pmd_offset(pgd, (vstart + (i*PAGE_SIZE)));
		pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
		pfn = pte->pte_low >> PAGE_SHIFT;
		HYPERVISOR_update_va_mapping(
			vstart + (i*PAGE_SIZE), __pte_ma(0), 0);
		phys_to_machine_mapping[(__pa(vstart)>>PAGE_SHIFT)+i] =
			INVALID_P2M_ENTRY;
		if (HYPERVISOR_dom_mem_op(MEMOP_decrease_reservation, 
					  &pfn, 1, 0) != 1) BUG();
	}
	/* 2. Get a new contiguous memory extent. */
	if (HYPERVISOR_dom_mem_op(MEMOP_increase_reservation,
				  &pfn, 1, order) != 1) BUG();
	/* 3. Map the new extent in place of old pages. */
	for (i = 0; i < (1<<order); i++) {
		pgd = pgd_offset_k(   (vstart + (i*PAGE_SIZE)));
		pmd = pmd_offset(pgd, (vstart + (i*PAGE_SIZE)));
		pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
		HYPERVISOR_update_va_mapping(
			vstart + (i*PAGE_SIZE),
			__pte_ma(((pfn+i)<<PAGE_SHIFT)|__PAGE_KERNEL), 0);
		xen_machphys_update(
			pfn+i, (__pa(vstart)>>PAGE_SHIFT)+i);
		phys_to_machine_mapping[(__pa(vstart)>>PAGE_SHIFT)+i] =
			pfn+i;
	}
	/* Flush updates through and flush the TLB. */
	flush_tlb_all();

        balloon_unlock(flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
			   dma_addr_t *dma_handle)
#else
void *dma_alloc_coherent(struct device *dev, size_t size,
			   dma_addr_t *dma_handle, int gfp)
#endif
{
	void *ret;
	unsigned int order = get_order(size);
	unsigned long vstart;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	int gfp = GFP_ATOMIC;

	if (hwdev == NULL || ((u32)hwdev->dma_mask < 0xffffffff))
		gfp |= GFP_DMA;
#else
	struct dma_coherent_mem *mem = dev ? dev->dma_mem : NULL;

	/* ignore region specifiers */
	gfp &= ~(__GFP_DMA | __GFP_HIGHMEM);

	if (mem) {
		int page = bitmap_find_free_region(mem->bitmap, mem->size,
						     order);
		if (page >= 0) {
			*dma_handle = mem->device_base + (page << PAGE_SHIFT);
			ret = mem->virt_base + (page << PAGE_SHIFT);
			memset(ret, 0, size);
			return ret;
		}
		if (mem->flags & DMA_MEMORY_EXCLUSIVE)
			return NULL;
	}

	if (dev == NULL || (dev->coherent_dma_mask < 0xffffffff))
		gfp |= GFP_DMA;
#endif

	vstart = __get_free_pages(gfp, order);
	ret = (void *)vstart;
	if (ret == NULL)
		return ret;

	xen_contig_memory(vstart, order);

	memset(ret, 0, size);
	*dma_handle = virt_to_bus(ret);

	return ret;
}

void pci_free_consistent(struct pci_dev *hwdev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
{
	free_pages((unsigned long)vaddr, get_order(size));
}
