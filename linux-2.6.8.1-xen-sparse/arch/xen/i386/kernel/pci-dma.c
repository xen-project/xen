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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define pte_offset_kernel pte_offset
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
	/* ignore region specifiers */
	gfp &= ~(__GFP_DMA | __GFP_HIGHMEM);

	if (dev == NULL || (dev->coherent_dma_mask < 0xffffffff))
		gfp |= GFP_DMA;
#endif

	vstart = __get_free_pages(gfp, order);
	ret = (void *)vstart;
	if (ret == NULL)
		return ret;

	/*
	 * Ensure multi-page extents are contiguous in machine memory.
	 * This code could be cleaned up some, and the number of
	 * hypercalls reduced.
	 */
	if (size > PAGE_SIZE) {
		pgd_t         *pgd; 
		pmd_t         *pmd;
		pte_t         *pte;
		unsigned long  pfn, i;
		scrub_pages(vstart, 1 << order);
		/* 1. Zap current PTEs, giving away the underlying pages. */
		for (i = 0; i < (1<<order); i++) {
			pgd = pgd_offset_k(   (vstart + (i*PAGE_SIZE)));
			pmd = pmd_offset(pgd, (vstart + (i*PAGE_SIZE)));
			pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
			pfn = pte->pte_low >> PAGE_SHIFT;
			queue_l1_entry_update(pte, 0);
			phys_to_machine_mapping[(__pa(ret)>>PAGE_SHIFT)+i] =
				INVALID_P2M_ENTRY;
			flush_page_update_queue();
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
			queue_l1_entry_update(
				pte, ((pfn+i)<<PAGE_SHIFT)|__PAGE_KERNEL);
			queue_machphys_update(
				pfn+i, (__pa(ret)>>PAGE_SHIFT)+i);
			phys_to_machine_mapping[(__pa(ret)>>PAGE_SHIFT)+i] =
				pfn+i;
		}
		/* Flush updates through and flush the TLB. */
		xen_tlb_flush();
	}

	memset(ret, 0, size);
	*dma_handle = virt_to_bus(ret);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
void pci_free_consistent(struct pci_dev *hwdev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
#else
void dma_free_coherent(struct device *dev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
#endif
{
	free_pages((unsigned long)vaddr, get_order(size));
}
