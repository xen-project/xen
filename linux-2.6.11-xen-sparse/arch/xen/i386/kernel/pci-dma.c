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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define pte_offset_kernel pte_offset
#define pud_t pgd_t
#define pud_offset(d, va) d
#endif

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
	pud_t         *pud; 
	pmd_t         *pmd;
	pte_t         *pte;
	unsigned long  pfn, i, flags;

	scrub_pages(vstart, 1 << order);

        balloon_lock(flags);

	/* 1. Zap current PTEs, giving away the underlying pages. */
	for (i = 0; i < (1<<order); i++) {
		pgd = pgd_offset_k(   (vstart + (i*PAGE_SIZE)));
		pud = pud_offset(pgd, (vstart + (i*PAGE_SIZE)));
		pmd = pmd_offset(pud, (vstart + (i*PAGE_SIZE)));
		pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
		pfn = pte->pte_low >> PAGE_SHIFT;
		queue_l1_entry_update(pte, 0);
		phys_to_machine_mapping[(__pa(vstart)>>PAGE_SHIFT)+i] =
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
		pud = pud_offset(pgd, (vstart + (i*PAGE_SIZE)));
		pmd = pmd_offset(pud, (vstart + (i*PAGE_SIZE)));
		pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
		queue_l1_entry_update(
			pte, ((pfn+i)<<PAGE_SHIFT)|__PAGE_KERNEL);
		queue_machphys_update(
			pfn+i, (__pa(vstart)>>PAGE_SHIFT)+i);
		phys_to_machine_mapping[(__pa(vstart)>>PAGE_SHIFT)+i] =
			pfn+i;
	}
	/* Flush updates through and flush the TLB. */
	xen_tlb_flush();

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
void pci_free_consistent(struct pci_dev *hwdev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
{
	free_pages((unsigned long)vaddr, get_order(size));
}
#else

void dma_free_coherent(struct device *dev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
{
	struct dma_coherent_mem *mem = dev ? dev->dma_mem : NULL;
	int order = get_order(size);
	
	if (mem && vaddr >= mem->virt_base && vaddr < (mem->virt_base + (mem->size << PAGE_SHIFT))) {
		int page = (vaddr - mem->virt_base) >> PAGE_SHIFT;

		bitmap_release_region(mem->bitmap, page, order);
	} else
		free_pages((unsigned long)vaddr, order);
}

int dma_declare_coherent_memory(struct device *dev, dma_addr_t bus_addr,
				dma_addr_t device_addr, size_t size, int flags)
{
	void __iomem *mem_base;
	int pages = size >> PAGE_SHIFT;
	int bitmap_size = (pages + 31)/32;

	if ((flags & (DMA_MEMORY_MAP | DMA_MEMORY_IO)) == 0)
		goto out;
	if (!size)
		goto out;
	if (dev->dma_mem)
		goto out;

	/* FIXME: this routine just ignores DMA_MEMORY_INCLUDES_CHILDREN */

	mem_base = ioremap(bus_addr, size);
	if (!mem_base)
		goto out;

	dev->dma_mem = kmalloc(sizeof(struct dma_coherent_mem), GFP_KERNEL);
	if (!dev->dma_mem)
		goto out;
	memset(dev->dma_mem, 0, sizeof(struct dma_coherent_mem));
	dev->dma_mem->bitmap = kmalloc(bitmap_size, GFP_KERNEL);
	if (!dev->dma_mem->bitmap)
		goto free1_out;
	memset(dev->dma_mem->bitmap, 0, bitmap_size);

	dev->dma_mem->virt_base = mem_base;
	dev->dma_mem->device_base = device_addr;
	dev->dma_mem->size = pages;
	dev->dma_mem->flags = flags;

	if (flags & DMA_MEMORY_MAP)
		return DMA_MEMORY_MAP;

	return DMA_MEMORY_IO;

 free1_out:
	kfree(dev->dma_mem->bitmap);
 out:
	return 0;
}
EXPORT_SYMBOL(dma_declare_coherent_memory);

void dma_release_declared_memory(struct device *dev)
{
	struct dma_coherent_mem *mem = dev->dma_mem;
	
	if(!mem)
		return;
	dev->dma_mem = NULL;
	iounmap(mem->virt_base);
	kfree(mem->bitmap);
	kfree(mem);
}
EXPORT_SYMBOL(dma_release_declared_memory);

void *dma_mark_declared_memory_occupied(struct device *dev,
					dma_addr_t device_addr, size_t size)
{
	struct dma_coherent_mem *mem = dev->dma_mem;
	int pages = (size + (device_addr & ~PAGE_MASK) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	int pos, err;

	if (!mem)
		return ERR_PTR(-EINVAL);

	pos = (device_addr - mem->device_base) >> PAGE_SHIFT;
	err = bitmap_allocate_region(mem->bitmap, pos, get_order(pages));
	if (err != 0)
		return ERR_PTR(err);
	return mem->virt_base + (pos << PAGE_SHIFT);
}
EXPORT_SYMBOL(dma_mark_declared_memory_occupied);

#endif
