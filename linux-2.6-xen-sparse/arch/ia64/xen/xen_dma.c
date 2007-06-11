/*
 * Copyright (C) 2007 Hewlett-Packard Development Company, L.P.
 * 	Alex Williamson <alex.williamson@hp.com>
 *
 * Basic DMA mapping services for Xen guests.
 * Based on arch/i386/kernel/pci-dma-xen.c.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <linux/bitops.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <asm/scatterlist.h>

#define IOMMU_BUG_ON(test)					\
do {								\
	if (unlikely(test)) {					\
		printk(KERN_ALERT "Fatal DMA error!\n");	\
		BUG();						\
	}							\
} while (0)


/*
 * This should be broken out of swiotlb and put in a common place
 * when merged with upstream Linux.
 */
static inline int
address_needs_mapping(struct device *dev, dma_addr_t addr)
{
	dma_addr_t mask = 0xffffffff;

	/* If the device has a mask, use it, otherwise default to 32 bits */
	if (dev && dev->dma_mask)
		mask = *dev->dma_mask;
	return (addr & ~mask) != 0;
}

int
xen_map_sg(struct device *dev, struct scatterlist *sg, int nents,
	   int direction)
{
	int i;

	for (i = 0 ; i < nents ; i++) {
		sg[i].dma_address = page_to_bus(sg[i].page) + sg[i].offset;
		sg[i].dma_length  = sg[i].length;

		IOMMU_BUG_ON(address_needs_mapping(dev, sg[i].dma_address));
	}

	return nents;
}
EXPORT_SYMBOL(xen_map_sg);

void
xen_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
	     int direction)
{
}
EXPORT_SYMBOL(xen_unmap_sg);

int
xen_dma_mapping_error(dma_addr_t dma_addr)
{
	return 0;
}
EXPORT_SYMBOL(xen_dma_mapping_error);

int
xen_dma_supported(struct device *dev, u64 mask)
{
	return 1;
}
EXPORT_SYMBOL(xen_dma_supported);

void *
xen_alloc_coherent(struct device *dev, size_t size,
		   dma_addr_t *dma_handle, gfp_t gfp)
{
	unsigned long vaddr;
	unsigned int order = get_order(size);

	vaddr = __get_free_pages(gfp, order);

	if (!vaddr)
		return NULL;

	if (xen_create_contiguous_region(vaddr, order,
					 fls64(dev->coherent_dma_mask))) {
		free_pages(vaddr, order);
		return NULL;
	}

	memset((void *)vaddr, 0, size);
	*dma_handle = virt_to_bus((void *)vaddr);

	return (void *)vaddr;
}
EXPORT_SYMBOL(xen_alloc_coherent);

void
xen_free_coherent(struct device *dev, size_t size,
		      void *vaddr, dma_addr_t dma_handle)
{
	unsigned int order =  get_order(size);

	xen_destroy_contiguous_region((unsigned long)vaddr, order);
	free_pages((unsigned long)vaddr, order);
}
EXPORT_SYMBOL(xen_free_coherent);

dma_addr_t
xen_map_single(struct device *dev, void *ptr, size_t size,
	       int direction)
{
	dma_addr_t dma_addr = virt_to_bus(ptr);

	IOMMU_BUG_ON(range_straddles_page_boundary(ptr, size));
	IOMMU_BUG_ON(address_needs_mapping(dev, dma_addr));

	return dma_addr;
}
EXPORT_SYMBOL(xen_map_single);

void
xen_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size,
		 int direction)
{
}
EXPORT_SYMBOL(xen_unmap_single);
