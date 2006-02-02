#ifndef _ASM_I386_DMA_MAPPING_H
#define _ASM_I386_DMA_MAPPING_H

/*
 * IOMMU interface. See Documentation/DMA-mapping.txt and DMA-API.txt for
 * documentation.
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <asm/cache.h>
#include <asm/io.h>
#include <asm/scatterlist.h>
#include <asm/swiotlb.h>

static inline int
address_needs_mapping(struct device *hwdev, dma_addr_t addr)
{
	dma_addr_t mask = 0xffffffff;
	/* If the device has a mask, use it, otherwise default to 32 bits */
	if (hwdev && hwdev->dma_mask)
		mask = *hwdev->dma_mask;
	return (addr & ~mask) != 0;
}

static inline int
range_straddles_page_boundary(void *p, size_t size)
{
	extern unsigned long *contiguous_bitmap;
	return (((((unsigned long)p & ~PAGE_MASK) + size) > PAGE_SIZE) &&
		!test_bit(__pa(p) >> PAGE_SHIFT, contiguous_bitmap));
}

#define dma_alloc_noncoherent(d, s, h, f) dma_alloc_coherent(d, s, h, f)
#define dma_free_noncoherent(d, s, v, h) dma_free_coherent(d, s, v, h)

void *dma_alloc_coherent(struct device *dev, size_t size,
			   dma_addr_t *dma_handle, gfp_t flag);

void dma_free_coherent(struct device *dev, size_t size,
			 void *vaddr, dma_addr_t dma_handle);

extern dma_addr_t
dma_map_single(struct device *dev, void *ptr, size_t size,
	       enum dma_data_direction direction);

extern void
dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size,
		 enum dma_data_direction direction);

extern int dma_map_sg(struct device *hwdev, struct scatterlist *sg,
		      int nents, enum dma_data_direction direction);
extern void dma_unmap_sg(struct device *hwdev, struct scatterlist *sg,
			 int nents, enum dma_data_direction direction);

extern dma_addr_t
dma_map_page(struct device *dev, struct page *page, unsigned long offset,
	     size_t size, enum dma_data_direction direction);

extern void
dma_unmap_page(struct device *dev, dma_addr_t dma_address, size_t size,
	       enum dma_data_direction direction);

extern void
dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle, size_t size,
			enum dma_data_direction direction);

extern void
dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle, size_t size,
                           enum dma_data_direction direction);

static inline void
dma_sync_single_range_for_cpu(struct device *dev, dma_addr_t dma_handle,
			      unsigned long offset, size_t size,
			      enum dma_data_direction direction)
{
	dma_sync_single_for_cpu(dev, dma_handle+offset, size, direction);
}

static inline void
dma_sync_single_range_for_device(struct device *dev, dma_addr_t dma_handle,
				 unsigned long offset, size_t size,
				 enum dma_data_direction direction)
{
	dma_sync_single_for_device(dev, dma_handle+offset, size, direction);
}

static inline void
dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg, int nelems,
		    enum dma_data_direction direction)
{
	if (swiotlb)
		swiotlb_sync_sg_for_cpu(dev,sg,nelems,direction);
	flush_write_buffers();
}

static inline void
dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg, int nelems,
		    enum dma_data_direction direction)
{
	if (swiotlb)
		swiotlb_sync_sg_for_device(dev,sg,nelems,direction);
	flush_write_buffers();
}

extern int
dma_mapping_error(dma_addr_t dma_addr);

extern int
dma_supported(struct device *dev, u64 mask);

static inline int
dma_set_mask(struct device *dev, u64 mask)
{
	if(!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;

	*dev->dma_mask = mask;

	return 0;
}

#ifdef __i386__
static inline int
dma_get_cache_alignment(void)
{
	/* no easy way to get cache size on all x86, so return the
	 * maximum possible, to be safe */
	return (1 << INTERNODE_CACHE_SHIFT);
}
#else
extern int dma_get_cache_alignment(void);
#endif

#define dma_is_consistent(d)	(1)

static inline void
dma_cache_sync(void *vaddr, size_t size,
	       enum dma_data_direction direction)
{
	flush_write_buffers();
}

#define ARCH_HAS_DMA_DECLARE_COHERENT_MEMORY
extern int
dma_declare_coherent_memory(struct device *dev, dma_addr_t bus_addr,
			    dma_addr_t device_addr, size_t size, int flags);

extern void
dma_release_declared_memory(struct device *dev);

extern void *
dma_mark_declared_memory_occupied(struct device *dev,
				  dma_addr_t device_addr, size_t size);

#endif
