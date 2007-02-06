#ifndef _ASM_IA64_DMA_MAPPING_H
#define _ASM_IA64_DMA_MAPPING_H

/*
 * Copyright (C) 2003-2004 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 */
#include <asm/machvec.h>
#ifdef CONFIG_XEN
/* Needed for arch/i386/kernel/swiotlb.c and arch/i386/kernel/pci-dma-xen.c */
#include <asm/hypervisor.h>
/* Needed for arch/i386/kernel/swiotlb.c */
#include <asm-i386/mach-xen/asm/swiotlb.h>
#endif

#ifndef CONFIG_XEN
#define dma_alloc_coherent	platform_dma_alloc_coherent
#define dma_alloc_noncoherent	platform_dma_alloc_coherent	/* coherent mem. is cheap */
#define dma_free_coherent	platform_dma_free_coherent
#define dma_free_noncoherent	platform_dma_free_coherent
#define dma_map_single		platform_dma_map_single
#define dma_map_sg		platform_dma_map_sg
#define dma_unmap_single	platform_dma_unmap_single
#define dma_unmap_sg		platform_dma_unmap_sg
#define dma_sync_single_for_cpu	platform_dma_sync_single_for_cpu
#define dma_sync_sg_for_cpu	platform_dma_sync_sg_for_cpu
#define dma_sync_single_for_device platform_dma_sync_single_for_device
#define dma_sync_sg_for_device	platform_dma_sync_sg_for_device
#define dma_mapping_error	platform_dma_mapping_error
#else
int dma_map_sg(struct device *hwdev, struct scatterlist *sg, int nents,
               enum dma_data_direction direction);
void dma_unmap_sg(struct device *hwdev, struct scatterlist *sg, int nents,
                  enum dma_data_direction direction);
int dma_supported(struct device *dev, u64 mask);
void *dma_alloc_coherent(struct device *dev, size_t size,
                         dma_addr_t *dma_handle, gfp_t gfp);
void dma_free_coherent(struct device *dev, size_t size, void *vaddr,
                       dma_addr_t dma_handle);
dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size,
                          enum dma_data_direction direction);
void dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size,
                      enum dma_data_direction direction);
void dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
                             size_t size, enum dma_data_direction direction);
void dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle,
                                size_t size,
                                enum dma_data_direction direction);
int dma_mapping_error(dma_addr_t dma_addr);

#define flush_write_buffers()	do { } while (0)
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
#endif

#define dma_map_page(dev, pg, off, size, dir)				\
	dma_map_single(dev, page_address(pg) + (off), (size), (dir))
#define dma_unmap_page(dev, dma_addr, size, dir)			\
	dma_unmap_single(dev, dma_addr, size, dir)

/*
 * Rest of this file is part of the "Advanced DMA API".  Use at your own risk.
 * See Documentation/DMA-API.txt for details.
 */

#define dma_sync_single_range_for_cpu(dev, dma_handle, offset, size, dir)	\
	dma_sync_single_for_cpu(dev, dma_handle, size, dir)
#define dma_sync_single_range_for_device(dev, dma_handle, offset, size, dir)	\
	dma_sync_single_for_device(dev, dma_handle, size, dir)

#ifndef CONFIG_XEN
#define dma_supported		platform_dma_supported
#endif

static inline int
dma_set_mask (struct device *dev, u64 mask)
{
	if (!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;
	*dev->dma_mask = mask;
	return 0;
}

extern int dma_get_cache_alignment(void);

static inline void
dma_cache_sync (void *vaddr, size_t size, enum dma_data_direction dir)
{
	/*
	 * IA-64 is cache-coherent, so this is mostly a no-op.  However, we do need to
	 * ensure that dma_cache_sync() enforces order, hence the mb().
	 */
	mb();
}

#define dma_is_consistent(dma_handle)	(1)	/* all we do is coherent memory... */

#ifdef CONFIG_XEN
/* arch/i386/kernel/swiotlb.o requires */
void contiguous_bitmap_init(unsigned long end_pfn);

static inline int
address_needs_mapping(struct device *hwdev, dma_addr_t addr)
{
	dma_addr_t mask = DMA_64BIT_MASK;
	/* If the device has a mask, use it, otherwise default to 64 bits */
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
#endif

#endif /* _ASM_IA64_DMA_MAPPING_H */
