#ifndef _I386_SCATTERLIST_H
#define _I386_SCATTERLIST_H

struct scatterlist {
    struct page		*page;
    unsigned int	offset;
    unsigned int	length;
    dma_addr_t		dma_address;
    unsigned int	dma_length;
};

/* These macros should be used after a pci_map_sg call has been done
 * to get bus addresses of each of the SG entries and their lengths.
 * You should only work with the number of sg entries pci_map_sg
 * returns.
 */
#define sg_dma_address(sg)	((sg)->dma_address)
#define sg_dma_len(sg)		((sg)->dma_length)

#define ISA_DMA_THRESHOLD (0x00ffffff)

#endif /* !(_I386_SCATTERLIST_H) */
