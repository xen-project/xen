/******************************************************************************
 * block.h
 *
 * Block IO communication rings.
 *
 * These are the ring data structures for buffering messages between 
 * the hypervisor and guestos's.  
 *
 * For now we'll start with our own rings for the block IO code instead
 * of using the network rings.  Hopefully, this will give us additional
 * flexibility in the future should we choose to move away from a 
 * ring producer consumer communication model.
 */

#ifndef __BLOCK_H__
#define __BLOCK_H__

typedef struct blk_tx_entry_st {
	unsigned long addr; /* virtual address */
	unsigned long size; /* in bytes */
} blk_tx_entry_t;

typedef struct blk_rx_entry_st {
	unsigned long addr; /* virtual address */
	unsigned long size; /* in bytes */
} blk_rx_entry_t;

typedef struct blk_ring_st {
	blk_tx_entry_t	*tx_ring;
	unsigned int	tx_prod, tx_cons, tx_event;
	unsigned int 	tx_ring_size;

	blk_rx_entry_t	*rx_ring;
	unsigned int	rx_prod, rx_cons, rx_event;
	unsigned int	rx_ring_size;
} blk_ring_t;

int blk_create_ring(int domain, unsigned long ptr);

#endif
