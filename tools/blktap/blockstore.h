/**************************************************************************
 * 
 * blockstore.h
 *
 * Simple block store interface
 *
 */
 
#ifndef __BLOCKSTORE_H__
#define __BLOCKSTORE_H__

#include <xc.h>

#define BLOCK_SIZE  4096
#define BLOCK_SHIFT   12
#define BLOCK_MASK  0xfffffffffffff000LL

/* XXX SMH: where is the below supposed to be defined???? */
#ifndef SECTOR_SHIFT 
#define SECTOR_SHIFT   9 
#endif


extern void *newblock();
extern void *readblock(u64 id);
extern u64 allocblock(void *block);
extern int writeblock(u64 id, void *block);
extern void freeblock(void *block);
extern int __init_blockstore(void);

#endif /* __BLOCKSTORE_H__ */
