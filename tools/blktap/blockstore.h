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

#define FREEBLOCK_SIZE  (BLOCK_SIZE / sizeof(u64)) - (3 * sizeof(u64))
#define FREEBLOCK_MAGIC 0x0fee0fee0fee0fee

typedef struct {
    u64 magic;
    u64 next;
    u64 count;
    u64 list[FREEBLOCK_SIZE];
} freeblock_t; 

#define BLOCKSTORE_MAGIC 0xaaaaaaa00aaaaaaa
#define BLOCKSTORE_SUPER 1ULL

typedef struct {
    u64 magic;
    u64 freelist_full;
    u64 freelist_current;
} blockstore_super_t;

extern void *newblock();
extern void *readblock(u64 id);
extern u64 allocblock(void *block);
extern int writeblock(u64 id, void *block);

/* Add this blockid to a freelist, to be recycled by the allocator. */
extern void releaseblock(u64 id);

/* this is a memory free() operation for block-sized allocations */
extern void freeblock(void *block);
extern int __init_blockstore(void);

/* debug for freelist. */
void freelist_count(int print_each);

#endif /* __BLOCKSTORE_H__ */
