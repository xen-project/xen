/*
 * Radix tree for mapping (up to) 63-bit virtual block IDs to
 * 63-bit global block IDs
 *
 * Pointers within the tree set aside the least significant bit to indicate
 * whther or not the target block is writable from this node.
 *
 * The block with ID 0 is assumed to be an empty block of all zeros
 */

#ifndef __RADIX_H__
#define __RADIX_H__

/* I don't really like exposing these, but... */
#define getid(x) (((x)>>1)&0x7fffffffffffffffLL)
#define putid(x) ((x)<<1)
#define writable(x) (((x)<<1)|1LL)
#define iswritable(x) ((x)&1LL)
#define ZERO 0LL
#define ONE 1LL
#define ONEMASK 0xffffffffffffffeLL

#define RADIX_TREE_MAP_SHIFT 9
#define RADIX_TREE_MAP_MASK 0x1ff
#define RADIX_TREE_MAP_ENTRIES 512

typedef uint64_t *radix_tree_node;


/*
 * main api
 * with these functions, the LSB of root always indicates
 * whether or not the block is writable, including the return
 * values of update and snapshot
 */
uint64_t lookup(int height, uint64_t root, uint64_t key);
uint64_t update(int height, uint64_t root, uint64_t key, uint64_t val);
uint64_t snapshot(uint64_t root);
int collapse(int height, uint64_t proot, uint64_t croot);
int isprivate(int height, uint64_t root, uint64_t key);


void __rcache_init(void);

#endif /* __RADIX_H__ */
