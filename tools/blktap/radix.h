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

/*
 * main api
 * with these functions, the LSB of root always indicates
 * whether or not the block is writable, including the return
 * values of update and snapshot
 */
u64 lookup(int height, u64 root, u64 key);
u64 update(int height, u64 root, u64 key, u64 val);
u64 snapshot(u64 root);
int collapse(int height, u64 proot, u64 croot);
int isprivate(int height, u64 root, u64 key);


void __rcache_init(void);

#endif /* __RADIX_H__ */
