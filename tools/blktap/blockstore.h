/**************************************************************************
 * 
 * blockstore.h
 *
 * Simple block store interface
 *
 */
 
#ifndef __BLOCKSTORE_H__
#define __BLOCKSTORE_H__

#ifndef __SHORT_INT_TYPES__
#define __SHORT_INT_TYPES__

#include <stdint.h>

typedef uint8_t            u8;
typedef uint16_t           u16;
typedef uint32_t           u32;
typedef uint64_t           u64;
typedef int8_t             s8;
typedef int16_t            s16;
typedef int32_t            s32;
typedef int64_t            s64;
                           
#endif /*  __SHORT_INT_TYPES__ */

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
