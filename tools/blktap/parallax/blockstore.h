/**************************************************************************
 * 
 * blockstore.h
 *
 * Simple block store interface
 *
 */
 
#ifndef __BLOCKSTORE_H__
#define __BLOCKSTORE_H__

#include <netinet/in.h>
#include <xenctrl.h>

#define BLOCK_SIZE  4096
#define BLOCK_SHIFT   12
#define BLOCK_MASK  0xfffffffffffff000LL

/* XXX SMH: where is the below supposed to be defined???? */
#ifndef SECTOR_SHIFT 
#define SECTOR_SHIFT   9 
#endif

#define FREEBLOCK_SIZE  (BLOCK_SIZE / sizeof(uint64_t)) - (3 * sizeof(uint64_t))
#define FREEBLOCK_MAGIC 0x0fee0fee0fee0feeULL

typedef struct {
    uint64_t magic;
    uint64_t next;
    uint64_t count;
    uint64_t list[FREEBLOCK_SIZE];
} freeblock_t; 

#define BLOCKSTORE_MAGIC 0xaaaaaaa00aaaaaaaULL
#define BLOCKSTORE_SUPER 1ULL

typedef struct {
    uint64_t magic;
    uint64_t freelist_full;
    uint64_t freelist_current;
} blockstore_super_t;

extern void *newblock();
extern void *readblock(uint64_t id);
extern uint64_t allocblock(void *block);
extern uint64_t allocblock_hint(void *block, uint64_t hint);
extern int writeblock(uint64_t id, void *block);

/* Add this blockid to a freelist, to be recycled by the allocator. */
extern void releaseblock(uint64_t id);

/* this is a memory free() operation for block-sized allocations */
extern void freeblock(void *block);
extern int __init_blockstore(void);

/* debug for freelist. */
void freelist_count(int print_each);
#define ALLOCFAIL (((uint64_t)(-1)))

/* Distribution
 */
#define BLOCKSTORED_PORT 9346

struct bshdr_t_struct {
    uint32_t            operation;
    uint32_t            flags;
    uint64_t            id;
    uint64_t            luid;
} __attribute__ ((packed));
typedef struct bshdr_t_struct bshdr_t;

struct bsmsg_t_struct {
    bshdr_t        hdr;
    unsigned char  block[BLOCK_SIZE];
} __attribute__ ((packed));

typedef struct bsmsg_t_struct bsmsg_t;

#define MSGBUFSIZE_OP    sizeof(uint32_t)
#define MSGBUFSIZE_FLAGS (sizeof(uint32_t) + sizeof(uint32_t))
#define MSGBUFSIZE_ID    (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t))
#define MSGBUFSIZE_BLOCK sizeof(bsmsg_t)

#define BSOP_READBLOCK  0x01
#define BSOP_WRITEBLOCK 0x02
#define BSOP_ALLOCBLOCK 0x03
#define BSOP_FREEBLOCK  0x04

#define BSOP_FLAG_ERROR 0x01

#define BS_ALLOC_SKIP 10
#define BS_ALLOC_HACK

/* Remote hosts and cluster map - XXX need to generalise
 */

/*

  Interim ID format is

  63 60 59                40 39                20 19                 0
  +----+--------------------+--------------------+--------------------+
  |map | replica 2          | replica 1          | replica 0          |
  +----+--------------------+--------------------+--------------------+

  The map is an index into a table detailing which machines form the
  cluster.

 */

#define BSID_REPLICA0(_id) ((_id)&0xfffffULL)
#define BSID_REPLICA1(_id) (((_id)>>20)&0xfffffULL)
#define BSID_REPLICA2(_id) (((_id)>>40)&0xfffffULL)
#define BSID_MAP(_id)      (((_id)>>60)&0xfULL)

#define BSID(_map, _rep0, _rep1, _rep2) ((((uint64_t)(_map))<<60) | \
                                         (((uint64_t)(_rep2))<<40) | \
                                         (((uint64_t)(_rep1))<<20) | ((uint64_t)(_rep0)))

typedef struct bsserver_t_struct {
    char              *hostname;
    struct sockaddr_in sin;
} bsserver_t;

#define MAX_SERVERS 16

#define CLUSTER_MAX_REPLICAS 3
typedef struct bscluster_t_struct {
    int servers[CLUSTER_MAX_REPLICAS];
} bscluster_t;

#define MAX_CLUSTERS 16

#endif /* __BLOCKSTORE_H__ */
