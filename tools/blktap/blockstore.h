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
extern u64 allocblock_hint(void *block, u64 hint);
extern int writeblock(u64 id, void *block);
extern void freeblock(void *block);
extern int __init_blockstore(void);

#define ALLOCFAIL (((u64)(-1)))

/* Distribution
 */
#define BLOCKSTORED_PORT 9346

struct bshdr_t_struct {
    u32            operation;
    u32            flags;
    u64            id;
} __attribute__ ((packed));
typedef struct bshdr_t_struct bshdr_t;

struct bsmsg_t_struct {
    bshdr_t        hdr;
    unsigned char  block[BLOCK_SIZE];
} __attribute__ ((packed));

typedef struct bsmsg_t_struct bsmsg_t;

#define MSGBUFSIZE_OP    sizeof(u32)
#define MSGBUFSIZE_FLAGS (sizeof(u32) + sizeof(u32))
#define MSGBUFSIZE_ID    (sizeof(u32) + sizeof(u32) + sizeof(u64))
#define MSGBUFSIZE_BLOCK sizeof(bsmsg_t)

#define BSOP_READBLOCK  0x01
#define BSOP_WRITEBLOCK 0x02
#define BSOP_ALLOCBLOCK 0x03

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

#define BSID(_map, _rep0, _rep1, _rep2) ((((u64)(_map))<<60) | \
                                         (((u64)(_rep2))<<40) | \
                                         (((u64)(_rep1))<<20) | ((u64)(_rep0)))

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
