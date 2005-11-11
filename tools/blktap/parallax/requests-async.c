/* requests-async.c
 *
 * asynchronous request dispatcher for radix access in parallax.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <pthread.h>
#include <err.h>
#include <zlib.h> /* for crc32() */
#include "requests-async.h"
#include "vdi.h"
#include "radix.h"

#define L1_IDX(_a) (((_a) & 0x0000000007fc0000ULL) >> 18)
#define L2_IDX(_a) (((_a) & 0x000000000003fe00ULL) >> 9)
#define L3_IDX(_a) (((_a) & 0x00000000000001ffULL))


#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

struct block_info {
    uint32_t        crc;
    uint32_t        unused;
};

struct io_req {
    enum { IO_OP_READ, IO_OP_WRITE } op;
    uint64_t        root;
    uint64_t        vaddr;
    int        state;
    io_cb_t    cb;
    void      *param;
    struct radix_lock *lock;

    /* internal stuff: */
    struct io_ret     retval;/* holds the return while we unlock. */
    char             *block; /* the block to write */
    radix_tree_node   radix[3];
    uint64_t               radix_addr[3];
    struct block_info bi;
};

void clear_w_bits(radix_tree_node node) 
{
    int i;
    for (i=0; i<RADIX_TREE_MAP_ENTRIES; i++)
        node[i] = node[i] & ONEMASK;
    return;
}

void clear_L3_w_bits(radix_tree_node node) 
{
    int i;
    for (i=0; i<RADIX_TREE_MAP_ENTRIES; i+=2)
        node[i] = node[i] & ONEMASK;
    return;
}

enum states {
    /* both */
    READ_L1,
    READ_L2,
    READ_L3,

    /* read */
    READ_LOCKED,
    READ_DATA,
    READ_UNLOCKED,
    RETURN_ZERO,

    /* write */
    WRITE_LOCKED,
    WRITE_DATA,
    WRITE_L3,
    WRITE_UNLOCKED,
    
    /* L3 Zero Path */
    ALLOC_DATA_L3z,
    WRITE_L3_L3z,
    
    /* L3 Fault Path */
    ALLOC_DATA_L3f,
    WRITE_L3_L3f,
    
    /* L2 Zero Path */
    ALLOC_DATA_L2z,
    WRITE_L2_L2z,
    ALLOC_L3_L2z,
    WRITE_L2_L3z,
    
    /* L2 Fault Path */
    READ_L3_L2f,
    ALLOC_DATA_L2f,
    WRITE_L2_L2f,
    ALLOC_L3_L2f,
    WRITE_L2_L3f,

    /* L1 Zero Path */
    ALLOC_DATA_L1z,
    ALLOC_L3_L1z,
    ALLOC_L2_L1z,
    WRITE_L1_L1z,

    /* L1 Fault Path */
    READ_L2_L1f,
    READ_L3_L1f,
    ALLOC_DATA_L1f,
    ALLOC_L3_L1f,
    ALLOC_L2_L1f,
    WRITE_L1_L1f,
    
};

enum radix_offsets {
    L1 = 0, 
    L2 = 1,
    L3 = 2
};


static void read_cb(struct io_ret ret, void *param);
static void write_cb(struct io_ret ret, void *param);

int vdi_read(vdi_t *vdi, uint64_t vaddr, io_cb_t cb, void *param)
{
    struct io_req *req;

    if (!VALID_VADDR(vaddr)) return ERR_BAD_VADDR;
    /* Every second line in the bottom-level radix tree is used to      */
    /* store crc32 values etc. We shift the vadder here to achied this. */
    vaddr <<= 1;

    req = (struct io_req *)malloc(sizeof (struct io_req));
    if (req == NULL) return ERR_NOMEM;

    req->radix[0] = req->radix[1] = req->radix[2] = NULL;	
    req->op    = IO_OP_READ;
    req->root  = vdi->radix_root;
    req->lock  = vdi->radix_lock; 
    req->vaddr = vaddr;
    req->cb    = cb;
    req->param = param;
    req->state = READ_LOCKED;

    block_rlock(req->lock, L1_IDX(vaddr), read_cb, req);
	
    return 0;
}


int   vdi_write(vdi_t *vdi, uint64_t vaddr, char *block, 
                io_cb_t cb, void *param)
{
    struct io_req *req;

    if (!VALID_VADDR(vaddr)) return ERR_BAD_VADDR;
    /* Every second line in the bottom-level radix tree is used to      */
    /* store crc32 values etc. We shift the vadder here to achied this. */
    vaddr <<= 1;

    req = (struct io_req *)malloc(sizeof (struct io_req));
    if (req == NULL) return ERR_NOMEM; 

    req->radix[0] = req->radix[1] = req->radix[2] = NULL;
    req->op     = IO_OP_WRITE;
    req->root   = vdi->radix_root;
    req->lock   = vdi->radix_lock; 
    req->vaddr  = vaddr;
    req->block  = block;
    /* Todo: add a pseodoheader to the block to include some location   */
    /* information in the CRC as well.                                  */
    req->bi.crc = (uint32_t) crc32(0L, Z_NULL, 0); 
    req->bi.crc = (uint32_t) crc32(req->bi.crc, block, BLOCK_SIZE); 
    req->bi.unused = 0xdeadbeef;

    req->cb     = cb;
    req->param  = param;
    req->radix_addr[L1] = getid(req->root); /* for consistency */
    req->state  = WRITE_LOCKED;

    block_wlock(req->lock, L1_IDX(vaddr), write_cb, req);


    return 0;
}

static void read_cb(struct io_ret ret, void *param)
{
    struct io_req *req = (struct io_req *)param;
    radix_tree_node node;
    uint64_t idx;
    char *block;
    void *req_param;

    DPRINTF("read_cb\n");
    /* get record */
    switch(req->state) {
    	
    case READ_LOCKED: 
    
        DPRINTF("READ_LOCKED\n");
    	req->state = READ_L1;
    	block_read(getid(req->root), read_cb, req); 
    	break;
    	
    case READ_L1: /* block is the radix root */

        DPRINTF("READ_L1\n");
        block = IO_BLOCK(ret);
        if (block == NULL) goto fail;
        node = (radix_tree_node) block;
        idx  = getid( node[L1_IDX(req->vaddr)] );
        free(block);
        if ( idx == ZERO ) {
            req->state = RETURN_ZERO;
            block_runlock(req->lock, L1_IDX(req->vaddr), read_cb, req);
        } else {
            req->state = READ_L2;
            block_read(idx, read_cb, req);
        }
        break;

    case READ_L2:

        DPRINTF("READ_L2\n");
        block = IO_BLOCK(ret);
        if (block == NULL) goto fail;
        node = (radix_tree_node) block;
        idx  = getid( node[L2_IDX(req->vaddr)] );
        free(block);
        if ( idx == ZERO ) {
            req->state = RETURN_ZERO;
            block_runlock(req->lock, L1_IDX(req->vaddr), read_cb, req);
        } else {
            req->state = READ_L3;
            block_read(idx, read_cb, req);
        }
        break;

    case READ_L3:
    {
        struct block_info *bi;

        DPRINTF("READ_L3\n");
        block = IO_BLOCK(ret);
        if (block == NULL) goto fail;
        node = (radix_tree_node) block;
        idx  = getid( node[L3_IDX(req->vaddr)] );
        bi = (struct block_info *) &node[L3_IDX(req->vaddr) + 1];
        req->bi = *bi;
        free(block);
        if ( idx == ZERO )  {
            req->state = RETURN_ZERO;
            block_runlock(req->lock, L1_IDX(req->vaddr), read_cb, req);
        } else {
            req->state = READ_DATA;
            block_read(idx, read_cb, req);
        }
        break;
    }
    case READ_DATA:
    {
        uint32_t crc;

        DPRINTF("READ_DATA\n");
        block = IO_BLOCK(ret);
        if (block == NULL) goto fail;

        /* crc check */
        crc = (uint32_t) crc32(0L, Z_NULL, 0); 
        crc = (uint32_t) crc32(crc, block, BLOCK_SIZE); 
        if (crc != req->bi.crc) {
            /* TODO: add a retry loop here.                          */
            /* Do this after the cache is added -- make sure to      */
            /* invalidate the bad page before reissuing the read.    */

            warn("Bad CRC on vaddr (%Lu:%d)\n", req->vaddr, req->bi.unused);
#ifdef PRINT_BADCRC_PAGES
            {
                int j;
                for (j=0; j<BLOCK_SIZE; j++) {
                    if isprint(block[j]) {
                        printf("%c", block[j]);
                    } else {
                        printf(".");
                    }
                    if ((j % 64) == 0) printf("\n");
                }
            }
#endif /* PRINT_BADCRC_PAGES */

            /* fast and loose for the moment. */
            /* goto fail;                     */
        }

        req->retval = ret;
        req->state = READ_UNLOCKED;
        block_runlock(req->lock, L1_IDX(req->vaddr), read_cb, req);
        break;
    }
    case READ_UNLOCKED:
    {
        struct io_ret r;
        io_cb_t cb;
        DPRINTF("READ_UNLOCKED\n");
        req_param = req->param;
        r         = req->retval;
        cb        = req->cb;
        free(req);
        cb(r, req_param);
        break;
    }
    
    case RETURN_ZERO:
    {
        struct io_ret r;
        io_cb_t cb;
        DPRINTF("RETURN_ZERO\n");
        req_param = req->param;
        cb        = req->cb;
        free(req);
        r.type = IO_BLOCK_T;
        r.u.b = newblock();
        cb(r, req_param);
        break;
    }
        
    default:
    	DPRINTF("*** Write: Bad state! (%d) ***\n", req->state);
    	goto fail;
    }
 
    return;

 fail:
    {
        struct io_ret r;
        io_cb_t cb;
        DPRINTF("asyn_read had a read error.\n");
        req_param = req->param;
        r         = ret;
        cb        = req->cb;
        free(req);
        cb(r, req_param);
    }


}

static void write_cb(struct io_ret r, void *param)
{
    struct io_req *req = (struct io_req *)param;
    radix_tree_node node;
    uint64_t a, addr;
    void *req_param;
    struct block_info *bi;

    switch(req->state) {
    	
    case WRITE_LOCKED:
        
        DPRINTF("WRITE_LOCKED (%llu)\n", L1_IDX(req->vaddr));
    	req->state = READ_L1;
    	block_read(getid(req->root), write_cb, req); 
    	break;
    	
    case READ_L1: /* block is the radix root */

        DPRINTF("READ_L1\n");
        node = (radix_tree_node) IO_BLOCK(r);
        if (node == NULL) goto fail;
        a    = node[L1_IDX(req->vaddr)];
        addr = getid(a);

        req->radix_addr[L2] = addr;
        req->radix[L1] = node;

        if ( addr == ZERO ) {
            /* L1 empty subtree: */
            req->state = ALLOC_DATA_L1z;
            block_alloc( req->block, write_cb, req );
        } else if ( !iswritable(a) ) {
            /* L1 fault: */
            req->state = READ_L2_L1f;
            block_read( addr, write_cb, req );
        } else {
            req->state = READ_L2;
            block_read( addr, write_cb, req );
        }
        break;
    
    case READ_L2:

        DPRINTF("READ_L2\n");
        node = (radix_tree_node) IO_BLOCK(r);
        if (node == NULL) goto fail;
        a    = node[L2_IDX(req->vaddr)];
        addr = getid(a);

        req->radix_addr[L3] = addr;
        req->radix[L2] = node;

        if ( addr == ZERO ) {
            /* L2 empty subtree: */
            req->state = ALLOC_DATA_L2z;
            block_alloc( req->block, write_cb, req );
        } else if ( !iswritable(a) ) {
            /* L2 fault: */
            req->state = READ_L3_L2f;
            block_read( addr, write_cb, req );
        } else {
            req->state = READ_L3;
            block_read( addr, write_cb, req );
        }
        break;
    
    case READ_L3:

        DPRINTF("READ_L3\n");
        node = (radix_tree_node) IO_BLOCK(r);
        if (node == NULL) goto fail;
        a    = node[L3_IDX(req->vaddr)];
        addr = getid(a);

        req->radix[L3] = node;

        if ( addr == ZERO ) {
            /* L3 fault: */
            req->state = ALLOC_DATA_L3z;
            block_alloc( req->block, write_cb, req );
        } else if ( !iswritable(a) ) {
            /* L3 fault: */
            req->state = ALLOC_DATA_L3f;
            block_alloc( req->block, write_cb, req );
        } else {
            req->state = WRITE_DATA;
            block_write( addr, req->block, write_cb, req );
        }
        break;
    
    case WRITE_DATA:

        DPRINTF("WRITE_DATA\n");
        /* The L3 radix points to the correct block, we just need to  */
        /* update the crc.                                            */
        if (IO_INT(r) < 0) goto fail;
        bi  = (struct block_info *) &req->radix[L3][L3_IDX(req->vaddr)+1];
        req->bi.unused = 101;
        *bi = req->bi;
        req->state = WRITE_L3;
        block_write(req->radix_addr[L3], (char*)req->radix[L3], write_cb, req);
        break;
    
    /* L3 Zero Path: */

    case ALLOC_DATA_L3z:

        DPRINTF("ALLOC_DATA_L3z\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L3][L3_IDX(req->vaddr)] = a;
        bi  = (struct block_info *) &req->radix[L3][L3_IDX(req->vaddr)+1];
        req->bi.unused = 102;
        *bi = req->bi;
        req->state = WRITE_L3_L3z;
        block_write(req->radix_addr[L3], (char*)req->radix[L3], write_cb, req);
        break;
    
    /* L3 Fault Path: */

    case ALLOC_DATA_L3f:
    
        DPRINTF("ALLOC_DATA_L3f\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L3][L3_IDX(req->vaddr)] = a;
        bi  = (struct block_info *) &req->radix[L3][L3_IDX(req->vaddr)+1];
        req->bi.unused = 103;
        *bi = req->bi;
        req->state = WRITE_L3_L3f;
        block_write(req->radix_addr[L3], (char*)req->radix[L3], write_cb, req);
        break;

    /* L2 Zero Path: */
        
    case ALLOC_DATA_L2z:

        DPRINTF("ALLOC_DATA_L2z\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L3] = newblock();
        req->radix[L3][L3_IDX(req->vaddr)] = a;
        bi  = (struct block_info *) &req->radix[L3][L3_IDX(req->vaddr)+1];
        req->bi.unused = 104;
        *bi = req->bi;
        req->state = ALLOC_L3_L2z;
        block_alloc( (char*)req->radix[L3], write_cb, req );
        break;

    case ALLOC_L3_L2z:

        DPRINTF("ALLOC_L3_L2z\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L2][L2_IDX(req->vaddr)] = a;
        req->state = WRITE_L2_L2z;
        block_write(req->radix_addr[L2], (char*)req->radix[L2], write_cb, req);
        break;
        
    /* L2 Fault Path: */
        
    case READ_L3_L2f:
    
    	DPRINTF("READ_L3_L2f\n");
        node = (radix_tree_node) IO_BLOCK(r);
        clear_L3_w_bits(node);
        if (node == NULL) goto fail;
        a    = node[L2_IDX(req->vaddr)];
        addr = getid(a);

        req->radix[L3] = node;
        req->state = ALLOC_DATA_L2f;
        block_alloc( req->block, write_cb, req );
        break;
                
    case ALLOC_DATA_L2f:

        DPRINTF("ALLOC_DATA_L2f\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L3][L3_IDX(req->vaddr)] = a;
        bi  = (struct block_info *) &req->radix[L3][L3_IDX(req->vaddr)+1];
        req->bi.unused = 105;
        *bi = req->bi;
        req->state = ALLOC_L3_L2f;
        block_alloc( (char*)req->radix[L3], write_cb, req );
        break;

    case ALLOC_L3_L2f:

        DPRINTF("ALLOC_L3_L2f\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L2][L2_IDX(req->vaddr)] = a;
        req->state = WRITE_L2_L2f;
        block_write(req->radix_addr[L2], (char*)req->radix[L2], write_cb, req);
        break;
        
    /* L1 Zero Path: */
    
    case ALLOC_DATA_L1z:

        DPRINTF("ALLOC_DATA_L1z\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L3] = newblock();
        req->radix[L3][L3_IDX(req->vaddr)] = a;
        bi  = (struct block_info *) &req->radix[L3][L3_IDX(req->vaddr)+1];
        req->bi.unused = 106;
        *bi = req->bi;
        req->state = ALLOC_L3_L1z;
        block_alloc( (char*)req->radix[L3], write_cb, req );
        break;
        
    case ALLOC_L3_L1z:

        DPRINTF("ALLOC_L3_L1z\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L2] = newblock();
        req->radix[L2][L2_IDX(req->vaddr)] = a;
        req->state = ALLOC_L2_L1z;
        block_alloc( (char*)req->radix[L2], write_cb, req );
        break;

    case ALLOC_L2_L1z:

        DPRINTF("ALLOC_L2_L1z\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L1][L1_IDX(req->vaddr)] = a;
        req->state = WRITE_L1_L1z;
        block_write(req->radix_addr[L1], (char*)req->radix[L1], write_cb, req);
        break;

    /* L1 Fault Path: */
        
    case READ_L2_L1f:
    
    	DPRINTF("READ_L2_L1f\n");
        node = (radix_tree_node) IO_BLOCK(r);
        clear_w_bits(node);
        if (node == NULL) goto fail;
        a    = node[L2_IDX(req->vaddr)];
        addr = getid(a);

        req->radix_addr[L3] = addr;
        req->radix[L2] = node;
        
        if (addr == ZERO) {
            /* nothing below L2, create an empty L3 and alloc data. */
            /* (So skip READ_L3_L1f.) */
            req->radix[L3] = newblock();
            req->state = ALLOC_DATA_L1f;
            block_alloc( req->block, write_cb, req );
        } else {
            req->state = READ_L3_L1f;
            block_read( addr, write_cb, req );
        }
        break;
        
    case READ_L3_L1f:
    
    	DPRINTF("READ_L3_L1f\n");
        node = (radix_tree_node) IO_BLOCK(r);
        clear_L3_w_bits(node);
        if (node == NULL) goto fail;
        a    = node[L2_IDX(req->vaddr)];
        addr = getid(a);

        req->radix[L3] = node;
        req->state = ALLOC_DATA_L1f;
        block_alloc( req->block, write_cb, req );
        break;
                
    case ALLOC_DATA_L1f:

        DPRINTF("ALLOC_DATA_L1f\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L3][L3_IDX(req->vaddr)] = a;
        bi  = (struct block_info *) &req->radix[L3][L3_IDX(req->vaddr)+1];
        req->bi.unused = 107;
        *bi = req->bi;
        req->state = ALLOC_L3_L1f;
        block_alloc( (char*)req->radix[L3], write_cb, req );
        break;

    case ALLOC_L3_L1f:

        DPRINTF("ALLOC_L3_L1f\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L2][L2_IDX(req->vaddr)] = a;
        req->state = ALLOC_L2_L1f;
        block_alloc( (char*)req->radix[L2], write_cb, req );
        break;

    case ALLOC_L2_L1f:

        DPRINTF("ALLOC_L2_L1f\n");
        addr = IO_ADDR(r);
        a = writable(addr);
        req->radix[L1][L1_IDX(req->vaddr)] = a;
        req->state = WRITE_L1_L1f;
        block_write(req->radix_addr[L1], (char*)req->radix[L1], write_cb, req);
        break;

    case WRITE_L3:
    case WRITE_L3_L3z:
    case WRITE_L3_L3f:
    case WRITE_L2_L2z:
    case WRITE_L2_L2f:
    case WRITE_L1_L1z:
    case WRITE_L1_L1f:
    {
    	int i;
        DPRINTF("DONE\n");
        /* free any saved node vals. */
        for (i=0; i<3; i++)
            if (req->radix[i] != 0) free(req->radix[i]);
        req->retval = r;
        req->state = WRITE_UNLOCKED;
        block_wunlock(req->lock, L1_IDX(req->vaddr), write_cb, req);
        break;
    }
    case WRITE_UNLOCKED:
    {
        struct io_ret r;
        io_cb_t cb;
        DPRINTF("WRITE_UNLOCKED!\n");
        req_param = req->param;
        r         = req->retval;
        cb        = req->cb;
        free(req);
        cb(r, req_param);
        break;
    }
        
    default:
    	DPRINTF("*** Write: Bad state! (%d) ***\n", req->state);
    	goto fail;
    }
    
    return;
    
 fail:
    {
        struct io_ret r;
        io_cb_t cb;
        int i;

        DPRINTF("asyn_write had a read error mid-way.\n");
        req_param = req->param;
        cb        = req->cb;
        r.type = IO_INT_T;
        r.u.i  = -1;
        /* free any saved node vals. */
        for (i=0; i<3; i++)
            free(req->radix[i]);
        free(req);
        cb(r, req_param);
    }
}

char *vdi_read_s(vdi_t *vdi, uint64_t vaddr)
{
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    char *block = NULL;
    int ret;

    void reads_cb(struct io_ret r, void *param) 
    {
        block = IO_BLOCK(r);
        pthread_mutex_unlock((pthread_mutex_t *)param);
    }

    pthread_mutex_lock(&m);
    ret = vdi_read(vdi, vaddr, reads_cb, &m);

    if (ret == 0) pthread_mutex_lock(&m);
    
    return block;
}


int vdi_write_s(vdi_t *vdi, uint64_t vaddr, char *block)
{
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    int ret, result;

    void writes_cb(struct io_ret r, void *param) 
    {
        result = IO_INT(r);
        pthread_mutex_unlock((pthread_mutex_t *)param);
    }

    pthread_mutex_lock(&m);
    ret = vdi_write(vdi, vaddr, block, writes_cb, &m);

    if (ret == 0) pthread_mutex_lock(&m);
    
    return result;
}
