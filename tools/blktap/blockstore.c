/**************************************************************************
 * 
 * blockstore.c
 *
 * Simple block store interface
 *
 */
 
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "blockstore.h"
#include "parallax-threaded.h"

#define BLOCKSTORE_REMOTE

#ifdef BLOCKSTORE_REMOTE

//#define BSDEBUG

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>

#define ENTER_QUEUE_CR (void)0
#define LEAVE_QUEUE_CR (void)0

bsserver_t bsservers[MAX_SERVERS];
bscluster_t bsclusters[MAX_CLUSTERS];

struct sockaddr_in sin_local;
int bssock = 0;

typedef struct bsq_t_struct {
    struct bsq_t_struct *prev;
    struct bsq_t_struct *next;
    int server;
    int length;
    struct msghdr msghdr;
    struct iovec iov[2];
    bshdr_t message;
    void *block;
} bsq_t;

bsq_t *bs_head = NULL;
bsq_t *bs_tail = NULL;

int send_message(bsq_t *qe) {
    int rc;

    qe->msghdr.msg_name = (void *)&(bsservers[qe->server].sin);
    qe->msghdr.msg_namelen = sizeof(struct sockaddr_in);
    qe->msghdr.msg_iov = qe->iov;
    if (qe->block)
        qe->msghdr.msg_iovlen = 2;
    else
        qe->msghdr.msg_iovlen = 1;
    qe->msghdr.msg_control = NULL;
    qe->msghdr.msg_controllen = 0;
    qe->msghdr.msg_flags = 0;

    qe->iov[0].iov_base = (void *)&(qe->message);
    qe->iov[0].iov_len = MSGBUFSIZE_ID;

    if (qe->block) {
        qe->iov[1].iov_base = qe->block;
        qe->iov[1].iov_len = BLOCK_SIZE;
    }

    rc = sendmsg(bssock, &(qe->msghdr), 0);
    //rc = sendto(bssock, (void *)&(qe->message), qe->length, 0,
    //           (struct sockaddr *)&(bsservers[qe->server].sin),
    //           sizeof(struct sockaddr_in));
    if (rc < 0)
        return rc;
    
    ENTER_QUEUE_CR;
    
    LEAVE_QUEUE_CR;

    return rc;
}

int recv_message(bsq_t *qe) {
    struct sockaddr_in from;
    //int flen = sizeof(from);
    int rc;

    qe->msghdr.msg_name = &from;
    qe->msghdr.msg_namelen = sizeof(struct sockaddr_in);
    qe->msghdr.msg_iov = qe->iov;
    if (qe->block)
        qe->msghdr.msg_iovlen = 2;
    else
        qe->msghdr.msg_iovlen = 1;
    qe->msghdr.msg_control = NULL;
    qe->msghdr.msg_controllen = 0;
    qe->msghdr.msg_flags = 0;

    qe->iov[0].iov_base = (void *)&(qe->message);
    qe->iov[0].iov_len = MSGBUFSIZE_ID;
    if (qe->block) {
        qe->iov[1].iov_base = qe->block;
        qe->iov[1].iov_len = BLOCK_SIZE;
    }

    rc = recvmsg(bssock, &(qe->msghdr), 0);

    //return recvfrom(bssock, (void *)&(qe->message), sizeof(bsmsg_t), 0,
    //               (struct sockaddr *)&from, &flen);
    return rc;
}

void *readblock_indiv(int server, u64 id) {
    void *block;
    bsq_t *qe;
    int len;

    qe = (bsq_t *)malloc(sizeof(bsq_t));
    if (!qe) {
        perror("readblock qe malloc");
        return NULL;
    }
    qe->block = malloc(BLOCK_SIZE);
    if (!qe->block) {
        perror("readblock qe malloc");
        free((void *)qe);
        return NULL;
    }

    qe->server = server;

    qe->message.operation = BSOP_READBLOCK;
    qe->message.flags = 0;
    qe->message.id = id;
    qe->length = MSGBUFSIZE_ID;

    if (send_message(qe) < 0) {
        perror("readblock sendto");
        goto err;
    }
    
    len = recv_message(qe);
    if (len < 0) {
        perror("readblock recv");
        goto err;
    }
    if ((qe->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "readblock server error\n");
        goto err;
    }
    if (len < MSGBUFSIZE_BLOCK) {
        fprintf(stderr, "readblock recv short (%u)\n", len);
        goto err;
    }
    /* akw: memory leak here? */
    /*
    if ((block = malloc(BLOCK_SIZE)) == NULL) {
        perror("readblock malloc");
        goto err;
    }
    */
    //memcpy(block, qe->message.block, BLOCK_SIZE);
    block = qe->block;

    free((void *)qe);
    return block;

    err:
    free(qe->block);
    free((void *)qe);
    return NULL;
}

/**
 * readblock: read a block from disk
 *   @id: block id to read
 *
 *   @return: pointer to block, NULL on error
 */
void *readblock(u64 id) {
    int map = (int)BSID_MAP(id);
    u64 xid;
    static int i = CLUSTER_MAX_REPLICAS - 1;
    void *block = NULL;

    /* special case for the "superblock" just use the first block on the
     * first replica. (extend to blocks < 6 for vdi bug)
     */
    if (id < 6) {
        block = readblock_indiv(bsclusters[map].servers[0], id);
        goto out;
    }

    i++;
    if (i >= CLUSTER_MAX_REPLICAS)
        i = 0;
    switch (i) {
    case 0:
        xid = BSID_REPLICA0(id);
        break;
    case 1:
        xid = BSID_REPLICA1(id);
        break;
    case 2:
        xid = BSID_REPLICA2(id);
        break;
    }
    
    block = readblock_indiv(bsclusters[map].servers[i], xid);

    out:
#ifdef BSDEBUG
    if (block)
        fprintf(stderr, "READ:  %016llx %02x%02x %02x%02x %02x%02x %02x%02x\n",
                id,
                (unsigned int)((unsigned char *)block)[0],
                (unsigned int)((unsigned char *)block)[1],
                (unsigned int)((unsigned char *)block)[2],
                (unsigned int)((unsigned char *)block)[3],
                (unsigned int)((unsigned char *)block)[4],
                (unsigned int)((unsigned char *)block)[5],
                (unsigned int)((unsigned char *)block)[6],
                (unsigned int)((unsigned char *)block)[7]);
    else
        fprintf(stderr, "READ:  %016llx NULL\n", id);
#endif
    return block;
}

int writeblock_indiv(int server, u64 id, void *block) {
    bsq_t *qe;
    int len;

    qe = (bsq_t *)malloc(sizeof(bsq_t));
    if (!qe) {
        perror("writeblock qe malloc");
        goto err;
    }
    qe->server = server;

    qe->message.operation = BSOP_WRITEBLOCK;
    qe->message.flags = 0;
    qe->message.id = id;
    //memcpy(qe->message.block, block, BLOCK_SIZE);
    qe->block = block;
    qe->length = MSGBUFSIZE_BLOCK;

    if (send_message(qe) < 0) {
        perror("writeblock sendto");
        goto err;
    }
    
    len = recv_message(qe);
    if (len < 0) {
        perror("writeblock recv");
        goto err;
    }
    if ((qe->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "writeblock server error\n");
        goto err;
    }
    if (len < MSGBUFSIZE_ID) {
        fprintf(stderr, "writeblock recv short (%u)\n", len);
        goto err;
    }

    free((void *)qe);
    return 0;

    err:
    free((void *)qe);
    return -1;
}

/**
 * writeblock: write an existing block to disk
 *   @id: block id
 *   @block: pointer to block
 *
 *   @return: zero on success, -1 on failure
 */
int writeblock(u64 id, void *block) {
    int map = (int)BSID_MAP(id);
    
    int rep0 = bsclusters[map].servers[0];
    int rep1 = bsclusters[map].servers[1];
    int rep2 = bsclusters[map].servers[2];

#ifdef BSDEBUG
    fprintf(stderr,
            "WRITE: %016llx %02x%02x %02x%02x %02x%02x %02x%02x\n",
            id,
            (unsigned int)((unsigned char *)block)[0],
            (unsigned int)((unsigned char *)block)[1],
            (unsigned int)((unsigned char *)block)[2],
            (unsigned int)((unsigned char *)block)[3],
            (unsigned int)((unsigned char *)block)[4],
            (unsigned int)((unsigned char *)block)[5],
            (unsigned int)((unsigned char *)block)[6],
            (unsigned int)((unsigned char *)block)[7]);
#endif

/* special case for the "superblock" just use the first block on the
     * first replica. (extend to blocks < 6 for vdi bug)
     */
    if (id < 6) {
        return writeblock_indiv(rep0, id, block);
    }

    if (writeblock_indiv(rep0, BSID_REPLICA0(id), block) < 0)
        return -1;
    if (writeblock_indiv(rep1, BSID_REPLICA1(id), block) < 0)
        return -1;
    if (writeblock_indiv(rep2, BSID_REPLICA2(id), block) < 0)
        return -1;
    return 0;
}

/**
 * allocblock: write a new block to disk
 *   @block: pointer to block
 *
 *   @return: new id of block on disk
 */
u64 allocblock(void *block) {
    return allocblock_hint(block, 0);
}

u64 allocblock_hint_indiv(int server, void *block, u64 hint) {
    bsq_t *qe;
    int len;

    qe = (bsq_t *)malloc(sizeof(bsq_t));
    if (!qe) {
        perror("allocblock_hint qe malloc");
        goto err;
    }
    qe->server = server;

    qe->message.operation = BSOP_ALLOCBLOCK;
    qe->message.flags = 0;
    qe->message.id = hint;
    //memcpy(qe->message.block, block, BLOCK_SIZE);
    qe->block = block;
    qe->length = MSGBUFSIZE_BLOCK;

    if (send_message(qe) < 0) {
        perror("allocblock_hint sendto");
        goto err;
    }
    
    len = recv_message(qe);
    if (len < 0) {
        perror("allocblock_hint recv");
        goto err;
    }
    if ((qe->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "allocblock_hint server error\n");
        goto err;
    }
    if (len < MSGBUFSIZE_ID) {
        fprintf(stderr, "allocblock_hint recv short (%u)\n", len);
        goto err;
    }

    free((void *)qe);
    return qe->message.id;

    err:
    free((void *)qe);
    return 0;
}

/**
 * allocblock_hint: write a new block to disk
 *   @block: pointer to block
 *   @hint: allocation hint
 *
 *   @return: new id of block on disk
 */
u64 allocblock_hint(void *block, u64 hint) {
    int map = (int)hint;
    
    int rep0 = bsclusters[map].servers[0];
    int rep1 = bsclusters[map].servers[1];
    int rep2 = bsclusters[map].servers[2];

    u64 id0, id1, id2;

    id0 = allocblock_hint_indiv(rep0, block, 0);
    if (id0 == 0)
        return 0;
    id1 = allocblock_hint_indiv(rep1, block, 0);
    if (id1 == 0)
        return 0;
    id2 = allocblock_hint_indiv(rep2, block, 0);
    if (id2 == 0)
        return 0;

#ifdef BSDEBUG
    fprintf(stderr, "ALLOC: %016llx %02x%02x %02x%02x %02x%02x %02x%02x\n",
            BSID(map, id0, id1, id2),
            (unsigned int)((unsigned char *)block)[0],
            (unsigned int)((unsigned char *)block)[1],
            (unsigned int)((unsigned char *)block)[2],
            (unsigned int)((unsigned char *)block)[3],
            (unsigned int)((unsigned char *)block)[4],
            (unsigned int)((unsigned char *)block)[5],
            (unsigned int)((unsigned char *)block)[6],
            (unsigned int)((unsigned char *)block)[7]);
#endif

    return BSID(map, id0, id1, id2);
}

#else /* /BLOCKSTORE_REMOTE */

 
/**
 * readblock: read a block from disk
 *   @id: block id to read
 *
 *   @return: pointer to block, NULL on error
 */

void *readblock(u64 id) {
    void *block;
    int block_fp;
    
    block_fp = open("blockstore.dat", O_RDONLY | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return NULL;
    }
    
    if (lseek64(block_fp, ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        printf ("%Ld ", id);
        printf ("%Ld\n", (id - 1) * BLOCK_SIZE);
        perror("readblock lseek");
        goto err;
    }
    if ((block = malloc(BLOCK_SIZE)) == NULL) {
        perror("readblock malloc");
        goto err;
    }
    if (read(block_fp, block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("readblock read");
        free(block);
        goto err;
    }
    close(block_fp);
    return block;
    
err:
    close(block_fp);
    return NULL;
}

/**
 * writeblock: write an existing block to disk
 *   @id: block id
 *   @block: pointer to block
 *
 *   @return: zero on success, -1 on failure
 */
int writeblock(u64 id, void *block) {
    
    int block_fp;
    
    block_fp = open("blockstore.dat", O_RDWR | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return -1;
    }

    if (lseek64(block_fp, ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        perror("writeblock lseek");
        goto err;
    }
    if (write(block_fp, block, BLOCK_SIZE) < 0) {
        perror("writeblock write");
        goto err;
    }
    close(block_fp);
    return 0;

err:
    close(block_fp);
    return -1;
}

/**
 * allocblock: write a new block to disk
 *   @block: pointer to block
 *
 *   @return: new id of block on disk
 */

u64 allocblock(void *block) {
    u64 lb;
    off64_t pos;
    int block_fp;
    
    block_fp = open("blockstore.dat", O_RDWR | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return 0;
    }

    pos = lseek64(block_fp, 0, SEEK_END);
    if (pos == (off64_t)-1) {
        perror("allocblock lseek");
        goto err;
    }
    if (pos % BLOCK_SIZE != 0) {
        fprintf(stderr, "file size not multiple of %d\n", BLOCK_SIZE);
        goto err;
    }
    if (write(block_fp, block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("allocblock write");
        goto err;
    }
    lb = pos / BLOCK_SIZE + 1;
//printf("alloc(%Ld)\n", lb);
    close(block_fp);
    return lb;
    
err:
    close(block_fp);
    return 0;
    
}

/**
 * allocblock_hint: write a new block to disk
 *   @block: pointer to block
 *   @hint: allocation hint
 *
 *   @return: new id of block on disk
 */
u64 allocblock_hint(void *block, u64 hint) {
    return allocblock(block);
}

#endif /* BLOCKSTORE_REMOTE */

/**
 * newblock: get a new in-memory block set to zeros
 *
 *   @return: pointer to new block, NULL on error
 */
void *newblock() {
    void *block = malloc(BLOCK_SIZE);
    if (block == NULL) {
        perror("newblock");
        return NULL;
    }
    memset(block, 0, BLOCK_SIZE);
    return block;
}


/**
 * freeblock: unallocate an in-memory block
 *   @id: block id (zero if this is only in-memory)
 *   @block: block to be freed
 */
void freeblock(void *block) {
    if (block != NULL)
        free(block);
}

static freeblock_t *new_freeblock(void)
{
    freeblock_t *fb;
    
    fb = newblock();
    
    if (fb == NULL) return NULL;
    
    fb->magic = FREEBLOCK_MAGIC;
    fb->next  = 0ULL;
    fb->count = 0ULL;
    memset(fb->list, 0, sizeof fb->list);
    
    return fb;
}

void releaseblock(u64 id)
{
    blockstore_super_t *bs_super;
    freeblock_t *fl_current;
    
    /* get superblock */
    bs_super = (blockstore_super_t *) readblock(BLOCKSTORE_SUPER);
    
    /* get freeblock_current */
    if (bs_super->freelist_current == 0ULL) 
    {
        fl_current = new_freeblock();
        bs_super->freelist_current = allocblock(fl_current);
        writeblock(BLOCKSTORE_SUPER, bs_super);
    } else {
        fl_current = readblock(bs_super->freelist_current);
    }
    
    /* if full, chain to superblock and allocate new current */
    
    if (fl_current->count == FREEBLOCK_SIZE) {
        fl_current->next = bs_super->freelist_full;
        writeblock(bs_super->freelist_current, fl_current);
        bs_super->freelist_full = bs_super->freelist_current;
        freeblock(fl_current);
        fl_current = new_freeblock();
        bs_super->freelist_current = allocblock(fl_current);
        writeblock(BLOCKSTORE_SUPER, bs_super);
    }
    
    /* append id to current */
    fl_current->list[fl_current->count++] = id;
    writeblock(bs_super->freelist_current, fl_current);
    
    freeblock(fl_current);
    freeblock(bs_super);
    
    
}

/* freelist debug functions: */
void freelist_count(int print_each)
{
    blockstore_super_t *bs_super;
    freeblock_t *fb;
    u64 total = 0, next;
    
    bs_super = (blockstore_super_t *) readblock(BLOCKSTORE_SUPER);
    
    if (bs_super->freelist_current == 0ULL) {
        printf("freelist is empty!\n");
        return;
    }
    
    fb = readblock(bs_super->freelist_current);
    printf("%Ld entires on current.\n", fb->count);
    total += fb->count;
    if (print_each == 1)
    {
        int i;
        for (i=0; i< fb->count; i++)
            printf("  %Ld\n", fb->list[i]);
    }
    
    freeblock(fb);
    
    if (bs_super->freelist_full == 0ULL) {
        printf("freelist_full is empty!\n");
        return;
    }
    
    next = bs_super->freelist_full;
    for (;;) {
        fb = readblock(next);
        total += fb->count;
        if (print_each == 1)
        {
            int i;
            for (i=0; i< fb->count; i++)
                printf("  %Ld\n", fb->list[i]);
        }
        next = fb->next;
        freeblock(fb);
        if (next == 0ULL) break;
    }
    printf("Total of %Ld ids on freelist.\n", total);
}

int __init_blockstore(void)
{
    int i;
    blockstore_super_t *bs_super;
    u64 ret;
    int block_fp;
    
#ifdef BLOCKSTORE_REMOTE
    struct hostent *addr;
/* james's list
    bsservers[0].hostname = "firebug.cl.cam.ac.uk";
    bsservers[1].hostname = "tetris.cl.cam.ac.uk";
    bsservers[2].hostname = "donkeykong.cl.cam.ac.uk";
    bsservers[3].hostname = "gunfighter.cl.cam.ac.uk";
    bsservers[4].hostname = "galaxian.cl.cam.ac.uk";
    bsservers[5].hostname = "firetrack.cl.cam.ac.uk";
    bsservers[6].hostname = "funfair.cl.cam.ac.uk";
    bsservers[7].hostname = "felix.cl.cam.ac.uk";
*/
    bsservers[0].hostname = "arcadians.cl.cam.ac.uk";
    bsservers[1].hostname = "uridium.cl.cam.ac.uk";
    bsservers[2].hostname = "shep.cl.cam.ac.uk";
    bsservers[3].hostname = "centipede.cl.cam.ac.uk";
    bsservers[4].hostname = "ghouls.cl.cam.ac.uk";
    bsservers[5].hostname = "phoenix.cl.cam.ac.uk";
    bsservers[6].hostname = "swarm.cl.cam.ac.uk";
    bsservers[7].hostname = "freefall.cl.cam.ac.uk";
    bsservers[8].hostname = NULL;
    bsservers[9].hostname = NULL;
    bsservers[10].hostname = NULL;
    bsservers[11].hostname = NULL;
    bsservers[12].hostname = NULL;
    bsservers[13].hostname = NULL;
    bsservers[14].hostname = NULL;
    bsservers[15].hostname = NULL;

    for (i = 0; i < MAX_SERVERS; i++) {
        if (!bsservers[i].hostname)
            continue;
        addr = gethostbyname(bsservers[i].hostname);
        if (!addr) {
            perror("bad hostname");
            return -1;
        }
        bsservers[i].sin.sin_family = addr->h_addrtype;
        bsservers[i].sin.sin_port = htons(BLOCKSTORED_PORT);
        bsservers[i].sin.sin_addr.s_addr = 
            ((struct in_addr *)(addr->h_addr))->s_addr;
    }

    /* Cluster map
     */
    bsclusters[0].servers[0] = 0;
    bsclusters[0].servers[1] = 1;
    bsclusters[0].servers[2] = 2;
    bsclusters[1].servers[0] = 1;
    bsclusters[1].servers[1] = 2;
    bsclusters[1].servers[2] = 3;
    bsclusters[2].servers[0] = 2;
    bsclusters[2].servers[1] = 3;
    bsclusters[2].servers[2] = 4;
    bsclusters[3].servers[0] = 3;
    bsclusters[3].servers[1] = 4;
    bsclusters[3].servers[2] = 5;
    bsclusters[4].servers[0] = 4;
    bsclusters[4].servers[1] = 5;
    bsclusters[4].servers[2] = 6;
    bsclusters[5].servers[0] = 5;
    bsclusters[5].servers[1] = 6;
    bsclusters[5].servers[2] = 7;
    bsclusters[6].servers[0] = 6;
    bsclusters[6].servers[1] = 7;
    bsclusters[6].servers[2] = 0;
    bsclusters[7].servers[0] = 7;
    bsclusters[7].servers[1] = 0;
    bsclusters[7].servers[2] = 1;

    /* Local socket set up
     */
    bssock = socket(AF_INET, SOCK_DGRAM, 0);
    if (bssock < 0) {
        perror("Bad socket");
        return -1;
    }
    memset(&sin_local, 0, sizeof(sin_local));
    sin_local.sin_family = AF_INET;
    sin_local.sin_port = htons(BLOCKSTORED_PORT);
    sin_local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(bssock, (struct sockaddr *)&sin_local, sizeof(sin_local)) < 0) {
        perror("bind");
        close(bssock);
        return -1;
    }

#else /* /BLOCKSTORE_REMOTE */
    block_fp = open("blockstore.dat", O_RDWR | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return -1;
        exit(-1);
    }
    
    if (lseek(block_fp, 0, SEEK_END) == 0) {
        bs_super = newblock();
        bs_super->magic            = BLOCKSTORE_MAGIC;
        bs_super->freelist_full    = 0LL;
        bs_super->freelist_current = 0LL;
        
        ret = allocblock(bs_super);
        
        freeblock(bs_super);
    } else {
        bs_super = (blockstore_super_t *) readblock(BLOCKSTORE_SUPER);
        if (bs_super->magic != BLOCKSTORE_MAGIC)
        {
            printf("BLOCKSTORE IS CORRUPT! (no magic in superblock!)\n");
            exit(-1);
        }
        freeblock(bs_super);
    }
        
    close(block_fp);
        
#endif /*  BLOCKSTORE_REMOTE */   
    return 0;
}
