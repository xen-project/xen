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
#include <sys/time.h>
#include <stdarg.h>
#include "blockstore.h"
#include <pthread.h>

//#define BLOCKSTORE_REMOTE
//#define BSDEBUG

#define RETRY_TIMEOUT 1000000 /* microseconds */

/*****************************************************************************
 * Debugging
 */
#ifdef BSDEBUG
void DB(char *format, ...)
{
    va_list args;
    fprintf(stderr, "[%05u] ", (int)pthread_getspecific(tid_key));
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}
#else
#define DB(format, ...) (void)0
#endif

#ifdef BLOCKSTORE_REMOTE

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>

/*****************************************************************************
 * Network state                                                             *
 *****************************************************************************/

/* The individual disk servers we talks to. These will be referenced by
 * an integer index into bsservers[].
 */
bsserver_t bsservers[MAX_SERVERS];

/* The cluster map. This is indexed by an integer cluster number.
 */
bscluster_t bsclusters[MAX_CLUSTERS];

/* Local socket.
 */
struct sockaddr_in sin_local;
int bssock = 0;

/*****************************************************************************
 * Notification                                                              *
 *****************************************************************************/

typedef struct pool_thread_t_struct {
    pthread_mutex_t ptmutex;
    pthread_cond_t ptcv;
    int newdata;
} pool_thread_t;

pool_thread_t pool_thread[READ_POOL_SIZE+1];

#define RECV_NOTIFY(tid) { \
    pthread_mutex_lock(&(pool_thread[tid].ptmutex)); \
    pool_thread[tid].newdata = 1; \
    DB("CV Waking %u", tid); \
    pthread_cond_signal(&(pool_thread[tid].ptcv)); \
    pthread_mutex_unlock(&(pool_thread[tid].ptmutex)); }
#define RECV_AWAIT(tid) { \
    pthread_mutex_lock(&(pool_thread[tid].ptmutex)); \
    if (pool_thread[tid].newdata) { \
        pool_thread[tid].newdata = 0; \
        DB("CV Woken %u", tid); \
    } \
    else { \
        DB("CV Waiting %u", tid); \
        pthread_cond_wait(&(pool_thread[tid].ptcv), \
                          &(pool_thread[tid].ptmutex)); \
    } \
    pthread_mutex_unlock(&(pool_thread[tid].ptmutex)); }

/*****************************************************************************
 * Message queue management                                                  *
 *****************************************************************************/

/* Protects the queue manipulation critcal regions.
 */
pthread_mutex_t ptmutex_queue;
#define ENTER_QUEUE_CR pthread_mutex_lock(&ptmutex_queue)
#define LEAVE_QUEUE_CR pthread_mutex_unlock(&ptmutex_queue)

pthread_mutex_t ptmutex_recv;
#define ENTER_RECV_CR pthread_mutex_lock(&ptmutex_recv)
#define LEAVE_RECV_CR pthread_mutex_unlock(&ptmutex_recv)

/* A message queue entry. We allocate one of these for every request we send.
 * Asynchronous reply reception also used one of these.
 */
typedef struct bsq_t_struct {
    struct bsq_t_struct *prev;
    struct bsq_t_struct *next;
    int status;
    int server;
    int length;
    struct msghdr msghdr;
    struct iovec iov[2];
    int tid;
    struct timeval tv_sent;
    bshdr_t message;
    void *block;
} bsq_t;

#define BSQ_STATUS_MATCHED 1

pthread_mutex_t ptmutex_luid;
#define ENTER_LUID_CR pthread_mutex_lock(&ptmutex_luid)
#define LEAVE_LUID_CR pthread_mutex_unlock(&ptmutex_luid)

static uint64_t luid_cnt = 0x1000ULL;
uint64_t new_luid(void) {
    uint64_t luid;
    ENTER_LUID_CR;
    luid = luid_cnt++;
    LEAVE_LUID_CR;
    return luid;
}

/* Queue of outstanding requests.
 */
bsq_t *bs_head = NULL;
bsq_t *bs_tail = NULL;
int bs_qlen = 0;

/*
 */
void queuedebug(char *msg) {
    bsq_t *q;
    ENTER_QUEUE_CR;
    fprintf(stderr, "Q: %s len=%u\n", msg, bs_qlen);
    for (q = bs_head; q; q = q->next) {
        fprintf(stderr, "  luid=%016llx server=%u\n",
                q->message.luid, q->server);
    }
    LEAVE_QUEUE_CR;
}

int enqueue(bsq_t *qe) {
    ENTER_QUEUE_CR;
    qe->next = NULL;
    qe->prev = bs_tail;
    if (!bs_head)
        bs_head = qe;
    else
        bs_tail->next = qe;
    bs_tail = qe;
    bs_qlen++;
    LEAVE_QUEUE_CR;
#ifdef BSDEBUG
    queuedebug("enqueue");
#endif
    return 0;
}

int dequeue(bsq_t *qe) {
    bsq_t *q;
    ENTER_QUEUE_CR;
    for (q = bs_head; q; q = q->next) {
        if (q == qe) {
            if (q->prev)
                q->prev->next = q->next;
            else 
                bs_head = q->next;
            if (q->next)
                q->next->prev = q->prev;
            else
                bs_tail = q->prev;
            bs_qlen--;
            goto found;
        }
    }

    LEAVE_QUEUE_CR;
#ifdef BSDEBUG
    queuedebug("dequeue not found");
#endif
    return 0;

    found:
    LEAVE_QUEUE_CR;
#ifdef BSDEBUG
    queuedebug("dequeue not found");
#endif
    return 1;
}

bsq_t *queuesearch(bsq_t *qe) {
    bsq_t *q;
    ENTER_QUEUE_CR;
    for (q = bs_head; q; q = q->next) {
        if ((qe->server == q->server) &&
            (qe->message.operation == q->message.operation) &&
            (qe->message.luid == q->message.luid)) {

            if ((q->message.operation == BSOP_READBLOCK) &&
                ((q->message.flags & BSOP_FLAG_ERROR) == 0)) {
                q->block = qe->block;
                qe->block = NULL;
            }
            q->length = qe->length;
            q->message.flags = qe->message.flags;
            q->message.id = qe->message.id;
            q->status |= BSQ_STATUS_MATCHED;

            if (q->prev)
                q->prev->next = q->next;
            else 
                bs_head = q->next;
            if (q->next)
                q->next->prev = q->prev;
            else
                bs_tail = q->prev;
            q->next = NULL;
            q->prev = NULL;
            bs_qlen--;
            goto found;
        }
    }

    LEAVE_QUEUE_CR;
#ifdef BSDEBUG
    queuedebug("queuesearch not found");
#endif
    return NULL;

    found:
    LEAVE_QUEUE_CR;
#ifdef BSDEBUG
    queuedebug("queuesearch found");
#endif
    return q;
}

/*****************************************************************************
 * Network communication                                                     *
 *****************************************************************************/

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

    qe->message.luid = new_luid();

    qe->status = 0;
    qe->tid = (int)pthread_getspecific(tid_key);
    if (enqueue(qe) < 0) {
        fprintf(stderr, "Error enqueuing request.\n");
        return -1;
    }

    gettimeofday(&(qe->tv_sent), NULL);
    DB("send_message to %d luid=%016llx\n", qe->server, qe->message.luid);
    rc = sendmsg(bssock, &(qe->msghdr), MSG_DONTWAIT);
    //rc = sendto(bssock, (void *)&(qe->message), qe->length, 0,
    //           (struct sockaddr *)&(bsservers[qe->server].sin),
    //           sizeof(struct sockaddr_in));
    if (rc < 0)
        return rc;

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

int get_server_number(struct sockaddr_in *sin) {
    int i;

#ifdef BSDEBUG2
    fprintf(stderr,
            "get_server_number(%u.%u.%u.%u/%u)\n",
            (unsigned int)sin->sin_addr.s_addr & 0xff,
            ((unsigned int)sin->sin_addr.s_addr >> 8) & 0xff,
            ((unsigned int)sin->sin_addr.s_addr >> 16) & 0xff,
            ((unsigned int)sin->sin_addr.s_addr >> 24) & 0xff,
            (unsigned int)sin->sin_port);
#endif

    for (i = 0; i < MAX_SERVERS; i++) {
        if (bsservers[i].hostname) {
#ifdef BSDEBUG2
            fprintf(stderr,
                    "get_server_number check %u.%u.%u.%u/%u\n",
                    (unsigned int)bsservers[i].sin.sin_addr.s_addr&0xff,
                    ((unsigned int)bsservers[i].sin.sin_addr.s_addr >> 8)&0xff,
                    ((unsigned int)bsservers[i].sin.sin_addr.s_addr >> 16)&0xff,
                    ((unsigned int)bsservers[i].sin.sin_addr.s_addr >> 24)&0xff,
                    (unsigned int)bsservers[i].sin.sin_port);
#endif
            if ((sin->sin_family == bsservers[i].sin.sin_family) &&
                (sin->sin_port == bsservers[i].sin.sin_port) &&
                (memcmp((void *)&(sin->sin_addr),
                        (void *)&(bsservers[i].sin.sin_addr),
                        sizeof(struct in_addr)) == 0)) {
                return i;
            }
        }        
    }

    return -1;
}

void *rx_buffer = NULL;
bsq_t rx_qe;
bsq_t *recv_any(void) {
    struct sockaddr_in from;
    int rc;
    
    DB("ENTER recv_any\n");

    rx_qe.msghdr.msg_name = &from;
    rx_qe.msghdr.msg_namelen = sizeof(struct sockaddr_in);
    rx_qe.msghdr.msg_iov = rx_qe.iov;
    if (!rx_buffer) {
        rx_buffer = malloc(BLOCK_SIZE);
        if (!rx_buffer) {
            perror("recv_any malloc");
            return NULL;
        }
    }
    rx_qe.block = rx_buffer;
    rx_buffer = NULL;
    rx_qe.msghdr.msg_iovlen = 2;
    rx_qe.msghdr.msg_control = NULL;
    rx_qe.msghdr.msg_controllen = 0;
    rx_qe.msghdr.msg_flags = 0;
    
    rx_qe.iov[0].iov_base = (void *)&(rx_qe.message);
    rx_qe.iov[0].iov_len = MSGBUFSIZE_ID;
    rx_qe.iov[1].iov_base = rx_qe.block;
    rx_qe.iov[1].iov_len = BLOCK_SIZE;

    rc = recvmsg(bssock, &(rx_qe.msghdr), 0);
    if (rc < 0) {
        perror("recv_any");
        return NULL;
    }

    rx_qe.length = rc;    
    rx_qe.server = get_server_number(&from);

    DB("recv_any from %d luid=%016llx len=%u\n",
       rx_qe.server, rx_qe.message.luid, rx_qe.length);

    return &rx_qe;
}

void recv_recycle_buffer(bsq_t *q) {
    if (q->block) {
        rx_buffer = q->block;
        q->block = NULL;
    }
}

// cycle through reading any incoming, searching for a match in the
// queue, until we have all we need.
int wait_recv(bsq_t **reqs, int numreqs) {
    bsq_t *q, *m;
    unsigned int x, i;
    int tid = (int)pthread_getspecific(tid_key);

    DB("ENTER wait_recv %u\n", numreqs);

    checkmatch:
    x = 0xffffffff;
    for (i = 0; i < numreqs; i++) {
        x &= reqs[i]->status;
    }
    if ((x & BSQ_STATUS_MATCHED)) {
        DB("LEAVE wait_recv\n");
        return numreqs;
    }

    RECV_AWAIT(tid);

    /*
    rxagain:
    ENTER_RECV_CR;
    q = recv_any();
    LEAVE_RECV_CR;
    if (!q)
        return -1;

    m = queuesearch(q);
    recv_recycle_buffer(q);
    if (!m) {
        fprintf(stderr, "Unmatched RX\n");
        goto rxagain;
    }
    */

    goto checkmatch;

}

/* retry
 */
static int retry_count = 0;
int retry(bsq_t *qe)
{
    int rc;
    gettimeofday(&(qe->tv_sent), NULL);
    DB("retry to %d luid=%016llx\n", qe->server, qe->message.luid);
    retry_count++;
    rc = sendmsg(bssock, &(qe->msghdr), MSG_DONTWAIT);
    if (rc < 0)
        return rc;
    return 0;
}

/* queue runner
 */
void *queue_runner(void *arg)
{
    for (;;) {
        struct timeval now;
        long long nowus, sus;
        bsq_t *q;
        int r;

        sleep(1);

        gettimeofday(&now, NULL);
        nowus = now.tv_usec + now.tv_sec * 1000000;
        ENTER_QUEUE_CR;
        r = retry_count;
        for (q = bs_head; q; q = q->next) {
            sus = q->tv_sent.tv_usec + q->tv_sent.tv_sec * 1000000;
            if ((nowus - sus) > RETRY_TIMEOUT) {
                if (retry(q) < 0) {
                    fprintf(stderr, "Error on sendmsg retry.\n");
                }
            }
        }
        if (r != retry_count) {
            fprintf(stderr, "RETRIES: %u %u\n", retry_count - r, retry_count);
        }
        LEAVE_QUEUE_CR;
    }
}

/* receive loop
 */
void *receive_loop(void *arg)
{
    bsq_t *q, *m;

    for(;;) {
        q = recv_any();
        if (!q) {
            fprintf(stderr, "recv_any error\n");
        }
        else {
            m = queuesearch(q);
            recv_recycle_buffer(q);
            if (!m) {
                fprintf(stderr, "Unmatched RX\n");
            }
            else {
                DB("RX MATCH");
                RECV_NOTIFY(m->tid);
            }
        }
    }
}
pthread_t pthread_recv;

/*****************************************************************************
 * Reading                                                                   *
 *****************************************************************************/

void *readblock_indiv(int server, uint64_t id) {
    void *block;
    bsq_t *qe;
    int len, rc;

    qe = (bsq_t *)malloc(sizeof(bsq_t));
    if (!qe) {
        perror("readblock qe malloc");
        return NULL;
    }
    qe->block = NULL;
    
    /*
    qe->block = malloc(BLOCK_SIZE);
    if (!qe->block) {
        perror("readblock qe malloc");
        free((void *)qe);
        return NULL;
    }
    */

    qe->server = server;

    qe->message.operation = BSOP_READBLOCK;
    qe->message.flags = 0;
    qe->message.id = id;
    qe->length = MSGBUFSIZE_ID;

    if (send_message(qe) < 0) {
        perror("readblock sendto");
        goto err;
    }
    
    /*len = recv_message(qe);
    if (len < 0) {
        perror("readblock recv");
        goto err;
    }*/

    rc = wait_recv(&qe, 1);
    if (rc < 0) {
        perror("readblock recv");
        goto err;
    }

    if ((qe->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "readblock server error\n");
        goto err;
    }
    if (qe->length < MSGBUFSIZE_BLOCK) {
        fprintf(stderr, "readblock recv short (%u)\n", len);
        goto err;
    }
    /* if ((block = malloc(BLOCK_SIZE)) == NULL) {
        perror("readblock malloc");
        goto err;
    }
    memcpy(block, qe->message.block, BLOCK_SIZE);
    */    
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
void *readblock(uint64_t id) {
    int map = (int)BSID_MAP(id);
    uint64_t xid;
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

/*****************************************************************************
 * Writing                                                                   *
 *****************************************************************************/

bsq_t *writeblock_indiv(int server, uint64_t id, void *block) {

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

    return qe;

    err:
    free((void *)qe);
    return NULL;
}
    

/**
 * writeblock: write an existing block to disk
 *   @id: block id
 *   @block: pointer to block
 *
 *   @return: zero on success, -1 on failure
 */
int writeblock(uint64_t id, void *block) {
    
    int map = (int)BSID_MAP(id);
    int rep0 = bsclusters[map].servers[0];
    int rep1 = bsclusters[map].servers[1];
    int rep2 = bsclusters[map].servers[2];
    bsq_t *reqs[3];
    int rc;

    reqs[0] = reqs[1] = reqs[2] = NULL;

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
        reqs[0] = writeblock_indiv(rep0, id, block);
        if (!reqs[0])
            return -1;
        rc = wait_recv(reqs, 1);
        return rc;
    }

    reqs[0] = writeblock_indiv(rep0, BSID_REPLICA0(id), block);
    if (!reqs[0])
        goto err;
    reqs[1] = writeblock_indiv(rep1, BSID_REPLICA1(id), block);
    if (!reqs[1])
        goto err;
    reqs[2] = writeblock_indiv(rep2, BSID_REPLICA2(id), block);
    if (!reqs[2])
        goto err;

    rc = wait_recv(reqs, 3);
    if (rc < 0) {
        perror("writeblock recv");
        goto err;
    }
    if ((reqs[0]->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "writeblock server0 error\n");
        goto err;
    }
    if ((reqs[1]->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "writeblock server1 error\n");
        goto err;
    }
    if ((reqs[2]->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "writeblock server2 error\n");
        goto err;
    }


    free((void *)reqs[0]);
    free((void *)reqs[1]);
    free((void *)reqs[2]);
    return 0;

    err:
    if (reqs[0]) {
        dequeue(reqs[0]);
        free((void *)reqs[0]);
    }
    if (reqs[1]) {
        dequeue(reqs[1]);
        free((void *)reqs[1]);
    }
    if (reqs[2]) {
        dequeue(reqs[2]);
        free((void *)reqs[2]);
    }
    return -1;
}

/*****************************************************************************
 * Allocation                                                                *
 *****************************************************************************/

/**
 * allocblock: write a new block to disk
 *   @block: pointer to block
 *
 *   @return: new id of block on disk
 */
uint64_t allocblock(void *block) {
    return allocblock_hint(block, 0);
}

bsq_t *allocblock_hint_indiv(int server, void *block, uint64_t hint) {
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
    
    return qe;

    err:
    free((void *)qe);
    return NULL;
}

/**
 * allocblock_hint: write a new block to disk
 *   @block: pointer to block
 *   @hint: allocation hint
 *
 *   @return: new id of block on disk
 */
uint64_t allocblock_hint(void *block, uint64_t hint) {
    int map = (int)hint;
    int rep0 = bsclusters[map].servers[0];
    int rep1 = bsclusters[map].servers[1];
    int rep2 = bsclusters[map].servers[2];
    bsq_t *reqs[3];
    int rc;
    uint64_t id0, id1, id2;

    reqs[0] = reqs[1] = reqs[2] = NULL;

    DB("ENTER allocblock\n");

    reqs[0] = allocblock_hint_indiv(rep0, block, hint);
    if (!reqs[0])
        goto err;
    reqs[1] = allocblock_hint_indiv(rep1, block, hint);
    if (!reqs[1])
        goto err;
    reqs[2] = allocblock_hint_indiv(rep2, block, hint);
    if (!reqs[2])
        goto err;

    rc = wait_recv(reqs, 3);
    if (rc < 0) {
        perror("allocblock recv");
        goto err;
    }
    if ((reqs[0]->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "allocblock server0 error\n");
        goto err;
    }
    if ((reqs[1]->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "allocblock server1 error\n");
        goto err;
    }
    if ((reqs[2]->message.flags & BSOP_FLAG_ERROR)) {
        fprintf(stderr, "allocblock server2 error\n");
        goto err;
    }

    id0 = reqs[0]->message.id;
    id1 = reqs[1]->message.id;
    id2 = reqs[2]->message.id;

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
    
    free((void *)reqs[0]);
    free((void *)reqs[1]);
    free((void *)reqs[2]);
    return BSID(map, id0, id1, id2);

    err:
    if (reqs[0]) {
        dequeue(reqs[0]);
        free((void *)reqs[0]);
    }
    if (reqs[1]) {
        dequeue(reqs[1]);
        free((void *)reqs[1]);
    }
    if (reqs[2]) {
        dequeue(reqs[2]);
        free((void *)reqs[2]);
    }
    return 0;
}

#else /* /BLOCKSTORE_REMOTE */

/*****************************************************************************
 * Local storage version                                                     *
 *****************************************************************************/
 
/**
 * readblock: read a block from disk
 *   @id: block id to read
 *
 *   @return: pointer to block, NULL on error
 */

void *readblock(uint64_t id) {
    void *block;
    int block_fp;
   
//printf("readblock(%llu)\n", id); 
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
int writeblock(uint64_t id, void *block) {
    
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

uint64_t allocblock(void *block) {
    uint64_t lb;
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
uint64_t allocblock_hint(void *block, uint64_t hint) {
    return allocblock(block);
}

#endif /* BLOCKSTORE_REMOTE */

/*****************************************************************************
 * Memory management                                                         *
 *****************************************************************************/

/**
 * newblock: get a new in-memory block set to zeros
 *
 *   @return: pointer to new block, NULL on error
 */
void *newblock(void) {
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

void releaseblock(uint64_t id)
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
    uint64_t total = 0, next;
    
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

/*****************************************************************************
 * Initialisation                                                            *
 *****************************************************************************/

int __init_blockstore(void)
{
    int i;
    blockstore_super_t *bs_super;
    uint64_t ret;
    int block_fp;
    
#ifdef BLOCKSTORE_REMOTE
    struct hostent *addr;

    pthread_mutex_init(&ptmutex_queue, NULL);
    pthread_mutex_init(&ptmutex_luid, NULL);
    pthread_mutex_init(&ptmutex_recv, NULL);
    /*pthread_mutex_init(&ptmutex_notify, NULL);*/
    for (i = 0; i <= READ_POOL_SIZE; i++) {
        pool_thread[i].newdata = 0;
        pthread_mutex_init(&(pool_thread[i].ptmutex), NULL);
        pthread_cond_init(&(pool_thread[i].ptcv), NULL);
    }

    bsservers[0].hostname = "firebug.cl.cam.ac.uk";
    bsservers[1].hostname = "planb.cl.cam.ac.uk";
    bsservers[2].hostname = "simcity.cl.cam.ac.uk";
    bsservers[3].hostname = NULL/*"gunfighter.cl.cam.ac.uk"*/;
    bsservers[4].hostname = NULL/*"galaxian.cl.cam.ac.uk"*/;
    bsservers[5].hostname = NULL/*"firetrack.cl.cam.ac.uk"*/;
    bsservers[6].hostname = NULL/*"funfair.cl.cam.ac.uk"*/;
    bsservers[7].hostname = NULL/*"felix.cl.cam.ac.uk"*/;
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

    pthread_create(&pthread_recv, NULL, receive_loop, NULL);
    pthread_create(&pthread_recv, NULL, queue_runner, NULL);

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

void __exit_blockstore(void)
{
    int i;
#ifdef BLOCKSTORE_REMOTE
    pthread_mutex_destroy(&ptmutex_recv);
    pthread_mutex_destroy(&ptmutex_luid);
    pthread_mutex_destroy(&ptmutex_queue);
    /*pthread_mutex_destroy(&ptmutex_notify);
      pthread_cond_destroy(&ptcv_notify);*/
    for (i = 0; i <= READ_POOL_SIZE; i++) {
        pthread_mutex_destroy(&(pool_thread[i].ptmutex));
        pthread_cond_destroy(&(pool_thread[i].ptcv));
    }
#endif
}
