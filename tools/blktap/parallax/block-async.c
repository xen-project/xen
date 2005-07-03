/* block-async.c
 * 
 * Asynchronous block wrappers for parallax.
 */
 
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "block-async.h"
#include "blockstore.h"
#include "vdi.h"


#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

/* We have a queue of outstanding I/O requests implemented as a 
 * circular producer-consumer ring with free-running buffers.
 * to allow reordering, this ring indirects to indexes in an 
 * ring of io_structs.
 * 
 * the block_* calls may either add an entry to this ring and return, 
 * or satisfy the request immediately and call the callback directly.
 * None of the io calls in parallax should be nested enough to worry 
 * about stack problems with this approach.
 */

struct read_args {
    u64 addr;
};

struct write_args {
    u64   addr;
    char *block;
};

struct alloc_args {
    char *block;
};
 
struct pending_io_req {
    enum {IO_READ, IO_WRITE, IO_ALLOC, IO_RWAKE, IO_WWAKE} op;
    union {
        struct read_args  r;
        struct write_args w;
        struct alloc_args a;
    } u;
    io_cb_t cb;
    void *param;
};

void radix_lock_init(struct radix_lock *r)
{
    int i;
    
    pthread_mutex_init(&r->lock, NULL);
    for (i=0; i < 1024; i++) {
        r->lines[i] = 0;
        r->waiters[i] = NULL;
        r->state[i] = ANY;
    }
}

/* maximum outstanding I/O requests issued asynchronously */
/* must be a power of 2.*/
#define MAX_PENDING_IO 1024

/* how many threads to concurrently issue I/O to the disk. */
#define IO_POOL_SIZE   10

static struct pending_io_req pending_io_reqs[MAX_PENDING_IO];
static int pending_io_list[MAX_PENDING_IO];
static unsigned long io_prod = 0, io_cons = 0, io_free = 0;
#define PENDING_IO_MASK(_x) ((_x) & (MAX_PENDING_IO - 1))
#define PENDING_IO_IDX(_x) ((_x) - pending_io_reqs)
#define PENDING_IO_ENT(_x) \
	(&pending_io_reqs[pending_io_list[PENDING_IO_MASK(_x)]])
#define CAN_PRODUCE_PENDING_IO ((io_free + MAX_PENDING_IO) != io_prod)
#define CAN_CONSUME_PENDING_IO (io_cons != io_prod)
static pthread_mutex_t pending_io_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  pending_io_cond = PTHREAD_COND_INITIALIZER;

static void init_pending_io(void)
{
    int i;
	
    for (i=0; i<MAX_PENDING_IO; i++)
        pending_io_list[i] = i;
		
} 

void block_read(u64 addr, io_cb_t cb, void *param)
{
    struct pending_io_req *req;
    
    pthread_mutex_lock(&pending_io_lock);
    assert(CAN_PRODUCE_PENDING_IO);
    
    req = PENDING_IO_ENT(io_prod++);
    DPRINTF("Produce (R) %lu (%p)\n", io_prod - 1, req);
    req->op = IO_READ;
    req->u.r.addr = addr;
    req->cb = cb;
    req->param = param;
    
    pthread_cond_signal(&pending_io_cond);
    pthread_mutex_unlock(&pending_io_lock);	
}


void block_write(u64 addr, char *block, io_cb_t cb, void *param)
{
    struct pending_io_req *req;
    
    pthread_mutex_lock(&pending_io_lock);
    assert(CAN_PRODUCE_PENDING_IO);
    
    req = PENDING_IO_ENT(io_prod++);
    DPRINTF("Produce (W) %lu (%p)\n", io_prod - 1, req);
    req->op = IO_WRITE;
    req->u.w.addr  = addr;
    req->u.w.block = block;
    req->cb = cb;
    req->param = param;
    
    pthread_cond_signal(&pending_io_cond);
    pthread_mutex_unlock(&pending_io_lock);	
}


void block_alloc(char *block, io_cb_t cb, void *param)
{
    struct pending_io_req *req;
	
    pthread_mutex_lock(&pending_io_lock);
    assert(CAN_PRODUCE_PENDING_IO);
    
    req = PENDING_IO_ENT(io_prod++);
    req->op = IO_ALLOC;
    req->u.a.block = block;
    req->cb = cb;
    req->param = param;
    
    pthread_cond_signal(&pending_io_cond);
    pthread_mutex_unlock(&pending_io_lock);	
}

void block_rlock(struct radix_lock *r, int row, io_cb_t cb, void *param)
{
    struct io_ret ret;
    pthread_mutex_lock(&r->lock);
    
    if (( r->lines[row] >= 0 ) && (r->state[row] != STOP)) {
        r->lines[row]++;
        r->state[row] = READ;
        DPRINTF("RLOCK  : %3d (row: %d)\n", r->lines[row], row);
        pthread_mutex_unlock(&r->lock);
        ret.type = IO_INT_T;
        ret.u.i = 0;
        cb(ret, param);
    } else {
        struct radix_wait **rwc;
        struct radix_wait *rw = 
            (struct radix_wait *) malloc (sizeof(struct radix_wait));
        DPRINTF("RLOCK  : %3d (row: %d) -- DEFERRED!\n", r->lines[row], row);
        rw->type  = RLOCK;
        rw->param = param;
        rw->cb    = cb;
        rw->next  = NULL;
        /* append to waiters list. */
        rwc = &r->waiters[row];
        while (*rwc != NULL) rwc = &(*rwc)->next;
        *rwc = rw;
        pthread_mutex_unlock(&r->lock);
        return;
    }
}


void block_wlock(struct radix_lock *r, int row, io_cb_t cb, void *param)
{
    struct io_ret ret;
    pthread_mutex_lock(&r->lock);
    
    /* the second check here is redundant -- just here for debugging now. */
    if ((r->state[row] == ANY) && ( r->lines[row] == 0 )) {
        r->state[row] = STOP;
        r->lines[row] = -1;
        DPRINTF("WLOCK  : %3d (row: %d)\n", r->lines[row], row);
        pthread_mutex_unlock(&r->lock);
        ret.type = IO_INT_T;
        ret.u.i = 0;
        cb(ret, param);
    } else {
        struct radix_wait **rwc;
        struct radix_wait *rw = 
            (struct radix_wait *) malloc (sizeof(struct radix_wait));
        DPRINTF("WLOCK  : %3d (row: %d) -- DEFERRED!\n", r->lines[row], row);
        rw->type  = WLOCK;
        rw->param = param;
        rw->cb    = cb;
        rw->next  = NULL;
        /* append to waiters list. */
        rwc = &r->waiters[row];
        while (*rwc != NULL) rwc = &(*rwc)->next;
        *rwc = rw;
        pthread_mutex_unlock(&r->lock);
        return;
    }
	
}

/* called with radix_lock locked and lock count of zero. */
static void wake_waiters(struct radix_lock *r, int row)
{
    struct pending_io_req *req;
    struct radix_wait *rw;
    
    if (r->lines[row] != 0) return;
    if (r->waiters[row] == NULL) return; 
    
    if (r->waiters[row]->type == WLOCK) {

        rw = r->waiters[row];
        pthread_mutex_lock(&pending_io_lock);
        assert(CAN_PRODUCE_PENDING_IO);
        
        req = PENDING_IO_ENT(io_prod++);
        req->op    = IO_WWAKE;
        req->cb    = rw->cb;
        req->param = rw->param;
        r->lines[row] = -1; /* write lock the row. */
        r->state[row] = STOP;
        r->waiters[row] = rw->next;
        free(rw);
        pthread_mutex_unlock(&pending_io_lock);
    
    } else /* RLOCK */ {

        while ((r->waiters[row] != NULL) && (r->waiters[row]->type == RLOCK)) {
            rw = r->waiters[row];
            pthread_mutex_lock(&pending_io_lock);
            assert(CAN_PRODUCE_PENDING_IO);
            
            req = PENDING_IO_ENT(io_prod++);
            req->op    = IO_RWAKE;
            req->cb    = rw->cb;
            req->param = rw->param;
            r->lines[row]++; /* read lock the row. */
            r->state[row] = READ; 
            r->waiters[row] = rw->next;
            free(rw);
            pthread_mutex_unlock(&pending_io_lock);
        }

        if (r->waiters[row] != NULL) /* There is a write queued still */
            r->state[row] = STOP;
    }	
    
    pthread_mutex_lock(&pending_io_lock);
    pthread_cond_signal(&pending_io_cond);
    pthread_mutex_unlock(&pending_io_lock);
}

void block_runlock(struct radix_lock *r, int row, io_cb_t cb, void *param)
{
    struct io_ret ret;
	
    pthread_mutex_lock(&r->lock);
    assert(r->lines[row] > 0); /* try to catch misuse. */
    r->lines[row]--;
    if (r->lines[row] == 0) {
        r->state[row] = ANY;
        wake_waiters(r, row);
    }
    pthread_mutex_unlock(&r->lock);
    cb(ret, param);
}

void block_wunlock(struct radix_lock *r, int row, io_cb_t cb, void *param)
{
    struct io_ret ret;
    
    pthread_mutex_lock(&r->lock);
    assert(r->lines[row] == -1); /* try to catch misuse. */
    r->lines[row] = 0;
    r->state[row] = ANY;
    wake_waiters(r, row);
    pthread_mutex_unlock(&r->lock);
    cb(ret, param);
}

/* consumer calls */
static void do_next_io_req(struct pending_io_req *req)
{
    struct io_ret          ret;
    void  *param;
    
    switch (req->op) {
    case IO_READ:
        ret.type = IO_BLOCK_T;
        ret.u.b  = readblock(req->u.r.addr);
        break;
    case IO_WRITE:
        ret.type = IO_INT_T;
        ret.u.i  = writeblock(req->u.w.addr, req->u.w.block);
        DPRINTF("wrote %d at %Lu\n", *(int *)(req->u.w.block), req->u.w.addr);
        break;
    case IO_ALLOC:
        ret.type = IO_ADDR_T;
        ret.u.a  = allocblock(req->u.a.block);
        break;
    case IO_RWAKE:
        DPRINTF("WAKE DEFERRED RLOCK!\n");
        ret.type = IO_INT_T;
        ret.u.i  = 0;
        break;
    case IO_WWAKE:
        DPRINTF("WAKE DEFERRED WLOCK!\n");
        ret.type = IO_INT_T;
        ret.u.i  = 0;
        break;
    default:
        DPRINTF("Unknown IO operation on pending list!\n");
        return;
    }
    
    param = req->param;
    pthread_mutex_lock(&pending_io_lock);
    pending_io_list[PENDING_IO_MASK(io_free++)] = PENDING_IO_IDX(req);
    pthread_mutex_unlock(&pending_io_lock);
	
    assert(req->cb != NULL);
    req->cb(ret, param);
    
}

void *io_thread(void *param) 
{
    int tid;
    struct pending_io_req *req;
    
    /* Set this thread's tid. */
    tid = *(int *)param;
    free(param);
    
start:
    pthread_mutex_lock(&pending_io_lock);
    while (io_prod == io_cons) {
        pthread_cond_wait(&pending_io_cond, &pending_io_lock);
    }
    
    if (io_prod == io_cons) {
        /* unnecessary wakeup. */
        pthread_mutex_unlock(&pending_io_lock);
        goto start;
    }
    
    req = PENDING_IO_ENT(io_cons++);
    pthread_mutex_unlock(&pending_io_lock);
	
    do_next_io_req(req);
    
    goto start;
	
}

static pthread_t io_pool[IO_POOL_SIZE];
void start_io_threads(void)

{	
    int i, tid=0;
    
    for (i=0; i < IO_POOL_SIZE; i++) {
        int ret, *t;
        t = (int *)malloc(sizeof(int));
        *t = tid++;
        ret = pthread_create(&io_pool[i], NULL, io_thread, t);
        if (ret != 0) printf("Error starting thread %d\n", i);
    }
	
}

void init_block_async(void)
{
    init_pending_io();
    start_io_threads();
}
