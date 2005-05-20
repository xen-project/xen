/* block-async.h
 * 
 * Asynchronous block wrappers for parallax.
 */
 
#ifndef _BLOCKASYNC_H_
#define _BLOCKASYNC_H_

#include <assert.h>
#include <xc.h>
#include "vdi.h"

struct io_ret
{
	enum {IO_ADDR_T, IO_BLOCK_T, IO_INT_T} type;
	union {
		u64   a;
		char *b;
		int   i;
	} u;
};

typedef void (*io_cb_t)(struct io_ret r, void *param);

/* per-vdi lock structures to make sure requests run in a safe order. */
struct radix_wait {
	enum {RLOCK, WLOCK} type;
	io_cb_t  cb;
	void    *param;
	struct radix_wait *next;
};

struct radix_lock {
	pthread_mutex_t lock;
	int                    lines[1024];
	struct radix_wait     *waiters[1024];
	enum {ANY, READ, STOP} state[1024];
};
void radix_lock_init(struct radix_lock *r);

void block_read(u64 addr, io_cb_t cb, void *param);
void block_write(u64 addr, char *block, io_cb_t cb, void *param);
void block_alloc(char *block, io_cb_t cb, void *param);
void block_rlock(struct radix_lock *r, int row, io_cb_t cb, void *param);
void block_wlock(struct radix_lock *r, int row, io_cb_t cb, void *param);
void block_runlock(struct radix_lock *r, int row, io_cb_t cb, void *param);
void block_wunlock(struct radix_lock *r, int row, io_cb_t cb, void *param);
void init_block_async(void);

static inline u64 IO_ADDR(struct io_ret r)
{
	assert(r.type == IO_ADDR_T);
	return r.u.a;
}

static inline char *IO_BLOCK(struct io_ret r)
{
	assert(r.type == IO_BLOCK_T);
	return r.u.b;
}

static inline int IO_INT(struct io_ret r)
{
	assert(r.type == IO_INT_T);
	return r.u.i;
}


#endif //_BLOCKASYNC_H_
