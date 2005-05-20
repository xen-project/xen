#ifndef _REQUESTSASYNC_H_
#define _REQUESTSASYNC_H_

#include "block-async.h"
#include "blockstore.h" /* for newblock etc. */

/*
#define BLOCK_SIZE 4096
#define ZERO 0ULL
#define getid(x) (((x)>>1)&0x7fffffffffffffffLLU)
#define iswritable(x) (((x) & 1LLU) != 0)
#define writable(x) (((x) << 1) | 1LLU)
#define readonly(x) ((u64)((x) << 1))
*/

int async_read (vdi_t *vdi, u64 vaddr, io_cb_t cb, void *param);
int async_write(vdi_t *vdi, u64 vaddr, char *block, io_cb_t cb, void *param);
             
#endif //_REQUESTSASYNC_H_
