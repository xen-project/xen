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

#define VADDR_MASK 0x0000000003ffffffLLU /* 26-bits = 256Gig */
#define VALID_VADDR(x) (((x) & VADDR_MASK) == (x))

int vdi_read (vdi_t *vdi, u64 vaddr, io_cb_t cb, void *param);
int vdi_write(vdi_t *vdi, u64 vaddr, char *block, io_cb_t cb, void *param);
             
/* synchronous versions: */
char *vdi_read_s (vdi_t *vdi, u64 vaddr);
int   vdi_write_s(vdi_t *vdi, u64 vaddr, char *block);

#define ERR_BAD_VADDR  -1
#define ERR_NOMEM      -2

#endif //_REQUESTSASYNC_H_
