/* blktaplib.h
 *
 * userland accessors to the block tap.
 *
 * for the moment this is rather simple.
 */
 
#ifndef __BLKTAPLIB_H__
#define __BLKTAPLIB_H__

#include <stdint.h>

typedef uint8_t            u8;
typedef uint16_t           u16;
typedef uint32_t           u32;
typedef uint64_t           u64;
typedef int8_t             s8;
typedef int16_t            s16;
typedef int32_t            s32;
typedef int64_t            s64;
                                                                                
#if defined(__i386__)
#define rmb() __asm__ __volatile__ ( "lock; addl $0,0(%%esp)" : : : "memory" )
#define wmb() __asm__ __volatile__ ( "" : : : "memory" )
#else
#error "Define barriers"
#endif
    
#include <sys/user.h>
#include <xen/xen.h>
#include <xen/io/blkif.h>
#include <xen/io/ring.h>
#include <xen/io/domain_controller.h>
#include "blkint.h"

#define BLKTAP_PASS     0 /* Keep passing this request as normal. */
#define BLKTAP_RESPOND  1 /* Request is now a reply.  Return it.  */
#define BLKTAP_STOLEN   2 /* Hook has stolen request.             */

#define domid_t unsigned short

inline unsigned int ID_TO_IDX(unsigned long id);
inline domid_t ID_TO_DOM(unsigned long id);

void blktap_register_ctrl_hook(char *name, int (*ch)(control_msg_t *));
void blktap_register_request_hook(char *name, int (*rh)(blkif_request_t *));
void blktap_register_response_hook(char *name, int (*rh)(blkif_response_t *));
void blktap_inject_response(blkif_response_t *);
int  blktap_attach_poll(int fd, short events, int (*func)(int));
void blktap_detach_poll(int fd);
int  blktap_listen(void);

/*-----[ Accessing attached data page mappings ]-------------------------*/
#define MMAP_PAGES_PER_REQUEST \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST + 1)
#define MMAP_VADDR(_req,_seg)                        \
    (mmap_vstart +                                   \
     ((_req) * MMAP_PAGES_PER_REQUEST * PAGE_SIZE) + \
     ((_seg) * PAGE_SIZE))

extern unsigned long mmap_vstart;


/*-----[ Defines that are only used by library clients ]-----------------*/

#ifndef __COMPILING_BLKTAP_LIB

static char *blkif_op_name[] = {
    [BLKIF_OP_READ]       = "READ",
    [BLKIF_OP_WRITE]      = "WRITE",
    [BLKIF_OP_PROBE]      = "PROBE",
};

#endif /* __COMPILING_BLKTAP_LIB */
    
#endif /* __BLKTAPLIB_H__ */
