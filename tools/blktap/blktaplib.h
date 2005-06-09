/* blktaplib.h
 *
 * userland accessors to the block tap.
 *
 */
 
#ifndef __BLKTAPLIB_H__
#define __BLKTAPLIB_H__

#include <xc.h>
#include <sys/user.h>
#include <xen/xen.h>
#include <xen/io/blkif.h>
#include <xen/io/ring.h>
#include <xen/io/domain_controller.h>

/* /dev/xen/blktap resides at device number major=10, minor=202        */ 
#define BLKTAP_MINOR 202

/* size of the extra VMA area to map in attached pages. */
#define BLKTAP_VMA_PAGES BLKIF_RING_SIZE

/* blktap IOCTLs:                                                      */
#define BLKTAP_IOCTL_KICK_FE         1
#define BLKTAP_IOCTL_KICK_BE         2
#define BLKTAP_IOCTL_SETMODE         3
#define BLKTAP_IOCTL_PRINT_IDXS      100   

/* blktap switching modes: (Set with BLKTAP_IOCTL_SETMODE)             */
#define BLKTAP_MODE_PASSTHROUGH      0x00000000  /* default            */
#define BLKTAP_MODE_INTERCEPT_FE     0x00000001
#define BLKTAP_MODE_INTERCEPT_BE     0x00000002
#define BLKTAP_MODE_COPY_FE          0x00000004
#define BLKTAP_MODE_COPY_BE          0x00000008
#define BLKTAP_MODE_COPY_FE_PAGES    0x00000010
#define BLKTAP_MODE_COPY_BE_PAGES    0x00000020

#define BLKTAP_MODE_INTERPOSE \
           (BLKTAP_MODE_INTERCEPT_FE | BLKTAP_MODE_INTERCEPT_BE)

#define BLKTAP_MODE_COPY_BOTH \
           (BLKTAP_MODE_COPY_FE | BLKTAP_MODE_COPY_BE)

#define BLKTAP_MODE_COPY_BOTH_PAGES \
           (BLKTAP_MODE_COPY_FE_PAGES | BLKTAP_MODE_COPY_BE_PAGES)

static inline int BLKTAP_MODE_VALID(unsigned long arg)
{
    return (
        ( arg == BLKTAP_MODE_PASSTHROUGH  ) ||
        ( arg == BLKTAP_MODE_INTERCEPT_FE ) ||
        ( arg == BLKTAP_MODE_INTERCEPT_BE ) ||
        ( arg == BLKTAP_MODE_INTERPOSE    ) ||
        ( (arg & ~BLKTAP_MODE_COPY_FE_PAGES) == BLKTAP_MODE_COPY_FE ) ||
        ( (arg & ~BLKTAP_MODE_COPY_BE_PAGES) == BLKTAP_MODE_COPY_BE ) ||
        ( (arg & ~BLKTAP_MODE_COPY_BOTH_PAGES) == BLKTAP_MODE_COPY_BOTH )
        );
}

/* Return values for handling messages in hooks. */
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

/* Accessing attached data page mappings */
#define MMAP_PAGES_PER_REQUEST \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST + 1)
#define MMAP_VADDR(_req,_seg)                        \
    (mmap_vstart +                                   \
     ((_req) * MMAP_PAGES_PER_REQUEST * PAGE_SIZE) + \
     ((_seg) * PAGE_SIZE))

extern unsigned long mmap_vstart;


/* Defines that are only used by library clients */

#ifndef __COMPILING_BLKTAP_LIB

static char *blkif_op_name[] = {
    [BLKIF_OP_READ]       = "READ",
    [BLKIF_OP_WRITE]      = "WRITE",
    [BLKIF_OP_PROBE]      = "PROBE",
};

#endif /* __COMPILING_BLKTAP_LIB */
    
#endif /* __BLKTAPLIB_H__ */
