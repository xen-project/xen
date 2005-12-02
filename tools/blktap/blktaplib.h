/* blktaplib.h
 *
 * userland accessors to the block tap.
 *
 * Sept 2/05 -- I'm scaling this back to only support block remappings
 * to user in a backend domain.  Passthrough and interposition can be readded
 * once transitive grants are available.
 */
 
#ifndef __BLKTAPLIB_H__
#define __BLKTAPLIB_H__

#include <xenctrl.h>
#include <sys/user.h>
#include <xen/xen.h>
#include <xen/io/blkif.h>
#include <xen/io/ring.h>
#include <xen/io/domain_controller.h>
#include <xs.h>

#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

/* /dev/xen/blktap resides at device number major=10, minor=202        */ 
#define BLKTAP_MINOR 202

/* size of the extra VMA area to map in attached pages. */
#define BLKTAP_VMA_PAGES BLK_RING_SIZE

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
        ( arg == BLKTAP_MODE_INTERPOSE    ) );
/*
    return (
        ( arg == BLKTAP_MODE_PASSTHROUGH  ) ||
        ( arg == BLKTAP_MODE_INTERCEPT_FE ) ||
        ( arg == BLKTAP_MODE_INTERCEPT_BE ) ||
        ( arg == BLKTAP_MODE_INTERPOSE    ) ||
        ( (arg & ~BLKTAP_MODE_COPY_FE_PAGES) == BLKTAP_MODE_COPY_FE ) ||
        ( (arg & ~BLKTAP_MODE_COPY_BE_PAGES) == BLKTAP_MODE_COPY_BE ) ||
        ( (arg & ~BLKTAP_MODE_COPY_BOTH_PAGES) == BLKTAP_MODE_COPY_BOTH )
        );
*/
}

/* Return values for handling messages in hooks. */
#define BLKTAP_PASS     0 /* Keep passing this request as normal. */
#define BLKTAP_RESPOND  1 /* Request is now a reply.  Return it.  */
#define BLKTAP_STOLEN   2 /* Hook has stolen request.             */

//#define domid_t unsigned short

inline unsigned int ID_TO_IDX(unsigned long id);
inline domid_t ID_TO_DOM(unsigned long id);

int  blktap_attach_poll(int fd, short events, int (*func)(int));
void blktap_detach_poll(int fd);
int  blktap_listen(void);

struct blkif;

typedef struct request_hook_st {
    char *name;
    int (*func)(struct blkif *, blkif_request_t *, int);
    struct request_hook_st *next;
} request_hook_t;

typedef struct response_hook_st {
    char *name;
    int (*func)(struct blkif *, blkif_response_t *, int);
    struct response_hook_st *next;
} response_hook_t;

struct blkif_ops {
    long int (*get_size)(struct blkif *blkif);
    long int (*get_secsize)(struct blkif *blkif);
    unsigned (*get_info)(struct blkif *blkif);
};

typedef struct blkif {
    domid_t domid;
    long int handle;

    long int pdev;
    long int readonly;

    enum { DISCONNECTED, CONNECTED } state;

    struct blkif_ops *ops;
    request_hook_t *request_hook_chain;
    response_hook_t *response_hook_chain;

    struct blkif *hash_next;

    void *prv;  /* device-specific data */
} blkif_t;

void register_new_blkif_hook(int (*fn)(blkif_t *blkif));
blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle);
blkif_t *alloc_blkif(domid_t domid);
int blkif_init(blkif_t *blkif, long int handle, long int pdev, 
               long int readonly);
void free_blkif(blkif_t *blkif);
void __init_blkif(void);


/* xenstore/xenbus: */
extern int add_blockdevice_probe_watch(struct xs_handle *h, 
                                       const char *domname);
int xs_fire_next_watch(struct xs_handle *h);


void blkif_print_hooks(blkif_t *blkif);
void blkif_register_request_hook(blkif_t *blkif, char *name, 
                             int (*rh)(blkif_t *, blkif_request_t *, int));
void blkif_register_response_hook(blkif_t *blkif, char *name, 
                             int (*rh)(blkif_t *, blkif_response_t *, int));
void blkif_inject_response(blkif_t *blkif, blkif_response_t *);
void blktap_kick_responses(void);

/* this must match the underlying driver... */
#define MAX_PENDING_REQS 64

/* Accessing attached data page mappings */
#define MMAP_PAGES                                              \
    (MAX_PENDING_REQS * BLKIF_MAX_SEGMENTS_PER_REQUEST)
#define MMAP_VADDR(_req,_seg)                                   \
    (mmap_vstart +                                              \
     ((_req) * BLKIF_MAX_SEGMENTS_PER_REQUEST * PAGE_SIZE) +    \
     ((_seg) * PAGE_SIZE))

extern unsigned long mmap_vstart;

/* Defines that are only used by library clients */

#ifndef __COMPILING_BLKTAP_LIB

static char *blkif_op_name[] = {
    [BLKIF_OP_READ]       = "READ",
    [BLKIF_OP_WRITE]      = "WRITE",
};

#endif /* __COMPILING_BLKTAP_LIB */
    
#endif /* __BLKTAPLIB_H__ */
