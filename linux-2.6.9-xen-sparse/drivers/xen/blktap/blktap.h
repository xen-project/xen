/*
 * blktap.h
 * 
 * Interfaces for the Xen block tap driver.
 * 
 * (c) 2004, Andrew Warfield, University of Cambridge
 * 
 */

#ifndef __BLKTAP_H__
#define __BLKTAP_H__

#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/config.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <asm-xen/ctrl_if.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/pgalloc.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/io/blkif.h>

/* -------[ debug / pretty printing ]--------------------------------- */

#if 0
#define ASSERT(_p) \
    if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#define DPRINTK(_f, _a...) printk(KERN_ALERT "(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define ASSERT(_p) ((void)0)
#define DPRINTK(_f, _a...) ((void)0)
#endif

#define WPRINTK(fmt, args...) printk(KERN_WARNING "blk_tap: " fmt, ##args)

/* -------[ connection / request tracking ]--------------------------- */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define VMALLOC_VMADDR(x) ((unsigned long)(x))
#endif

extern spinlock_t blkif_io_lock;

typedef struct blkif_st {
    /* Unique identifier for this interface. */
    domid_t          domid;
    unsigned int     handle;
    /* Physical parameters of the comms window. */
    unsigned long    shmem_frame;
    unsigned int     evtchn;
    int              irq;
    /* Comms information. */
    blkif_ring_t    *blk_ring_base; /* ioremap()'ed ptr to shmem_frame. */
    BLKIF_RING_IDX     blk_req_cons;  /* Request consumer. */
    BLKIF_RING_IDX     blk_resp_prod; /* Private version of resp. producer. */
    
    enum { DISCONNECTED, DISCONNECTING, CONNECTED } status;
    /*
     * DISCONNECT response is deferred until pending requests are ack'ed.
     * We therefore need to store the id from the original request.
     */    u8               disconnect_rspid;
    struct blkif_st *hash_next;
    struct list_head blkdev_list;
    spinlock_t       blk_ring_lock;
    atomic_t         refcnt;
    
    struct work_struct work;
} blkif_t;

typedef struct {
    blkif_t       *blkif;
    unsigned long  id;
    int            nr_pages;
    unsigned long  mach_fas[BLKIF_MAX_SEGMENTS_PER_REQUEST];
    unsigned long  virt_fas[BLKIF_MAX_SEGMENTS_PER_REQUEST];
    int            next_free;
} active_req_t;


/* -------[ block ring structs ]-------------------------------------- */

/* Types of ring. */
#define BLKIF_REQ_RING_TYPE 1
#define BLKIF_RSP_RING_TYPE 2

/* generic ring struct. */
typedef struct blkif_generic_ring_struct {
    int type;
} blkif_generic_ring_t;

/* A requestor's view of a ring. */
typedef struct blkif_req_ring_struct {

    int type;                    /* Will be BLKIF_REQ_RING_TYPE        */
    BLKIF_RING_IDX req_prod;     /* PRIVATE req_prod index             */
    BLKIF_RING_IDX rsp_cons;     /* Response consumer index            */
    blkif_ring_t *ring;          /* Pointer to shared ring struct      */

} blkif_req_ring_t;

#define BLKIF_REQ_RING_INIT { BLKIF_REQ_RING_TYPE, 0, 0, 0 }

/* A responder's view of a ring. */
typedef struct blkif_rsp_ring_struct {

    int type;       
    BLKIF_RING_IDX rsp_prod;     /* PRIVATE rsp_prod index             */
    BLKIF_RING_IDX req_cons;     /* Request consumer index             */
    blkif_ring_t *ring;          /* Pointer to shared ring struct      */

} blkif_rsp_ring_t;

#define BLKIF_RSP_RING_INIT = { BLKIF_RSP_RING_TYPE, 0, 0, 0 }

#define RING(a) (blkif_generic_ring_t *)(a)

inline int BLKTAP_RING_FULL(blkif_generic_ring_t *ring);


/* -------[ interposition -> character device interface ]------------- */

/* /dev/xen/blktap resides at device number major=10, minor=200        */ 
#define BLKTAP_MINOR 202

/* size of the extra VMA area to map in attached pages. */
#define BLKTAP_VMA_PAGES BLKIF_RING_SIZE

/* blktap IOCTLs:                                                      */
#define BLKTAP_IOCTL_KICK_FE         1
#define BLKTAP_IOCTL_KICK_BE         2
#define BLKTAP_IOCTL_SETMODE         3

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



/* -------[ Mappings to User VMA ]------------------------------------ */
#define MAX_PENDING_REQS 64
#define BATCH_PER_DOMAIN 16
extern struct vm_area_struct *blktap_vma;

/* The following are from blkback.c and should probably be put in a
 * header and included from there.
 * The mmap area described here is where attached data pages eill be mapped.
 */
 
extern unsigned long mmap_vstart;
#define MMAP_PAGES_PER_REQUEST \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST + 1)
#define MMAP_PAGES             \
    (MAX_PENDING_REQS * MMAP_PAGES_PER_REQUEST)
#define MMAP_VADDR(_req,_seg)                        \
    (mmap_vstart +                                   \
     ((_req) * MMAP_PAGES_PER_REQUEST * PAGE_SIZE) + \
     ((_seg) * PAGE_SIZE))

/* immediately before the mmap area, we have a bunch of pages reserved
 * for shared memory rings.
 */

#define RING_PAGES 128 
extern unsigned long rings_vstart;

/* -------[ Here be globals ]----------------------------------------- */

extern unsigned long blktap_mode;


/* blkif struct, containing ring to FE domain */
extern blkif_t ptfe_blkif; 

/* Connection to a single backend domain. */
extern blkif_ring_t *blk_ptbe_ring;   /* Ring from the PT to the BE dom    */ 
extern BLKIF_RING_IDX ptbe_resp_cons; /* Response consumer for comms ring. */
extern BLKIF_RING_IDX ptbe_req_prod;  /* Private request producer.         */

/* Rings up to user space. */ 
extern blkif_req_ring_t fe_ring;// = BLKIF_REQ_RING_INIT;
extern blkif_rsp_ring_t be_ring;// = BLKIF_RSP_RING_INIT;

/* Event channel to backend domain. */
extern unsigned int blkif_ptbe_evtchn;

/* User ring status... this will soon vanish into a ring struct. */
extern unsigned long blktap_ring_ok;

/* -------[ ...and function prototypes. ]----------------------------- */

/* init function for character device interface.                       */
int blktap_init(void);

/* interfaces to the char driver, passing messages to and from apps.   */
void blktap_kick_user(void);
int blktap_write_to_ring(blkif_request_t *req);


/* user ring access functions: */
int blktap_write_fe_ring(blkif_request_t *req);
int blktap_write_be_ring(blkif_response_t *rsp);
int blktap_read_fe_ring(void);
int blktap_read_be_ring(void);

/* and the helpers they call: */
inline int write_resp_to_fe_ring(blkif_response_t *rsp);
inline void kick_fe_domain(void);

inline int write_req_to_be_ring(blkif_request_t *req);
inline void kick_be_domain(void);

/* Interrupt handlers. */
irqreturn_t blkif_ptbe_int(int irq, void *dev_id, 
                                  struct pt_regs *ptregs);
irqreturn_t blkif_ptfe_int(int irq, void *dev_id, struct pt_regs *regs);

/* Control message receiver. */
extern void blkif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id);

#define __BLKINT_H__
#endif
