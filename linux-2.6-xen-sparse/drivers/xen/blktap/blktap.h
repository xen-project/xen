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
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/pgalloc.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/io/blkif.h>
#include <asm-xen/xen-public/io/ring.h>

/* Used to signal to the backend that this is a tap domain. */
#define BLKTAP_COOKIE 0xbeadfeed

/* -------[ debug / pretty printing ]--------------------------------- */

#define PRINTK(_f, _a...) printk(KERN_ALERT "(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#if 0
#define DPRINTK(_f, _a...) printk(KERN_ALERT "(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

#if 1
#define ASSERT(_p) \
    if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif

#define WPRINTK(fmt, args...) printk(KERN_WARNING "blk_tap: " fmt, ##args)


/* -------[ state descriptors ]--------------------------------------- */

#define BLKIF_STATE_CLOSED       0
#define BLKIF_STATE_DISCONNECTED 1
#define BLKIF_STATE_CONNECTED    2

/* -------[ connection tracking ]------------------------------------- */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define VMALLOC_VMADDR(x) ((unsigned long)(x))
#endif

extern spinlock_t blkif_io_lock;

typedef struct blkif_st {
    /* Unique identifier for this interface. */
    domid_t             domid;
    unsigned int        handle;
    /* Physical parameters of the comms window. */
    unsigned long       shmem_frame;
    unsigned int        evtchn;
    /* Comms information. */
    blkif_back_ring_t   blk_ring;
    
    enum { DISCONNECTED, DISCONNECTING, CONNECTED } status;
    /*
     * DISCONNECT response is deferred until pending requests are ack'ed.
     * We therefore need to store the id from the original request.
     */    
    u8                  disconnect_rspid;
    struct blkif_st    *hash_next;
    struct list_head    blkdev_list;
    spinlock_t          blk_ring_lock;
    atomic_t            refcnt;
    struct work_struct work;
#ifdef CONFIG_XEN_BLKDEV_GRANT
    u16 shmem_handle;
    unsigned long shmem_vaddr;
    grant_ref_t shmem_ref;
#endif
} blkif_t;

blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle);
void blkif_disconnect_complete(blkif_t *blkif);
#define blkif_get(_b) (atomic_inc(&(_b)->refcnt))
#define blkif_put(_b)                             \
    do {                                          \
        if ( atomic_dec_and_test(&(_b)->refcnt) ) \
            blkif_disconnect_complete(_b);        \
    } while (0)


/* -------[ active request tracking ]--------------------------------- */

typedef struct {
    blkif_t       *blkif;
    unsigned long  id;
    int            nr_pages;
    int            next_free;
} active_req_t;

typedef unsigned int ACTIVE_RING_IDX;

active_req_t *lookup_active_req(ACTIVE_RING_IDX idx);

extern inline unsigned int ID_TO_IDX(unsigned long id) 
{ 
    return ( id & 0x0000ffff );
}

extern inline domid_t ID_TO_DOM(unsigned long id) 
{ 
    return (id >> 16); 
}

void active_reqs_init(void);

/* -------[ interposition -> character device interface ]------------- */

/* /dev/xen/blktap resides at device number major=10, minor=200        */ 
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



/* -------[ Mappings to User VMA ]------------------------------------ */
#define BATCH_PER_DOMAIN 16

/* -------[ Here be globals ]----------------------------------------- */
extern unsigned long blktap_mode;

/* Connection to a single backend domain. */
extern blkif_front_ring_t blktap_be_ring;
extern unsigned int blktap_be_evtchn;
extern unsigned int blktap_be_state;

/* User ring status. */
extern unsigned long blktap_ring_ok;

/* -------[ ...and function prototypes. ]----------------------------- */

/* init function for character device interface.                       */
int blktap_init(void);

/* init function for the blkif cache. */
void __init blkif_interface_init(void);
void __init blkdev_schedule_init(void);
void blkif_deschedule(blkif_t *blkif);

/* interfaces to the char driver, passing messages to and from apps.   */
void blktap_kick_user(void);

/* user ring access functions: */
int blktap_write_fe_ring(blkif_request_t *req);
int blktap_write_be_ring(blkif_response_t *rsp);
int blktap_write_ctrl_ring(ctrl_msg_t *msg);

/* fe/be ring access functions: */
int write_resp_to_fe_ring(blkif_t *blkif, blkif_response_t *rsp);
int write_req_to_be_ring(blkif_request_t *req);

/* event notification functions */
void kick_fe_domain(blkif_t *blkif);
void kick_be_domain(void);

/* Interrupt handlers. */
irqreturn_t blkif_ptbe_int(int irq, void *dev_id, 
                                  struct pt_regs *ptregs);
irqreturn_t blkif_ptfe_int(int irq, void *dev_id, struct pt_regs *regs);

/* Control message receiver. */
extern void blkif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id);

/* debug */
void print_fe_ring_idxs(void);
void print_be_ring_idxs(void);
        
#define __BLKINT_H__
#endif
