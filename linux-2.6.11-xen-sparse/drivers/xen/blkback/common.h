
#ifndef __BLKIF__BACKEND__COMMON_H__
#define __BLKIF__BACKEND__COMMON_H__

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/pgalloc.h>
#include <asm-xen/ctrl_if.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/io/blkif.h>

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
typedef struct rb_root rb_root_t;
typedef struct rb_node rb_node_t;
#else
struct block_device;
#endif

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
    /* VBDs attached to this interface. */
    rb_root_t        vbd_rb;        /* Mapping from 16-bit vdevices to VBDs. */
    spinlock_t       vbd_lock;      /* Protects VBD mapping. */
    /* Private fields. */
    enum { DISCONNECTED, DISCONNECTING, CONNECTED } status;
    /*
     * DISCONNECT response is deferred until pending requests are ack'ed.
     * We therefore need to store the id from the original request.
     */
    u8               disconnect_rspid;
    struct blkif_st *hash_next;
    struct list_head blkdev_list;
    spinlock_t       blk_ring_lock;
    atomic_t         refcnt;

    struct work_struct work;
} blkif_t;

void blkif_create(blkif_be_create_t *create);
void blkif_destroy(blkif_be_destroy_t *destroy);
void blkif_connect(blkif_be_connect_t *connect);
int  blkif_disconnect(blkif_be_disconnect_t *disconnect, u8 rsp_id);
void blkif_disconnect_complete(blkif_t *blkif);
blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle);
#define blkif_get(_b) (atomic_inc(&(_b)->refcnt))
#define blkif_put(_b)                             \
    do {                                          \
        if ( atomic_dec_and_test(&(_b)->refcnt) ) \
            blkif_disconnect_complete(_b);        \
    } while (0)

/* An entry in a list of xen_extents. */
typedef struct _blkif_extent_le { 
    blkif_extent_t extent;               /* an individual extent */
    struct _blkif_extent_le *next;       /* and a pointer to the next */ 
    struct block_device *bdev;
} blkif_extent_le_t; 

typedef struct _vbd { 
    blkif_vdev_t       vdevice;   /* what the domain refers to this vbd as */
    unsigned char      readonly;  /* Non-zero -> read-only */
    unsigned char      type;      /* VDISK_TYPE_xxx */
    blkif_extent_le_t *extents;   /* list of xen_extents making up this vbd */
    rb_node_t          rb;        /* for linking into R-B tree lookup struct */
} vbd_t; 

void vbd_create(blkif_be_vbd_create_t *create); 
void vbd_grow(blkif_be_vbd_grow_t *grow); 
void vbd_shrink(blkif_be_vbd_shrink_t *shrink);
void vbd_destroy(blkif_be_vbd_destroy_t *delete); 
int vbd_probe(blkif_t *blkif, vdisk_t *vbd_info, int max_vbds);
void destroy_all_vbds(blkif_t *blkif);

/* Describes a [partial] disk extent (part of a block io request) */
typedef struct {
    unsigned short       dev;
    unsigned short       nr_sects;
    struct block_device *bdev;
    unsigned long        buffer;
    blkif_sector_t       sector_number;
} phys_seg_t;

int vbd_translate(phys_seg_t *pseg, blkif_t *blkif, int operation); 

void blkif_interface_init(void);
void blkif_ctrlif_init(void);

void blkif_deschedule(blkif_t *blkif);

irqreturn_t blkif_be_int(int irq, void *dev_id, struct pt_regs *regs);

#endif /* __BLKIF__BACKEND__COMMON_H__ */
