
#ifndef __BLKIF__BACKEND__COMMON_H__
#define __BLKIF__BACKEND__COMMON_H__

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/pgalloc.h>
#include <asm-xen/evtchn.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/io/blkif.h>
#include <asm-xen/xen-public/io/ring.h>
#include <asm-xen/gnttab.h>

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

struct vbd {
    blkif_vdev_t   handle;      /* what the domain refers to this vbd as */
    unsigned char  readonly;    /* Non-zero -> read-only */
    unsigned char  type;        /* VDISK_xxx */
    blkif_pdev_t   pdevice;     /* phys device that this vbd maps to */
    struct block_device *bdev;
}; 

typedef struct blkif_st {
    /* Unique identifier for this interface. */
    domid_t           domid;
    unsigned int      handle;
    /* Physical parameters of the comms window. */
    unsigned long     shmem_frame;
    unsigned int      evtchn;
    unsigned int      remote_evtchn;
    /* Comms information. */
    blkif_back_ring_t blk_ring;
    /* VBDs attached to this interface. */
    struct vbd        vbd;
    /* Private fields. */
    enum { DISCONNECTED, CONNECTED } status;
#ifdef CONFIG_XEN_BLKDEV_TAP_BE
    /* Is this a blktap frontend */
    unsigned int     is_blktap;
#endif
    struct list_head blkdev_list;
    spinlock_t       blk_ring_lock;
    atomic_t         refcnt;

    struct work_struct free_work;
    u16 shmem_handle;
    unsigned long shmem_vaddr;
    grant_ref_t shmem_ref;
} blkif_t;

void blkif_create(blkif_be_create_t *create);
void blkif_destroy(blkif_be_destroy_t *destroy);
void blkif_connect(blkif_be_connect_t *connect);
int  blkif_disconnect(blkif_be_disconnect_t *disconnect, u8 rsp_id);
void blkif_disconnect_complete(blkif_t *blkif);
blkif_t *alloc_blkif(domid_t domid);
void free_blkif_callback(blkif_t *blkif);
int blkif_map(blkif_t *blkif, unsigned long shared_page, unsigned int evtchn);

#define blkif_get(_b) (atomic_inc(&(_b)->refcnt))
#define blkif_put(_b)                             \
    do {                                          \
        if ( atomic_dec_and_test(&(_b)->refcnt) ) \
            free_blkif_callback(_b);		  \
    } while (0)

/* Create a vbd. */
int vbd_create(blkif_t *blkif, blkif_vdev_t vdevice, blkif_pdev_t pdevice,
	       int readonly);
void vbd_free(struct vbd *vbd);

unsigned long vbd_size(struct vbd *vbd);
unsigned int vbd_info(struct vbd *vbd);
unsigned long vbd_secsize(struct vbd *vbd);

struct phys_req {
    unsigned short       dev;
    unsigned short       nr_sects;
    struct block_device *bdev;
    blkif_sector_t       sector_number;
};

int vbd_translate(struct phys_req *req, blkif_t *blkif, int operation); 

void blkif_interface_init(void);

void blkif_deschedule(blkif_t *blkif);

void blkif_xenbus_init(void);

irqreturn_t blkif_be_int(int irq, void *dev_id, struct pt_regs *regs);

#endif /* __BLKIF__BACKEND__COMMON_H__ */
