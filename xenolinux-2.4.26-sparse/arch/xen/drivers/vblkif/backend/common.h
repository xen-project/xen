/******************************************************************************
 * arch/xen/drivers/vblkif/backend/common.h
 */

#ifndef __VBLKIF__BACKEND__COMMON_H__
#define __VBLKIF__BACKEND__COMMON_H__

#include <linux/config.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <asm/ctrl_if.h>
#include <asm/io.h>
#include "../vblkif.h"

#ifndef NDEBUG
#define ASSERT(_p) \
    if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#define DPRINTK(_f, _a...) printk("(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define ASSERT(_p) ((void)0)
#define DPRINTK(_f, _a...) ((void)0)
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
    blk_ring_t      *blk_ring_base; /* ioremap()'ed ptr to shmem_frame. */
    BLK_RING_IDX     blk_req_cons;  /* Request consumer. */
    BLK_RING_IDX     blk_resp_prod; /* Private version of response producer. */
    /* VBDs attached to this interface. */
    rb_root_t        vbd_rb;        /* Mapping from 16-bit vdevices to VBDs. */
    spinlock_t       vbd_lock;      /* Protects VBD mapping. */
    /* Private fields. */
    struct blkif_st *hash_next;
    struct list_head blkdev_list;
    spinlock_t       blk_ring_lock;
} blkif_t;

void blkif_create(blkif_create_t *create);
void blkif_destroy(blkif_destroy_t *destroy);
blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle);
void blkif_get(blkif_t *blkif);
void blkif_put(blkif_t *blkif);

/* An entry in a list of xen_extents. */
typedef struct _blkif_extent_le { 
    blkif_extent_t extent;               /* an individual extent */
    struct _blkif_extent_le *next;       /* and a pointer to the next */ 
} blkif_extent_le_t; 

typedef struct _vbd { 
    blkif_vdev_t       vdevice;   /* what the domain refers to this vbd as */
    unsigned char      mode;      /* VBD_MODE_{R,W} */
    unsigned char      type;      /* XD_TYPE_xxx */
    blkif_extent_le_t *extents;   /* list of xen_extents making up this vbd */
    rb_node_t          rb;        /* for linking into R-B tree lookup struct */
} vbd_t; 

long vbd_create(blkif_vbd_create_t *create_params); 
long vbd_grow(blkif_vbd_grow_t *grow_params); 
long vbd_shrink(blkif_vbd_shrink_t *shrink_params);
long vbd_destroy(blkif_vbd_destroy_t *delete_params); 

void destroy_all_vbds(struct task_struct *p);

typedef struct {
    blkif_t       *blkif;
    unsigned long  id;
    atomic_t       pendcnt;
    unsigned short operation;
    unsigned short status;
} pending_req_t;

/* Describes a [partial] disk extent (part of a block io request) */
typedef struct {
    unsigned short dev;
    unsigned short nr_sects;
    unsigned long  buffer;
    xen_sector_t   sector_number;
} phys_seg_t;

int vbd_translate(phys_seg_t *pseg, blkif_t *blkif, int operation); 

int vblkif_be_controller_init(void);

void vblkif_be_int(int irq, void *dev_id, struct pt_regs *regs);

#endif /* __VBLKIF__BACKEND__COMMON_H__ */
