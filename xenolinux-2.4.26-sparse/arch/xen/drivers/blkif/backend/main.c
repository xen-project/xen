/******************************************************************************
 * arch/xen/drivers/blkif/backend/main.c
 * 
 * Back-end of the driver for virtual block devices. This portion of the
 * driver exports a 'unified' block-device interface that can be accessed
 * by any operating system that implements a compatible front end. A 
 * reference front-end implementation can be found in:
 *  arch/xen/drivers/blkif/frontend
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 */

#include "common.h"

/*
 * These are rather arbitrary. They are fairly large because adjacent requests
 * pulled from a communication ring are quite likely to end up being part of
 * the same scatter/gather request at the disc.
 * 
 * ** TRY INCREASING 'MAX_PENDING_REQS' IF WRITE SPEEDS SEEM TOO LOW **
 * This will increase the chances of being able to write whole tracks.
 * 64 should be enough to keep us competitive with Linux.
 */
#define MAX_PENDING_REQS 64
#define BATCH_PER_DOMAIN 16

static struct vm_struct *mmap_vma;
#define MMAP_PAGES_PER_SEGMENT \
    ((BLKIF_MAX_SEGMENTS_PER_REQUEST >> (PAGE_SHIFT-9)) + 1)
#define MMAP_PAGES_PER_REQUEST \
    (2 * BLKIF_MAX_SEGMENTS_PER_REQUEST * MMAP_PAGES_PER_SEGMENT)
#define MMAP_PAGES             \
    (MAX_PENDING_REQS * MMAP_PAGES_PER_REQUEST)
#define MMAP_VADDR(_req,_seg)            \
    ((unsigned long)mmap_vma->addr +     \
     ((_req) * MMAP_PAGES_PER_REQUEST * PAGE_SIZE) + \
     ((_seg) * MMAP_PAGES_PER_SEGMENT * PAGE_SIZE))

/*
 * Each outstanding request that we've passed to the lower device layers has a 
 * 'pending_req' allocated to it. Each buffer_head that completes decrements 
 * the pendcnt towards zero. When it hits zero, the specified domain has a 
 * response queued for it, with the saved 'id' passed back.
 * 
 * We can't allocate pending_req's in order, since they may complete out of 
 * order. We therefore maintain an allocation ring. This ring also indicates 
 * when enough work has been passed down -- at that point the allocation ring 
 * will be empty.
 */
static pending_req_t pending_reqs[MAX_PENDING_REQS];
static unsigned char pending_ring[MAX_PENDING_REQS];
static spinlock_t pend_prod_lock = SPIN_LOCK_UNLOCKED;
/* NB. We use a different index type to differentiate from shared blk rings. */
typedef unsigned int PEND_RING_IDX;
#define MASK_PEND_IDX(_i) ((_i)&(MAX_PENDING_REQS-1))
static PEND_RING_IDX pending_prod, pending_cons;
#define NR_PENDING_REQS (MAX_PENDING_REQS - pending_prod + pending_cons)

static kmem_cache_t *buffer_head_cachep;

static int do_block_io_op(blkif_t *blkif, int max_to_do);
static void dispatch_probe(blkif_t *blkif, blkif_request_t *req);
static void dispatch_rw_block_io(blkif_t *blkif, blkif_request_t *req);
static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st);


/******************************************************************
 * BLOCK-DEVICE SCHEDULER LIST MAINTENANCE
 */

static struct list_head io_schedule_list;
static spinlock_t io_schedule_list_lock;

static int __on_blkdev_list(blkif_t *blkif)
{
    return blkif->blkdev_list.next != NULL;
}

static void remove_from_blkdev_list(blkif_t *blkif)
{
    unsigned long flags;
    if ( !__on_blkdev_list(blkif) ) return;
    spin_lock_irqsave(&io_schedule_list_lock, flags);
    if ( __on_blkdev_list(blkif) )
    {
        list_del(&blkif->blkdev_list);
        blkif->blkdev_list.next = NULL;
        blkif_put(blkif);
    }
    spin_unlock_irqrestore(&io_schedule_list_lock, flags);
}

static void add_to_blkdev_list_tail(blkif_t *blkif)
{
    unsigned long flags;
    if ( __on_blkdev_list(blkif) ) return;
    spin_lock_irqsave(&io_schedule_list_lock, flags);
    if ( !__on_blkdev_list(blkif) && (blkif->status == CONNECTED) )
    {
        list_add_tail(&blkif->blkdev_list, &io_schedule_list);
        blkif_get(blkif);
    }
    spin_unlock_irqrestore(&io_schedule_list_lock, flags);
}


/******************************************************************
 * SCHEDULER FUNCTIONS
 */

static void io_schedule(unsigned long unused)
{
    blkif_t          *blkif;
    struct list_head *ent;

    /* Queue up a batch of requests. */
    while ( (NR_PENDING_REQS < MAX_PENDING_REQS) &&
            !list_empty(&io_schedule_list) )
    {
        ent = io_schedule_list.next;
        blkif = list_entry(ent, blkif_t, blkdev_list);
        blkif_get(blkif);
        remove_from_blkdev_list(blkif);
        if ( do_block_io_op(blkif, BATCH_PER_DOMAIN) )
            add_to_blkdev_list_tail(blkif);
        blkif_put(blkif);
    }

    /* Push the batch through to disc. */
    run_task_queue(&tq_disk);
}

static DECLARE_TASKLET(io_schedule_tasklet, io_schedule, 0);

static void maybe_trigger_io_schedule(void)
{
    /*
     * Needed so that two processes, who together make the following predicate
     * true, don't both read stale values and evaluate the predicate
     * incorrectly. Incredibly unlikely to stall the scheduler on x86, but...
     */
    smp_mb();

    if ( (NR_PENDING_REQS < (MAX_PENDING_REQS/2)) &&
         !list_empty(&io_schedule_list) )
        tasklet_schedule(&io_schedule_tasklet);
}



/******************************************************************
 * COMPLETION CALLBACK -- Called as bh->b_end_io()
 */

static void end_block_io_op(struct buffer_head *bh, int uptodate)
{
    pending_req_t *pending_req = bh->b_private;
    unsigned long  flags;

    /* An error fails the entire request. */
    if ( !uptodate )
    {
        DPRINTK("Buffer not up-to-date at end of operation\n");
        pending_req->status = BLKIF_RSP_ERROR;
    }

    if ( atomic_dec_and_test(&pending_req->pendcnt) )
    {
        int pending_idx = pending_req - pending_reqs;
        vmfree_area_pages(MMAP_VADDR(pending_idx, 0), 
                          MMAP_PAGES_PER_REQUEST * PAGE_SIZE);
        make_response(pending_req->blkif, pending_req->id,
                      pending_req->operation, pending_req->status);
        blkif_put(pending_req->blkif);
        spin_lock_irqsave(&pend_prod_lock, flags);
        pending_ring[MASK_PEND_IDX(pending_prod++)] = pending_idx;
        spin_unlock_irqrestore(&pend_prod_lock, flags);
        maybe_trigger_io_schedule();
    }
}



/******************************************************************************
 * NOTIFICATION FROM GUEST OS.
 */

void blkif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
    blkif_t *blkif = dev_id;
    add_to_blkdev_list_tail(blkif);
    maybe_trigger_io_schedule();
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */

static int do_block_io_op(blkif_t *blkif, int max_to_do)
{
    blkif_ring_t *blk_ring = blkif->blk_ring_base;
    blkif_request_t *req;
    BLK_RING_IDX i;
    int more_to_do = 0;

    /* Take items off the comms ring, taking care not to overflow. */
    for ( i = blkif->blk_req_cons; 
          (i != blk_ring->req_prod) && ((i-blkif->blk_resp_prod) != 
                                        BLK_RING_SIZE);
          i++ )
    {
        if ( (max_to_do-- == 0) || (NR_PENDING_REQS == MAX_PENDING_REQS) )
        {
            more_to_do = 1;
            break;
        }
        
        req = &blk_ring->ring[MASK_BLK_IDX(i)].req;
        switch ( req->operation )
        {
        case BLKIF_OP_READ:
        case BLKIF_OP_WRITE:
            dispatch_rw_block_io(blkif, req);
            break;

        case BLKIF_OP_PROBE:
            dispatch_probe(blkif, req);
            break;

        default:
            DPRINTK("error: unknown block io operation [%d]\n",
                    blk_ring->ring[i].req.operation);
            make_response(blkif, blk_ring->ring[i].req.id, 
                          blk_ring->ring[i].req.operation, BLKIF_RSP_ERROR);
            break;
        }
    }

    blkif->blk_req_cons = i;
    return more_to_do;
}

static void dispatch_probe(blkif_t *blkif, blkif_request_t *req)
{
    int      i, rc, pending_idx = pending_ring[MASK_PEND_IDX(pending_cons)];
    pgprot_t prot;

    /* Check that number of segments is sane. */
    if ( unlikely(req->nr_segments == 0) || 
         unlikely(req->nr_segments > BLKIF_MAX_SEGMENTS_PER_REQUEST) )
    {
        DPRINTK("Bad number of segments in request (%d)\n", req->nr_segments);
        goto bad_descriptor;
    }

    prot = __pgprot(_PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW);
    for ( i = 0; i < req->nr_segments; i++ )
    {
        if ( (req->buffer_and_sects[i] & ~PAGE_MASK) != (PAGE_SIZE / 512) )
            goto bad_descriptor;
        rc = direct_remap_area_pages(&init_mm, 
                                     MMAP_VADDR(pending_idx, i),
                                     req->buffer_and_sects[i] & PAGE_MASK, 
                                     PAGE_SIZE, prot, blkif->domid);
        if ( rc != 0 )
            goto bad_descriptor;
    }

    rc = vbd_probe(blkif, (vdisk_t *)MMAP_VADDR(pending_idx, 0), 
                   (req->nr_segments * PAGE_SIZE) / sizeof(vdisk_t));

    vmfree_area_pages(MMAP_VADDR(pending_idx, 0), 
                      MMAP_PAGES_PER_REQUEST * PAGE_SIZE);
    make_response(blkif, req->id, req->operation, rc);
    return;

 bad_descriptor:
    vmfree_area_pages(MMAP_VADDR(pending_idx, 0), 
                      MMAP_PAGES_PER_REQUEST * PAGE_SIZE);
    make_response(blkif, req->id, req->operation, BLKIF_RSP_ERROR);
}

static void dispatch_rw_block_io(blkif_t *blkif, blkif_request_t *req)
{
    extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]); 
    struct buffer_head *bh;
    int operation = (req->operation == BLKIF_OP_WRITE) ? WRITE : READ;
    unsigned short nr_sects;
    unsigned long buffer;
    int i, tot_sects, pending_idx = pending_ring[MASK_PEND_IDX(pending_cons)];
    pending_req_t *pending_req;
    pgprot_t       prot;

    /* We map virtual scatter/gather segments to physical segments. */
    int new_segs, nr_psegs = 0;
    phys_seg_t phys_seg[BLKIF_MAX_SEGMENTS_PER_REQUEST * 2];

    /* Check that number of segments is sane. */
    if ( unlikely(req->nr_segments == 0) || 
         unlikely(req->nr_segments > BLKIF_MAX_SEGMENTS_PER_REQUEST) )
    {
        DPRINTK("Bad number of segments in request (%d)\n", req->nr_segments);
        goto bad_descriptor;
    }

    /*
     * Check each address/size pair is sane, and convert into a
     * physical device and block offset. Note that if the offset and size
     * crosses a virtual extent boundary, we may end up with more
     * physical scatter/gather segments than virtual segments.
     */
    for ( i = tot_sects = 0; i < req->nr_segments; i++, tot_sects += nr_sects )
    {
        buffer   = req->buffer_and_sects[i] & ~0x1FF;
        nr_sects = req->buffer_and_sects[i] &  0x1FF;

        if ( unlikely(nr_sects == 0) )
            continue;

        if ( unlikely(nr_sects > BLKIF_MAX_SECTORS_PER_SEGMENT) )
        {
            DPRINTK("Too many sectors in segment\n");
            goto bad_descriptor;
        }

        phys_seg[nr_psegs].dev           = req->device;
        phys_seg[nr_psegs].sector_number = req->sector_number + tot_sects;
        phys_seg[nr_psegs].buffer        = buffer;
        phys_seg[nr_psegs].nr_sects      = nr_sects;

        /* Translate the request into the relevant 'physical device' */
        new_segs = vbd_translate(&phys_seg[nr_psegs], blkif, operation);
        if ( new_segs < 0 )
        { 
            DPRINTK("access denied: %s of [%llu,%llu] on dev=%04x\n", 
                    operation == READ ? "read" : "write", 
                    req->sector_number + tot_sects, 
                    req->sector_number + tot_sects + nr_sects, 
                    req->device); 
            goto bad_descriptor;
        }
  
        nr_psegs += new_segs;
        ASSERT(nr_psegs <= BLKIF_MAX_SEGMENTS_PER_REQUEST*2);
    }

    /* Nonsensical zero-sized request? */
    if ( unlikely(nr_psegs == 0) )
        goto bad_descriptor;

    if ( operation == READ )
        prot = __pgprot(_PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW);
    else
        prot = __pgprot(_PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED);

    for ( i = 0; i < nr_psegs; i++ )
    {
        unsigned long sz = ((phys_seg[i].buffer & ~PAGE_MASK) + 
                            (phys_seg[i].nr_sects << 9) + 
                            (PAGE_SIZE - 1)) & PAGE_MASK;
        int rc = direct_remap_area_pages(&init_mm, 
                                         MMAP_VADDR(pending_idx, i),
                                         phys_seg[i].buffer & PAGE_MASK, 
                                         sz, prot, blkif->domid);
        if ( rc != 0 )
        {
            DPRINTK("invalid buffer\n");
            vmfree_area_pages(MMAP_VADDR(pending_idx, 0), 
                              MMAP_PAGES_PER_REQUEST * PAGE_SIZE);
            goto bad_descriptor;
        }
    }

    pending_req = &pending_reqs[pending_idx];
    pending_req->blkif     = blkif;
    pending_req->id        = req->id;
    pending_req->operation = operation;
    pending_req->status    = BLKIF_RSP_OKAY;
    atomic_set(&pending_req->pendcnt, nr_psegs);
    pending_cons++;

    blkif_get(blkif);

    /* Now we pass each segment down to the real blkdev layer. */
    for ( i = 0; i < nr_psegs; i++ )
    {
        bh = kmem_cache_alloc(buffer_head_cachep, GFP_ATOMIC);
        if ( unlikely(bh == NULL) )
            panic("bh is null\n");
        memset(bh, 0, sizeof (struct buffer_head));

        init_waitqueue_head(&bh->b_wait);
        bh->b_size          = phys_seg[i].nr_sects << 9;
        bh->b_dev           = phys_seg[i].dev;
        bh->b_rdev          = phys_seg[i].dev;
        bh->b_rsector       = (unsigned long)phys_seg[i].sector_number;
        bh->b_data          = (char *)MMAP_VADDR(pending_idx, i) +
            (phys_seg[i].buffer & ~PAGE_MASK);
        bh->b_end_io        = end_block_io_op;
        bh->b_private       = pending_req;

        bh->b_state = (1 << BH_Mapped) | (1 << BH_Lock) | 
            (1 << BH_Req) | (1 << BH_Launder);
        if ( operation == WRITE )
            bh->b_state |= (1 << BH_JBD) | (1 << BH_Req) | (1 << BH_Uptodate);

        atomic_set(&bh->b_count, 1);

        /* Dispatch a single request. We'll flush it to disc later. */
        generic_make_request(operation, bh);
    }

    return;

 bad_descriptor:
    make_response(blkif, req->id, req->operation, BLKIF_RSP_ERROR);
} 



/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */


static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st)
{
    blkif_response_t *resp;
    unsigned long     flags;

    /* Place on the response ring for the relevant domain. */ 
    spin_lock_irqsave(&blkif->blk_ring_lock, flags);
    resp = &blkif->blk_ring_base->
        ring[MASK_BLK_IDX(blkif->blk_resp_prod)].resp;
    resp->id        = id;
    resp->operation = op;
    resp->status    = st;
    wmb();
    blkif->blk_ring_base->resp_prod = ++blkif->blk_resp_prod;
    spin_unlock_irqrestore(&blkif->blk_ring_lock, flags);

    /* Kick the relevant domain. */
    notify_via_evtchn(blkif->evtchn);
}

void blkif_deschedule(blkif_t *blkif)
{
    remove_from_blkdev_list(blkif);
}

static int __init init_module(void)
{
    int i;

    blkif_interface_init();

    if ( (mmap_vma = get_vm_area(MMAP_PAGES * PAGE_SIZE, VM_IOREMAP)) == NULL )
    {
        printk(KERN_WARNING "Could not allocate VMA for blkif backend.\n");
        return -ENOMEM;
    }

    pending_cons = 0;
    pending_prod = MAX_PENDING_REQS;
    memset(pending_reqs, 0, sizeof(pending_reqs));
    for ( i = 0; i < MAX_PENDING_REQS; i++ )
        pending_ring[i] = i;
    
    spin_lock_init(&io_schedule_list_lock);
    INIT_LIST_HEAD(&io_schedule_list);

    buffer_head_cachep = kmem_cache_create(
        "buffer_head_cache", sizeof(struct buffer_head),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);

    blkif_ctrlif_init();

    return 0;
}

static void cleanup_module(void)
{
}

module_init(init_module);
module_exit(cleanup_module);
