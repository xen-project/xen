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

static unsigned long mmap_vstart;
#define MMAP_PAGES_PER_REQUEST \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST + 1)
#define MMAP_PAGES             \
    (MAX_PENDING_REQS * MMAP_PAGES_PER_REQUEST)
#define MMAP_VADDR(_req,_seg)                        \
    (mmap_vstart +                                   \
     ((_req) * MMAP_PAGES_PER_REQUEST * PAGE_SIZE) + \
     ((_seg) * PAGE_SIZE))

/*
 * Each outstanding request that we've passed to the lower device layers has a 
 * 'pending_req' allocated to it. Each buffer_head that completes decrements 
 * the pendcnt towards zero. When it hits zero, the specified domain has a 
 * response queued for it, with the saved 'id' passed back.
 */
typedef struct {
    blkif_t       *blkif;
    unsigned long  id;
    int            nr_pages;
    atomic_t       pendcnt;
    unsigned short operation;
    int            status;
} pending_req_t;

/*
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static kmem_cache_t *buffer_head_cachep;
#endif

static int do_block_io_op(blkif_t *blkif, int max_to_do);
static void dispatch_probe(blkif_t *blkif, blkif_request_t *req);
static void dispatch_rw_block_io(blkif_t *blkif, blkif_request_t *req);
static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st);

static void fast_flush_area(int idx, int nr_pages)
{
    multicall_entry_t mcl[MMAP_PAGES_PER_REQUEST];
    int               i;

    for ( i = 0; i < nr_pages; i++ )
    {
        mcl[i].op = __HYPERVISOR_update_va_mapping;
        mcl[i].args[0] = MMAP_VADDR(idx, i) >> PAGE_SHIFT;
        mcl[i].args[1] = 0;
        mcl[i].args[2] = 0;
    }

    mcl[nr_pages-1].args[2] = UVMF_FLUSH_TLB;
    if ( unlikely(HYPERVISOR_multicall(mcl, nr_pages) != 0) )
        BUG();
}


/******************************************************************
 * BLOCK-DEVICE SCHEDULER LIST MAINTENANCE
 */

static struct list_head blkio_schedule_list;
static spinlock_t blkio_schedule_list_lock;

static int __on_blkdev_list(blkif_t *blkif)
{
    return blkif->blkdev_list.next != NULL;
}

static void remove_from_blkdev_list(blkif_t *blkif)
{
    unsigned long flags;
    if ( !__on_blkdev_list(blkif) ) return;
    spin_lock_irqsave(&blkio_schedule_list_lock, flags);
    if ( __on_blkdev_list(blkif) )
    {
        list_del(&blkif->blkdev_list);
        blkif->blkdev_list.next = NULL;
        blkif_put(blkif);
    }
    spin_unlock_irqrestore(&blkio_schedule_list_lock, flags);
}

static void add_to_blkdev_list_tail(blkif_t *blkif)
{
    unsigned long flags;
    if ( __on_blkdev_list(blkif) ) return;
    spin_lock_irqsave(&blkio_schedule_list_lock, flags);
    if ( !__on_blkdev_list(blkif) && (blkif->status == CONNECTED) )
    {
        list_add_tail(&blkif->blkdev_list, &blkio_schedule_list);
        blkif_get(blkif);
    }
    spin_unlock_irqrestore(&blkio_schedule_list_lock, flags);
}


/******************************************************************
 * SCHEDULER FUNCTIONS
 */

static DECLARE_WAIT_QUEUE_HEAD(blkio_schedule_wait);

static int blkio_schedule(void *arg)
{
    DECLARE_WAITQUEUE(wq, current);

    blkif_t          *blkif;
    struct list_head *ent;

    daemonize(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        "xenblkd"
#endif
        );

    for ( ; ; )
    {
        /* Wait for work to do. */
        add_wait_queue(&blkio_schedule_wait, &wq);
        set_current_state(TASK_INTERRUPTIBLE);
        if ( (NR_PENDING_REQS == MAX_PENDING_REQS) || 
             list_empty(&blkio_schedule_list) )
            schedule();
        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&blkio_schedule_wait, &wq);

        /* Queue up a batch of requests. */
        while ( (NR_PENDING_REQS < MAX_PENDING_REQS) &&
                !list_empty(&blkio_schedule_list) )
        {
            ent = blkio_schedule_list.next;
            blkif = list_entry(ent, blkif_t, blkdev_list);
            blkif_get(blkif);
            remove_from_blkdev_list(blkif);
            if ( do_block_io_op(blkif, BATCH_PER_DOMAIN) )
                add_to_blkdev_list_tail(blkif);
            blkif_put(blkif);
        }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        /* Push the batch through to disc. */
        run_task_queue(&tq_disk);
#endif
    }
}

static void maybe_trigger_blkio_schedule(void)
{
    /*
     * Needed so that two processes, who together make the following predicate
     * true, don't both read stale values and evaluate the predicate
     * incorrectly. Incredibly unlikely to stall the scheduler on x86, but...
     */
    smp_mb();

    if ( (NR_PENDING_REQS < (MAX_PENDING_REQS/2)) &&
         !list_empty(&blkio_schedule_list) )
        wake_up(&blkio_schedule_wait);
}



/******************************************************************
 * COMPLETION CALLBACK -- Called as bh->b_end_io()
 */

static void __end_block_io_op(pending_req_t *pending_req, int uptodate)
{
    unsigned long flags;

    /* An error fails the entire request. */
    if ( !uptodate )
    {
        DPRINTK("Buffer not up-to-date at end of operation\n");
        pending_req->status = BLKIF_RSP_ERROR;
    }

    if ( atomic_dec_and_test(&pending_req->pendcnt) )
    {
        int pending_idx = pending_req - pending_reqs;
        fast_flush_area(pending_idx, pending_req->nr_pages);
        make_response(pending_req->blkif, pending_req->id,
                      pending_req->operation, pending_req->status);
        blkif_put(pending_req->blkif);
        spin_lock_irqsave(&pend_prod_lock, flags);
        pending_ring[MASK_PEND_IDX(pending_prod++)] = pending_idx;
        spin_unlock_irqrestore(&pend_prod_lock, flags);
        maybe_trigger_blkio_schedule();
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static void end_block_io_op(struct buffer_head *bh, int uptodate)
{
    __end_block_io_op(bh->b_private, uptodate);
    kmem_cache_free(buffer_head_cachep, bh);
}
#else
static int end_block_io_op(struct bio *bio, unsigned int done, int error)
{
    if ( done || error )
        __end_block_io_op(bio->bi_private, (done && !error));
    bio_put(bio);
    return error;
}
#endif


/******************************************************************************
 * NOTIFICATION FROM GUEST OS.
 */

irqreturn_t blkif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
    blkif_t *blkif = dev_id;
    add_to_blkdev_list_tail(blkif);
    maybe_trigger_blkio_schedule();
    return IRQ_HANDLED;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */

static int do_block_io_op(blkif_t *blkif, int max_to_do)
{
    blkif_ring_t *blk_ring = blkif->blk_ring_base;
    blkif_request_t *req;
    BLKIF_RING_IDX i, rp;
    int more_to_do = 0;

    rp = blk_ring->req_prod;
    rmb(); /* Ensure we see queued requests up to 'rp'. */

    /* Take items off the comms ring, taking care not to overflow. */
    for ( i = blkif->blk_req_cons; 
          (i != rp) && ((i-blkif->blk_resp_prod) != BLKIF_RING_SIZE);
          i++ )
    {
        if ( (max_to_do-- == 0) || (NR_PENDING_REQS == MAX_PENDING_REQS) )
        {
            more_to_do = 1;
            break;
        }
        
        req = &blk_ring->ring[MASK_BLKIF_IDX(i)].req;
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
    int rsp = BLKIF_RSP_ERROR;
    int pending_idx = pending_ring[MASK_PEND_IDX(pending_cons)];

    /* We expect one buffer only. */
    if ( unlikely(req->nr_segments != 1) )
        goto out;

    /* Make sure the buffer is page-sized. */
    if ( (blkif_first_sect(req->frame_and_sects[0]) != 0) ||
         (blkif_last_sect(req->frame_and_sects[0]) != 7) )
        goto out;

    if ( HYPERVISOR_update_va_mapping_otherdomain(
        MMAP_VADDR(pending_idx, 0) >> PAGE_SHIFT,
        (pte_t) { (req->frame_and_sects[0] & PAGE_MASK) | __PAGE_KERNEL },
        0, blkif->domid) )
        goto out;

    rsp = vbd_probe(blkif, (vdisk_t *)MMAP_VADDR(pending_idx, 0), 
                    PAGE_SIZE / sizeof(vdisk_t));

 out:
    fast_flush_area(pending_idx, 1);
    make_response(blkif, req->id, req->operation, rsp);
}

static void dispatch_rw_block_io(blkif_t *blkif, blkif_request_t *req)
{
    extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]); 
    int operation = (req->operation == BLKIF_OP_WRITE) ? WRITE : READ;
    short nr_sects;
    unsigned long buffer, fas;
    int i, tot_sects, pending_idx = pending_ring[MASK_PEND_IDX(pending_cons)];
    pending_req_t *pending_req;
    unsigned long  remap_prot;
    multicall_entry_t mcl[MMAP_PAGES_PER_REQUEST];

    /* We map virtual scatter/gather segments to physical segments. */
    int new_segs, nr_psegs = 0;
    phys_seg_t phys_seg[BLKIF_MAX_SEGMENTS_PER_REQUEST + 1];

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
        fas      = req->frame_and_sects[i];
        buffer   = (fas & PAGE_MASK) | (blkif_first_sect(fas) << 9);
        nr_sects = blkif_last_sect(fas) - blkif_first_sect(fas) + 1;

        if ( nr_sects <= 0 )
            goto bad_descriptor;

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
        ASSERT(nr_psegs <= (BLKIF_MAX_SEGMENTS_PER_REQUEST+1));
    }

    /* Nonsensical zero-sized request? */
    if ( unlikely(nr_psegs == 0) )
        goto bad_descriptor;

    if ( operation == READ )
        remap_prot = _PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW;
    else
        remap_prot = _PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED;

    for ( i = 0; i < nr_psegs; i++ )
    {
        mcl[i].op = __HYPERVISOR_update_va_mapping_otherdomain;
        mcl[i].args[0] = MMAP_VADDR(pending_idx, i) >> PAGE_SHIFT;
        mcl[i].args[1] = (phys_seg[i].buffer & PAGE_MASK) | remap_prot;
        mcl[i].args[2] = 0;
        mcl[i].args[3] = blkif->domid;

        phys_to_machine_mapping[__pa(MMAP_VADDR(pending_idx, i))>>PAGE_SHIFT] =
            FOREIGN_FRAME(phys_seg[i].buffer >> PAGE_SHIFT);
    }

    if ( unlikely(HYPERVISOR_multicall(mcl, nr_psegs) != 0) )
        BUG();

    for ( i = 0; i < nr_psegs; i++ )
    {
        if ( unlikely(mcl[i].args[5] != 0) )
        {
            DPRINTK("invalid buffer -- could not remap it\n");
            fast_flush_area(pending_idx, nr_psegs);
            goto bad_descriptor;
        }
    }

    pending_req = &pending_reqs[pending_idx];
    pending_req->blkif     = blkif;
    pending_req->id        = req->id;
    pending_req->operation = operation;
    pending_req->status    = BLKIF_RSP_OKAY;
    pending_req->nr_pages  = nr_psegs;
    atomic_set(&pending_req->pendcnt, nr_psegs);
    pending_cons++;

    blkif_get(blkif);

    /* Now we pass each segment down to the real blkdev layer. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    for ( i = 0; i < nr_psegs; i++ )
    {
        struct buffer_head *bh;

        bh = kmem_cache_alloc(buffer_head_cachep, GFP_ATOMIC);
        if ( unlikely(bh == NULL) )
        {
            __end_block_io_op(pending_req, 0);
            continue;
        }

        memset(bh, 0, sizeof (struct buffer_head));

        init_waitqueue_head(&bh->b_wait);
        bh->b_size          = phys_seg[i].nr_sects << 9;
        bh->b_dev           = phys_seg[i].dev;
        bh->b_rdev          = phys_seg[i].dev;
        bh->b_rsector       = (unsigned long)phys_seg[i].sector_number;
        bh->b_data          = (char *)MMAP_VADDR(pending_idx, i) +
            (phys_seg[i].buffer & ~PAGE_MASK);
        bh->b_page          = virt_to_page(MMAP_VADDR(pending_idx, i));
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
#else
    for ( i = 0; i < nr_psegs; i++ )
    {
        struct bio *bio;
        struct bio_vec *bv;

        bio = bio_alloc(GFP_ATOMIC, 1);
        if ( unlikely(bio == NULL) )
        {
            __end_block_io_op(pending_req, 0);
            continue;
        }

        bio->bi_bdev    = phys_seg[i].bdev;
        bio->bi_private = pending_req;
        bio->bi_end_io  = end_block_io_op;
        bio->bi_sector  = phys_seg[i].sector_number;
        bio->bi_rw      = operation;

        bv = bio_iovec_idx(bio, 0);
        bv->bv_page   = virt_to_page(MMAP_VADDR(pending_idx, i));
        bv->bv_len    = phys_seg[i].nr_sects << 9;
        bv->bv_offset = phys_seg[i].buffer & ~PAGE_MASK;

        bio->bi_size    = bv->bv_len;
        bio->bi_vcnt++;

        submit_bio(operation, bio);
    }
#endif

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
        ring[MASK_BLKIF_IDX(blkif->blk_resp_prod)].resp;
    resp->id        = id;
    resp->operation = op;
    resp->status    = st;
    wmb(); /* Ensure other side can see the response fields. */
    blkif->blk_ring_base->resp_prod = ++blkif->blk_resp_prod;
    spin_unlock_irqrestore(&blkif->blk_ring_lock, flags);

    /* Kick the relevant domain. */
    notify_via_evtchn(blkif->evtchn);
}

void blkif_deschedule(blkif_t *blkif)
{
    remove_from_blkdev_list(blkif);
}

static int __init blkif_init(void)
{
    int i;

    if ( !(xen_start_info.flags & SIF_INITDOMAIN) &&
         !(xen_start_info.flags & SIF_BLK_BE_DOMAIN) )
        return 0;

    blkif_interface_init();

    if ( (mmap_vstart = allocate_empty_lowmem_region(MMAP_PAGES)) == 0 )
        BUG();

    pending_cons = 0;
    pending_prod = MAX_PENDING_REQS;
    memset(pending_reqs, 0, sizeof(pending_reqs));
    for ( i = 0; i < MAX_PENDING_REQS; i++ )
        pending_ring[i] = i;
    
    spin_lock_init(&blkio_schedule_list_lock);
    INIT_LIST_HEAD(&blkio_schedule_list);

    if ( kernel_thread(blkio_schedule, 0, CLONE_FS | CLONE_FILES) < 0 )
        BUG();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    buffer_head_cachep = kmem_cache_create(
        "buffer_head_cache", sizeof(struct buffer_head),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
#endif

    blkif_ctrlif_init();

    return 0;
}

__initcall(blkif_init);
