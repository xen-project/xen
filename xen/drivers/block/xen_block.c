/******************************************************************************
 * xen_block.c
 *
 * process incoming block io requests from guestos's.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/blkdev.h>
#include <xen/event.h>
#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <asm-i386/io.h>
#include <asm/domain_page.h>
#include <xen/spinlock.h>
#include <xen/keyhandler.h>
#include <xen/interrupt.h>
#include <xen/vbd.h>
#include <xen/slab.h>
#include <xen/shadow.h>

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

static struct buffer_head *completed_bhs[NR_CPUS] __cacheline_aligned;

static int lock_buffer(struct task_struct *p,
                       unsigned long buffer,
                       unsigned short size,
                       int writeable_buffer);
static void unlock_buffer(unsigned long buffer,
                          unsigned short size,
                          int writeable_buffer);

static void io_schedule(unsigned long unused);
static int do_block_io_op_domain(struct task_struct *p, int max_to_do);
static void dispatch_rw_block_io(struct task_struct *p, 
                                 blk_ring_req_entry_t *req);
static void make_response(struct task_struct *p, unsigned long id, 
                          unsigned short op, unsigned long st);


/******************************************************************
 * BLOCK-DEVICE SCHEDULER LIST MAINTENANCE
 */

static struct list_head io_schedule_list;
static spinlock_t io_schedule_list_lock;

static int __on_blkdev_list(struct task_struct *p)
{
    return p->blkdev_list.next != NULL;
}

static void remove_from_blkdev_list(struct task_struct *p)
{
    unsigned long flags;
    if ( !__on_blkdev_list(p) ) return;
    spin_lock_irqsave(&io_schedule_list_lock, flags);
    if ( __on_blkdev_list(p) )
    {
        list_del(&p->blkdev_list);
        p->blkdev_list.next = NULL;
        put_task_struct(p);
    }
    spin_unlock_irqrestore(&io_schedule_list_lock, flags);
}

static void add_to_blkdev_list_tail(struct task_struct *p)
{
    unsigned long flags;
    if ( __on_blkdev_list(p) ) return;
    spin_lock_irqsave(&io_schedule_list_lock, flags);
    if ( !__on_blkdev_list(p) )
    {
        list_add_tail(&p->blkdev_list, &io_schedule_list);
        get_task_struct(p);
    }
    spin_unlock_irqrestore(&io_schedule_list_lock, flags);
}


/******************************************************************
 * SCHEDULER FUNCTIONS
 */

static DECLARE_TASKLET(io_schedule_tasklet, io_schedule, 0);

static void io_schedule(unsigned long unused)
{
    struct task_struct *p;
    struct list_head *ent;

    /* Queue up a batch of requests. */
    while ( (NR_PENDING_REQS < MAX_PENDING_REQS) &&
            !list_empty(&io_schedule_list) )
    {
        ent = io_schedule_list.next;
        p = list_entry(ent, struct task_struct, blkdev_list);
        get_task_struct(p);
        remove_from_blkdev_list(p);
        if ( do_block_io_op_domain(p, BATCH_PER_DOMAIN) )
            add_to_blkdev_list_tail(p);
        put_task_struct(p);
    }

    /* Push the batch through to disc. */
    run_task_queue(&tq_disk);
}

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

static void end_block_io_op_softirq(struct softirq_action *h)
{
    pending_req_t *pending_req;
    struct buffer_head *bh, *nbh;
    unsigned int cpu = smp_processor_id();

    local_irq_disable();
    bh = completed_bhs[cpu];
    completed_bhs[cpu] = NULL;
    local_irq_enable();

    while ( bh != NULL )
    {
        pending_req = bh->pending_req;
        
        unlock_buffer(virt_to_phys(bh->b_data), 
                      bh->b_size, 
                      (pending_req->operation==READ));
        
        if ( atomic_dec_and_test(&pending_req->pendcnt) )
        {
            make_response(pending_req->domain, pending_req->id,
                          pending_req->operation, pending_req->status);
            put_task_struct(pending_req->domain);
            spin_lock(&pend_prod_lock);
            pending_ring[MASK_PEND_IDX(pending_prod)] = 
                pending_req - pending_reqs;
            pending_prod++;
            spin_unlock(&pend_prod_lock);
            maybe_trigger_io_schedule();
        }
        
        nbh = bh->b_reqnext;
        kmem_cache_free(buffer_head_cachep, bh);
        bh = nbh;
    }
}

static void end_block_io_op(struct buffer_head *bh, int uptodate)
{
    unsigned long flags;
    unsigned int cpu = smp_processor_id();

    /* An error fails the entire request. */
    if ( !uptodate )
    {
        DPRINTK("Buffer not up-to-date at end of operation\n");
        bh->pending_req->status = 2;
    }

    local_irq_save(flags);
    bh->b_reqnext = completed_bhs[cpu];
    completed_bhs[cpu] = bh;
    local_irq_restore(flags);

    __cpu_raise_softirq(cpu, BLKDEV_RESPONSE_SOFTIRQ);
}


/* ----[ Syscall Interface ]------------------------------------------------*/

long do_block_io_op(block_io_op_t *u_block_io_op)
{
    long ret = 0;
    block_io_op_t op; 
    struct task_struct *p = current;

    if ( unlikely(copy_from_user(&op, u_block_io_op, sizeof(op)) != 0) )
        return -EFAULT;

    switch ( op.cmd )
    {
    case BLOCK_IO_OP_SIGNAL: 
	/* simply indicates there're reqs outstanding => add current to list */
	add_to_blkdev_list_tail(p);
	maybe_trigger_io_schedule();
	break; 

    case BLOCK_IO_OP_RESET:
        /* Avoid a race with the tasklet. */
        remove_from_blkdev_list(p);
        if ( p->blk_req_cons != p->blk_resp_prod )
        {
            /* Interface isn't quiescent. */
            ret = -EINVAL;
        }
        else
        {
            p->blk_req_cons = p->blk_resp_prod = 0;
            ret = 0;
        }
        break;

    case BLOCK_IO_OP_RING_ADDRESS:
        op.u.ring_mfn = virt_to_phys(p->blk_ring_base) >> PAGE_SHIFT;
        ret = copy_to_user(u_block_io_op, &op, sizeof(op)) ? -EFAULT : 0;
        break;

    case BLOCK_IO_OP_VBD_CREATE:  
	/* create a new VBD */
	ret = vbd_create(&op.u.create_params); 
	break; 

    case BLOCK_IO_OP_VBD_GROW:  
	/* append an extent to a VBD */
	ret = vbd_grow(&op.u.grow_params); 
	break; 

    case BLOCK_IO_OP_VBD_SHRINK:  
	/* remove teh final extent from a VBD */
	ret = vbd_shrink(&op.u.shrink_params); 
	break; 

    case BLOCK_IO_OP_VBD_SET_EXTENTS:  
	/* a fresh extent list for the given VBD */
	ret = vbd_setextents(&op.u.setextents_params); 
	break; 

    case BLOCK_IO_OP_VBD_DELETE:  
	/* delete a VBD */
	ret = vbd_delete(&op.u.delete_params); 
	break; 

    case BLOCK_IO_OP_VBD_PROBE: 
	/* query VBD information for self or others (or all) */
	if ( (ret = vbd_probe(&op.u.probe_params)) == 0 )
	    copy_to_user(u_block_io_op, &op, sizeof(op)); 
	break;

    case BLOCK_IO_OP_VBD_INFO: 
	/* query information about a particular VBD */
        if ( (ret = vbd_info(&op.u.info_params)) == 0 ) 
	    copy_to_user(u_block_io_op, &op, sizeof(op)); 
	break; 
        
    default: 
	ret = -ENOSYS; 
    } 

    return ret;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */

static int lock_buffer(struct task_struct *p,
                       unsigned long buffer,
                       unsigned short size,
                       int writeable_buffer)
{
    unsigned long    pfn;
    struct pfn_info *page;

    for ( pfn = buffer >> PAGE_SHIFT; 
          pfn < ((buffer + size + PAGE_SIZE - 1) >> PAGE_SHIFT);
          pfn++ )
    {
        if ( unlikely(pfn >= max_page) )
            goto fail;

        page = &frame_table[pfn];

        if ( unlikely(!get_page(page, p)) )
            goto fail;

        if ( writeable_buffer && 
             unlikely(!get_page_type(page, PGT_writeable_page)) )
        {
            put_page(page);
            goto fail;
        }
    }

    return 1;

 fail:
    while ( pfn-- > (buffer >> PAGE_SHIFT) )
    {        
        if ( writeable_buffer )
            put_page_type(&frame_table[pfn]);
        put_page(&frame_table[pfn]);
    }
    return 0;
}

static void unlock_buffer(unsigned long buffer,
                          unsigned short size,
                          int writeable_buffer)
{
    unsigned long pfn;

    for ( pfn = buffer >> PAGE_SHIFT; 
          pfn < ((buffer + size + PAGE_SIZE - 1) >> PAGE_SHIFT);
          pfn++ )
    {

	/* Find the domain from the frame_table. Yuk... */
	struct task_struct *p = frame_table[pfn].u.domain;

	if( p->mm.shadow_mode == SHM_logdirty )
	    mark_dirty( &p->mm, pfn );	


        if ( writeable_buffer )
            put_page_type(&frame_table[pfn]);
        put_page(&frame_table[pfn]);

    }
}

static int do_block_io_op_domain(struct task_struct *p, int max_to_do)
{
    blk_ring_t *blk_ring = p->blk_ring_base;
    blk_ring_req_entry_t *req;
    BLK_RING_IDX i;
    int more_to_do = 0;

    /* Take items off the comms ring, taking care not to overflow. */
    for ( i = p->blk_req_cons; 
	  (i != blk_ring->req_prod) && ((i-p->blk_resp_prod) != BLK_RING_SIZE);
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
	case XEN_BLOCK_READ:
	case XEN_BLOCK_WRITE:
	    dispatch_rw_block_io(p, req);
	    break;

	default:
            DPRINTK("error: unknown block io operation [%d]\n",
                    blk_ring->ring[i].req.operation);
            make_response(p, blk_ring->ring[i].req.id, 
                          blk_ring->ring[i].req.operation, 1);
            break;
	}
    }

    p->blk_req_cons = i;
    return more_to_do;
}

static void dispatch_rw_block_io(struct task_struct *p, 
                                 blk_ring_req_entry_t *req)
{
    extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]); 
    struct buffer_head *bh;
    int operation = (req->operation == XEN_BLOCK_WRITE) ? WRITE : READ;
    unsigned short nr_sects;
    unsigned long buffer;
    int i, tot_sects;
    pending_req_t *pending_req;

    /* We map virtual scatter/gather segments to physical segments. */
    int new_segs, nr_psegs = 0;
    phys_seg_t phys_seg[MAX_BLK_SEGS * 2];

    /* Check that number of segments is sane. */
    if ( unlikely(req->nr_segments == 0) || 
         unlikely(req->nr_segments > MAX_BLK_SEGS) )
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
        {
            DPRINTK("zero-sized data request\n");
            goto bad_descriptor;
        }

	phys_seg[nr_psegs].dev           = req->device;
	phys_seg[nr_psegs].sector_number = req->sector_number + tot_sects;
	phys_seg[nr_psegs].buffer        = buffer;
	phys_seg[nr_psegs].nr_sects      = nr_sects;

        /* Translate the request into the relevant 'physical device' */
	new_segs = vbd_translate(&phys_seg[nr_psegs], p, operation);
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
        ASSERT(nr_psegs <= MAX_BLK_SEGS*2);
    }

    for ( i = 0; i < nr_psegs; i++ )
    {
        if ( unlikely(!lock_buffer(p, phys_seg[i].buffer, 
                                   phys_seg[i].nr_sects << 9,
                                   operation==READ)) )
	{
            DPRINTK("invalid buffer\n");
            while ( i-- > 0 )
                unlock_buffer(phys_seg[i].buffer, 
                              phys_seg[i].nr_sects << 9,
                              operation==READ);
            goto bad_descriptor;
	}
    }

    pending_req = &pending_reqs[pending_ring[MASK_PEND_IDX(pending_cons++)]];
    pending_req->domain    = p;
    pending_req->id        = req->id;
    pending_req->operation = operation;
    pending_req->status    = 0;
    atomic_set(&pending_req->pendcnt, nr_psegs);

    get_task_struct(p);

    /* Now we pass each segment down to the real blkdev layer. */
    for ( i = 0; i < nr_psegs; i++ )
    {
        bh = kmem_cache_alloc(buffer_head_cachep, GFP_KERNEL);
        if ( unlikely(bh == NULL) )
            panic("bh is null\n");
        memset(bh, 0, sizeof (struct buffer_head));
    
        bh->b_size          = phys_seg[i].nr_sects << 9;
        bh->b_dev           = phys_seg[i].dev;
        bh->b_rsector       = (unsigned long)phys_seg[i].sector_number;

	/* SMH: we store a 'pseudo-virtual' bogus address in b_data since
	   later code will undo this transformation (i.e. +-PAGE_OFFSET). */
        bh->b_data          = phys_to_virt(phys_seg[i].buffer);
	
	/* SMH: bh_phys() uses the below field as a 'cheap' virt_to_phys */
	bh->b_page          = &frame_table[phys_seg[i].buffer>>PAGE_SHIFT]; 
        bh->b_end_io        = end_block_io_op;
        bh->pending_req     = pending_req;

        if ( operation == WRITE )
        {
            bh->b_state = (1 << BH_JBD) | (1 << BH_Mapped) | (1 << BH_Req) |
                (1 << BH_Dirty) | (1 << BH_Uptodate) | (1 << BH_Write);
        } 
        else
        {
            bh->b_state = (1 << BH_Mapped) | (1 << BH_Read);
        }

        /* Dispatch a single request. We'll flush it to disc later. */
        ll_rw_block(operation, 1, &bh);
    }

    return;

 bad_descriptor:
    make_response(p, req->id, req->operation, 1);
} 



/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */


static void make_response(struct task_struct *p, unsigned long id, 
			  unsigned short op, unsigned long st)
{
    blk_ring_resp_entry_t *resp;

    /* Place on the response ring for the relevant domain. */ 
    spin_lock(&p->blk_ring_lock);
    resp = &p->blk_ring_base->ring[MASK_BLK_IDX(p->blk_resp_prod)].resp;
    resp->id        = id;
    resp->operation = op;
    resp->status    = st;
    wmb();
    p->blk_ring_base->resp_prod = ++p->blk_resp_prod;
    spin_unlock(&p->blk_ring_lock);
    
    /* Kick the relevant domain. */
    send_guest_virq(p, VIRQ_BLKDEV);
}

static void dump_blockq(u_char key, void *dev_id, struct pt_regs *regs) 
{
    unsigned long flags;
    struct task_struct *p;
    blk_ring_t *blk_ring;
    int i;

    printk("Dumping block queue stats: nr_pending = %d"
           " (prod=0x%08x,cons=0x%08x)\n",
           NR_PENDING_REQS, pending_prod, pending_cons);

    read_lock_irqsave(&tasklist_lock, flags);
    for_each_domain ( p )
    {
        printk("Domain: %llu\n", p->domain);
        blk_ring = p->blk_ring_base;
        printk("  req_prod:0x%08x, req_cons:0x%08x resp_prod:0x%08x/"
               "0x%08x on_list=%d\n",
               blk_ring->req_prod, p->blk_req_cons,
               blk_ring->resp_prod, p->blk_resp_prod,
               __on_blkdev_list(p));
    }
    read_unlock_irqrestore(&tasklist_lock, flags);

    for ( i = 0; i < MAX_PENDING_REQS; i++ )
    {
        printk("Pend%d: dom=%p, id=%08lx, cnt=%d, op=%d, status=%d\n",
               i, pending_reqs[i].domain, pending_reqs[i].id,
               atomic_read(&pending_reqs[i].pendcnt), 
               pending_reqs[i].operation, pending_reqs[i].status);
    }
}

/* Start-of-day initialisation for a new domain. */
void init_blkdev_info(struct task_struct *p)
{
    if ( unlikely(sizeof(*p->blk_ring_base) > PAGE_SIZE) )
        BUG();

    p->blk_ring_base = (blk_ring_t *)get_free_page(GFP_KERNEL);
    clear_page(p->blk_ring_base);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(p->blk_ring_base), p);

    machine_to_phys_mapping[virt_to_phys(p->blk_ring_base)>>PAGE_SHIFT] =
	0x80000002; // magic value aids debugging

    p->blkdev_list.next = NULL;
    spin_lock_init(&p->vbd_lock);
}

/* End-of-day teardown for a domain. */
void destroy_blkdev_info(struct task_struct *p)
{
    ASSERT(!__on_blkdev_list(p));
    UNSHARE_PFN(virt_to_page(p->blk_ring_base));
    destroy_all_vbds(p);
}

void unlink_blkdev_info(struct task_struct *p)
{
    unsigned long flags;

    spin_lock_irqsave(&io_schedule_list_lock, flags);
    if ( __on_blkdev_list(p) )
    {
        list_del(&p->blkdev_list);
        p->blkdev_list.next = (void *)0xdeadbeef; /* prevent reinsertion */
        put_task_struct(p);
    }
    spin_unlock_irqrestore(&io_schedule_list_lock, flags);
}

void initialize_block_io ()
{
    int i;

    pending_cons = 0;
    pending_prod = MAX_PENDING_REQS;
    memset(pending_reqs, 0, sizeof(pending_reqs));
    for ( i = 0; i < MAX_PENDING_REQS; i++ )
        pending_ring[i] = i;
    
    for ( i = 0; i < NR_CPUS; i++ )
        completed_bhs[i] = NULL;
        
    open_softirq(BLKDEV_RESPONSE_SOFTIRQ, end_block_io_op_softirq, NULL);

    spin_lock_init(&io_schedule_list_lock);
    INIT_LIST_HEAD(&io_schedule_list);

    buffer_head_cachep = kmem_cache_create(
        "buffer_head_cache", sizeof(struct buffer_head),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);

    add_key_handler('b', dump_blockq, "dump xen ide blkdev statistics");
}
