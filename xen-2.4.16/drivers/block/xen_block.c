/*
 * xen-block.c
 *
 * process incoming block io requests from guestos's.
 */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/sched.h>
#include <xeno/blkdev.h>
#include <xeno/event.h>
#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <asm-i386/io.h>
#include <asm/spinlock.h>
#include <xeno/keyhandler.h>

#define XEN_BLK_DEBUG 0
#define XEN_BLK_DEBUG_LEVEL KERN_ALERT

typedef struct blk_request {
    struct buffer_head *bh;
    void               *id;
    struct task_struct *domain;
} blk_request_t;
#define MAX_PENDING_REQS 32
#define BATCH_PER_DOMAIN 8
static kmem_cache_t *blk_request_cachep;
static atomic_t nr_pending;

static int do_block_io_op_domain(struct task_struct* task, int max_to_do);
static int dispatch_rw_block_io(int index);
static int dispatch_probe_block_io(int index);
static int dispatch_debug_block_io(int index);

static spinlock_t io_schedule_lock;
static struct list_head io_schedule_list;

static int on_blkdev_list(struct task_struct *p)
{
    return p->blkdev_list.next != NULL;
}

static void remove_from_blkdev_list(struct task_struct *p)
{
    list_del(&p->blkdev_list);
    p->blkdev_list.next = NULL;
}

static void add_to_blkdev_list(struct task_struct *p)
{
    list_add(&p->blkdev_list, &io_schedule_list);
}

static void add_to_blkdev_list_tail(struct task_struct *p)
{
    list_add_tail(&p->blkdev_list, &io_schedule_list);
}

static void io_schedule(void)
{
    struct task_struct *p;
    struct list_head *ent;

    while ( (atomic_read(&nr_pending) < (MAX_PENDING_REQS / 2)) &&
            !list_empty(&io_schedule_list) &&
            spin_trylock(&io_schedule_lock) )
    {
        while ( (atomic_read(&nr_pending) < MAX_PENDING_REQS) &&
                !list_empty(&io_schedule_list) )
        {
            ent = io_schedule_list.next;
            p = list_entry(ent, struct task_struct, blkdev_list);
            remove_from_blkdev_list(p);
            if ( do_block_io_op_domain(p, BATCH_PER_DOMAIN) )
                add_to_blkdev_list_tail(p);
        }
        spin_unlock(&io_schedule_lock);
    }
}


/*
 * end_block_io_op:
 *  IO has completed.  Need to notify the guest operating system.
 *  Called from ll_rw_block -- currently /DIRECTLY/ -- XXX FIXME 
 *  (e.g. hook into proper end processing of ll_rw) 
 */
void end_block_io_op(struct buffer_head * bh)
{
    unsigned long cpu_mask;
    blk_request_t *blk_request = NULL;
    unsigned long flags;
    struct task_struct *p;
    int position = 0;
    blk_ring_t *blk_ring;

    if (XEN_BLK_DEBUG)  
	printk(XEN_BLK_DEBUG_LEVEL "XEN end_block_io_op,  bh: %lx\n",
	       (unsigned long)bh);
    
    if ( (blk_request = (blk_request_t *)bh->b_xen_request) == NULL) 
        goto bad_interrupt;
    atomic_dec(&nr_pending);
    
    p = blk_request->domain;

    /* Place on the response ring for the relevant domain. */ 
    spin_lock_irqsave(&p->blk_ring_lock, flags);
    blk_ring = p->blk_ring_base;
    position = blk_ring->resp_prod;
    blk_ring->resp_ring[position].id     = blk_request->id;
    blk_ring->resp_ring[position].status = 0;
    blk_ring->resp_prod = BLK_RESP_RING_INC(blk_ring->resp_prod);
    spin_unlock_irqrestore(&p->blk_ring_lock, flags);
    
    /* Kick the relevant domain. */
    cpu_mask = mark_guest_event(p, _EVENT_BLK_RESP);
    guest_event_notify(cpu_mask); 

    /* Free state associated with this request. */
    if ( blk_request->bh ) 
        kfree(blk_request->bh);     
    kmem_cache_free(blk_request_cachep, blk_request);

    /* Get more work to do. */
    io_schedule();

    return;

 bad_interrupt:
    printk (KERN_ALERT
            "   block io interrupt received for unknown buffer [0x%lx]\n",
            (unsigned long) bh);
    BUG();
    return;
}


/*
 * do_block_io_op:
 *  Accept a block io request from a guest operating system.
 *  There is an entry in the hypervisor_call_table (xen/arch/i386/entry.S).
 */
long do_block_io_op(void)
{
    if ( !on_blkdev_list(current) )
    {
        spin_lock_irq(&io_schedule_lock);
        add_to_blkdev_list_tail(current);
        spin_unlock_irq(&io_schedule_lock);
    }

    io_schedule();

    return 0L;
}


static int do_block_io_op_domain(struct task_struct* task, int max_to_do)
{
    blk_ring_t *blk_ring = task->blk_ring_base;
    int loop, status = 0;

    if (XEN_BLK_DEBUG)  
	printk(XEN_BLK_DEBUG_LEVEL "XEN do_block_io_op %d %d\n",
	       blk_ring->req_cons, blk_ring->req_prod);

    for ( loop = blk_ring->req_cons; 
	  loop != blk_ring->req_prod; 
	  loop = BLK_REQ_RING_INC(loop) ) 
    {
	status = 1;

        if ( max_to_do-- == 0 ) break;
        
	switch (blk_ring->req_ring[loop].operation) {

	case XEN_BLOCK_READ:
	case XEN_BLOCK_WRITE:
	    status = dispatch_rw_block_io(loop);
	    break;

	case XEN_BLOCK_PROBE:
	    status = dispatch_probe_block_io(loop);
	    break;

	case XEN_BLOCK_DEBUG:
	    status = dispatch_debug_block_io(loop);
	    break;

	default:
	    printk (KERN_ALERT "error: unknown block io operation [%d]\n",
		    blk_ring->req_ring[loop].operation);
	    BUG();
	}

	if ( status ) break;
    }

    blk_ring->req_cons = loop;
    return status;
}


static int dispatch_debug_block_io (int index)
{
    printk (KERN_ALERT "dispatch_debug_block_io: UNIMPL\n"); 
    return 1; 
}


static int dispatch_probe_block_io (int index)
{
    extern void ide_probe_devices(xen_disk_info_t *xdi);
    blk_ring_t *blk_ring = current->blk_ring_base;
    xen_disk_info_t *xdi;
    
    xdi = phys_to_virt((unsigned long)blk_ring->req_ring[index].buffer);
    
    ide_probe_devices(xdi);

    blk_ring->resp_ring[blk_ring->resp_prod].id = blk_ring->req_ring[index].id;
    blk_ring->resp_ring[blk_ring->resp_prod].status = 0;
    blk_ring->resp_prod = BLK_RESP_RING_INC(blk_ring->resp_prod);
    
    return 0;
}


static int dispatch_rw_block_io (int index)
{
    extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]); 
    blk_ring_t *blk_ring = current->blk_ring_base;
    struct buffer_head *bh;
    struct request_queue *rq;
    int operation;
    blk_request_t *blk_request;
    
    /*
     * check to make sure that the block request seems at least
     * a bit legitimate
     */
    if ((blk_ring->req_ring[index].block_size & (0x200 - 1)) != 0) {
	printk(KERN_ALERT "    error: dodgy block size: %d\n", 
	       blk_ring->req_ring[index].block_size);
	BUG();
    }
    
    if(blk_ring->req_ring[index].buffer == NULL) { 
	printk(KERN_ALERT "xen_block: bogus buffer from guestOS\n"); 
	BUG();
    }

    if (XEN_BLK_DEBUG) {
	printk(XEN_BLK_DEBUG_LEVEL "    req_cons: %d  req_prod %d  index: %d "
	       "op: %s, pri: %s\n", blk_ring->req_cons, blk_ring->req_prod, 
	       index, 
	       (blk_ring->req_ring[index].operation == XEN_BLOCK_READ ? 
		"read" : "write"), 
	       (blk_ring->req_ring[index].priority == XEN_BLOCK_SYNC ? 
		"sync" : "async"));
    }

    /* XXX KAF: A bit racey maybe? The whole wake-up pending needs fixing. */
    if ( atomic_read(&nr_pending) >= MAX_PENDING_REQS )
        return 1;
    atomic_inc(&nr_pending);
    blk_request = kmem_cache_alloc(blk_request_cachep, GFP_ATOMIC);

    /* we'll be doing this frequently, would a cache be appropriate? */
    bh = (struct buffer_head *) kmalloc(sizeof(struct buffer_head), 
					GFP_KERNEL);
    if (!bh) {
	printk(KERN_ALERT "ERROR: bh is null\n");
	BUG();
    }

    /* set just the important bits of the buffer header */
    memset (bh, 0, sizeof (struct buffer_head));
    
    bh->b_blocknr       = blk_ring->req_ring[index].block_number;
    bh->b_size          = blk_ring->req_ring[index].block_size; 
    bh->b_dev           = blk_ring->req_ring[index].device; 
    bh->b_rsector       = blk_ring->req_ring[index].sector_number;
    bh->b_data          = phys_to_virt((unsigned long)
				       blk_ring->req_ring[index].buffer);
    bh->b_count.counter = 1;
    bh->b_xen_request   = (void *)blk_request;  
    
    if (blk_ring->req_ring[index].operation == XEN_BLOCK_WRITE) {
	bh->b_state = ((1 << BH_JBD) | (1 << BH_Mapped) | (1 << BH_Req) |
		       (1 << BH_Dirty) | (1 << BH_Uptodate));
	operation = WRITE;
    } else {
	bh->b_state = (1 << BH_Mapped);
	operation = READ;
    }

    /* save meta data about request */
    blk_request->id     = blk_ring->req_ring[index].id;
    blk_request->bh     = bh;
    blk_request->domain = current; 
    
    /* dispatch single block request */
    ll_rw_block(operation, 1, &bh);       /* linux top half */
    rq = blk_get_queue(bh->b_rdev);                         
    generic_unplug_device(rq);            /* linux bottom half */

    return 0;
}


static void dump_blockq(u_char key, void *dev_id, struct pt_regs *regs) 
{
    printk("Dumping block queue stats: nr_pending = %d\n",
           atomic_read(&nr_pending));
}


/* Start-of-day initialisation for a new domain. */
void init_blkdev_info(struct task_struct *p)
{
    if ( sizeof(*p->blk_ring_base) > PAGE_SIZE ) BUG();
    p->blk_ring_base = (blk_ring_t *)get_free_page(GFP_KERNEL);
    clear_page(p->blk_ring_base);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(p->blk_ring_base), p->domain);
    p->blkdev_list.next = NULL;
}


/* End-of-day teardown for a domain. XXX Outstanding requests? */
void destroy_blkdev_info(struct task_struct *p)
{
    unsigned long flags;
    if ( on_blkdev_list(p) )
    {
        spin_lock_irqsave(&io_schedule_lock, flags);
        if ( on_blkdev_list(p) ) remove_from_blkdev_list(p);
        spin_unlock_irqrestore(&io_schedule_lock, flags);
    }
    UNSHARE_PFN(virt_to_page(p->blk_ring_base));
    free_page((unsigned long)p->blk_ring_base);
}


void initialize_block_io ()
{
    atomic_set(&nr_pending, 0);

    spin_lock_init(&io_schedule_lock);
    INIT_LIST_HEAD(&io_schedule_list);

    blk_request_cachep = kmem_cache_create(
        "blk_request_cache", sizeof(blk_request_t),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    
    add_key_handler('b', dump_blockq, "dump xen ide blkdev stats");     
}



