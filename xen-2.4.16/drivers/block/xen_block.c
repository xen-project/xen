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
#include <xeno/interrupt.h>

#define XEN_BLK_DEBUG 0
#define XEN_BLK_DEBUG_LEVEL KERN_ALERT

typedef struct blk_request
{
    struct buffer_head *bh;
    void               *id;
    struct task_struct *domain;
} blk_request_t;

#define MAX_PENDING_REQS 32
#define BATCH_PER_DOMAIN 8

static kmem_cache_t *blk_request_cachep;
static atomic_t nr_pending;

static void io_schedule(unsigned long unused);
static int do_block_io_op_domain(struct task_struct* task, int max_to_do);
static void dispatch_rw_block_io(struct task_struct *p, int index);
static void dispatch_probe_block_io(struct task_struct *p, int index);
static void dispatch_debug_block_io(struct task_struct *p, int index);


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
    }
    spin_unlock_irqrestore(&io_schedule_list_lock, flags);
}

static void add_to_blkdev_list(struct task_struct *p)
{
    unsigned long flags;
    if ( __on_blkdev_list(p) ) return;
    spin_lock_irqsave(&io_schedule_list_lock, flags);
    if ( !__on_blkdev_list(p) )
    {
        list_add(&p->blkdev_list, &io_schedule_list);
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

    while ( (atomic_read(&nr_pending) < MAX_PENDING_REQS) &&
            !list_empty(&io_schedule_list) )
    {
        ent = io_schedule_list.next;
        p = list_entry(ent, struct task_struct, blkdev_list);
        remove_from_blkdev_list(p);
        if ( do_block_io_op_domain(p, BATCH_PER_DOMAIN) )
            add_to_blkdev_list_tail(p);
    }
}

static void maybe_trigger_io_schedule(void)
{
    if ( (atomic_read(&nr_pending) < (MAX_PENDING_REQS/2)) &&
         !list_empty(&io_schedule_list) )
    {
        tasklet_schedule(&io_schedule_tasklet);
    }
}



/******************************************************************
 * COMPLETION CALLBACK -- XXX Hook properly into bh->b_end_io
 */

void end_block_io_op(struct buffer_head * bh)
{
    unsigned long cpu_mask;
    blk_request_t *blk_request = NULL;
    unsigned long flags;
    struct task_struct *p;
    int position = 0;
    blk_ring_t *blk_ring;

    if ( XEN_BLK_DEBUG )  
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

    maybe_trigger_io_schedule();

    return;

 bad_interrupt:
    printk (KERN_ALERT
            "   block io interrupt received for unknown buffer [0x%lx]\n",
            (unsigned long) bh);
    BUG();
    return;
}



/******************************************************************
 * GUEST-OS SYSCALL -- Indicates there are requests outstanding.
 */

long do_block_io_op(void)
{
    add_to_blkdev_list_tail(current);
    maybe_trigger_io_schedule();
    return 0L;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */

static int do_block_io_op_domain(struct task_struct* task, int max_to_do)
{
    blk_ring_t *blk_ring = task->blk_ring_base;
    int loop, more_to_do = 0;

    if (XEN_BLK_DEBUG)  
	printk(XEN_BLK_DEBUG_LEVEL "XEN do_block_io_op %d %d\n",
	       blk_ring->req_cons, blk_ring->req_prod);

    for ( loop = blk_ring->req_cons; 
	  loop != blk_ring->req_prod; 
	  loop = BLK_REQ_RING_INC(loop) ) 
    {
        if ( max_to_do-- == 0 )
        {
            more_to_do = 1;
            break;
        }
        
	switch (blk_ring->req_ring[loop].operation)
        {
	case XEN_BLOCK_READ:
	case XEN_BLOCK_WRITE:
	    dispatch_rw_block_io(task, loop);
	    break;

	case XEN_BLOCK_PROBE:
	    dispatch_probe_block_io(task, loop);
	    break;

	case XEN_BLOCK_DEBUG:
	    dispatch_debug_block_io(task, loop);
	    break;

	default:
	    printk (KERN_ALERT "error: unknown block io operation [%d]\n",
		    blk_ring->req_ring[loop].operation);
	    BUG();
	}
    }

    blk_ring->req_cons = loop;
    return more_to_do;
}

static void dispatch_debug_block_io(struct task_struct *p, int index)
{
    printk (KERN_ALERT "dispatch_debug_block_io: UNIMPL\n"); 
}

static void dispatch_probe_block_io(struct task_struct *p, int index)
{
    extern void ide_probe_devices(xen_disk_info_t *xdi);
    blk_ring_t *blk_ring = p->blk_ring_base;
    xen_disk_info_t *xdi;
    
    xdi = phys_to_virt((unsigned long)blk_ring->req_ring[index].buffer);
    
    ide_probe_devices(xdi);

    blk_ring->resp_ring[blk_ring->resp_prod].id = blk_ring->req_ring[index].id;
    blk_ring->resp_ring[blk_ring->resp_prod].status = 0;
    blk_ring->resp_prod = BLK_RESP_RING_INC(blk_ring->resp_prod);
}

static void dispatch_rw_block_io(struct task_struct *p, int index)
{
    extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]); 
    blk_ring_t *blk_ring = p->blk_ring_base;
    struct buffer_head *bh;
    struct request_queue *rq;
    int operation;
    blk_request_t *blk_request;
    
    /*
     * check to make sure that the block request seems at least
     * a bit legitimate
     */
    if ( (blk_ring->req_ring[index].block_size & (0x200 - 1)) != 0 )
    {
	printk(KERN_ALERT "    error: dodgy block size: %d\n", 
	       blk_ring->req_ring[index].block_size);
	BUG();
    }
    
    if ( blk_ring->req_ring[index].buffer == NULL )
    { 
	printk(KERN_ALERT "xen_block: bogus buffer from guestOS\n"); 
	BUG();
    }

    if (XEN_BLK_DEBUG)
	printk(XEN_BLK_DEBUG_LEVEL "    req_cons: %d  req_prod %d  index: %d "
	       "op: %s, pri: %s\n", blk_ring->req_cons, blk_ring->req_prod, 
	       index, 
	       (blk_ring->req_ring[index].operation == XEN_BLOCK_READ ? 
		"read" : "write"), 
	       (blk_ring->req_ring[index].priority == XEN_BLOCK_SYNC ? 
		"sync" : "async"));

    atomic_inc(&nr_pending);
    blk_request = kmem_cache_alloc(blk_request_cachep, GFP_ATOMIC);

    /* we'll be doing this frequently, would a cache be appropriate? */
    bh = (struct buffer_head *) kmalloc(sizeof(struct buffer_head), 
					GFP_KERNEL);
    if ( bh == NULL )
    {
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
    
    if (blk_ring->req_ring[index].operation == XEN_BLOCK_WRITE)
    {
	bh->b_state = ((1 << BH_JBD) | (1 << BH_Mapped) | (1 << BH_Req) |
		       (1 << BH_Dirty) | (1 << BH_Uptodate));
	operation = WRITE;
    } 
    else
    {
	bh->b_state = (1 << BH_Mapped);
	operation = READ;
    }

    /* save meta data about request */
    blk_request->id     = blk_ring->req_ring[index].id;
    blk_request->bh     = bh;
    blk_request->domain = p; 
    
    /* dispatch single block request */
    ll_rw_block(operation, 1, &bh);       /* linux top half */
    rq = blk_get_queue(bh->b_rdev);                         
    generic_unplug_device(rq);            /* linux bottom half */
}



/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */

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
    remove_from_blkdev_list(p);
    UNSHARE_PFN(virt_to_page(p->blk_ring_base));
    free_page((unsigned long)p->blk_ring_base);
}

void initialize_block_io ()
{
    atomic_set(&nr_pending, 0);

    spin_lock_init(&io_schedule_list_lock);
    INIT_LIST_HEAD(&io_schedule_list);

    blk_request_cachep = kmem_cache_create(
        "blk_request_cache", sizeof(blk_request_t),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    
    add_key_handler('b', dump_blockq, "dump xen ide blkdev stats");     
}



