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

#if 1
#define DPRINTK(_f, _a...) printk( _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

/*
 * These are rather arbitrary. They are fairly large because adjacent
 * requests pulled from a communication ring are quite likely to end
 * up being part of the same scatter/gather request at the disc.
 * It might be a good idea to add scatter/gather support explicitly to
 * the scatter/gather ring (eg. each request has an array of N pointers);
 * then these values would better reflect real costs at the disc.
 */
#define MAX_PENDING_REQS 32
#define BATCH_PER_DOMAIN 8

static kmem_cache_t *buffer_head_cachep;
static atomic_t nr_pending;

static void io_schedule(unsigned long unused);
static int do_block_io_op_domain(struct task_struct *p, int max_to_do);
static void dispatch_rw_block_io(struct task_struct *p, int index);
static void dispatch_probe_block_io(struct task_struct *p, int index);
static void dispatch_debug_block_io(struct task_struct *p, int index);
static void make_response(struct task_struct *p, void *id, unsigned long st);


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

    /* Queue up a batch of requests. */
    while ( (atomic_read(&nr_pending) < MAX_PENDING_REQS) &&
            !list_empty(&io_schedule_list) )
    {
        ent = io_schedule_list.next;
        p = list_entry(ent, struct task_struct, blkdev_list);
        remove_from_blkdev_list(p);
        if ( do_block_io_op_domain(p, BATCH_PER_DOMAIN) )
            add_to_blkdev_list_tail(p);
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

    if ( (atomic_read(&nr_pending) < (MAX_PENDING_REQS/2)) &&
         !list_empty(&io_schedule_list) )
    {
        tasklet_schedule(&io_schedule_tasklet);
    }
}



/******************************************************************
 * COMPLETION CALLBACK -- Called as bh->b_end_io()
 */

static void end_block_io_op(struct buffer_head *bh, int uptodate)
{
    struct pfn_info *page;
    unsigned long pfn;

    for ( pfn = virt_to_phys(bh->b_data) >> PAGE_SHIFT; 
          pfn < ((virt_to_phys(bh->b_data) + bh->b_size + PAGE_SIZE - 1) >> 
                 PAGE_SHIFT);
          pfn++ )
    {
        page = frame_table + pfn;
        if ( ((bh->b_state & (1 << BH_Read)) != 0) &&
             (put_page_type(page) == 0) )
            page->flags &= ~PG_type_mask;
        put_page_tot(page);
    }

    atomic_dec(&nr_pending);
    make_response(bh->b_xen_domain, bh->b_xen_id, uptodate ? 0 : 1);

    kmem_cache_free(buffer_head_cachep, bh);

    maybe_trigger_io_schedule();
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

static int do_block_io_op_domain(struct task_struct* p, int max_to_do)
{
    blk_ring_t *blk_ring = p->blk_ring_base;
    int i, more_to_do = 0;

    for ( i = p->blk_req_cons; 
	  i != blk_ring->req_prod; 
	  i = BLK_RING_INC(i) ) 
    {
        if ( max_to_do-- == 0 )
        {
            more_to_do = 1;
            break;
        }
        
	switch ( blk_ring->ring[i].req.operation )
        {
	case XEN_BLOCK_READ:
	case XEN_BLOCK_WRITE:
	    dispatch_rw_block_io(p, i);
	    break;

	case XEN_BLOCK_PROBE:
	    dispatch_probe_block_io(p, i);
	    break;

	case XEN_BLOCK_DEBUG:
	    dispatch_debug_block_io(p, i);
	    break;

	default:
	    panic("error: unknown block io operation [%d]\n",
                  blk_ring->ring[i].req.operation);
	}
    }

    p->blk_req_cons = i;
    return more_to_do;
}

static void dispatch_debug_block_io(struct task_struct *p, int index)
{
    DPRINTK("dispatch_debug_block_io: unimplemented\n"); 
}

static void dispatch_probe_block_io(struct task_struct *p, int index)
{
    extern void ide_probe_devices(xen_disk_info_t *xdi);
    blk_ring_t *blk_ring = p->blk_ring_base;
    xen_disk_info_t *xdi;

    xdi = phys_to_virt((unsigned long)blk_ring->ring[index].req.buffer);    
    ide_probe_devices(xdi);

    make_response(p, blk_ring->ring[index].req.id, 0);
}

static void dispatch_rw_block_io(struct task_struct *p, int index)
{
    extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]); 
    blk_ring_t *blk_ring = p->blk_ring_base;
    struct buffer_head *bh;
    int operation;
    unsigned short size;
    unsigned long buffer, pfn;
    struct pfn_info *page;

    operation = (blk_ring->ring[index].req.operation == XEN_BLOCK_WRITE) ? 
        WRITE : READ;

    /* Sectors are 512 bytes. Make sure request size is a multiple. */
    size = blk_ring->ring[index].req.block_size; 
    if ( (size == 0) || (size & (0x200 - 1)) != 0 )
    {
	DPRINTK("dodgy block size: %d\n", 
                blk_ring->ring[index].req.block_size);
        goto bad_descriptor;
    }

    /* Buffer address should be sector aligned. */
    buffer = (unsigned long)blk_ring->ring[index].req.buffer;
    if ( (buffer & (0x200 - 1)) != 0 )
    {
        DPRINTK("unaligned buffer %08lx\n", buffer);
        goto bad_descriptor;
    }

    /* A request may span multiple page frames. Each must be checked. */
    for ( pfn = buffer >> PAGE_SHIFT; 
          pfn < ((buffer + size + PAGE_SIZE - 1) >> PAGE_SHIFT);
          pfn++ )
    {
        /* Each frame must be within bounds of machine memory. */
        if ( pfn >= max_page )
        {
            DPRINTK("pfn out of range: %08lx\n", pfn);
            goto bad_descriptor;
        }

        page = frame_table + pfn;

        /* Each frame must belong to the requesting domain. */
        if ( (page->flags & PG_domain_mask) != p->domain )
        {
            DPRINTK("bad domain: expected %d, got %ld\n", 
                    p->domain, page->flags & PG_domain_mask);
            goto bad_descriptor;
        }

        /* If reading into the frame, the frame must be writeable. */
        if ( operation == READ )
        {
            if ( (page->flags & PG_type_mask) != PGT_writeable_page )
            {
                DPRINTK("non-writeable page passed for block read\n");
                goto bad_descriptor;
            }
            get_page_type(page);
        }

        /* Xen holds a frame reference until the operation is complete. */
        get_page_tot(page);
    }

    atomic_inc(&nr_pending);
    bh = kmem_cache_alloc(buffer_head_cachep, GFP_KERNEL);
    if ( bh == NULL ) panic("bh is null\n");

    /* set just the important bits of the buffer header */
    memset (bh, 0, sizeof (struct buffer_head));
    
    bh->b_blocknr       = blk_ring->ring[index].req.block_number;
    bh->b_size          = size;
    bh->b_dev           = blk_ring->ring[index].req.device; 
    bh->b_rsector       = blk_ring->ring[index].req.sector_number;
    bh->b_data          = phys_to_virt(buffer);
    bh->b_count.counter = 1;
    bh->b_end_io        = end_block_io_op;

    /* Save meta data about request. */
    bh->b_xen_domain    = p;
    bh->b_xen_id        = blk_ring->ring[index].req.id;

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
    return;

 bad_descriptor:
    make_response(p, blk_ring->ring[index].req.id, 1);
    return;
}



/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */

static void make_response(struct task_struct *p, void *id, unsigned long st)
{
    unsigned long cpu_mask, flags;
    int position;
    blk_ring_t *blk_ring;

    /* Place on the response ring for the relevant domain. */ 
    spin_lock_irqsave(&p->blk_ring_lock, flags);
    blk_ring = p->blk_ring_base;
    position = blk_ring->resp_prod;
    blk_ring->ring[position].resp.id     = id;
    blk_ring->ring[position].resp.status = st;
    blk_ring->resp_prod = BLK_RING_INC(position);
    spin_unlock_irqrestore(&p->blk_ring_lock, flags);
    
    /* Kick the relevant domain. */
    cpu_mask = mark_guest_event(p, _EVENT_BLK_RESP);
    guest_event_notify(cpu_mask); 
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
    remove_from_blkdev_list(p);
    UNSHARE_PFN(virt_to_page(p->blk_ring_base));
    free_page((unsigned long)p->blk_ring_base);
}

void initialize_block_io ()
{
    atomic_set(&nr_pending, 0);

    spin_lock_init(&io_schedule_list_lock);
    INIT_LIST_HEAD(&io_schedule_list);

    buffer_head_cachep = kmem_cache_create(
        "buffer_head_cache", sizeof(struct buffer_head),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    
    add_key_handler('b', dump_blockq, "dump xen ide blkdev stats");     
}
