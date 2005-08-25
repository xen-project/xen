/******************************************************************************
 * blktap_datapath.c
 * 
 * XenLinux virtual block-device tap.
 * Block request routing data path.
 * 
 * Copyright (c) 2004, Andrew Warfield
 * -- see full header in blktap.c
 */
 
#include "blktap.h"
#include <asm-xen/evtchn.h>

/*-----[ The data paths ]-------------------------------------------------*/

/* Connection to a single backend domain. */
blkif_front_ring_t blktap_be_ring;

/*-----[ Tracking active requests ]---------------------------------------*/

/* this must be the same as MAX_PENDING_REQS in blkback.c */
#define MAX_ACTIVE_REQS ((ACTIVE_RING_IDX)64U)

active_req_t     active_reqs[MAX_ACTIVE_REQS];
ACTIVE_RING_IDX  active_req_ring[MAX_ACTIVE_REQS];
spinlock_t       active_req_lock = SPIN_LOCK_UNLOCKED;
ACTIVE_RING_IDX  active_prod, active_cons;
#define MASK_ACTIVE_IDX(_i) ((_i)&(MAX_ACTIVE_REQS-1))
#define ACTIVE_IDX(_ar) (_ar - active_reqs)
#define NR_ACTIVE_REQS (MAX_ACTIVE_REQS - active_prod + active_cons)

inline active_req_t *get_active_req(void) 
{
    ACTIVE_RING_IDX idx;
    active_req_t *ar;
    unsigned long flags;
        
    ASSERT(active_cons != active_prod);   
    
    spin_lock_irqsave(&active_req_lock, flags);
    idx =  active_req_ring[MASK_ACTIVE_IDX(active_cons++)];
    ar = &active_reqs[idx];
    spin_unlock_irqrestore(&active_req_lock, flags);
    
    return ar;
}

inline void free_active_req(active_req_t *ar) 
{
    unsigned long flags;
        
    spin_lock_irqsave(&active_req_lock, flags);
    active_req_ring[MASK_ACTIVE_IDX(active_prod++)] = ACTIVE_IDX(ar);
    spin_unlock_irqrestore(&active_req_lock, flags);
}

active_req_t *lookup_active_req(ACTIVE_RING_IDX idx)
{
    return &active_reqs[idx];   
}

void active_reqs_init(void)
{
    ACTIVE_RING_IDX i;
    
    active_cons = 0;
    active_prod = MAX_ACTIVE_REQS;
    memset(active_reqs, 0, sizeof(active_reqs));
    for ( i = 0; i < MAX_ACTIVE_REQS; i++ )
        active_req_ring[i] = i;
}

/* Requests passing through the tap to the backend hijack the id field
 * in the request message.  In it we put the AR index _AND_ the fe domid.
 * the domid is used by the backend to map the pages properly.
 */

static inline unsigned long MAKE_ID(domid_t fe_dom, ACTIVE_RING_IDX idx)
{
    return ( (fe_dom << 16) | MASK_ACTIVE_IDX(idx) );
}

/*-----[ Ring helpers ]---------------------------------------------------*/

static void maybe_trigger_blktap_schedule(void);

inline int write_resp_to_fe_ring(blkif_t *blkif, blkif_response_t *rsp)
{
    blkif_response_t *resp_d;
    active_req_t *ar;
    
    ar = &active_reqs[ID_TO_IDX(rsp->id)];
    rsp->id = ar->id;
            
    resp_d = RING_GET_RESPONSE(&blkif->blk_ring,
            blkif->blk_ring.rsp_prod_pvt);
    memcpy(resp_d, rsp, sizeof(blkif_response_t));
    wmb();
    blkif->blk_ring.rsp_prod_pvt++;
            
    blkif_put(ar->blkif);
    free_active_req(ar);
    
    return 0;
}

inline int write_req_to_be_ring(blkif_request_t *req)
{
    blkif_request_t *req_d;

    if ( blktap_be_state != BLKIF_STATE_CONNECTED ) {
        WPRINTK("Tap trying to access an unconnected backend!\n");
        return 0;
    }
    
    req_d = RING_GET_REQUEST(&blktap_be_ring,
            blktap_be_ring.req_prod_pvt);
    memcpy(req_d, req, sizeof(blkif_request_t));
    wmb();
    blktap_be_ring.req_prod_pvt++;
            
    return 0;
}

void kick_fe_domain(blkif_t *blkif) 
{
    RING_PUSH_RESPONSES(&blkif->blk_ring);
    notify_via_evtchn(blkif->evtchn);
    DPRINTK("notified FE(dom %u)\n", blkif->domid);

    /* We just feed up a batch of request slots... */
    maybe_trigger_blktap_schedule();
    
}

void kick_be_domain(void)
{
    if ( blktap_be_state != BLKIF_STATE_CONNECTED ) 
        return;
    
    wmb(); /* Ensure that the frontend can see the requests. */
    RING_PUSH_REQUESTS(&blktap_be_ring);
    notify_via_evtchn(blktap_be_evtchn);
    DPRINTK("notified BE\n");
}

/*-----[ Data to/from Frontend (client) VMs ]-----------------------------*/

/*-----[ Scheduler list maint -from blkback ]--- */

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


/*-----[ Scheduler functions - from blkback ]--- */

static DECLARE_WAIT_QUEUE_HEAD(blkio_schedule_wait);

static int do_block_io_op(blkif_t *blkif, int max_to_do);

static int blkio_schedule(void *arg)
{
    DECLARE_WAITQUEUE(wq, current);

    blkif_t          *blkif;
    struct list_head *ent;

    daemonize(
        "xentapd"
        );

    for ( ; ; )
    {
        /* Wait for work to do. */
        add_wait_queue(&blkio_schedule_wait, &wq);
        set_current_state(TASK_INTERRUPTIBLE);
        if ( (NR_ACTIVE_REQS == MAX_ACTIVE_REQS) || 
             list_empty(&blkio_schedule_list) )
            schedule();
        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&blkio_schedule_wait, &wq);

        /* Queue up a batch of requests. */
        while ( (NR_ACTIVE_REQS < MAX_ACTIVE_REQS) &&
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
    }
}

static void maybe_trigger_blktap_schedule(void)
{
    /*
     * Needed so that two processes, who together make the following predicate
     * true, don't both read stale values and evaluate the predicate
     * incorrectly. Incredibly unlikely to stall the scheduler on x86, but...
     */
    smp_mb();

    if ( (NR_ACTIVE_REQS < (MAX_ACTIVE_REQS/2)) &&
         !list_empty(&blkio_schedule_list) ) 
        wake_up(&blkio_schedule_wait);
}

void blkif_deschedule(blkif_t *blkif)
{
    remove_from_blkdev_list(blkif);
}

void __init blkdev_schedule_init(void)
{
    spin_lock_init(&blkio_schedule_list_lock);
    INIT_LIST_HEAD(&blkio_schedule_list);

    if ( kernel_thread(blkio_schedule, 0, CLONE_FS | CLONE_FILES) < 0 )
        BUG();
}
    
/*-----[ Interrupt entry from a frontend ]------ */

irqreturn_t blkif_ptfe_int(int irq, void *dev_id, struct pt_regs *regs)
{
    blkif_t *blkif = dev_id;

    add_to_blkdev_list_tail(blkif);
    maybe_trigger_blktap_schedule();
    return IRQ_HANDLED;
}

/*-----[ Other Frontend Ring functions ]-------- */

/* irqreturn_t blkif_ptfe_int(int irq, void *dev_id, struct pt_regs *regs)*/
static int do_block_io_op(blkif_t *blkif, int max_to_do)
{
    /* we have pending messages from the real frontend. */

    blkif_request_t *req_s;
    RING_IDX i, rp;
    unsigned long flags;
    active_req_t *ar;
    int more_to_do = 0;
    int notify_be = 0, notify_user = 0;
    
    /* lock both rings */
    spin_lock_irqsave(&blkif_io_lock, flags);

    rp = blkif->blk_ring.sring->req_prod;
    rmb();
    
    for ( i = blkif->blk_ring.req_cons; 
         (i != rp) && 
            !RING_REQUEST_CONS_OVERFLOW(&blkif->blk_ring, i);
          i++ )
    {
        
        if ((--max_to_do == 0) || (NR_ACTIVE_REQS == MAX_ACTIVE_REQS)) 
        {
            more_to_do = 1;
            break;
        }
        
        req_s = RING_GET_REQUEST(&blkif->blk_ring, i);
        /* This is a new request:  
         * Assign an active request record, and remap the id. 
         */
        ar = get_active_req();
        ar->id = req_s->id;
        ar->nr_pages = req_s->nr_segments; 
        blkif_get(blkif);
        ar->blkif = blkif;
        req_s->id = MAKE_ID(blkif->domid, ACTIVE_IDX(ar));
        /* WPRINTK("%3u < %3lu\n", ID_TO_IDX(req_s->id), ar->id); */

        /* FE -> BE interposition point is here. */
        
        /* ------------------------------------------------------------- */
        /* BLKIF_OP_PROBE_HACK:                                          */
        /* Signal to the backend that we are a tap domain.               */

        if (req_s->operation == BLKIF_OP_PROBE) {
            DPRINTK("Adding BLKTAP_COOKIE to PROBE request.\n");
            req_s->frame_and_sects[1] = BLKTAP_COOKIE;
        }

        /* ------------------------------------------------------------- */

        /* If we are in MODE_INTERCEPT_FE or MODE_COPY_FE: */
        if ( (blktap_mode & BLKTAP_MODE_INTERCEPT_FE) ||
             (blktap_mode & BLKTAP_MODE_COPY_FE) ) {
            
            /* Copy the response message to UFERing */
            /* In MODE_INTERCEPT_FE, map attached pages into the app vma */
            /* In MODE_COPY_FE_PAGES, copy attached pages into the app vma */

            DPRINTK("req->UFERing\n"); 
            blktap_write_fe_ring(req_s);
            notify_user = 1;
        }

        /* If we are not in MODE_INTERCEPT_FE or MODE_INTERCEPT_BE: */
        if ( !((blktap_mode & BLKTAP_MODE_INTERCEPT_FE) ||
               (blktap_mode & BLKTAP_MODE_INTERCEPT_BE)) ) {
            
            /* be included to prevent noise from the fe when its off */
            /* copy the request message to the BERing */

            DPRINTK("blktap: FERing[%u] -> BERing[%u]\n", 
                    (unsigned)i & (RING_SIZE(&blktap_be_ring)-1),
                    (unsigned)blktap_be_ring.req_prod_pvt & 
                    (RING_SIZE((&blktap_be_ring)-1)));
            
            write_req_to_be_ring(req_s);
            notify_be = 1;
        }
    }

    blkif->blk_ring.req_cons = i;
    
    /* unlock rings */
    spin_unlock_irqrestore(&blkif_io_lock, flags);
    
    if (notify_user)
        blktap_kick_user();
    if (notify_be)
        kick_be_domain();
    
    return more_to_do;
}

/*-----[ Data to/from Backend (server) VM ]------------------------------*/


irqreturn_t blkif_ptbe_int(int irq, void *dev_id, 
                                  struct pt_regs *ptregs)
{
    blkif_response_t  *resp_s;
    blkif_t *blkif;
    RING_IDX rp, i;
    unsigned long flags;

    DPRINTK("PT got BE interrupt.\n");

    /* lock both rings */
    spin_lock_irqsave(&blkif_io_lock, flags);
    
    rp = blktap_be_ring.sring->rsp_prod;
    rmb();
      
    for ( i = blktap_be_ring.rsp_cons; i != rp; i++)
    {
        resp_s = RING_GET_RESPONSE(&blktap_be_ring, i);
        
        /* BE -> FE interposition point is here. */
    
        blkif = active_reqs[ID_TO_IDX(resp_s->id)].blkif;
        
        /* If we are in MODE_INTERCEPT_BE or MODE_COPY_BE: */
        if ( (blktap_mode & BLKTAP_MODE_INTERCEPT_BE) ||
             (blktap_mode & BLKTAP_MODE_COPY_BE) ) {

            /* Copy the response message to UBERing */
            /* In MODE_INTERCEPT_BE, map attached pages into the app vma */
            /* In MODE_COPY_BE_PAGES, copy attached pages into the app vma */

            DPRINTK("rsp->UBERing\n"); 
            blktap_write_be_ring(resp_s);
            blktap_kick_user();

        }
       
        /* If we are NOT in MODE_INTERCEPT_BE or MODE_INTERCEPT_FE: */
        if ( !((blktap_mode & BLKTAP_MODE_INTERCEPT_BE) ||
               (blktap_mode & BLKTAP_MODE_INTERCEPT_FE)) ) {
            
            /* (fe included to prevent random interference from the BE) */
            /* Copy the response message to FERing */
         
            DPRINTK("blktap: BERing[%u] -> FERing[%u]\n", 
                    (unsigned)i & (RING_SIZE(&blkif->blk_ring)-1),
                    (unsigned)blkif->blk_ring.rsp_prod_pvt & 
                    (RING_SIZE((&blkif->blk_ring)-1)));

            write_resp_to_fe_ring(blkif, resp_s);
            kick_fe_domain(blkif);

        }
    }
    
    blktap_be_ring.rsp_cons = i;
    

    spin_unlock_irqrestore(&blkif_io_lock, flags);
    
    return IRQ_HANDLED;
}

/* Debug : print the current ring indices. */

void print_be_ring_idxs(void)
{
    if (blktap_be_ring.sring != NULL) {
        WPRINTK("BE Ring: \n--------\n");
        WPRINTK("BE: rsp_cons: %2d, req_prod_prv: %2d "
            "| req_prod: %2d, rsp_prod: %2d\n",
            blktap_be_ring.rsp_cons,
            blktap_be_ring.req_prod_pvt,
            blktap_be_ring.sring->req_prod,
            blktap_be_ring.sring->rsp_prod);
    }
}        
