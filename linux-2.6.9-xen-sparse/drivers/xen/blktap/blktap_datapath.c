/******************************************************************************
 * blktap_datapath.c
 * 
 * XenLinux virtual block-device tap.
 * Block request routing data path.
 * 
 * Copyright (c) 2004, Andrew Warfield
 *
 */
 
#include "blktap.h"

/*-----[ The data paths ]-------------------------------------------------*/
 
/* Connections to the frontend domains.*/
blkif_t   ptfe_blkif; 
 
/* Connection to a single backend domain. */
blkif_ring_t *blk_ptbe_ring;   /* Ring from the PT to the BE dom    */ 
BLKIF_RING_IDX ptbe_resp_cons; /* Response consumer for comms ring. */
BLKIF_RING_IDX ptbe_req_prod;  /* Private request producer.         */

/* Rings up to user space. */ 
blkif_req_ring_t fe_ring;// = BLKIF_REQ_RING_INIT;
blkif_rsp_ring_t be_ring;// = BLKIF_RSP_RING_INIT;

/*-----[ Ring helpers ]---------------------------------------------------*/

inline int BLKTAP_RING_FULL(blkif_generic_ring_t *ring)
{
    if (ring->type == BLKIF_REQ_RING_TYPE) {
        blkif_req_ring_t *r = (blkif_req_ring_t *)ring;
        return ( ( r->req_prod - r->rsp_cons ) == BLKIF_RING_SIZE );
    }
    
    /* for now assume that there is always room in the response path. */
    return 0;
}

/*-----[ Tracking active requests ]---------------------------------------*/

/* this must be the same as MAX_PENDING_REQS in blkback.c */
#define MAX_ACTIVE_REQS 64

active_req_t  active_reqs[MAX_ACTIVE_REQS];
unsigned char active_req_ring[MAX_ACTIVE_REQS];
spinlock_t    active_req_lock = SPIN_LOCK_UNLOCKED;
typedef unsigned int ACTIVE_RING_IDX;
ACTIVE_RING_IDX active_prod, active_cons;
#define MASK_ACTIVE_IDX(_i) ((_i)&(MAX_ACTIVE_REQS-1))
#define ACTIVE_IDX(_ar) (_ar - active_reqs)

inline active_req_t *get_active_req(void) 
{
    ASSERT(active_cons != active_prod);    
    return &active_reqs[MASK_ACTIVE_IDX(active_cons++)];
}

inline void free_active_req(active_req_t *ar) 
{
    unsigned long flags;
        
    spin_lock_irqsave(&active_req_lock, flags);
    active_req_ring[MASK_ACTIVE_IDX(active_prod++)] = ACTIVE_IDX(ar);
    spin_unlock_irqrestore(&active_req_lock, flags);
}

inline void active_reqs_init(void)
{
    ACTIVE_RING_IDX i;
    
    active_cons = 0;
    active_prod = MAX_ACTIVE_REQS;
    memset(active_reqs, 0, sizeof(active_reqs));
    for ( i = 0; i < MAX_ACTIVE_REQS; i++ )
        active_req_ring[i] = i;
}

/*-----[ Data to/from Frontend (client) VMs ]-----------------------------*/

irqreturn_t blkif_ptfe_int(int irq, void *dev_id, struct pt_regs *regs)
{
    /* we have pending messages from the real frontend. */

    blkif_request_t *req_s, *req_d;
    BLKIF_RING_IDX fe_rp;
    unsigned long flags;
    int notify;
    unsigned long i;
    active_req_t *ar;
    
    DPRINTK("PT got FE interrupt.\n");
    
    /* lock both rings */
    spin_lock_irqsave(&blkif_io_lock, flags);

    /* While there are REQUESTS on FERing: */
    fe_rp = ptfe_blkif.blk_ring_base->req_prod;
    rmb();
    notify = (ptfe_blkif.blk_req_cons != fe_rp);

    for (i = ptfe_blkif.blk_req_cons; i != fe_rp; i++) {

        /* Get the next request */
        req_s = &ptfe_blkif.blk_ring_base->ring[MASK_BLKIF_IDX(i)].req;
        
        /* This is a new request:  
         * Assign an active request record, and remap the id. 
         */
        ar = get_active_req();
        ar->id = req_s->id;
        req_s->id = ACTIVE_IDX(ar);
        DPRINTK("%3lu < %3lu\n", req_s->id, ar->id);

        /* FE -> BE interposition point is here. */
        
        /* ------------------------------------------------------------- */
        /* BLKIF_OP_PROBE_HACK:                                          */
        /* Until we have grant tables, we need to allow the backent to   */
        /* map pages that are either from this domain, or more commonly  */
        /* from the real front end.  We achieve this in a terrible way,  */
        /* by passing the front end's domid allong with PROBE messages   */
        /* Once grant tables appear, this should all go away.            */

        if (req_s->operation == BLKIF_OP_PROBE) {
            DPRINTK("Adding FE domid to PROBE request.\n");
            (domid_t)(req_s->frame_and_sects[1]) = ptfe_blkif.domid;
        }

        /* ------------------------------------------------------------- */

        /* If we are in MODE_INTERCEPT_FE or MODE_COPY_FE: */
        if ( (blktap_mode & BLKTAP_MODE_INTERCEPT_FE) ||
             (blktap_mode & BLKTAP_MODE_COPY_FE) ) {
            
            /* Copy the response message to UFERing */
            /* In MODE_INTERCEPT_FE, map attached pages into the app vma */
            /* In MODE_COPY_FE_PAGES, copy attached pages into the app vma */

            /* XXX: mapping/copying of attached pages is still not done! */

            DPRINTK("req->UFERing\n"); 
            blktap_write_fe_ring(req_s);


        }

        /* If we are not in MODE_INTERCEPT_FE or MODE_INTERCEPT_BE: */
        if ( !((blktap_mode & BLKTAP_MODE_INTERCEPT_FE) ||
               (blktap_mode & BLKTAP_MODE_INTERCEPT_BE)) ) {
            
            /* be included to prevent noise from the fe when its off */
            /* copy the request message to the BERing */

            DPRINTK("blktap: FERing[%u] -> BERing[%u]\n", 
                    (unsigned)MASK_BLKIF_IDX(i), 
                    (unsigned)MASK_BLKIF_IDX(ptbe_req_prod));

            req_d = &blk_ptbe_ring->ring[MASK_BLKIF_IDX(ptbe_req_prod)].req;
            
            memcpy(req_d, req_s, sizeof(blkif_request_t));

            ptbe_req_prod++;
        }
    }

    ptfe_blkif.blk_req_cons = i;

    /* If we have forwarded any responses, notify the appropriate ends. */
    if (notify) {

        /* we have sent stuff to the be, notify it. */
        if ( !((blktap_mode & BLKTAP_MODE_INTERCEPT_FE) ||
               (blktap_mode & BLKTAP_MODE_INTERCEPT_BE)) ) {
            wmb();
            blk_ptbe_ring->req_prod = ptbe_req_prod;

            notify_via_evtchn(blkif_ptbe_evtchn);
            DPRINTK(" -- and notified.\n");
        }

        /* we sent stuff to the app, notify it. */
        if ( (blktap_mode & BLKTAP_MODE_INTERCEPT_FE) ||
             (blktap_mode & BLKTAP_MODE_COPY_FE) ) {

            blktap_kick_user();
        }
    }

    /* unlock rings */
    spin_unlock_irqrestore(&blkif_io_lock, flags);

    return IRQ_HANDLED;
}

inline int write_req_to_be_ring(blkif_request_t *req)
{
    blkif_request_t *req_d;

    req_d = &blk_ptbe_ring->ring[MASK_BLKIF_IDX(ptbe_req_prod)].req;
    memcpy(req_d, req, sizeof(blkif_request_t));
    ptbe_req_prod++;

    return 0;
}

inline void kick_be_domain(void) {
    wmb();
    blk_ptbe_ring->req_prod = ptbe_req_prod;
    notify_via_evtchn(blkif_ptbe_evtchn);
}

/*-----[ Data to/from Backend (server) VM ]------------------------------*/


irqreturn_t blkif_ptbe_int(int irq, void *dev_id, 
                                  struct pt_regs *ptregs)
{
    blkif_response_t  *resp_s, *resp_d;
    BLKIF_RING_IDX be_rp;
    unsigned long flags;
    int notify;
    unsigned long i;
    active_req_t *ar;

    DPRINTK("PT got BE interrupt.\n");

    /* lock both rings */
    spin_lock_irqsave(&blkif_io_lock, flags);
    
    /* While there are RESPONSES on BERing: */
    be_rp = blk_ptbe_ring->resp_prod;
    rmb();
    notify = (ptbe_resp_cons != be_rp);
    
    for ( i = ptbe_resp_cons; i != be_rp; i++ )
    {
        /* BE -> FE interposition point is here. */
        
        /* Get the next response */
        resp_s = &blk_ptbe_ring->ring[MASK_BLKIF_IDX(i)].resp;
    
       
        /* If we are in MODE_INTERCEPT_BE or MODE_COPY_BE: */
        if ( (blktap_mode & BLKTAP_MODE_INTERCEPT_BE) ||
             (blktap_mode & BLKTAP_MODE_COPY_BE) ) {

            /* Copy the response message to UBERing */
            /* In MODE_INTERCEPT_BE, map attached pages into the app vma */
            /* In MODE_COPY_BE_PAGES, copy attached pages into the app vma */

            /* XXX: copy/map the attached page! */

            DPRINTK("rsp->UBERing\n"); 
            blktap_write_be_ring(resp_s);

        }
       
        /* If we are NOT in MODE_INTERCEPT_BE or MODE_INTERCEPT_FE: */
        if ( !((blktap_mode & BLKTAP_MODE_INTERCEPT_BE) ||
               (blktap_mode & BLKTAP_MODE_INTERCEPT_FE)) ) {
            
            /* (fe included to prevent random interference from the BE) */
            /* Copy the response message to FERing */
         
            DPRINTK("blktap: BERing[%u] -> FERing[%u]\n", 
                    (unsigned) MASK_BLKIF_IDX(i), 
                    (unsigned) MASK_BLKIF_IDX(ptfe_blkif.blk_resp_prod));

            /* remap id, and free the active req. blkif lookup goes here too.*/
            ar = &active_reqs[resp_s->id];
            DPRINTK("%3lu > %3lu\n", resp_s->id, ar->id);
            resp_s->id = ar->id;
            free_active_req(ar);
           
            resp_d = &ptfe_blkif.blk_ring_base->ring[
                MASK_BLKIF_IDX(ptfe_blkif.blk_resp_prod)].resp;

            memcpy(resp_d, resp_s, sizeof(blkif_response_t));
            
            ptfe_blkif.blk_resp_prod++;

        }
    }

    ptbe_resp_cons = i;
    
    /* If we have forwarded any responses, notify the apropriate domains. */
    if (notify) {

        /* we have sent stuff to the fe.  notify it. */
        if ( !((blktap_mode & BLKTAP_MODE_INTERCEPT_BE) ||
               (blktap_mode & BLKTAP_MODE_INTERCEPT_FE)) ) {
            wmb();
            ptfe_blkif.blk_ring_base->resp_prod = ptfe_blkif.blk_resp_prod;
        
            notify_via_evtchn(ptfe_blkif.evtchn);
            DPRINTK(" -- and notified.\n");
        }

        /* we sent stuff to the app, notify it. */
        if ( (blktap_mode & BLKTAP_MODE_INTERCEPT_BE) ||
             (blktap_mode & BLKTAP_MODE_COPY_BE) ) {

            blktap_kick_user();
        }
    }

    spin_unlock_irqrestore(&blkif_io_lock, flags);
    return IRQ_HANDLED;
}

inline int write_resp_to_fe_ring(blkif_response_t *rsp)
{
    blkif_response_t *resp_d;
    active_req_t *ar;
    
    /* remap id, and free the active req. blkif lookup goes here too.*/
    ar = &active_reqs[rsp->id];
    DPRINTK("%3lu > %3lu\n", rsp->id, ar->id);
    rsp->id = ar->id;
    free_active_req(ar);
            
    resp_d = &ptfe_blkif.blk_ring_base->ring[
        MASK_BLKIF_IDX(ptfe_blkif.blk_resp_prod)].resp;

    memcpy(resp_d, rsp, sizeof(blkif_response_t));
    ptfe_blkif.blk_resp_prod++;

    return 0;
}

inline void kick_fe_domain(void) {
    wmb();
    ptfe_blkif.blk_ring_base->resp_prod = ptfe_blkif.blk_resp_prod;
    notify_via_evtchn(ptfe_blkif.evtchn);
    
}

static inline void flush_requests(void)
{
    wmb(); /* Ensure that the frontend can see the requests. */
    blk_ptbe_ring->req_prod = ptbe_req_prod;
    notify_via_evtchn(blkif_ptbe_evtchn);
}

/*-----[ Data to/from user space ]----------------------------------------*/


int blktap_write_fe_ring(blkif_request_t *req)
{
    blkif_request_t *target;
    int error, i;

    /*
     * This is called to pass a request from the real frontend domain's
     * blkif ring to the character device.
     */

    if ( ! blktap_ring_ok ) {
        DPRINTK("blktap: fe_ring not ready for a request!\n");
        return 0;
    }

    if ( BLKTAP_RING_FULL(RING(&fe_ring)) ) {
        DPRINTK("blktap: fe_ring is full, can't add.\n");
        return 0;
    }

    target = &fe_ring.ring->ring[MASK_BLKIF_IDX(fe_ring.req_prod)].req;
    memcpy(target, req, sizeof(*req));

/* maybe move this stuff out into a seperate func ------------------- */

    /*
     * For now, map attached page into a fixed position into the vma.
     * XXX: make this map to a free page.
     */

    /* Attempt to map the foreign pages directly in to the application */
    for (i=0; i<target->nr_segments; i++) {

        /* get an unused virtual address from the char device */
        /* store the old page address */
        /* replace the address with the virtual address */

        /* blktap_vma->vm_start+((2+i)*PAGE_SIZE) */

        error = direct_remap_area_pages(blktap_vma->vm_mm, 
                                        MMAP_VADDR(req->id, i), 
                                        target->frame_and_sects[0] & PAGE_MASK,
                                        PAGE_SIZE,
                                        blktap_vma->vm_page_prot,
                                        ptfe_blkif.domid);
        if ( error != 0 ) {
            printk(KERN_INFO "remapping attached page failed! (%d)\n", error);
            return 0;
        }
    }
    /* fix the address of the attached page in the message. */
    /* TODO:      preserve the segment number stuff here... */
    /* target->frame_and_sects[0] = blktap_vma->vm_start + PAGE_SIZE;*/
/* ------------------------------------------------------------------ */

    
    fe_ring.req_prod++;

    return 0;
}

int blktap_write_be_ring(blkif_response_t *rsp)
{
    blkif_response_t *target;

    /*
     * This is called to pass a request from the real backend domain's
     * blkif ring to the character device.
     */

    if ( ! blktap_ring_ok ) {
        DPRINTK("blktap: be_ring not ready for a request!\n");
        return 0;
    }

    if ( BLKTAP_RING_FULL(RING(&be_ring)) ) {
        DPRINTK("blktap: be_ring is full, can't add.\n");
        return 0;
    }

    target = &be_ring.ring->ring[MASK_BLKIF_IDX(be_ring.rsp_prod)].resp;
    memcpy(target, rsp, sizeof(*rsp));


    /* XXX: map attached pages and fix-up addresses in the copied address. */

    be_ring.rsp_prod++;

    return 0;
}

int blktap_read_fe_ring(void)
{
    /* This is called to read responses from the UFE ring. */

    BLKIF_RING_IDX fe_rp;
    unsigned long i;
    int notify;

    DPRINTK("blktap_read_fe_ring()\n");

    fe_rp = fe_ring.ring->resp_prod;
    rmb();
    notify = (fe_rp != fe_ring.rsp_cons);

    /* if we are forwarding from UFERring to FERing */
    if (blktap_mode & BLKTAP_MODE_INTERCEPT_FE) {

        /* for each outstanding message on the UFEring  */
        for ( i = fe_ring.rsp_cons; i != fe_rp; i++ ) {

            /* XXX: remap pages on that message as necessary */
            /* copy the message to the UBEring */

            DPRINTK("resp->fe_ring\n");
            write_resp_to_fe_ring(&fe_ring.ring->ring[MASK_BLKIF_IDX(i)].resp);
        }
    
        fe_ring.rsp_cons = fe_rp;

        /* notify the fe if necessary */
        if ( notify ) {
            DPRINTK("kick_fe_domain()\n");
            kick_fe_domain();
        }
    }

    return 0;
}

int blktap_read_be_ring(void)
{
    /* This is called to read responses from the UBE ring. */

    BLKIF_RING_IDX be_rp;
    unsigned long i;
    int notify;

    DPRINTK("blktap_read_be_ring()\n");

    be_rp = be_ring.ring->req_prod;
    rmb();
    notify = (be_rp != be_ring.req_cons);

    /* if we are forwarding from UFERring to FERing */
    if (blktap_mode & BLKTAP_MODE_INTERCEPT_BE) {

        /* for each outstanding message on the UFEring  */
        for ( i = be_ring.req_cons; i != be_rp; i++ ) {

            /* XXX: remap pages on that message as necessary */
            /* copy the message to the UBEring */

            DPRINTK("req->be_ring\n");
            write_req_to_be_ring(&be_ring.ring->ring[MASK_BLKIF_IDX(i)].req);
        }
    
        be_ring.req_cons = be_rp;

        /* notify the fe if necessary */
        if ( notify ) {
            DPRINTK("kick_be_domain()\n");
            kick_be_domain();
        }
    }

    return 0;
}
