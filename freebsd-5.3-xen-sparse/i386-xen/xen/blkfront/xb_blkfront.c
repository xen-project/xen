/*-
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * XenoBSD block device driver
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <vm/vm.h>
#include <vm/pmap.h>

#include <sys/bio.h>
#include <sys/bus.h>
#include <sys/conf.h>

#include <machine/bus.h>
#include <sys/rman.h>
#include <machine/resource.h>
#include <machine/intr_machdep.h>
#include <machine/vmparam.h>

#include <machine/hypervisor.h>
#include <machine/hypervisor-ifs.h>
#include <machine/xen-os.h>
#include <machine/xen_intr.h>
#include <machine/evtchn.h>

#include <geom/geom_disk.h>
#include <machine/ctrl_if.h>
#include <machine/xenfunc.h>



#ifdef CONFIG_XEN_BLKDEV_GRANT
#include <machine/gnttab.h>
#endif

/* prototypes */
struct xb_softc;
static void xb_startio(struct xb_softc *sc);
static void xb_vbdinit(void);
static void blkif_control_send(blkif_request_t *req, blkif_response_t *rsp);
static void blkif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id);
static void blkif_control_probe_send(blkif_request_t *req, blkif_response_t *rsp, unsigned long address);

struct xb_softc {
    device_t		  xb_dev;
    struct disk		  xb_disk;		/* disk params */
    struct bio_queue_head xb_bioq;		/* sort queue */
    struct resource 	 *xb_irq;
    void		 *xb_resp_handler;
    int			  xb_unit;
    int			  xb_flags;
    struct xb_softc      *xb_next_blocked;
#define XB_OPEN	(1<<0)		/* drive is open (can't shut down) */
};

/* Control whether runtime update of vbds is enabled. */
#define ENABLE_VBD_UPDATE 1

#if ENABLE_VBD_UPDATE
static void vbd_update(void);
#else
static void vbd_update(void){};
#endif

#define BLKIF_STATE_CLOSED       0
#define BLKIF_STATE_DISCONNECTED 1
#define BLKIF_STATE_CONNECTED    2

static char *blkif_state_name[] = {
    [BLKIF_STATE_CLOSED]       = "closed",
    [BLKIF_STATE_DISCONNECTED] = "disconnected",
    [BLKIF_STATE_CONNECTED]    = "connected",
};

static char * blkif_status_name[] = {
    [BLKIF_INTERFACE_STATUS_CLOSED]       = "closed",
    [BLKIF_INTERFACE_STATUS_DISCONNECTED] = "disconnected",
    [BLKIF_INTERFACE_STATUS_CONNECTED]    = "connected",
    [BLKIF_INTERFACE_STATUS_CHANGED]      = "changed",
};

#define WPRINTK(fmt, args...) printk("[XEN] " fmt, ##args)

static int blkif_handle;
static unsigned int blkif_state = BLKIF_STATE_CLOSED;
static unsigned int blkif_evtchn;
static unsigned int blkif_irq;

static int blkif_control_rsp_valid;
static blkif_response_t blkif_control_rsp;

static blkif_front_ring_t   blk_ring;

#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

#ifdef CONFIG_XEN_BLKDEV_GRANT
static domid_t rdomid = 0;
static grant_ref_t gref_head, gref_terminal;
#define MAXIMUM_OUTSTANDING_BLOCK_REQS \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST * BLKIF_RING_SIZE)
#endif

static struct xb_softc *xb_kick_pending_head = NULL;
static struct xb_softc *xb_kick_pending_tail = NULL;
static struct mtx blkif_io_block_lock;

static unsigned long rec_ring_free;		
blkif_request_t rec_ring[BLK_RING_SIZE];

/* XXX move to xb_vbd.c when VBD update support is added */
#define MAX_VBDS 64
static vdisk_t xb_diskinfo[MAX_VBDS];
static int xb_ndisks;

#define XBD_SECTOR_SIZE		512	/* XXX: assume for now */
#define XBD_SECTOR_SHFT		9

static unsigned int xb_kick_pending;

static struct mtx blkif_io_lock;


static int xb_recovery = 0;           /* "Recovery in progress" flag.  Protected
                                       * by the blkif_io_lock */


void blkif_completion(blkif_request_t *req);
void xb_response_intr(void *);

/* XXX: This isn't supported in FreeBSD, so ignore it for now. */
#define TASK_UNINTERRUPTIBLE    0

static inline int 
GET_ID_FROM_FREELIST( void )
{
    unsigned long free = rec_ring_free;

    KASSERT(free <= BLK_RING_SIZE, ("free %lu > RING_SIZE", free));

    rec_ring_free = rec_ring[free].id;

    rec_ring[free].id = 0x0fffffee; /* debug */

    return free;
}

static inline void 
ADD_ID_TO_FREELIST( unsigned long id )
{
    rec_ring[id].id = rec_ring_free;
    rec_ring_free = id;
}

static inline void 
translate_req_to_pfn(blkif_request_t *xreq,
		     blkif_request_t *req)
{
    int i;

    xreq->operation     = req->operation;
    xreq->nr_segments   = req->nr_segments;
    xreq->device        = req->device;
    /* preserve id */
    xreq->sector_number = req->sector_number;

    for ( i = 0; i < req->nr_segments; i++ ){
#ifdef CONFIG_XEN_BLKDEV_GRANT
        xreq->frame_and_sects[i] = req->frame_and_sects[i];
#else
        xreq->frame_and_sects[i] = xpmap_mtop(req->frame_and_sects[i]);
#endif
    }
}

static inline void translate_req_to_mfn(blkif_request_t *xreq,
                                        blkif_request_t *req)
{
    int i;

    xreq->operation     = req->operation;
    xreq->nr_segments   = req->nr_segments;
    xreq->device        = req->device;
    xreq->id            = req->id;   /* copy id (unlike above) */
    xreq->sector_number = req->sector_number;

    for ( i = 0; i < req->nr_segments; i++ ){
#ifdef CONFIG_XEN_BLKDEV_GRANT
        xreq->frame_and_sects[i] = req->frame_and_sects[i];
#else
        xreq->frame_and_sects[i] = xpmap_ptom(req->frame_and_sects[i]);
#endif
    }
}


static inline void flush_requests(void)
{
    RING_PUSH_REQUESTS(&blk_ring);
    notify_via_evtchn(blkif_evtchn);
}


#if ENABLE_VBD_UPDATE
static void vbd_update()
{
    XENPRINTF(">\n");
    XENPRINTF("<\n");
}
#endif /* ENABLE_VBD_UPDATE */

void
xb_response_intr(void *xsc)
{
    struct xb_softc *sc = NULL;
    struct bio *bp;
    blkif_response_t *bret;
    RING_IDX i, rp; 
    unsigned long flags;
    
    mtx_lock_irqsave(&blkif_io_lock, flags);

    if ( unlikely(blkif_state == BLKIF_STATE_CLOSED) || 
         unlikely(xb_recovery) ) {
        mtx_unlock_irqrestore(&blkif_io_lock, flags);
        return;
    }

    rp = blk_ring.sring->rsp_prod;
    rmb(); /* Ensure we see queued responses up to 'rp'. */

    /* sometimes we seem to lose i/o.  stay in the interrupt handler while
     * there is stuff to process: continually recheck the response producer.
     */
 process_rcvd:
    for ( i = blk_ring.rsp_cons; i != (rp = blk_ring.sring->rsp_prod); i++ ) {
	unsigned long id;
        bret = RING_GET_RESPONSE(&blk_ring, i);

	id = bret->id;
	bp = (struct bio *)rec_ring[id].id;

	blkif_completion(&rec_ring[id]);

	ADD_ID_TO_FREELIST(id);	/* overwrites req */

        switch ( bret->operation ) {
        case BLKIF_OP_READ:
	    /* had an unaligned buffer that needs to be copied */
	    if (bp->bio_driver1)
		bcopy(bp->bio_data, bp->bio_driver1, bp->bio_bcount);
        case BLKIF_OP_WRITE:

	    /* free the copy buffer */
	    if (bp->bio_driver1) {
		    free(bp->bio_data, M_DEVBUF);
		    bp->bio_data = bp->bio_driver1;
		    bp->bio_driver1 = NULL;
	    }

	    if ( unlikely(bret->status != BLKIF_RSP_OKAY) ) {
		XENPRINTF("Bad return from blkdev data request: %x\n", 
			  bret->status);
	    	bp->bio_flags |= BIO_ERROR;
	    }

	    sc = (struct xb_softc *)bp->bio_disk->d_drv1;

	    if (bp->bio_flags & BIO_ERROR)
		bp->bio_error = EIO;
	    else
		bp->bio_resid = 0;

	    biodone(bp);
            break;
	case BLKIF_OP_PROBE:
            memcpy(&blkif_control_rsp, bret, sizeof(*bret));
            blkif_control_rsp_valid = 1;
            break;
        default:
	    panic("received invalid operation");
            break;
        }
    }
    
    blk_ring.rsp_cons = i;

    if (xb_kick_pending) {
	unsigned long flags;
	mtx_lock_irqsave(&blkif_io_block_lock, flags);
   	xb_kick_pending = FALSE;
	/* Run as long as there are blocked devs or queue fills again */
	while ((NULL != xb_kick_pending_head) && (FALSE == xb_kick_pending)) {
	    struct xb_softc *xb_cur = xb_kick_pending_head;
	    xb_kick_pending_head = xb_cur->xb_next_blocked;
	    if(NULL == xb_kick_pending_head) {
		xb_kick_pending_tail = NULL;
	    }
	    xb_cur->xb_next_blocked = NULL;
	    mtx_unlock_irqrestore(&blkif_io_block_lock, flags);
	    xb_startio(xb_cur);
	    mtx_lock_irqsave(&blkif_io_block_lock, flags);
	}
	mtx_unlock_irqrestore(&blkif_io_block_lock, flags);

	if(blk_ring.rsp_cons != blk_ring.sring->rsp_prod) {
	    /* Consume those, too */
	    goto process_rcvd;
	}
    }

    mtx_unlock_irqrestore(&blkif_io_lock, flags);
}

static int
xb_open(struct disk *dp)
{
    struct xb_softc	*sc = (struct xb_softc *)dp->d_drv1;

    if (sc == NULL) {
	printk("xb%d: not found", sc->xb_unit);
	return (ENXIO);
    }

    /* block dev not active */
    if (blkif_state != BLKIF_STATE_CONNECTED) {
	printk("xb%d: bad state: %dn", sc->xb_unit, blkif_state);
	return(ENXIO);
    }

    sc->xb_flags |= XB_OPEN;
    return (0);
}

static int
xb_close(struct disk *dp)
{
    struct xb_softc	*sc = (struct xb_softc *)dp->d_drv1;

    if (sc == NULL)
	return (ENXIO);
    sc->xb_flags &= ~XB_OPEN;
    return (0);
}

static int
xb_ioctl(struct disk *dp, u_long cmd, void *addr, int flag, struct thread *td)
{
    struct xb_softc	*sc = (struct xb_softc *)dp->d_drv1;

    if (sc == NULL)
	return (ENXIO);

    return (ENOTTY);
}

/*
 * Dequeue buffers and place them in the shared communication ring.
 * Return when no more requests can be accepted or all buffers have 
 * been queued.
 *
 * Signal XEN once the ring has been filled out.
 */
static void
xb_startio(struct xb_softc *sc)
{
    struct bio		*bp;
    unsigned long  	buffer_ma;
    blkif_request_t     *req;
    int			s, queued = 0;
    unsigned long id;
    unsigned int fsect, lsect;
#ifdef CONFIG_XEN_BLKDEV_GRANT
    int ref;
#endif

    
    if (unlikely(blkif_state != BLKIF_STATE_CONNECTED))
	return;

    s = splbio();

    for (bp = bioq_first(&sc->xb_bioq);
         bp && !RING_FULL(&blk_ring);
	 blk_ring.req_prod_pvt++, queued++, bp = bioq_first(&sc->xb_bioq)) {
	
	/* Check if the buffer is properly aligned */
	if ((vm_offset_t)bp->bio_data & PAGE_MASK) {
		int align = (bp->bio_bcount < PAGE_SIZE/2) ? XBD_SECTOR_SIZE : 
		    					     PAGE_SIZE;
		caddr_t newbuf = malloc(bp->bio_bcount + align, M_DEVBUF, 
					M_WAITOK);
		caddr_t alignbuf = (char *)roundup2((u_long)newbuf, align);

		/* save a copy of the current buffer */
		bp->bio_driver1 = bp->bio_data;

		/* Copy the data for a write */
		if (bp->bio_cmd == BIO_WRITE)
		    bcopy(bp->bio_data, alignbuf, bp->bio_bcount);
		bp->bio_data = alignbuf;
	}
		
    	bioq_remove(&sc->xb_bioq, bp);
	buffer_ma = vtomach(bp->bio_data);
	fsect = (buffer_ma & PAGE_MASK) >> XBD_SECTOR_SHFT;
	lsect = fsect + (bp->bio_bcount >> XBD_SECTOR_SHFT) - 1;

	KASSERT((buffer_ma & (XBD_SECTOR_SIZE-1)) == 0,
	       ("XEN buffer must be sector aligned"));
	KASSERT(lsect <= 7, 
	       ("XEN disk driver data cannot cross a page boundary"));
	
	buffer_ma &= ~PAGE_MASK;

    	/* Fill out a communications ring structure. */
    	req 		  = RING_GET_REQUEST(&blk_ring, 
					     blk_ring.req_prod_pvt);
	id		  = GET_ID_FROM_FREELIST();
	rec_ring[id].id= (unsigned long)bp;

    	req->id 	  = id;
    	req->operation 	  = (bp->bio_cmd == BIO_READ) ? BLKIF_OP_READ :
						         BLKIF_OP_WRITE;

    	req->sector_number= (blkif_sector_t)bp->bio_pblkno;
    	req->device 	  = xb_diskinfo[sc->xb_unit].device;

    	req->nr_segments  = 1;	/* not doing scatter/gather since buffer
    				 * chaining is not supported.
				 */
#ifdef CONFIG_XEN_BLKDEV_GRANT
            /* install a grant reference. */
            ref = gnttab_claim_grant_reference(&gref_head, gref_terminal);
            KASSERT( ref != -ENOSPC, ("grant_reference failed") );

            gnttab_grant_foreign_access_ref(
                        ref,
                        rdomid,
                        buffer_ma >> PAGE_SHIFT,
                        req->operation & 1 ); /* ??? */

            req->frame_and_sects[0] =
                (((uint32_t) ref) << 16) | (fsect << 3) | lsect;
#else
	/*
	 * upper bits represent the machine address of the buffer and the
	 * lower bits is the number of sectors to be read/written.
	 */
	req->frame_and_sects[0] = buffer_ma | (fsect << 3) | lsect; 
#endif
	/* Keep a private copy so we can reissue requests when recovering. */
	translate_req_to_pfn( &rec_ring[id], req);

    }

    if (RING_FULL(&blk_ring)) {
	unsigned long flags;
	mtx_lock_irqsave(&blkif_io_block_lock, flags);
	xb_kick_pending = TRUE;
        /* If we are not already on blocked list, add us */
        if((NULL == sc->xb_next_blocked) && (xb_kick_pending_tail != sc)) {

            if(NULL == xb_kick_pending_head) {
                xb_kick_pending_head = xb_kick_pending_tail = sc;
            } else {
                xb_kick_pending_tail->xb_next_blocked = sc;
                xb_kick_pending_tail = sc;
            }
        }
        mtx_unlock_irqrestore(&blkif_io_block_lock, flags);
    }
    
    if (queued != 0) 
	flush_requests();
    splx(s);
}

/*
 * Read/write routine for a buffer.  Finds the proper unit, place it on
 * the sortq and kick the controller.
 */
static void
xb_strategy(struct bio *bp)
{
    struct xb_softc	*sc = (struct xb_softc *)bp->bio_disk->d_drv1;
    int			s;

    /* bogus disk? */
    if (sc == NULL) {
	bp->bio_error = EINVAL;
	bp->bio_flags |= BIO_ERROR;
	goto bad;
    }

    s = splbio();
    /*
     * Place it in the queue of disk activities for this disk
     */
    bioq_disksort(&sc->xb_bioq, bp);
    splx(s);

    xb_startio(sc);
    return;

 bad:
    /*
     * Correctly set the bio to indicate a failed tranfer.
     */
    bp->bio_resid = bp->bio_bcount;
    biodone(bp);
    return;
}


static int
xb_create(int unit)
{
    struct xb_softc	*sc;
    int			error = 0;
    
    sc = (struct xb_softc *)malloc(sizeof(*sc), M_DEVBUF, M_WAITOK);
    sc->xb_unit = unit;
    sc->xb_next_blocked = NULL;

    memset(&sc->xb_disk, 0, sizeof(sc->xb_disk)); 
    sc->xb_disk.d_unit = unit;
    sc->xb_disk.d_open = xb_open;
    sc->xb_disk.d_close = xb_close;
    sc->xb_disk.d_ioctl = xb_ioctl;
    sc->xb_disk.d_strategy = xb_strategy;
    sc->xb_disk.d_name = "xbd";
    sc->xb_disk.d_drv1 = sc;
    sc->xb_disk.d_sectorsize = XBD_SECTOR_SIZE;
    sc->xb_disk.d_mediasize = xb_diskinfo[sc->xb_unit].capacity 
					<< XBD_SECTOR_SHFT;
#if 0
    sc->xb_disk.d_maxsize = DFLTPHYS;
#else /* XXX: xen can't handle large single i/o requests */
    sc->xb_disk.d_maxsize = 4096;
#endif

    XENPRINTF("attaching device 0x%x unit %d capacity %llu\n",
    	       xb_diskinfo[sc->xb_unit].device, sc->xb_unit,
    	       sc->xb_disk.d_mediasize);

    disk_create(&sc->xb_disk, DISK_VERSION_00);
    bioq_init(&sc->xb_bioq);

    return error;
}

/* XXX move to xb_vbd.c when vbd update support is added */
static void
xb_vbdinit(void)
{
    int i;
    blkif_request_t req;
    blkif_response_t rsp; 
    vdisk_t *buf;

    buf = (vdisk_t *)malloc(PAGE_SIZE, M_DEVBUF, M_WAITOK);

    /* Probe for disk information. */
    memset(&req, 0, sizeof(req)); 
    req.operation = BLKIF_OP_PROBE;
    req.nr_segments = 1;
#ifdef CONFIG_XEN_BLKDEV_GRANT
    blkif_control_probe_send(&req, &rsp,
                             (unsigned long)(vtomach(buf)));
    
#else
    req.frame_and_sects[0] = vtomach(buf) | 7;
    blkif_control_send(&req, &rsp);
#endif
    if ( rsp.status <= 0 ) {
        printk("xb_identify: Could not identify disks (%d)\n", rsp.status);
    	free(buf, M_DEVBUF);
        return;
    }
    
    if ((xb_ndisks = rsp.status) > MAX_VBDS)
	xb_ndisks = MAX_VBDS;

    memcpy(xb_diskinfo, buf, xb_ndisks * sizeof(vdisk_t));

    for (i = 0; i < xb_ndisks; i++)
	xb_create(i);

    free(buf, M_DEVBUF);
}


/*****************************  COMMON CODE  *******************************/

#ifdef CONFIG_XEN_BLKDEV_GRANT
static void 
blkif_control_probe_send(blkif_request_t *req, blkif_response_t *rsp,
                              unsigned long address)
{
    int ref = gnttab_claim_grant_reference(&gref_head, gref_terminal);
    KASSERT( ref != -ENOSPC, ("couldn't get grant reference") );

    gnttab_grant_foreign_access_ref( ref, rdomid, address >> PAGE_SHIFT, 0 );

    req->frame_and_sects[0] = (((uint32_t) ref) << 16) | 7;

    blkif_control_send(req, rsp);
}
#endif

void 
blkif_control_send(blkif_request_t *req, blkif_response_t *rsp)
{
    unsigned long flags, id;
    blkif_request_t *req_d;

 retry:
    while ( RING_FULL(&blk_ring) )
    {
	tsleep( req, PWAIT | PCATCH, "blkif", hz);
    }

    mtx_lock_irqsave(&blkif_io_lock, flags);
    if (  RING_FULL(&blk_ring) )
    {
        mtx_unlock_irqrestore(&blkif_io_lock, flags);
        goto retry;
    }

    req_d = RING_GET_REQUEST(&blk_ring, blk_ring.req_prod_pvt);
    *req_d = *req;    

    id = GET_ID_FROM_FREELIST();
    req_d->id = id;
    rec_ring[id].id = (unsigned long) req;

    translate_req_to_pfn( &rec_ring[id], req );

    blk_ring.req_prod_pvt++;
    flush_requests();

    mtx_unlock_irqrestore(&blkif_io_lock, flags);

    while ( !blkif_control_rsp_valid )
    {
	tsleep( &blkif_control_rsp_valid, PWAIT | PCATCH, "blkif", hz);
    }

    memcpy(rsp, &blkif_control_rsp, sizeof(*rsp));
    blkif_control_rsp_valid = 0;
}


/* Send a driver status notification to the domain controller. */
static void 
send_driver_status(int ok)
{
    ctrl_msg_t cmsg = {
        .type    = CMSG_BLKIF_FE,
        .subtype = CMSG_BLKIF_FE_DRIVER_STATUS,
        .length  = sizeof(blkif_fe_driver_status_t),
    };
    blkif_fe_driver_status_t *msg = (void*)cmsg.msg;
    
    msg->status = (ok ? BLKIF_DRIVER_STATUS_UP : BLKIF_DRIVER_STATUS_DOWN);

    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}

/* Tell the controller to bring up the interface. */
static void 
blkif_send_interface_connect(void)
{
    ctrl_msg_t cmsg = {
        .type    = CMSG_BLKIF_FE,
        .subtype = CMSG_BLKIF_FE_INTERFACE_CONNECT,
        .length  = sizeof(blkif_fe_interface_connect_t),
    };
    blkif_fe_interface_connect_t *msg = (void*)cmsg.msg;
    
    msg->handle      = 0;
    msg->shmem_frame = (vtomach(blk_ring.sring) >> PAGE_SHIFT);
    
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}

static void 
blkif_free(void)
{

    unsigned long flags;

    printk("[XEN] Recovering virtual block device driver\n");
            
    /* Prevent new requests being issued until we fix things up. */
    mtx_lock_irqsave(&blkif_io_lock, flags);
    xb_recovery = 1;
    blkif_state = BLKIF_STATE_DISCONNECTED;
    mtx_unlock_irqrestore(&blkif_io_lock, flags);

    /* Free resources associated with old device channel. */
    if (blk_ring.sring != NULL) {
        free(blk_ring.sring, M_DEVBUF);
        blk_ring.sring = NULL;
    }
    /* free_irq(blkif_irq, NULL);*/
    blkif_irq = 0;
    
    unbind_evtchn_from_irq(blkif_evtchn);
    blkif_evtchn = 0;
}

static void 
blkif_close(void)
{
}

/* Move from CLOSED to DISCONNECTED state. */
static void 
blkif_disconnect(void)
{
    if (blk_ring.sring) free(blk_ring.sring, M_DEVBUF);
    blk_ring.sring = (blkif_sring_t *)malloc(PAGE_SIZE, M_DEVBUF, M_WAITOK);
    SHARED_RING_INIT(blk_ring.sring);
    FRONT_RING_INIT(&blk_ring, blk_ring.sring, PAGE_SIZE);
    blkif_state  = BLKIF_STATE_DISCONNECTED;
    blkif_send_interface_connect();
}

static void 
blkif_reset(void)
{
    printk("[XEN] Recovering virtual block device driver\n");
    blkif_free();
    blkif_disconnect();
}

static void 
blkif_recover(void)
{

    int i;
    blkif_request_t *req;

    /* Hmm, requests might be re-ordered when we re-issue them.
     * This will need to be fixed once we have barriers */

    /* Stage 1 : Find active and move to safety. */
    for ( i = 0; i < BLK_RING_SIZE; i++ ) {
        if ( rec_ring[i].id >= KERNBASE ) {
	    req = RING_GET_REQUEST(&blk_ring, 
                                   blk_ring.req_prod_pvt);
	    translate_req_to_mfn(req, &rec_ring[i]);
            blk_ring.req_prod_pvt++;
        }
    }

    printk("blkfront: recovered %d descriptors\n",blk_ring.req_prod_pvt);
	    
    /* Stage 2 : Set up shadow list. */
    for ( i = 0; i < blk_ring.req_prod_pvt; i++ ) {
	req = RING_GET_REQUEST(&blk_ring, i);
	rec_ring[i].id = req->id;
        req->id = i;
        translate_req_to_pfn(&rec_ring[i], req);
    }

    /* Stage 3 : Set up free list. */
    for ( ; i < BLK_RING_SIZE; i++ ){
        rec_ring[i].id = i+1;
    }
    rec_ring_free = blk_ring.req_prod_pvt;
    rec_ring[BLK_RING_SIZE-1].id = 0x0fffffff;

    /* blk_ring.req_prod will be set when we flush_requests().*/
    wmb();

    /* Switch off recovery mode, using a memory barrier to ensure that
     * it's seen before we flush requests - we don't want to miss any
     * interrupts. */
    xb_recovery = 0;
    wmb();

    /* Kicks things back into life. */
    flush_requests();

    /* Now safe to left other peope use interface. */
    blkif_state = BLKIF_STATE_CONNECTED;
}

static void 
blkif_connect(blkif_fe_interface_status_t *status)
{
    int err = 0;

    blkif_evtchn = status->evtchn;
    blkif_irq    = bind_evtchn_to_irq(blkif_evtchn);
#ifdef CONFIG_XEN_BLKDEV_GRANT
    rdomid       = status->domid;
#endif


    err = intr_add_handler("xbd", blkif_irq, 
			   (driver_intr_t *)xb_response_intr, NULL,
			   INTR_TYPE_BIO | INTR_MPSAFE, NULL);
    if(err){
        printk("[XEN] blkfront request_irq failed (err=%d)\n", err);
        return;
    }

    if ( xb_recovery ) {
        blkif_recover();
    } else {
        /* Probe for discs attached to the interface. */
	xb_vbdinit();

        /* XXX: transition state after probe */
        blkif_state = BLKIF_STATE_CONNECTED;
    }
    
    /* Kick pending requests. */
#if 0 /* XXX: figure out sortq logic */
    mtx_lock_irq(&blkif_io_lock);
    kick_pending_request_queues();
    mtx_unlock_irq(&blkif_io_lock);
#endif
}

static void 
unexpected(blkif_fe_interface_status_t *status)
{
    WPRINTK(" Unexpected blkif status %s in state %s\n", 
           blkif_status_name[status->status],
           blkif_state_name[blkif_state]);
}

static void 
blkif_status(blkif_fe_interface_status_t *status)
{
    if (status->handle != blkif_handle) {
        WPRINTK(" Invalid blkif: handle=%u", status->handle);
        return;
    }

    switch (status->status) {

    case BLKIF_INTERFACE_STATUS_CLOSED:
        switch(blkif_state){
        case BLKIF_STATE_CLOSED:
            unexpected(status);
            break;
        case BLKIF_STATE_DISCONNECTED:
        case BLKIF_STATE_CONNECTED:
            unexpected(status);
            blkif_close();
            break;
        }
        break;

    case BLKIF_INTERFACE_STATUS_DISCONNECTED:
        switch(blkif_state){
        case BLKIF_STATE_CLOSED:
            blkif_disconnect();
            break;
        case BLKIF_STATE_DISCONNECTED:
        case BLKIF_STATE_CONNECTED:
            unexpected(status);
            blkif_reset();
            break;
        }
        break;

    case BLKIF_INTERFACE_STATUS_CONNECTED:
        switch(blkif_state){
        case BLKIF_STATE_CLOSED:
            unexpected(status);
            blkif_disconnect();
            blkif_connect(status);
            break;
        case BLKIF_STATE_DISCONNECTED:
            blkif_connect(status);
            break;
        case BLKIF_STATE_CONNECTED:
            unexpected(status);
            blkif_connect(status);
            break;
        }
        break;

   case BLKIF_INTERFACE_STATUS_CHANGED:
        switch(blkif_state){
        case BLKIF_STATE_CLOSED:
        case BLKIF_STATE_DISCONNECTED:
            unexpected(status);
            break;
        case BLKIF_STATE_CONNECTED:
            vbd_update();
            break;
        }
       break;

    default:
        WPRINTK("Invalid blkif status: %d\n", status->status);
        break;
    }
}


static void 
blkif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_BLKIF_FE_INTERFACE_STATUS:
        if ( msg->length != sizeof(blkif_fe_interface_status_t) )
            goto parse_error;
        blkif_status((blkif_fe_interface_status_t *)
                     &msg->msg[0]);
        break;        
    default:
        goto parse_error;
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    msg->length = 0;
    ctrl_if_send_response(msg);
}

static int 
wait_for_blkif(void)
{
    int err = 0;
    int i;
    send_driver_status(1);

    /*
     * We should read 'nr_interfaces' from response message and wait
     * for notifications before proceeding. For now we assume that we
     * will be notified of exactly one interface.
     */
    for ( i=0; (blkif_state != BLKIF_STATE_CONNECTED) && (i < 10*hz); i++ )
    {
	tsleep(&blkif_state, PWAIT | PCATCH, "blkif", hz);
    }

    if (blkif_state != BLKIF_STATE_CONNECTED){
        printk("[XEN] Timeout connecting block device driver!\n");
        err = -ENOSYS;
    }
    return err;
}


static void
xb_init(void *unused)
{
    int i;

    printk("[XEN] Initialising virtual block device driver\n");

#ifdef CONFIG_XEN_BLKDEV_GRANT
    if ( 0 > gnttab_alloc_grant_references( MAXIMUM_OUTSTANDING_BLOCK_REQS,
                                            &gref_head, &gref_terminal ))
        return;
    printk("Blkif frontend is using grant tables.\n");
#endif
 
    xb_kick_pending = FALSE;
    xb_kick_pending_head = NULL;
    xb_kick_pending_tail = NULL;

    rec_ring_free = 0;
    for (i = 0; i < BLK_RING_SIZE; i++) {
	rec_ring[i].id = i+1;
    }
    rec_ring[BLK_RING_SIZE-1].id = 0x0fffffff;

    (void)ctrl_if_register_receiver(CMSG_BLKIF_FE, blkif_ctrlif_rx, 0);

    wait_for_blkif();
}

#if 0 /* XXX not yet */
void
blkdev_suspend(void)
{
}

void 
blkdev_resume(void)
{
    send_driver_status(1);
}
#endif

void 
blkif_completion(blkif_request_t *req)
{
    int i;

#ifdef CONFIG_XEN_BLKDEV_GRANT
    grant_ref_t gref;

    for ( i = 0; i < req->nr_segments; i++ )
    {
        gref = blkif_gref_from_fas(req->frame_and_sects[i]);
        gnttab_release_grant_reference(&gref_head, gref);
    }
#else
    /* This is a hack to get the dirty logging bits set */
    switch ( req->operation )
    {
    case BLKIF_OP_READ:
	for ( i = 0; i < req->nr_segments; i++ )
	{
	    unsigned long pfn = req->frame_and_sects[i] >> PAGE_SHIFT;
	    unsigned long mfn = xen_phys_machine[pfn];
	    xen_machphys_update(mfn, pfn);
	}
	break;
    }
#endif    
}
MTX_SYSINIT(ioreq, &blkif_io_lock, "BIO LOCK", MTX_SPIN | MTX_NOWITNESS); /* XXX how does one enroll a lock? */
 MTX_SYSINIT(ioreq_block, &blkif_io_block_lock, "BIO BLOCK LOCK", MTX_SPIN | MTX_NOWITNESS);
SYSINIT(xbdev, SI_SUB_PSEUDO, SI_ORDER_ANY, xb_init, NULL)
