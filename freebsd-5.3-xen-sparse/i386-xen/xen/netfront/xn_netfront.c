/*
 *
 * Copyright (c) 2004 Kip Macy
 * All rights reserved.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "opt_nfsroot.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <net/bpf.h>

#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/clock.h>      /* for DELAY */
#include <machine/bus_memio.h>
#include <machine/bus.h>
#include <machine/resource.h>
#include <machine/frame.h>


#include <sys/bus.h>
#include <sys/rman.h>

#include <machine/intr_machdep.h>

#include <machine/xen-os.h>
#include <machine/hypervisor.h>
#include <machine/hypervisor-ifs.h>
#include <machine/xen_intr.h>
#include <machine/evtchn.h>
#include <machine/ctrl_if.h>

struct xn_softc;
static void xn_txeof(struct xn_softc *);
static void xn_rxeof(struct xn_softc *);
static void xn_alloc_rx_buffers(struct xn_softc *);

static void xn_tick_locked(struct xn_softc *);
static void xn_tick(void *);

static void xn_intr(void *);
static void xn_start_locked(struct ifnet *);
static void xn_start(struct ifnet *);
static int  xn_ioctl(struct ifnet *, u_long, caddr_t);
static void xn_ifinit_locked(struct xn_softc *);
static void xn_ifinit(void *);
static void xn_stop(struct xn_softc *);
#ifdef notyet
static void xn_watchdog(struct ifnet *);
#endif
/* Xenolinux helper functions */
static void network_connect(struct xn_softc *, netif_fe_interface_status_t *);
static void create_netdev(int handle, struct xn_softc **);
static void netif_ctrlif_rx(ctrl_msg_t *,unsigned long);

static void xn_free_rx_ring(struct xn_softc *);

static void xn_free_tx_ring(struct xn_softc *);



/* XXX: This isn't supported in FreeBSD, so ignore it for now. */
#define TASK_UNINTERRUPTIBLE	0
#define INVALID_P2M_ENTRY (~0UL)

/*
 * If the backend driver is pipelining transmit requests then we can be very
 * aggressive in avoiding new-packet notifications -- only need to send a
 * notification if there are no outstanding unreceived responses.
 * If the backend may be buffering our transmit buffers for any reason then we
 * are rather more conservative.
 */
#ifdef CONFIG_XEN_NETDEV_FRONTEND_PIPELINED_TRANSMITTER
#define TX_TEST_IDX resp_prod /* aggressive: any outstanding responses? */
#else
#define TX_TEST_IDX req_cons  /* conservative: not seen all our requests? */
#endif

/*
 * Mbuf pointers. We need these to keep track of the virtual addresses
 * of our mbuf chains since we can only convert from virtual to physical,
 * not the other way around.  The size must track the free index arrays.
 */
struct xn_chain_data {
	struct mbuf		*xn_tx_chain[NETIF_TX_RING_SIZE+1];
        struct mbuf		*xn_rx_chain[NETIF_RX_RING_SIZE+1];
};

struct xn_softc {
	struct arpcom		arpcom;		/* interface info */
	device_t		xn_dev;
	SLIST_ENTRY(xn_softc)	xn_links;
        struct mtx              xn_mtx;
	void			*xn_intrhand;
	struct resource		*xn_res;
	u_int8_t		xn_ifno;	/* interface number */
	struct xn_chain_data	xn_cdata;	/* mbufs */

        netif_tx_interface_t    *xn_tx_if;
        netif_rx_interface_t    *xn_rx_if;

	int			xn_if_flags;
	int			xn_txcnt;
	int			xn_rxbufcnt;
	struct callout	        xn_stat_ch;
	unsigned int		xn_irq;
        unsigned int            xn_evtchn;  


    /* What is the status of our connection to the remote backend? */
#define BEST_CLOSED       0
#define BEST_DISCONNECTED 1
#define BEST_CONNECTED    2
    	unsigned int 		xn_backend_state;

    /* Is this interface open or closed (down or up)? */
#define UST_CLOSED        0
#define UST_OPEN          1
    	unsigned int 		xn_user_state;
    
    /* Receive-ring batched refills. */
#define RX_MIN_TARGET 64	/* XXX: larger than linux.  was causing packet
				 * loss at the default of 8.
				 */
#define RX_MAX_TARGET NETIF_RX_RING_SIZE
	int 			xn_rx_target;	/* number to allocate */
	struct mbuf		*xn_rx_batch;	/* head of the batch queue */
	struct mbuf		*xn_rx_batchtail;
	int			xn_rx_batchlen;	/* how many queued */

        int                     xn_rx_resp_cons;
        int                     xn_tx_resp_cons;
        unsigned short          xn_rx_free_idxs[NETIF_RX_RING_SIZE+1];
        unsigned short          xn_tx_free_idxs[NETIF_RX_RING_SIZE+1];
};

static unsigned long           	xn_rx_pfns[NETIF_RX_RING_SIZE];
static multicall_entry_t       	xn_rx_mcl[NETIF_RX_RING_SIZE+1];
static mmu_update_t		xn_rx_mmu[NETIF_RX_RING_SIZE];

static SLIST_HEAD(, xn_softc) xn_dev_list =
       SLIST_HEAD_INITIALIZER(xn_dev_list);

#define XN_LOCK_INIT(_sc, _name) \
        mtx_init(&(_sc)->xn_mtx, _name, MTX_NETWORK_LOCK, MTX_DEF)
#define XN_LOCK(_sc)           mtx_lock(&(_sc)->xn_mtx)
#define XN_LOCK_ASSERT(_sc)    mtx_assert(&(_sc)->xn_mtx, MA_OWNED)
#define XN_UNLOCK(_sc)         mtx_unlock(&(_sc)->xn_mtx)
#define XN_LOCK_DESTROY(_sc)   mtx_destroy(&(_sc)->xn_mtx)

/* Access macros for acquiring freeing slots in xn_free_{tx,rx}_idxs[]. */
#define ADD_ID_TO_FREELIST(_list, _id)             \
    (_list)[(_id)] = (_list)[0];                   \
    (_list)[0]     = (_id);
#define GET_ID_FROM_FREELIST(_list)                \
 ({ unsigned short _id = (_list)[0]; \
    (_list)[0]  = (_list)[_id];                    \
    (unsigned short)_id; })
#define FREELIST_EMPTY(_list, _maxid) 		   \
    ((_list)[0] == (_maxid+1))

static char *status_name[] = {
    [NETIF_INTERFACE_STATUS_CLOSED]       = "closed",
    [NETIF_INTERFACE_STATUS_DISCONNECTED] = "disconnected",
    [NETIF_INTERFACE_STATUS_CONNECTED]    = "connected",
    [NETIF_INTERFACE_STATUS_CHANGED]      = "changed",
};

static char *be_state_name[] = {
    [BEST_CLOSED]       = "closed",
    [BEST_DISCONNECTED] = "disconnected",
    [BEST_CONNECTED]    = "connected",
};

#define IPRINTK(fmt, args...) \
    printk("[XEN] " fmt, ##args)
#define WPRINTK(fmt, args...) \
    printk("[XEN] " fmt, ##args)

static struct xn_softc *
find_sc_by_handle(unsigned int handle)
{
    struct xn_softc *sc;
    SLIST_FOREACH(sc, &xn_dev_list, xn_links)
    {
        if ( sc->xn_ifno == handle )
            return sc;
    }
    return NULL;
}

/** Network interface info. */
struct netif_ctrl {
    /** Number of interfaces. */
    int interface_n;
    /** Number of connected interfaces. */
    int connected_n;
    /** Error code. */
    int err;
    int up;
};

static struct netif_ctrl netctrl;

static void 
netctrl_init(void)
{
    /* 
     * netctrl is already in bss, why are we setting it?
     */
    memset(&netctrl, 0, sizeof(netctrl)); 
    netctrl.up = NETIF_DRIVER_STATUS_DOWN;
}

/** Get or set a network interface error.
 */
static int 
netctrl_err(int err)
{
    if ( (err < 0) && !netctrl.err )
        netctrl.err = err;
    return netctrl.err;
}

/** Test if all network interfaces are connected.
 *
 * @return 1 if all connected, 0 if not, negative error code otherwise
 */
static int 
netctrl_connected(void)
{
    int ok;
    XENPRINTF("err %d up %d\n", netctrl.err, netctrl.up);
    if (netctrl.err)
	ok = netctrl.err;
    else if (netctrl.up == NETIF_DRIVER_STATUS_UP)
	ok = (netctrl.connected_n == netctrl.interface_n);
    else
	ok = 0;

    return ok;
}

/** Count the connected network interfaces.
 *
 * @return connected count
 */
static int 
netctrl_connected_count(void)
{
    
    struct xn_softc *sc;
    unsigned int connected;

    connected = 0;
    
    SLIST_FOREACH(sc, &xn_dev_list, xn_links)
    {
        if ( sc->xn_backend_state == BEST_CONNECTED )
            connected++;
    }

    netctrl.connected_n = connected;
    XENPRINTF("> connected_n=%d interface_n=%d\n",
              netctrl.connected_n, netctrl.interface_n);
    return connected;
}

static __inline struct mbuf* 
makembuf (struct mbuf *buf)
{
	struct mbuf *m = NULL;

        MGETHDR (m, M_DONTWAIT, MT_DATA);

        if (! m)
               return 0;

	M_MOVE_PKTHDR(m, buf);

        MCLGET (m, M_DONTWAIT);

        m->m_pkthdr.len = buf->m_pkthdr.len;
        m->m_len = buf->m_len;
	m_copydata(buf, 0, buf->m_pkthdr.len, mtod(m,caddr_t) );
	m->m_ext.ext_args = (vm_paddr_t *)vtophys(mtod(m,caddr_t));

       	return m;
}



static void
xn_free_rx_ring(struct xn_softc *sc)
{
#if 0
    int i;
    
    for (i = 0; i < NETIF_RX_RING_SIZE; i++) {
	if (sc->xn_cdata.xn_rx_chain[MASK_NETIF_RX_IDX(i)] != NULL) {
	    m_freem(sc->xn_cdata.xn_rx_chain[MASK_NETIF_RX_IDX(i)]);
	    sc->xn_cdata.xn_rx_chain[MASK_NETIF_RX_IDX(i)] = NULL;
	}
    }
    
    sc->xn_rx_resp_cons = 0;
    sc->xn_rx_if->req_prod = 0;
    sc->xn_rx_if->event = sc->xn_rx_resp_cons ;
#endif
}

static void
xn_free_tx_ring(struct xn_softc *sc)
{
#if 0
    int i;
    
    for (i = 0; i < NETIF_TX_RING_SIZE; i++) {
	if (sc->xn_cdata.xn_tx_chain[MASK_NETIF_TX_IDX(i)] != NULL) {
	    m_freem(sc->xn_cdata.xn_tx_chain[MASK_NETIF_TX_IDX(i)]);
	    sc->xn_cdata.xn_tx_chain[MASK_NETIF_TX_IDX(i)] = NULL;
	}
    }
    
    return;
#endif
}

static void
xn_alloc_rx_buffers(struct xn_softc *sc)
{
    unsigned short id;
    struct mbuf *m_new, *next;
    int i, batch_target;
    NETIF_RING_IDX req_prod = sc->xn_rx_if->req_prod;

    if (unlikely(sc->xn_backend_state != BEST_CONNECTED) )
	    return;

    /*
     * Allocate skbuffs greedily, even though we batch updates to the
     * receive ring. This creates a less bursty demand on the memory allocator,
     * so should reduce the chance of failed allocation requests both for
     * ourself and for other kernel subsystems.
     */
    batch_target = sc->xn_rx_target - (req_prod - sc->xn_rx_resp_cons);
    for ( i = sc->xn_rx_batchlen; i < batch_target; i++, sc->xn_rx_batchlen++) {
	MGETHDR(m_new, M_DONTWAIT, MT_DATA);
	if (m_new == NULL) 
	    break;
	
	MCLGET(m_new, M_DONTWAIT);
	if (!(m_new->m_flags & M_EXT)) {
	    m_freem(m_new);
	    break;
	}
	m_new->m_len = m_new->m_pkthdr.len = MCLBYTES;

	/* queue the mbufs allocated */
	if (!sc->xn_rx_batch)
	    	sc->xn_rx_batch = m_new;

	if (sc->xn_rx_batchtail)
	    sc->xn_rx_batchtail->m_next = m_new;
	sc->xn_rx_batchtail = m_new;
    }

    /* Is the batch large enough to be worthwhile? */
    if ( i < (sc->xn_rx_target/2)  )
        return;

    for (i = 0, m_new = sc->xn_rx_batch; m_new; 
	 i++, sc->xn_rx_batchlen--, m_new = next) {

	next = m_new->m_next;
	m_new->m_next = NULL;

	m_new->m_ext.ext_args = (vm_paddr_t *)vtophys(m_new->m_ext.ext_buf);

	id = GET_ID_FROM_FREELIST(sc->xn_rx_free_idxs);
	KASSERT(id != 0, ("alloc_rx_buffers: found free receive index of 0\n"));
	sc->xn_cdata.xn_rx_chain[MASK_NETIF_RX_IDX(id)] = m_new;

	sc->xn_rx_if->ring[MASK_NETIF_RX_IDX(req_prod + i)].req.id = id;

	xn_rx_pfns[i] = vtomach(mtod(m_new,vm_offset_t)) >> PAGE_SHIFT;

	/* Remove this page from pseudo phys map before passing back to Xen. */
    	xen_phys_machine[((unsigned long)m_new->m_ext.ext_args >> PAGE_SHIFT)] 
		= INVALID_P2M_ENTRY;
	    	
	xn_rx_mcl[i].op = __HYPERVISOR_update_va_mapping;
	xn_rx_mcl[i].args[0] = (unsigned long)mtod(m_new,vm_offset_t);
	xn_rx_mcl[i].args[1] = 0;
	xn_rx_mcl[i].args[2] = 0;

    } 

    KASSERT(i, ("no mbufs processed"));	/* should have returned earlier */
    KASSERT(sc->xn_rx_batchlen == 0, ("not all mbufs processed"));
    sc->xn_rx_batch = sc->xn_rx_batchtail = NULL;
    
    /*
     * We may have allocated buffers which have entries outstanding
     in the page * update queue -- make sure we flush those first!  */
    PT_UPDATES_FLUSH();

    /* After all PTEs have been zapped we blow away stale TLB entries. */
    xn_rx_mcl[i-1].args[2] = UVMF_FLUSH_TLB;

    /* Give away a batch of pages. */
    xn_rx_mcl[i].op = __HYPERVISOR_dom_mem_op;
    xn_rx_mcl[i].args[0] = (unsigned long) MEMOP_decrease_reservation;
    xn_rx_mcl[i].args[1] = (unsigned long)xn_rx_pfns;
    xn_rx_mcl[i].args[2] = (unsigned long)i;
    xn_rx_mcl[i].args[3] = 0;
    xn_rx_mcl[i].args[4] = DOMID_SELF;

    /* Zap PTEs and give away pages in one big multicall. */
    (void)HYPERVISOR_multicall(xn_rx_mcl, i+1);

    /* Check return status of HYPERVISOR_dom_mem_op(). */
    if ( xn_rx_mcl[i].args[5] != i )
        panic("Unable to reduce memory reservation\n");

    /* Above is a suitable barrier to ensure backend will see requests. */
    sc->xn_rx_if->req_prod = req_prod + i;

    /* Adjust our floating fill target if we risked running out of buffers. */
    if ( ((req_prod - sc->xn_rx_if->resp_prod) < (sc->xn_rx_target / 4)) &&
         ((sc->xn_rx_target *= 2) > RX_MAX_TARGET) )
        sc->xn_rx_target = RX_MAX_TARGET;
}

static void
xn_rxeof(struct xn_softc *sc)
{
    struct ifnet *ifp;
    netif_rx_response_t  *rx;
    NETIF_RING_IDX i, rp;
    mmu_update_t *mmu = xn_rx_mmu;
    multicall_entry_t *mcl = xn_rx_mcl;
    struct mbuf *tail_mbuf = NULL, *head_mbuf = NULL, *m, *next;
    
    XN_LOCK_ASSERT(sc);
    if (sc->xn_backend_state != BEST_CONNECTED)
	return;

    ifp = &sc->arpcom.ac_if;

    rp = sc->xn_rx_if->resp_prod;
    rmb();	/* Ensure we see queued responses up to 'rp'. */

    for (i = sc->xn_rx_resp_cons; i != rp; i++) {

	rx = &sc->xn_rx_if->ring[MASK_NETIF_RX_IDX(i)].resp;
	KASSERT(rx->id != 0, ("xn_rxeof: found free receive index of 0\n"));

        /*
         * An error here is very odd. Usually indicates a backend bug,
         * low-memory condition, or that we didn't have reservation headroom.
         * Whatever - print an error and queue the id again straight away.
         */
        if (unlikely(rx->status <= 0)) {
	    printk("bad buffer on RX ring!(%d)\n", rx->status);
	    sc->xn_rx_if->ring[MASK_NETIF_RX_IDX(sc->xn_rx_if->req_prod)].req.id
			= rx->id;
	    wmb();
	    sc->xn_rx_if->req_prod++;
            continue;
        }

	m = (struct mbuf *)
	    	sc->xn_cdata.xn_rx_chain[MASK_NETIF_RX_IDX(rx->id)];
	if (m->m_next)
	    panic("mbuf is already part of a valid mbuf chain");
	ADD_ID_TO_FREELIST(sc->xn_rx_free_idxs, rx->id);

	m->m_data += (rx->addr & PAGE_MASK);
	m->m_pkthdr.len = m->m_len = rx->status;
	m->m_pkthdr.rcvif = ifp;

	/* Remap the page. */
	mmu->ptr = (rx->addr & ~PAGE_MASK) | MMU_MACHPHYS_UPDATE;
	mmu->val = (unsigned long)m->m_ext.ext_args >> PAGE_SHIFT;
	mmu++;
	mcl->op = __HYPERVISOR_update_va_mapping;
	mcl->args[0] = (unsigned long)m->m_data;
	mcl->args[1] = (rx->addr & ~PAGE_MASK) | PG_KERNEL;
	mcl->args[2] = 0;
	mcl++;

    	xen_phys_machine[((unsigned long)m->m_ext.ext_args >> PAGE_SHIFT)] = 
	    	(rx->addr >> PAGE_SHIFT);

	if (unlikely(!head_mbuf))
	    head_mbuf = m;

	if (tail_mbuf)
	    tail_mbuf->m_next = m;
	tail_mbuf = m;

	sc->xn_cdata.xn_rx_chain[MASK_NETIF_RX_IDX(rx->id)] = NULL;
	sc->xn_rxbufcnt++;
    }

    /* Do all the remapping work, and M->P updates,  in one big hypercall. */
    if (likely((mcl - xn_rx_mcl) != 0)) {
	mcl->op = __HYPERVISOR_mmu_update;
	mcl->args[0] = (unsigned long)xn_rx_mmu;
	mcl->args[1] = mmu - xn_rx_mmu;
	mcl->args[2] = 0;
	mcl++;
	(void)HYPERVISOR_multicall(xn_rx_mcl, mcl - xn_rx_mcl);
    }


    /* 
     * Process all the mbufs after the remapping is complete.
     * Break the mbuf chain first though.
     */
    for (m = head_mbuf; m; m = next) {
	next = m->m_next;
	m->m_next = NULL;

	ifp->if_ipackets++;

    	XN_UNLOCK(sc);

	/* Pass it up. */
	(*ifp->if_input)(ifp, m);
    	XN_LOCK(sc);
    }
    
    sc->xn_rx_resp_cons = i;

    /* If we get a callback with very few responses, reduce fill target. */
    /* NB. Note exponential increase, linear decrease. */
    if (((sc->xn_rx_if->req_prod - sc->xn_rx_if->resp_prod) > 
	    ((3*sc->xn_rx_target) / 4)) && (--sc->xn_rx_target < RX_MIN_TARGET))
        sc->xn_rx_target = RX_MIN_TARGET;

    xn_alloc_rx_buffers(sc);

    sc->xn_rx_if->event = i + 1;
}

static void 
xn_txeof(struct xn_softc *sc)
{
    NETIF_RING_IDX i, prod;
    unsigned short id;
    struct ifnet *ifp;
    struct mbuf *m;

    XN_LOCK_ASSERT(sc);

    if (sc->xn_backend_state != BEST_CONNECTED)
	return;

    ifp = &sc->arpcom.ac_if;
    ifp->if_timer = 0;

    do {
	prod = sc->xn_tx_if->resp_prod;

	for (i = sc->xn_tx_resp_cons; i != prod; i++) {
	    	id = sc->xn_tx_if->ring[MASK_NETIF_TX_IDX(i)].resp.id;
	    	m = sc->xn_cdata.xn_tx_chain[MASK_NETIF_TX_IDX(id)]; 

		KASSERT(m != NULL, ("mbuf not found in xn_tx_chain"));
		M_ASSERTVALID(m);

	    	m_freem(m);
	    	sc->xn_cdata.xn_tx_chain[MASK_NETIF_TX_IDX(id)] = NULL;
		ADD_ID_TO_FREELIST(sc->xn_tx_free_idxs, id);
		sc->xn_txcnt--;
	}
	sc->xn_tx_resp_cons = prod;

        /*
         * Set a new event, then check for race with update of tx_cons. Note
         * that it is essential to schedule a callback, no matter how few
         * buffers are pending. Even if there is space in the transmit ring,
         * higher layers may be blocked because too much data is outstanding:
         * in such cases notification from Xen is likely to be the only kick
         * that we'll get.
         */
	sc->xn_tx_if->event = 
	    prod + ((sc->xn_tx_if->req_prod - prod) >> 1) + 1;

	mb();

    } while (prod != sc->xn_tx_if->resp_prod);
}

static void
xn_intr(void *xsc)
{
    struct xn_softc *sc = xsc;
    struct ifnet *ifp = &sc->arpcom.ac_if;

    XN_LOCK(sc);

    /* sometimes we seem to lose packets.  stay in the interrupt handler while
     * there is stuff to process: continually recheck the response producer.
     */
    do {
    	xn_txeof(sc);

    	if (sc->xn_rx_resp_cons != sc->xn_rx_if->resp_prod &&
		sc->xn_user_state == UST_OPEN)
		xn_rxeof(sc);
    
    	if (ifp->if_flags & IFF_RUNNING && ifp->if_snd.ifq_head != NULL)
		xn_start_locked(ifp);
    } while (sc->xn_rx_resp_cons != sc->xn_rx_if->resp_prod &&
		sc->xn_user_state == UST_OPEN);

    XN_UNLOCK(sc);
    return;
}

static void
xn_tick_locked(struct xn_softc *sc) 
{
    XN_LOCK_ASSERT(sc);
    callout_reset(&sc->xn_stat_ch, hz, xn_tick, sc);

    /* XXX placeholder for printing debug information */
     
}


static void
xn_tick(void *xsc) 
{
    struct xn_softc *sc;
    
    sc = xsc;
    XN_LOCK(sc);
    xn_tick_locked(sc);
    XN_UNLOCK(sc);
     
}
static void
xn_start_locked(struct ifnet *ifp) 
{
    unsigned short id;
    struct mbuf *m_head, *new_m;
    struct xn_softc *sc = ifp->if_softc;
    netif_tx_request_t *tx;
    NETIF_RING_IDX i, start;

    if (sc->xn_backend_state != BEST_CONNECTED)
	return;

    for (i = start = sc->xn_tx_if->req_prod; TRUE; i++, sc->xn_txcnt++) {

    	IF_DEQUEUE(&ifp->if_snd, m_head);
    	if (m_head == NULL) 
	    break;

	if (FREELIST_EMPTY(sc->xn_tx_free_idxs, NETIF_TX_RING_SIZE)) {
	    IF_PREPEND(&ifp->if_snd, m_head);
	    ifp->if_flags |= IFF_OACTIVE;
	    break;
	}

	i = sc->xn_tx_if->req_prod;

	id = GET_ID_FROM_FREELIST(sc->xn_tx_free_idxs);

	/*
	 * Start packing the mbufs in this chain into
	 * the fragment pointers. Stop when we run out
	 * of fragments or hit the end of the mbuf chain.
	 */
	new_m = makembuf(m_head);
	tx = &(sc->xn_tx_if->ring[MASK_NETIF_TX_IDX(i)].req);
	tx->id = id;
	tx->size = new_m->m_pkthdr.len;
	new_m->m_next = NULL;
	new_m->m_nextpkt = NULL;

	m_freem(m_head);
	tx->addr = vtomach(mtod(new_m, vm_offset_t));
		
	sc->xn_cdata.xn_tx_chain[MASK_NETIF_TX_IDX(id)] = new_m;
	BPF_MTAP(ifp, new_m);
    }

    sc->xn_tx_if->req_prod = i;
    xn_txeof(sc);

    /* Only notify Xen if we really have to. */
    if (sc->xn_tx_if->TX_TEST_IDX == start)
	notify_via_evtchn(sc->xn_evtchn);
    return;
}    

static void
xn_start(struct ifnet *ifp)
{
    struct xn_softc *sc;
    sc = ifp->if_softc;
    XN_LOCK(sc);
    xn_start_locked(ifp);
    XN_UNLOCK(sc);
}



/* equivalent of network_open() in Linux */
static void 
xn_ifinit_locked(struct xn_softc *sc) 
{
    struct ifnet *ifp;

    XN_LOCK_ASSERT(sc);

    ifp = &sc->arpcom.ac_if;
    
    if (ifp->if_flags & IFF_RUNNING) 
	return;
	
    xn_stop(sc);

    sc->xn_user_state = UST_OPEN;

    xn_alloc_rx_buffers(sc);
    sc->xn_rx_if->event = sc->xn_rx_resp_cons + 1;

    ifp->if_flags |= IFF_RUNNING;
    ifp->if_flags &= ~IFF_OACTIVE;

    callout_reset(&sc->xn_stat_ch, hz, xn_tick, sc);

}


static void 
xn_ifinit(void *xsc)
{
    struct xn_softc *sc = xsc;
    
    XN_LOCK(sc);
    xn_ifinit_locked(sc);
    XN_UNLOCK(sc);

}


static int
xn_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
    struct xn_softc *sc = ifp->if_softc;
    struct ifreq *ifr = (struct ifreq *) data;
    int mask, error = 0;
    switch(cmd) {
    case SIOCSIFMTU:
	/* XXX can we alter the MTU on a VN ?*/
#ifdef notyet
	if (ifr->ifr_mtu > XN_JUMBO_MTU)
	    error = EINVAL;
	else 
#endif
	    {
		ifp->if_mtu = ifr->ifr_mtu;
		ifp->if_flags &= ~IFF_RUNNING;
		xn_ifinit(sc);
	    }
	break;
    case SIOCSIFFLAGS:
	XN_LOCK(sc);
	if (ifp->if_flags & IFF_UP) {
	    /*
	     * If only the state of the PROMISC flag changed,
	     * then just use the 'set promisc mode' command
	     * instead of reinitializing the entire NIC. Doing
	     * a full re-init means reloading the firmware and
	     * waiting for it to start up, which may take a
	     * second or two.
	     */
#ifdef notyet
	    /* No promiscuous mode with Xen */
	    if (ifp->if_flags & IFF_RUNNING &&
		ifp->if_flags & IFF_PROMISC &&
		!(sc->xn_if_flags & IFF_PROMISC)) {
		XN_SETBIT(sc, XN_RX_MODE,
			  XN_RXMODE_RX_PROMISC);
	    } else if (ifp->if_flags & IFF_RUNNING &&
		       !(ifp->if_flags & IFF_PROMISC) &&
		       sc->xn_if_flags & IFF_PROMISC) {
		XN_CLRBIT(sc, XN_RX_MODE,
			  XN_RXMODE_RX_PROMISC);
	    } else
#endif
		xn_ifinit_locked(sc);
	} else {
	    if (ifp->if_flags & IFF_RUNNING) {
		xn_stop(sc);
	    }
	}
	sc->xn_if_flags = ifp->if_flags;
	XN_UNLOCK(sc);
	error = 0;
	break;
    case SIOCSIFCAP:
	mask = ifr->ifr_reqcap ^ ifp->if_capenable;
	if (mask & IFCAP_HWCSUM) {
	    if (IFCAP_HWCSUM & ifp->if_capenable)
		ifp->if_capenable &= ~IFCAP_HWCSUM;
	    else
		ifp->if_capenable |= IFCAP_HWCSUM;
	}
	error = 0;
	break;
    case SIOCADDMULTI:
    case SIOCDELMULTI:
#ifdef notyet
	if (ifp->if_flags & IFF_RUNNING) {
	    XN_LOCK(sc);
	    xn_setmulti(sc);
	    XN_UNLOCK(sc);
	    error = 0;
	}
#endif
	/* FALLTHROUGH */
    case SIOCSIFMEDIA:
    case SIOCGIFMEDIA:
	error = EINVAL;
	break;
    default:
	error = ether_ioctl(ifp, cmd, data);
    }
    
    return (error);
}

static void
xn_stop(struct xn_softc *sc)
{	
    struct ifnet *ifp;

    XN_LOCK_ASSERT(sc);
    
    ifp = &sc->arpcom.ac_if;

    callout_stop(&sc->xn_stat_ch);

    xn_free_rx_ring(sc);
    xn_free_tx_ring(sc);
    
    ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);
}

/* START of Xenolinux helper functions adapted to FreeBSD */
static void
network_connect(struct xn_softc *sc, netif_fe_interface_status_t *status)
{
    struct ifnet *ifp;
    int i, requeue_idx;
    netif_tx_request_t *tx;

    XN_LOCK(sc);

    ifp = &sc->arpcom.ac_if;
    /* first time through, setup the ifp info */
    if (ifp->if_softc == NULL) {
    	ifp->if_softc = sc;
    	if_initname(ifp, "xn", sc->xn_ifno);
    	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX;
    	ifp->if_ioctl = xn_ioctl;
    	ifp->if_output = ether_output;
    	ifp->if_start = xn_start;
#ifdef notyet
    	ifp->if_watchdog = xn_watchdog;
#endif
    	ifp->if_init = xn_ifinit;
    	ifp->if_mtu = ETHERMTU;
    	ifp->if_snd.ifq_maxlen = NETIF_TX_RING_SIZE - 1;

#ifdef notyet
    	ifp->if_hwassist = XN_CSUM_FEATURES;
    	ifp->if_capabilities = IFCAP_HWCSUM;
    	ifp->if_capenable = ifp->if_capabilities;
#endif    

    	ether_ifattach(ifp, sc->arpcom.ac_enaddr);
    	callout_init(&sc->xn_stat_ch, CALLOUT_MPSAFE);
    }

    /* Recovery procedure: */

    /* Step 1: Reinitialise variables. */
    sc->xn_rx_resp_cons = sc->xn_tx_resp_cons = 0;
    sc->xn_rxbufcnt = sc->xn_txcnt = 0;
    sc->xn_rx_if->event = sc->xn_tx_if->event = 1;

    /* Step 2: Rebuild the RX and TX ring contents.
     * NB. We could just free the queued TX packets now but we hope
     * that sending them out might do some good.  We have to rebuild
     * the RX ring because some of our pages are currently flipped out
     * so we can't just free the RX skbs.
     */

    /* Rebuild the TX buffer freelist and the TX ring itself.
     * NB. This reorders packets.  We could keep more private state
     * to avoid this but maybe it doesn't matter so much given the
     * interface has been down.
     */
    for ( requeue_idx = 0, i = 1; i <= NETIF_TX_RING_SIZE; i++ )
    {
	    if (sc->xn_cdata.xn_tx_chain[i] != NULL)
            {
                struct mbuf *m = sc->xn_cdata.xn_tx_chain[i];
                
                tx = &sc->xn_tx_if->ring[requeue_idx++].req;
                
                tx->id   = i;
		tx->addr = vtomach(mtod(m, vm_offset_t));
		tx->size = m->m_pkthdr.len;
		sc->xn_txcnt++;
            }
    }
    wmb();
    sc->xn_tx_if->req_prod = requeue_idx;

    /* Rebuild the RX buffer freelist and the RX ring itself. */
    for ( requeue_idx = 0, i = 1; i <= NETIF_RX_RING_SIZE; i++ )
	if (sc->xn_cdata.xn_rx_chain[i] != NULL) 
            sc->xn_rx_if->ring[requeue_idx++].req.id = i;
    wmb();                
    sc->xn_rx_if->req_prod = requeue_idx;

    printk("[XEN] Netfront recovered tx=%d rxfree=%d\n",
       	   sc->xn_tx_if->req_prod,sc->xn_rx_if->req_prod);


    /* Step 3: All public and private state should now be sane.  Get
     * ready to start sending and receiving packets and give the driver
     * domain a kick because we've probably just requeued some
     * packets.
     */
    sc->xn_backend_state = BEST_CONNECTED;
    wmb();
    notify_via_evtchn(status->evtchn);  
    xn_txeof(sc);

    XN_UNLOCK(sc);
}


static void 
vif_show(struct xn_softc *sc)
{
#if DEBUG
    if (sc) {
        IPRINTK("<vif handle=%u %s(%s) evtchn=%u irq=%u tx=%p rx=%p>\n",
               sc->xn_ifno,
               be_state_name[sc->xn_backend_state],
               sc->xn_user_state ? "open" : "closed",
               sc->xn_evtchn,
               sc->xn_irq,
               sc->xn_tx_if,
               sc->xn_rx_if);
    } else {
        IPRINTK("<vif NULL>\n");
    }
#endif
}

/* Send a connect message to xend to tell it to bring up the interface. */
static void 
send_interface_connect(struct xn_softc *sc)
{
    ctrl_msg_t cmsg = {
        .type    = CMSG_NETIF_FE,
        .subtype = CMSG_NETIF_FE_INTERFACE_CONNECT,
        .length  = sizeof(netif_fe_interface_connect_t),
    };
    netif_fe_interface_connect_t *msg = (void*)cmsg.msg;

    vif_show(sc); 
    msg->handle = sc->xn_ifno;
    msg->tx_shmem_frame = (vtomach(sc->xn_tx_if) >> PAGE_SHIFT);
    msg->rx_shmem_frame = (vtomach(sc->xn_rx_if) >> PAGE_SHIFT);
        
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}

/* Send a driver status notification to the domain controller. */
static int 
send_driver_status(int ok)
{
    int err = 0;
    ctrl_msg_t cmsg = {
        .type    = CMSG_NETIF_FE,
        .subtype = CMSG_NETIF_FE_DRIVER_STATUS,
        .length  = sizeof(netif_fe_driver_status_t),
    };
    netif_fe_driver_status_t *msg = (void*)cmsg.msg;

    msg->status = (ok ? NETIF_DRIVER_STATUS_UP : NETIF_DRIVER_STATUS_DOWN);
    err = ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
    return err;
}

/* Stop network device and free tx/rx queues and irq.
 */
static void 
vif_release(struct xn_softc *sc)
{
    /* Stop old i/f to prevent errors whilst we rebuild the state. */
    XN_LOCK(sc);
    /* sc->xn_backend_state = BEST_DISCONNECTED; */
    XN_UNLOCK(sc);
    
    /* Free resources. */
    if(sc->xn_tx_if != NULL) {
        unbind_evtchn_from_irq(sc->xn_evtchn);
	free(sc->xn_tx_if, M_DEVBUF);
	free(sc->xn_rx_if, M_DEVBUF);
        sc->xn_irq = 0;
        sc->xn_evtchn = 0;
        sc->xn_tx_if = NULL;
        sc->xn_rx_if = NULL;
    }
}

/* Release vif resources and close it down completely.
 */
static void 
vif_close(struct xn_softc *sc)
{
    vif_show(sc);
    WPRINTK("Unexpected netif-CLOSED message in state %s\n",
            be_state_name[sc->xn_backend_state]);
    vif_release(sc);
    sc->xn_backend_state = BEST_CLOSED;
    /* todo: take dev down and free. */
    vif_show(sc);
}

/* Move the vif into disconnected state.
 * Allocates tx/rx pages.
 * Sends connect message to xend.
 */
static void 
vif_disconnect(struct xn_softc *sc)
{
    if (sc->xn_tx_if) free(sc->xn_tx_if, M_DEVBUF);
    if (sc->xn_rx_if) free(sc->xn_rx_if, M_DEVBUF);

    // Before this sc->xn_tx_if and sc->xn_rx_if had better be null.
    sc->xn_tx_if = (netif_tx_interface_t *)malloc(PAGE_SIZE,M_DEVBUF,M_WAITOK);
    sc->xn_rx_if = (netif_rx_interface_t *)malloc(PAGE_SIZE,M_DEVBUF,M_WAITOK);
    memset(sc->xn_tx_if, 0, PAGE_SIZE);
    memset(sc->xn_rx_if, 0, PAGE_SIZE);
    sc->xn_backend_state = BEST_DISCONNECTED;
    send_interface_connect(sc);
    vif_show(sc);
}

/* Begin interface recovery.
 *
 * NB. Whilst we're recovering, we turn the carrier state off.  We
 * take measures to ensure that this device isn't used for
 * anything.  We also stop the queue for this device.  Various
 * different approaches (e.g. continuing to buffer packets) have
 * been tested but don't appear to improve the overall impact on
 * TCP connections.
 *
 * TODO: (MAW) Change the Xend<->Guest protocol so that a recovery
 * is initiated by a special "RESET" message - disconnect could
 * just mean we're not allowed to use this interface any more.
 */
static void 
vif_reset(struct xn_softc *sc)
{
    IPRINTK("Attempting to reconnect network interface: handle=%u\n",
            sc->xn_ifno);    
    vif_release(sc);
    vif_disconnect(sc);
    vif_show(sc);
}

/* Move the vif into connected state.
 * Sets the mac and event channel from the message.
 * Binds the irq to the event channel.
 */
static void
vif_connect(
    struct xn_softc *sc, netif_fe_interface_status_t *status)
{
    memcpy(sc->arpcom.ac_enaddr, status->mac, ETHER_ADDR_LEN);
    network_connect(sc, status);

    sc->xn_evtchn = status->evtchn;
    sc->xn_irq = bind_evtchn_to_irq(sc->xn_evtchn);

    (void)intr_add_handler("xn", sc->xn_irq, (driver_intr_t *)xn_intr, sc,
			   INTR_TYPE_NET | INTR_MPSAFE, &sc->xn_intrhand);
    netctrl_connected_count();
    /* vif_wake(dev); Not needed for FreeBSD */
    vif_show(sc);
}

/** Create a network device.
 * @param handle device handle
 */
static void 
create_netdev(int handle, struct xn_softc **sc)
{
    int i;

    *sc = (struct xn_softc *)malloc(sizeof(**sc), M_DEVBUF, M_WAITOK);
    memset(*sc, 0, sizeof(struct xn_softc));

    (*sc)->xn_backend_state = BEST_CLOSED;
    (*sc)->xn_user_state    = UST_CLOSED;
    (*sc)->xn_ifno 	 = handle;
    
    XN_LOCK_INIT(*sc, "xnetif");
    (*sc)->xn_rx_target	= RX_MIN_TARGET;

    /* Initialise {tx,rx}_skbs to be a free chain containing every entry. */
    for ( i = 0; i <= NETIF_TX_RING_SIZE; i++ )
        (*sc)->xn_tx_free_idxs[i] = (i+1);
    for ( i = 0; i <= NETIF_RX_RING_SIZE; i++ )
        (*sc)->xn_rx_free_idxs[i] = (i+1);

    SLIST_INSERT_HEAD(&xn_dev_list, *sc, xn_links);
}

/* Get the target interface for a status message.
 * Creates the interface when it makes sense.
 * The returned interface may be null when there is no error.
 *
 * @param status status message
 * @param sc return parameter for interface state
 * @return 0 on success, error code otherwise
 */
static int 
target_vif(netif_fe_interface_status_t *status, struct xn_softc **sc)
{
    int err = 0;

    XENPRINTF("> handle=%d\n", status->handle);
    if ( status->handle < 0 )
    {
        err = -EINVAL;
        goto exit;
    }

    if ( (*sc = find_sc_by_handle(status->handle)) != NULL )
        goto exit;

    if ( status->status == NETIF_INTERFACE_STATUS_CLOSED )
        goto exit;
    if ( status->status == NETIF_INTERFACE_STATUS_CHANGED )
        goto exit;

    /* It's a new interface in a good state - create it. */
    XENPRINTF("> create device...\n");
    create_netdev(status->handle, sc);
    netctrl.interface_n++;

exit:
    return err;
}

/* Handle an interface status message. */
static void 
netif_interface_status(netif_fe_interface_status_t *status)
{
    int err = 0;
    struct xn_softc *sc = NULL;
    
    XENPRINTF("> status=%s handle=%d\n",
            status_name[status->status], status->handle);

    if ( (err = target_vif(status, &sc)) != 0 )
    {
        WPRINTK("Invalid netif: handle=%u\n", status->handle);
        return;
    }

    if ( sc == NULL )
    {
        XENPRINTF("> no vif\n");
        return;
    }

    vif_show(sc);

    switch ( status->status )
    {
    case NETIF_INTERFACE_STATUS_CLOSED:
        switch ( sc->xn_backend_state )
        {
        case BEST_CLOSED:
        case BEST_DISCONNECTED:
        case BEST_CONNECTED:
            vif_close(sc);
            break;
        }
        break;

    case NETIF_INTERFACE_STATUS_DISCONNECTED:
        switch ( sc->xn_backend_state )
        {
        case BEST_CLOSED:
            vif_disconnect(sc);
            break;
        case BEST_DISCONNECTED:
        case BEST_CONNECTED:
            vif_reset(sc);
            break;
        }
        break;

    case NETIF_INTERFACE_STATUS_CONNECTED:
        switch ( sc->xn_backend_state )
        {
        case BEST_CLOSED:
            WPRINTK("Unexpected netif status %s in state %s\n",
                    status_name[status->status],
                    be_state_name[sc->xn_backend_state]);
            vif_disconnect(sc);
            vif_connect(sc, status);
            break;
        case BEST_DISCONNECTED:
            vif_connect(sc, status);
            break;
        }
        break;

    case NETIF_INTERFACE_STATUS_CHANGED:
        /*
         * The domain controller is notifying us that a device has been
         * added or removed.
         */
        break;

    default:
        WPRINTK("Invalid netif status code %d\n", status->status);
        break;
    }
    vif_show(sc);
}

/*
 * Initialize the network control interface. 
 */
static void 
netif_driver_status(netif_fe_driver_status_t *status)
{
    XENPRINTF("> status=%d\n", status->status);
    netctrl.up = status->status;
    //netctrl.interface_n = status->max_handle;
    //netctrl.connected_n = 0;
    netctrl_connected_count();
}

/* Receive handler for control messages. */
static void 
netif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_NETIF_FE_INTERFACE_STATUS:
        if ( msg->length != sizeof(netif_fe_interface_status_t) )
            goto error;
        netif_interface_status((netif_fe_interface_status_t *)
                               &msg->msg[0]);
        break;

    case CMSG_NETIF_FE_DRIVER_STATUS:
        if ( msg->length != sizeof(netif_fe_driver_status_t) )
            goto error;
        netif_driver_status((netif_fe_driver_status_t *)
                            &msg->msg[0]);
        break;

    error:
    default:
        msg->length = 0;
        break;
    }

    ctrl_if_send_response(msg);   
}

#if 1
/* Wait for all interfaces to be connected.
 *
 * This works OK, but we'd like to use the probing mode (see below).
 */
static int probe_interfaces(void)
{
    int err = 0, conn = 0;
    int wait_i, wait_n = 100;
    for ( wait_i = 0; wait_i < wait_n; wait_i++)
    { 
        XENPRINTF("> wait_i=%d\n", wait_i);
        conn = netctrl_connected();
        if(conn) break;
	tsleep(&xn_dev_list, PWAIT | PCATCH, "netif", hz);
    }

    XENPRINTF("> wait finished...\n");
    if ( conn <= 0 )
    {
        err = netctrl_err(-ENETDOWN);
        WPRINTK("Failed to connect all virtual interfaces: err=%d\n", err);
    }

    XENPRINTF("< err=%d\n", err);

    return err;
}
#else
/* Probe for interfaces until no more are found.
 *
 * This is the mode we'd like to use, but at the moment it panics the kernel.
*/
static int 
probe_interfaces(void)
{
    int err = 0;
    int wait_i, wait_n = 100;
    ctrl_msg_t cmsg = {
        .type    = CMSG_NETIF_FE,
        .subtype = CMSG_NETIF_FE_INTERFACE_STATUS,
        .length  = sizeof(netif_fe_interface_status_t),
    };
    netif_fe_interface_status_t msg = {};
    ctrl_msg_t rmsg = {};
    netif_fe_interface_status_t *reply = (void*)rmsg.msg;
    int state = TASK_UNINTERRUPTIBLE;
    uint32_t query = -1;


    netctrl.interface_n = 0;
    for ( wait_i = 0; wait_i < wait_n; wait_i++ )
    { 
        XENPRINTF("> wait_i=%d query=%d\n", wait_i, query);
        msg.handle = query;
        memcpy(cmsg.msg, &msg, sizeof(msg));
        XENPRINTF("> set_current_state...\n");
        set_current_state(state);
        XENPRINTF("> rmsg=%p msg=%p, reply=%p\n", &rmsg, rmsg.msg, reply);
        XENPRINTF("> sending...\n");
        err = ctrl_if_send_message_and_get_response(&cmsg, &rmsg, state);
        XENPRINTF("> err=%d\n", err);
        if(err) goto exit;
        XENPRINTF("> rmsg=%p msg=%p, reply=%p\n", &rmsg, rmsg.msg, reply);
        if((int)reply->handle < 0){
            // No more interfaces.
            break;
        }
        query = -reply->handle - 2;
        XENPRINTF(">netif_interface_status ...\n");
        netif_interface_status(reply);
    }

  exit:
    if ( err )
    {
        err = netctrl_err(-ENETDOWN);
        WPRINTK("Connecting virtual network interfaces failed: err=%d\n", err);
    }

    XENPRINTF("< err=%d\n", err);
    return err;
}

#endif

static void
xn_init(void *unused)
{
    
    int err = 0;
    
    netctrl_init();
    (void)ctrl_if_register_receiver(CMSG_NETIF_FE, netif_ctrlif_rx,
				    CALLBACK_IN_BLOCKING_CONTEXT);

    send_driver_status(1);
    err = probe_interfaces();

    if (err)
	ctrl_if_unregister_receiver(CMSG_NETIF_FE, netif_ctrlif_rx);
}

SYSINIT(xndev, SI_SUB_PSEUDO, SI_ORDER_ANY, xn_init, NULL)
