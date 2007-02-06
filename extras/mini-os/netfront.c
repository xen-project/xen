/* Minimal network driver for Mini-OS. 
 * Copyright (c) 2006-2007 Jacob Gorm Hansen, University of Copenhagen.
 * Based on netfront.c from Xen Linux.
 *
 * Does not handle fragments or extras.
 */

#include <os.h>
#include <xenbus.h>
#include <events.h>
#include <errno.h>
#include <xen/io/netif.h>
#include <gnttab.h>
#include <xmalloc.h>
#include <time.h>

void init_rx_buffers(void);

struct net_info {
    struct netif_tx_front_ring tx;
    struct netif_rx_front_ring rx;
    int tx_ring_ref;
    int rx_ring_ref;
    unsigned int evtchn, local_port;

} net_info;


char* xenbus_printf(xenbus_transaction_t xbt,
        char* node,char* path,
        char* fmt,unsigned int arg)
{
    char fullpath[256];
    char val[256];

    sprintf(fullpath,"%s/%s",node,path);
    sprintf(val,fmt,arg);
    xenbus_write(xbt,fullpath,val);

    return NULL;
}


#define NET_TX_RING_SIZE __RING_SIZE((struct netif_tx_sring *)0, PAGE_SIZE)
#define NET_RX_RING_SIZE __RING_SIZE((struct netif_rx_sring *)0, PAGE_SIZE)
#define GRANT_INVALID_REF 0


unsigned short rx_freelist[NET_RX_RING_SIZE];
unsigned short tx_freelist[NET_TX_RING_SIZE];

struct net_buffer {
    void* page;
    int gref;
};
struct net_buffer rx_buffers[NET_RX_RING_SIZE];
struct net_buffer tx_buffers[NET_TX_RING_SIZE];

static inline void add_id_to_freelist(unsigned int id,unsigned short* freelist)
{
    freelist[id] = freelist[0];
    freelist[0]  = id;
}

static inline unsigned short get_id_from_freelist(unsigned short* freelist)
{
    unsigned int id = freelist[0];
    freelist[0] = freelist[id];
    return id;
}

__attribute__((weak)) void netif_rx(unsigned char* data,int len)
{
    printk("%d bytes incoming at %p\n",len,data);
}

__attribute__((weak)) void net_app_main(void*si,unsigned char*mac) {}

static inline int xennet_rxidx(RING_IDX idx)
{
    return idx & (NET_RX_RING_SIZE - 1);
}

void network_rx(void)
{
    struct net_info *np = &net_info;
    RING_IDX rp,cons;
    struct netif_rx_response *rx;


moretodo:
    rp = np->rx.sring->rsp_prod;
    rmb(); /* Ensure we see queued responses up to 'rp'. */
    cons = np->rx.rsp_cons;

    int nr_consumed=0;
    while ((cons != rp))
    {
        struct net_buffer* buf;
        unsigned char* page;

        rx = RING_GET_RESPONSE(&np->rx, cons);

        if (rx->flags & NETRXF_extra_info)
        {
            printk("+++++++++++++++++++++ we have extras!\n");
            continue;
        }


        if (rx->status == NETIF_RSP_NULL) continue;

        int id = rx->id;

        buf = &rx_buffers[id];
        page = (unsigned char*)buf->page;
        gnttab_end_access(buf->gref);

        if(rx->status>0)
        {
            netif_rx(page+rx->offset,rx->status);
        }

        add_id_to_freelist(id,rx_freelist);

        nr_consumed++;

        ++cons;
    }
    np->rx.rsp_cons=rp;

    int more;
    RING_FINAL_CHECK_FOR_RESPONSES(&np->rx,more);
    if(more) goto moretodo;

    RING_IDX req_prod = np->rx.req_prod_pvt;

    int i;
    netif_rx_request_t *req;

    for(i=0; i<nr_consumed; i++)
    {
        int id = xennet_rxidx(req_prod + i);
        req = RING_GET_REQUEST(&np->rx, req_prod + i);
        struct net_buffer* buf = &rx_buffers[id];
        void* page = buf->page;

        buf->gref = req->gref = 
            gnttab_grant_access(0,virt_to_mfn(page),0);

        req->id = id;
    }

    wmb();

    np->rx.req_prod_pvt = req_prod + i;
    
    int notify;
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&np->rx, notify);
    if (notify)
        notify_remote_via_evtchn(np->evtchn);

}

void network_tx_buf_gc(void)
{


    RING_IDX cons, prod;
    unsigned short id;
    struct net_info *np = &net_info;

    do {
        prod = np->tx.sring->rsp_prod;
        rmb(); /* Ensure we see responses up to 'rp'. */

        for (cons = np->tx.rsp_cons; cons != prod; cons++) 
        {
            struct netif_tx_response *txrsp;

            txrsp = RING_GET_RESPONSE(&np->tx, cons);
            if (txrsp->status == NETIF_RSP_NULL)
                continue;

            id  = txrsp->id;
            struct net_buffer* buf = &tx_buffers[id];
            gnttab_end_access(buf->gref);
            buf->gref=GRANT_INVALID_REF;

            add_id_to_freelist(id,tx_freelist);
        }

        np->tx.rsp_cons = prod;

        /*
         * Set a new event, then check for race with update of tx_cons.
         * Note that it is essential to schedule a callback, no matter
         * how few tx_buffers are pending. Even if there is space in the
         * transmit ring, higher layers may be blocked because too much
         * data is outstanding: in such cases notification from Xen is
         * likely to be the only kick that we'll get.
         */
        np->tx.sring->rsp_event =
            prod + ((np->tx.sring->req_prod - prod) >> 1) + 1;
        mb();
    } while ((cons == prod) && (prod != np->tx.sring->rsp_prod));


}

void netfront_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
    int flags;

    local_irq_save(flags);

    network_tx_buf_gc();
    network_rx();

    local_irq_restore(flags);
}

char* backend;

void init_netfront(void* si)
{
    xenbus_transaction_t xbt;
    struct net_info* info = &net_info;
    char* err;
    char* message=NULL;
    char nodename[] = "device/vif/0";
    struct netif_tx_sring *txs;
    struct netif_rx_sring *rxs;
    int retry=0;
    int i;
    char* mac;
    char* msg;

    printk("************************ NETFRONT **********\n\n\n");

    for(i=0;i<NET_TX_RING_SIZE;i++)
    {
        add_id_to_freelist(i,tx_freelist);
        tx_buffers[i].page = (char*)alloc_page();
    }

    for(i=0;i<NET_RX_RING_SIZE;i++)
    {
        add_id_to_freelist(i,rx_freelist);
        rx_buffers[i].page = (char*)alloc_page();
    }

    txs = (struct netif_tx_sring*) alloc_page();
    rxs = (struct netif_rx_sring *) alloc_page();
    memset(txs,0,PAGE_SIZE);
    memset(rxs,0,PAGE_SIZE);


    SHARED_RING_INIT(txs);
    SHARED_RING_INIT(rxs);
    FRONT_RING_INIT(&info->tx, txs, PAGE_SIZE);
    FRONT_RING_INIT(&info->rx, rxs, PAGE_SIZE);

    info->tx_ring_ref = gnttab_grant_access(0,virt_to_mfn(txs),0);
    info->rx_ring_ref = gnttab_grant_access(0,virt_to_mfn(rxs),0);

    evtchn_alloc_unbound_t op;
    op.dom = DOMID_SELF;
    op.remote_dom = 0;
    HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
    clear_evtchn(op.port);        /* Without, handler gets invoked now! */
    info->local_port = bind_evtchn(op.port, netfront_handler, NULL);
    info->evtchn=op.port;

again:
    err = xenbus_transaction_start(&xbt);
    if (err) {
        printk("starting transaction\n");
    }

    err = xenbus_printf(xbt, nodename, "tx-ring-ref","%u",
                info->tx_ring_ref);
    if (err) {
        message = "writing tx ring-ref";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, nodename, "rx-ring-ref","%u",
                info->rx_ring_ref);
    if (err) {
        message = "writing rx ring-ref";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, nodename,
                "event-channel", "%u", info->evtchn);
    if (err) {
        message = "writing event-channel";
        goto abort_transaction;
    }

    err = xenbus_printf(xbt, nodename, "request-rx-copy", "%u", 1);

    if (err) {
        message = "writing request-rx-copy";
        goto abort_transaction;
    }

    err = xenbus_printf(xbt, nodename, "state", "%u",
            4); /* connected */


    err = xenbus_transaction_end(xbt, 0, &retry);
    if (retry) {
            goto again;
        printk("completing transaction\n");
    }

    goto done;

abort_transaction:
    xenbus_transaction_end(xbt, 1, &retry);

done:

    msg = xenbus_read(XBT_NIL, "device/vif/0/backend", &backend);
    msg = xenbus_read(XBT_NIL, "device/vif/0/mac", &mac);

    if ((backend == NULL) || (mac == NULL)) {
        struct evtchn_close op = { info->local_port };
        printk("%s: backend/mac failed\n", __func__);
        unbind_evtchn(info->local_port);
        HYPERVISOR_event_channel_op(EVTCHNOP_close, &op);
        return;
    }

    printk("backend at %s\n",backend);
    printk("mac is %s\n",mac);

    char path[256];
    sprintf(path,"%s/state",backend);

    xenbus_watch_path(XBT_NIL, path);

    xenbus_wait_for_value(path,"4");

    //free(backend);

    printk("**************************\n");

    init_rx_buffers();

    unsigned char rawmac[6];
        /* Special conversion specifier 'hh' needed for __ia64__. Without
           this mini-os panics with 'Unaligned reference'. */
    sscanf(mac,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &rawmac[0],
            &rawmac[1],
            &rawmac[2],
            &rawmac[3],
            &rawmac[4],
            &rawmac[5]);

    net_app_main(si,rawmac);
}

void shutdown_netfront(void)
{
    //xenbus_transaction_t xbt;
    char* err;
    char nodename[] = "device/vif/0";

    char path[256];

    printk("close network: backend at %s\n",backend);

    err = xenbus_printf(XBT_NIL, nodename, "state", "%u", 6); /* closing */
    sprintf(path,"%s/state",backend);

    xenbus_wait_for_value(path,"6");

    err = xenbus_printf(XBT_NIL, nodename, "state", "%u", 1);

    xenbus_wait_for_value(path,"2");

    unbind_all_ports();

}


void init_rx_buffers(void)
{
    struct net_info* np = &net_info;
    int i, requeue_idx;
    netif_rx_request_t *req;
    int notify;

    /* Rebuild the RX buffer freelist and the RX ring itself. */
    for (requeue_idx = 0, i = 0; i < NET_RX_RING_SIZE; i++) 
    {
        struct net_buffer* buf = &rx_buffers[requeue_idx];
        req = RING_GET_REQUEST(&np->rx, requeue_idx);

        buf->gref = req->gref = 
            gnttab_grant_access(0,virt_to_mfn(buf->page),0);

        req->id = requeue_idx;

        requeue_idx++;
    }

    np->rx.req_prod_pvt = requeue_idx;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&np->rx, notify);

    if (notify) 
        notify_remote_via_evtchn(np->evtchn);

    np->rx.sring->rsp_event = np->rx.rsp_cons + 1;
}


void netfront_xmit(unsigned char* data,int len)
{
    int flags;
    local_irq_save(flags);

    struct net_info* info = &net_info;
    struct netif_tx_request *tx;
    RING_IDX i = info->tx.req_prod_pvt;
    int notify;
    int id = get_id_from_freelist(tx_freelist);
    struct net_buffer* buf = &tx_buffers[id];
    void* page = buf->page;

    tx = RING_GET_REQUEST(&info->tx, i);

    memcpy(page,data,len);

    buf->gref = 
        tx->gref = gnttab_grant_access(0,virt_to_mfn(page),0);

    tx->offset=0;
    tx->size = len;
    tx->flags=0;
    tx->id = id;
    info->tx.req_prod_pvt = i + 1;

    wmb();

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->tx, notify);

    if(notify) notify_remote_via_evtchn(info->evtchn);

    network_tx_buf_gc();

    local_irq_restore(flags);
}
