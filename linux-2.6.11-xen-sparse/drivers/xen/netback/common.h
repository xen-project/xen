/******************************************************************************
 * arch/xen/drivers/netif/backend/common.h
 */

#ifndef __NETIF__BACKEND__COMMON_H__
#define __NETIF__BACKEND__COMMON_H__

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <asm-xen/ctrl_if.h>
#include <asm-xen/xen-public/io/netif.h>
#include <asm/io.h>
#include <asm/pgalloc.h>

#if 0
#define ASSERT(_p) \
    if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#define DPRINTK(_f, _a...) printk(KERN_ALERT "(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define ASSERT(_p) ((void)0)
#define DPRINTK(_f, _a...) ((void)0)
#endif

typedef struct netif_st {
    /* Unique identifier for this interface. */
    domid_t          domid;
    unsigned int     handle;

    /* Physical parameters of the comms window. */
    unsigned long    tx_shmem_frame;
    unsigned long    rx_shmem_frame;
    unsigned int     evtchn;
    int              irq;

    /* The shared rings and indexes. */
    netif_tx_interface_t *tx;
    netif_rx_interface_t *rx;

    /* Private indexes into shared ring. */
    NETIF_RING_IDX rx_req_cons;
    NETIF_RING_IDX rx_resp_prod; /* private version of shared variable */
    NETIF_RING_IDX tx_req_cons;
    NETIF_RING_IDX tx_resp_prod; /* private version of shared variable */

    /* Transmit shaping: allow 'credit_bytes' every 'credit_usec'. */
    unsigned long   credit_bytes;
    unsigned long   credit_usec;
    unsigned long   remaining_credit;
    struct timer_list credit_timeout;

    /* Miscellaneous private stuff. */
    enum { DISCONNECTED, DISCONNECTING, CONNECTED } status;
    int active;
    /*
     * DISCONNECT response is deferred until pending requests are ack'ed.
     * We therefore need to store the id from the original request.
     */
    u8               disconnect_rspid;
    struct netif_st *hash_next;
    struct list_head list;  /* scheduling list */
    atomic_t         refcnt;
    struct net_device *dev;
    struct net_device_stats stats;

    struct work_struct work;
} netif_t;

void netif_create(netif_be_create_t *create);
void netif_destroy(netif_be_destroy_t *destroy);
void netif_connect(netif_be_connect_t *connect);
int  netif_disconnect(netif_be_disconnect_t *disconnect, u8 rsp_id);
void netif_disconnect_complete(netif_t *netif);
netif_t *netif_find_by_handle(domid_t domid, unsigned int handle);
#define netif_get(_b) (atomic_inc(&(_b)->refcnt))
#define netif_put(_b)                             \
    do {                                          \
        if ( atomic_dec_and_test(&(_b)->refcnt) ) \
            netif_disconnect_complete(_b);        \
    } while (0)

void netif_interface_init(void);
void netif_ctrlif_init(void);

void netif_schedule_work(netif_t *netif);
void netif_deschedule_work(netif_t *netif);

int netif_be_start_xmit(struct sk_buff *skb, struct net_device *dev);
struct net_device_stats *netif_be_get_stats(struct net_device *dev);
irqreturn_t netif_be_int(int irq, void *dev_id, struct pt_regs *regs);

#endif /* __NETIF__BACKEND__COMMON_H__ */
