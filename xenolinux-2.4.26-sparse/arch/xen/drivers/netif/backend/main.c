/******************************************************************************
 * arch/xen/drivers/netif/backend/main.c
 * 
 * Back-end of the driver for virtual block devices. This portion of the
 * driver exports a 'unified' block-device interface that can be accessed
 * by any operating system that implements a compatible front end. A 
 * reference front-end implementation can be found in:
 *  arch/xen/drivers/netif/frontend
 * 
 * Copyright (c) 2002-2004, K A Fraser
 */

#include "common.h"

static void make_tx_response(netif_t *netif, 
                             u16      id,
                             s8       st);
static void make_rx_response(netif_t     *netif, 
                             u16          id, 
                             s8           st,
                             netif_addr_t addr,
                             u16          size);

/* Don't currently gate addition of an interface to the tx scheduling list. */
#define tx_work_exists(_if) (1)

#define MAX_PENDING_REQS 256
static struct vm_struct *mmap_vma;
#define MMAP_VADDR(_req) ((unsigned long)mmap_vma->addr + ((_req) * PAGE_SIZE))

/*static pending_req_t pending_reqs[MAX_PENDING_REQS];*/
static u16 pending_ring[MAX_PENDING_REQS];
static spinlock_t pend_prod_lock = SPIN_LOCK_UNLOCKED;
/* NB. We use a different index type to differentiate from shared blk rings. */
typedef unsigned int PEND_RING_IDX;
#define MASK_PEND_IDX(_i) ((_i)&(MAX_PENDING_REQS-1))
static PEND_RING_IDX pending_prod, pending_cons;
#define NR_PENDING_REQS (MAX_PENDING_REQS - pending_prod + pending_cons)

/*
 * This is the primary RECEIVE function for a network interface.
 * Note that, from the p.o.v. of /this/ OS it looks like a transmit.
 */
static void netif_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    netif_t *netif = (netif_t *)dev->priv;
    s8 status = BLKIF_RSP_OKAY;
    u16 size;
    mmu_update_t mmu[4];

    memcpy(skb->mac.ethernet->h_dest, netif->vmac, ETH_ALEN);
    if ( ntohs(skb->mac.ethernet->h_proto) == ETH_P_ARP )
        memcpy(skb->nh.raw + 18, netif->vmac, ETH_ALEN);

    spin_lock(&netif->rx_lock);

    mmu[0].val  = (unsigned long)(netif->domid<<16) & ~0xFFFFUL;
    mmu[0].ptr  = (unsigned long)(netif->domid<< 0) & ~0xFFFFUL;
    mmu[1].val  = (unsigned long)(netif->domid>>16) & ~0xFFFFUL;
    mmu[1].ptr  = (unsigned long)(netif->domid>>32) & ~0xFFFFUL;
    mmu[0].ptr |= MMU_EXTENDED_COMMAND;
    mmu[0].val |= MMUEXT_SET_SUBJECTDOM_L;
    mmu[1].ptr |= MMU_EXTENDED_COMMAND;
    mmu[1].val |= MMUEXT_SET_SUBJECTDOM_H;

    mmu[2].ptr  = ptr | MMU_EXTENDED_COMMAND;
    mmu[2].val  = MMUEXT_REASSIGN_PAGE;

    mmu[3].ptr  = ppte;
    mmu[3].val  = newpage;

    if ( unlikely(HYPERVISOR_mmu_update(mmu, 4) < 0) )
    {
        status = BLKIF_RSP_ERROR;
        goto out;
    }

    /* Record this so they can be billed. */
    netif->total_packets_received++;
    netif->total_bytes_received += size;

 out:
    make_rx_response(netif, rx->id, status, addr, size);
    spin_unlock(&netif->rx_lock);    
    dev_kfree_skb(skb);
}


/*************************************************************
 * NEW TRANSMIT SCHEDULER
 * 
 * NB. We ought also to only send a limited number of bytes to the NIC
 * for transmission at any one time (to avoid head-of-line blocking).
 * However, driver rings are small enough that they provide a reasonable
 * limit.
 * 
 * eg. 3c905 has 16 descriptors == 8 packets, at 100Mbps
 *     e1000 has 256 descriptors == 128 packets, at 1000Mbps
 *     tg3 has 512 descriptors == 256 packets, at 1000Mbps
 * 
 * So, worst case is tg3 with 256 1500-bytes packets == 375kB.
 * This would take 3ms, and represents our worst-case HoL blocking cost.
 * 
 * We think this is reasonable.
 */

struct list_head net_schedule_list;
spinlock_t net_schedule_list_lock;

static int __on_net_schedule_list(netif_t *netif)
{
    return netif->list.next != NULL;
}

static void remove_from_net_schedule_list(netif_t *netif)
{
    spin_lock(&net_schedule_list_lock);
    ASSERT(__on_net_schedule_list(netif));
    list_del(&netif->list);
    netif->list.next = NULL;
    netif_put(netif);
    spin_unlock(&net_schedule_list_lock);
}

static void add_to_net_schedule_list_tail(netif_t *netif)
{
    if ( __on_net_schedule_list(netif) )
        return;

    spin_lock(&net_schedule_list_lock);
    if ( likely(!__on_net_schedule_list(netif)) )
    {
        list_add_tail(&netif->list, &net_schedule_list);
        netif_get(netif);
    }
    spin_unlock(&net_schedule_list_lock);
}


static void tx_skb_release(struct sk_buff *skb);
    
static inline int init_tx_header(netif_t *netif, u8 *data, 
                                 unsigned int len, struct net_device *dev)
{
    int proto = ntohs(*(unsigned short *)(data + 12));

    memcpy(data + ETH_ALEN, dev->dev_addr, ETH_ALEN);
        
    switch ( proto )
    {
    case ETH_P_ARP:
        if ( len < 42 ) break;
        memcpy(data + 22, dev->dev_addr, ETH_ALEN);
        break;
    case ETH_P_IP:
        break;
    default:
        /* Unsupported protocols are onyl allowed to/from NETIF0/0. */
        if ( (netif->domain->domain != 0) || (netif->idx != 0) )
            proto = 0;
        break;
    }
    return proto;
}


static void tx_credit_callback(unsigned long data)
{
    netif_t *netif = (netif_t *)data;

    netif->remaining_credit = netif->credit_bytes;

    if ( tx_work_exists(netif) )
    {
        add_to_net_schedule_list_tail(netif);
        maybe_schedule_tx_action();
    }    
}

static void net_tx_action(unsigned long unused)
{
    struct list_head *ent;
    struct sk_buff *skb;
    netif_t *netif;
    netif_tx_request_t txreq;
    u16 pending_idx;
    pgprot_t prot = __pgprot(_PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED);

    while ( (NR_PENDING_REQS < MAX_PENDING_REQS) &&
            !list_empty(&net_schedule_list) )
    {
        /* Get a netif from the list with work to do. */
        ent = net_schedule_list.next;
        netif = list_entry(ent, netif_t, list);
        netif_get(netif);
        remove_from_net_schedule_list(netif);

        /* Work to do? */
        i = netif->tx_req_cons;
        if ( (i == shared_idxs->tx_req_prod) && 
             ((i-netif->tx_resp_prod) == NETIF_TX_RING_SIZE) )
        {
            netif_put(netif);
            continue;
        }
        memcpy(&txreq, &netif->tx->ring[MASK_NETIF_TX_IDX(i)].req, 
               sizeof(txreq));
        netif->tx_req_cons++;

#if 0
        /* Credit-based scheduling. */
        if ( tx.size > netif->remaining_credit )
        {
            s_time_t now = NOW(), next_credit = 
                netif->credit_timeout.expires + MICROSECS(netif->credit_usec);
            if ( next_credit <= now )
            {
                netif->credit_timeout.expires = now;
                netif->remaining_credit = netif->credit_bytes;
            }
            else
            {
                netif->remaining_credit = 0;
                netif->credit_timeout.expires  = next_credit;
                netif->credit_timeout.data     = (unsigned long)netif;
                netif->credit_timeout.function = tx_credit_callback;
                netif->credit_timeout.cpu      = smp_processor_id();
                add_ac_timer(&netif->credit_timeout);
                break;
            }
        }
        netif->remaining_credit -= tx.size;
#endif

        add_to_net_schedule_list_tail(netif);

        if ( unlikely(txreq.size <= PKT_PROT_LEN) || 
             unlikely(txreq.size > ETH_FRAME_LEN) )
        {
            DPRINTK("Bad packet size: %d\n", txreq.size);
            make_tx_response(netif, txreq.id, NETIF_RSP_ERROR);
            netif_put(netif);
            continue; 
        }

        /* No crossing a page boundary as the payload mustn't fragment. */
        if ( unlikely(((txreq.addr & ~PAGE_MASK) + txreq.size) >= PAGE_SIZE) ) 
        {
            DPRINTK("tx.addr: %lx, size: %u, end: %lu\n", 
                    txreq.addr, txreq.size, 
                    (txreq.addr &~PAGE_MASK) + txreq.size);
            make_tx_response(netif, txreq.id, NETIF_RSP_ERROR);
            netif_put(netif);
            continue;
        }

        pending_idx = pending_ring[MASK_PEND_IDX(pending_cons)];

        if ( direct_remap_area_pages(&init_mm,
                                     MMAP_VADDR(pending_idx),
                                     txreq.addr & PAGE_MASK,
                                     PAGE_SIZE, prot, netif->domid) != 0 )
        {
            DPRINTK("Bad page frame\n");
            make_tx_response(netif, tx.id, NETIF_RSP_ERROR);
            netif_put(netif);
            continue;
        }
            
        if ( unlikely((skb = alloc_skb(PKT_PROT_LEN, GFP_ATOMIC)) == NULL) )
        {
            make_tx_response(netif, tx.id, BLKIF_RSP_ERROR);
            netif_put(netif);
            vmfree_area_pages(MMAP_VADDR(pending_idx), PAGE_SIZE);
            break;
        }
        
        __skb_put(PKT_PROT_LEN);
        memcpy(skb->data, src, PKT_PROT_LEN);
        protocol = __constant_htons(
            init_tx_header(netif, g_data, tx.size, the_dev));
        if ( protocol == 0 )
        {
            make_tx_response(netif, tx.id, NETIF_RSP_ERROR);
            netif_put(netif);
            dev_kfree_skb(skb);
            goto cleanup_and_continue;
        }

        skb->dev        = netif->dev;
        skb->protocol   = eth_type_trans(skb, skb->dev);
        
        /* Append the packet payload as a fragment. */
        skb_shinfo(skb)->frags[0].page        = 
          &mem_map[txreq.addr >> PAGE_SHIFT];
        skb_shinfo(skb)->frags[0].size        = txreq.size - PKT_PROT_LEN;
        skb_shinfo(skb)->frags[0].page_offset = 
            (txreq.addr + PKT_PROT_LEN) & ~PAGE_MASK;
        skb_shinfo(skb)->nr_frags = 1;
        skb->data_len  = tx->size - PKT_PROT_LEN;
        skb->len      += skb->data_len;

        /* Destructor information. */
        skb->destructor = tx_skb_release;
        skb_shinfo(skb)->frags[MAX_SKB_FRAGS-1].page = (struct page *)netif;
        skb_shinfo(skb)->frags[MAX_SKB_FRAGS-1].size = pending_idx;

        /* Record the transmission so they can be billed. */
        netif->total_packets_sent++;
        netif->total_bytes_sent += tx->size;

        pending_cons++;
        netif_rx(skb);
        netif->dev->last_rx = jiffies;
    }
}

DECLARE_TASKLET(net_tx_tasklet, net_tx_action, 0);


static inline void maybe_schedule_tx_action(void)
{
    smp_mb();
    if ( !netif_queue_stopped(the_dev) &&
         !list_empty(&net_schedule_list) )
        tasklet_schedule(&net_tx_tasklet);
}


/* Destructor function for tx skbs. */
static void tx_skb_release(struct sk_buff *skb)
{
    int i;
    netif_t *netif = (netif_t)skb_shinfo(skb)->frags[MAX_SKB_FRAGS-1].page;
    u16 pending_idx = skb_shinfo(skb)->frags[MAX_SKB_FRAGS-1].size;

    vmfree_area_pages(MMAP_VADDR(pending_idx), PAGE_SIZE);
    
    skb_shinfo(skb)->nr_frags = 0; 
    
    spin_lock(&netif->tx_lock);
    make_tx_response(netif, skb->guest_id, NETIF_RSP_OKAY);
    spin_unlock(&netif->tx_lock);
    
    /*
     * Checks below must happen after the above response is posted. This avoids
     * a possible race with a guest OS on another CPU.
     */
    mb();
    
    if ( tx_work_exists(netif) )
    {
        add_to_net_schedule_list_tail(netif);
        maybe_schedule_tx_action();        
    }
    
    netif_put(netif);
}


long flush_bufs_for_netif(netif_t *netif)
{
    NET_RING_IDX i;

    /* Return any outstanding receive buffers to the guest OS. */
    spin_lock(&netif->rx_lock);
    for ( i = netif->rx_req_cons; 
          (i != netif->rx->req_prod) &&
              ((i-netif->rx_resp_prod) != NETIF_RX_RING_SIZE);
          i++ )
    {
        make_rx_response(netif,
                         netif->rx->ring[MASK_NETIF_RX_IDX(i)].req.id,
                         NETIF_RSP_DROPPED, 0, 0);
    }
    netif->rx_req_cons = i;
    spin_unlock(&netif->rx_lock);

    /*
     * Flush pending transmit buffers. The guest may still have to wait for
     * buffers that are queued at a physical NIC.
     */
    spin_lock(&netif->tx_lock);
    for ( i = netif->tx_req_cons; 
          (i != netif->tx->req_prod) &&
              ((i-netif->tx_resp_prod) != NETIF_TX_RING_SIZE);
          i++ )
    {
        make_tx_response(netif,
                         netif->tx->ring[MASK_NETIF_TX_IDX(i)].req.id,
                         NETIF_RSP_DROPPED);
    }
    netif->tx_req_cons = i;
    spin_unlock(&netif->tx_lock);

    return 0;
}

void netif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
    netif_t *netif = dev_id;
    if ( tx_work_exists(netif) )
    {
        add_to_net_schedule_list_tail(netif);
        maybe_schedule_tx_action();
    }
}

static void make_tx_response(netif_t *netif, 
                             u16      id,
                             s8       st)
{
    NET_RING_IDX i = netif->tx_resp_prod;
    netif_tx_response_t *resp;

    resp = &netif->tx->ring[MASK_NETIF_TX_IDX(i)].resp;
    resp->id     = id;
    resp->status = st;
    wmb();
    netif->tx->resp_prod = netif->tx_resp_prod = ++i;

    mb(); /* Update producer before checking event threshold. */
    if ( i == netif->tx->event )
        notify_via_evtchn(netif->evtchn);
}


static void make_rx_response(netif_t     *netif, 
                             u16          id, 
                             s8           st,
                             netif_addr_t addr,
                             u16          size)
{
    NET_RING_IDX i = netif->rx_resp_prod;
    netif_rx_response_t *resp;

    resp = &netif->rx->ring[MASK_NETIF_RX_IDX(i)].resp;
    resp->addr   = addr;
    resp->id     = id;
    resp->status = (s16)size;
    if ( st < 0 )
        resp->status = (s16)st;
    wmb();
    netif->rx->resp_prod = netif->rx_resp_prod = ++i;

    mb(); /* Update producer before checking event threshold. */
    if ( i == netif->rx->event )
        notify_via_evtchn(netif->evtchn);
}


static int __init init_module(void)
{
    netif_interface_init();

    if ( (mmap_vma = get_vm_area(MAX_PENDING_REQS * PAGE_SIZE, 
                                 VM_IOREMAP)) == NULL )
    {
        printk(KERN_WARNING "Could not allocate VMA for netif backend.\n");
        return -ENOMEM;
    }

    netif_ctrlif_init();

    return 0;
}


static void cleanup_module(void)
{
}


module_init(init_module);
module_exit(cleanup_module);
