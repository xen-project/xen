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
#include <asm/hypervisor-ifs/dom_mem_ops.h>

static void net_tx_action(unsigned long unused);
static void netif_page_release(struct page *page);
static void make_tx_response(netif_t *netif, 
                             u16      id,
                             s8       st);
static void make_rx_response(netif_t     *netif, 
                             u16          id, 
                             s8           st,
                             netif_addr_t addr,
                             u16          size);

static DECLARE_TASKLET(net_tx_tasklet, net_tx_action, 0);

/* Don't currently gate addition of an interface to the tx scheduling list. */
#define tx_work_exists(_if) (1)

#define MAX_PENDING_REQS 256
static unsigned long mmap_vstart;
#define MMAP_VADDR(_req) (mmap_vstart + ((_req) * PAGE_SIZE))

#define PKT_PROT_LEN (ETH_HLEN + 20)

static u16 pending_id[MAX_PENDING_REQS];
static netif_t *pending_netif[MAX_PENDING_REQS];
static u16 pending_ring[MAX_PENDING_REQS];
static spinlock_t pend_prod_lock = SPIN_LOCK_UNLOCKED;
typedef unsigned int PEND_RING_IDX;
#define MASK_PEND_IDX(_i) ((_i)&(MAX_PENDING_REQS-1))
static PEND_RING_IDX pending_prod, pending_cons;
#define NR_PENDING_REQS (MAX_PENDING_REQS - pending_prod + pending_cons)

static struct list_head net_schedule_list;
static spinlock_t net_schedule_list_lock;

#define MAX_MFN_ALLOC 64
static unsigned long mfn_list[MAX_MFN_ALLOC];
static unsigned int alloc_index = 0;
static spinlock_t mfn_lock = SPIN_LOCK_UNLOCKED;
static void __refresh_mfn_list(void)
{
    int ret;
    dom_mem_op_t op;
    op.op = MEMOP_RESERVATION_INCREASE;
    op.u.increase.size  = MAX_MFN_ALLOC;
    op.u.increase.pages = mfn_list;
    if ( (ret = HYPERVISOR_dom_mem_op(&op)) != MAX_MFN_ALLOC )
    {
        printk(KERN_ALERT "Unable to increase memory reservation (%d)\n", ret);
        BUG();
    }
    alloc_index = MAX_MFN_ALLOC;
}
static unsigned long get_new_mfn(void)
{
    unsigned long mfn, flags;
    spin_lock_irqsave(&mfn_lock, flags);
    if ( alloc_index == 0 )
        __refresh_mfn_list();
    mfn = mfn_list[--alloc_index];
    spin_unlock_irqrestore(&mfn_lock, flags);
    return mfn;
}
static void dealloc_mfn(unsigned long mfn)
{
    unsigned long flags;
    spin_lock_irqsave(&mfn_lock, flags);
    mfn_list[alloc_index++] = mfn;
    spin_unlock_irqrestore(&mfn_lock, flags);
}

static inline void maybe_schedule_tx_action(void)
{
    smp_mb();
    if ( (NR_PENDING_REQS < (MAX_PENDING_REQS/2)) &&
         !list_empty(&net_schedule_list) )
        tasklet_schedule(&net_tx_tasklet);
}

/*
 * This is the primary RECEIVE function for a network interface.
 * Note that, from the p.o.v. of /this/ OS it looks like a transmit.
 */
int netif_be_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    netif_t *netif = (netif_t *)dev->priv;
    s8 status = NETIF_RSP_OKAY;
    u16 size=0, id;
    mmu_update_t mmu[6];
    pgd_t *pgd; pmd_t *pmd; pte_t *pte;
    unsigned long vdata, mdata=0, new_mfn;

    /* Drop the packet if the target domain has no receive buffers. */
    if ( (netif->rx_req_cons == netif->rx->req_prod) ||
         ((netif->rx_req_cons-netif->rx_resp_prod) == NETIF_RX_RING_SIZE) )
    {
        dev_kfree_skb(skb);
        return 0;
    }

    id = netif->rx->ring[MASK_NETIF_RX_IDX(netif->rx_req_cons++)].req.id;
 
    /*
     * We do not copy the packet unless:
     *  1. It is fragmented; or
     *  2. It spans a page boundary; or
     *  3. We cannot be sure the whole data page is allocated.
     * The copying method is taken from skb_copy().
     */
    if ( (skb_shinfo(skb)->nr_frags != 0) ||
         (((unsigned long)skb->end ^ (unsigned long)skb->head) & PAGE_MASK) ||
         ((skb->end - skb->head) < (PAGE_SIZE/2)) )
    {
        struct sk_buff *nskb = alloc_skb(PAGE_SIZE-1024, GFP_ATOMIC);
        int hlen = skb->data - skb->head;
        if ( unlikely(nskb == NULL) )
        {
            DPRINTK("DOM%llu couldn't get memory for skb.\n", netif->domid);
            status = NETIF_RSP_ERROR;
            goto out;
        }
        skb_reserve(nskb, hlen);
        __skb_put(nskb, skb->len);
        (void)skb_copy_bits(skb, -hlen, nskb->head, hlen + skb->len);
        dev_kfree_skb(skb);
        skb = nskb;
    }

    vdata = (unsigned long)skb->data;
    mdata = virt_to_machine(vdata);
    size  = skb->tail - skb->data;

    new_mfn = get_new_mfn();

    pgd = pgd_offset_k(   (vdata & PAGE_MASK));
    pmd = pmd_offset(pgd, (vdata & PAGE_MASK));
    pte = pte_offset(pmd, (vdata & PAGE_MASK));

    mmu[0].val  = (unsigned long)(netif->domid<<16) & ~0xFFFFUL;
    mmu[0].ptr  = (unsigned long)(netif->domid<< 0) & ~0xFFFFUL;
    mmu[1].val  = (unsigned long)(netif->domid>>16) & ~0xFFFFUL;
    mmu[1].ptr  = (unsigned long)(netif->domid>>32) & ~0xFFFFUL;
    mmu[0].ptr |= MMU_EXTENDED_COMMAND;
    mmu[0].val |= MMUEXT_SET_SUBJECTDOM_L;
    mmu[1].ptr |= MMU_EXTENDED_COMMAND;
    mmu[1].val |= MMUEXT_SET_SUBJECTDOM_H;

    mmu[2].ptr  = (mdata & PAGE_MASK) | MMU_EXTENDED_COMMAND;
    mmu[2].val  = MMUEXT_REASSIGN_PAGE;

    mmu[3].ptr  = MMU_EXTENDED_COMMAND;
    mmu[3].val  = MMUEXT_RESET_SUBJECTDOM;

    mmu[4].ptr  = virt_to_machine(pte);
    mmu[4].val  = (new_mfn << PAGE_SHIFT) | __PAGE_KERNEL;

    mmu[5].ptr  = (new_mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
    mmu[5].val  = __pa(vdata) >> PAGE_SHIFT;

    if ( unlikely(HYPERVISOR_mmu_update(mmu, 6) < 0) )
    {
        DPRINTK("Failed MMU update transferring to DOM%llu\n", netif->domid);
        dealloc_mfn(new_mfn);
        status = NETIF_RSP_ERROR;
        goto out;
    }

    phys_to_machine_mapping[__pa(vdata) >> PAGE_SHIFT] = new_mfn;

    netif->stats.rx_bytes += size;
    netif->stats.rx_packets++;

 out:
    spin_lock(&netif->rx_lock);
    make_rx_response(netif, id, status, mdata, size);
    spin_unlock(&netif->rx_lock);    
    dev_kfree_skb(skb);
    return 0;
}

struct net_device_stats *netif_be_get_stats(struct net_device *dev)
{
    netif_t *netif = dev->priv;
    return &netif->stats;
}

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
    if ( !__on_net_schedule_list(netif) && (netif->status == CONNECTED) )
    {
        list_add_tail(&netif->list, &net_schedule_list);
        netif_get(netif);
    }
    spin_unlock(&net_schedule_list_lock);
}

static inline void netif_schedule_work(netif_t *netif)
{
    if ( (netif->tx_req_cons != netif->tx->req_prod) &&
         ((netif->tx_req_cons-netif->tx_resp_prod) != NETIF_TX_RING_SIZE) )
    {
        add_to_net_schedule_list_tail(netif);
        maybe_schedule_tx_action();
    }
}

void netif_deschedule(netif_t *netif)
{
    remove_from_net_schedule_list(netif);
}

#if 0
static void tx_credit_callback(unsigned long data)
{
    netif_t *netif = (netif_t *)data;
    netif->remaining_credit = netif->credit_bytes;
    netif_schedule_work(netif);
}
#endif

static void net_tx_action(unsigned long unused)
{
    struct list_head *ent;
    struct sk_buff *skb;
    netif_t *netif;
    netif_tx_request_t txreq;
    u16 pending_idx;
    NETIF_RING_IDX i;
    pgprot_t prot = __pgprot(_PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED);
    struct page *page;

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
        if ( (i == netif->tx->req_prod) ||
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

        netif_schedule_work(netif);

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
            DPRINTK("txreq.addr: %lx, size: %u, end: %lu\n", 
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
            make_tx_response(netif, txreq.id, NETIF_RSP_ERROR);
            netif_put(netif);
            continue;
        }
        phys_to_machine_mapping[__pa(MMAP_VADDR(pending_idx)) >> PAGE_SHIFT] =
            txreq.addr >> PAGE_SHIFT;

        if ( unlikely((skb = alloc_skb(PKT_PROT_LEN, GFP_ATOMIC)) == NULL) )
        {
            DPRINTK("Can't allocate a skb in start_xmit.\n");
            make_tx_response(netif, txreq.id, NETIF_RSP_ERROR);
            netif_put(netif);
            vmfree_area_pages(MMAP_VADDR(pending_idx), PAGE_SIZE);
            break;
        }
        
        __skb_put(skb, PKT_PROT_LEN);
        memcpy(skb->data, 
               (void *)(MMAP_VADDR(pending_idx)|(txreq.addr&~PAGE_MASK)),
               PKT_PROT_LEN);

        page = virt_to_page(MMAP_VADDR(pending_idx));

        /* Append the packet payload as a fragment. */
        skb_shinfo(skb)->frags[0].page        = page;
        skb_shinfo(skb)->frags[0].size        = txreq.size - PKT_PROT_LEN;
        skb_shinfo(skb)->frags[0].page_offset = 
            (txreq.addr + PKT_PROT_LEN) & ~PAGE_MASK;
        skb_shinfo(skb)->nr_frags = 1;
        skb->data_len  = txreq.size - PKT_PROT_LEN;
        skb->len      += skb->data_len;

        skb->dev      = netif->dev;
        skb->protocol = eth_type_trans(skb, skb->dev);

        /* Destructor information. */
        atomic_set(&page->count, 1);
        page->mapping = (struct address_space *)netif_page_release;
        pending_id[pending_idx] = txreq.id;
        pending_netif[pending_idx] = netif;

        netif->stats.tx_bytes += txreq.size;
        netif->stats.tx_packets++;

        pending_cons++;

        netif_rx(skb);
        netif->dev->last_rx = jiffies;
    }
}

static void netif_page_release(struct page *page)
{
    unsigned long flags;
    netif_t *netif;
    u16 pending_idx;

    pending_idx = page - virt_to_page(mmap_vstart);

    netif = pending_netif[pending_idx];

    vmfree_area_pages(MMAP_VADDR(pending_idx), PAGE_SIZE);
        
    spin_lock(&netif->tx_lock);
    make_tx_response(netif, pending_id[pending_idx], NETIF_RSP_OKAY);
    spin_unlock(&netif->tx_lock);

    /*
     * Scheduling checks must happen after the above response is posted.
     * This avoids a possible race with a guest OS on another CPU.
     */
    mb();
    netif_schedule_work(netif);

    netif_put(netif);
 
    spin_lock_irqsave(&pend_prod_lock, flags);
    pending_ring[MASK_PEND_IDX(pending_prod++)] = pending_idx;
    spin_unlock_irqrestore(&pend_prod_lock, flags);
}

#if 0
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
#endif

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
    int i;

    if ( !(start_info.flags & SIF_INITDOMAIN) )
        return 0;

    netif_interface_init();

    if ( (mmap_vstart = allocate_empty_lowmem_region(MAX_PENDING_REQS)) == 0 )
        BUG();

    pending_cons = 0;
    pending_prod = MAX_PENDING_REQS;
    for ( i = 0; i < MAX_PENDING_REQS; i++ )
        pending_ring[i] = i;

    spin_lock_init(&net_schedule_list_lock);
    INIT_LIST_HEAD(&net_schedule_list);

    netif_ctrlif_init();

    return 0;
}

static void cleanup_module(void)
{
    BUG();
}

module_init(init_module);
module_exit(cleanup_module);
