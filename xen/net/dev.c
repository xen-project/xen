/*
 * 	NET3	Protocol independent device support routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/bitops.h>
#include <xen/config.h>
#include <xen/delay.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/socket.h>
#include <xen/sockios.h>
#include <xen/errno.h>
#include <xen/interrupt.h>
#include <xen/if_ether.h>
#include <xen/netdevice.h>
#include <xen/etherdevice.h>
#include <xen/skbuff.h>
#include <xen/brlock.h>
#include <xen/init.h>
#include <xen/module.h>
#include <xen/event.h>
#include <xen/shadow.h>
#include <asm/domain_page.h>
#include <asm/pgalloc.h>
#include <asm/io.h>
#include <xen/perfc.h>

#define BUG_TRAP ASSERT
#define notifier_call_chain(_a,_b,_c) ((void)0)
#define rtmsg_ifinfo(_a,_b,_c) ((void)0)
#define rtnl_lock() ((void)0)
#define rtnl_unlock() ((void)0)

struct skb_completion_queues skb_queue[NR_CPUS] __cacheline_aligned;

static int get_tx_bufs(net_vif_t *vif);

static void make_tx_response(net_vif_t     *vif, 
                             unsigned short id, 
                             unsigned char  st);
static void make_rx_response(net_vif_t     *vif, 
                             unsigned short id, 
                             unsigned short size,
                             unsigned char  st,
                             unsigned char  off);

struct net_device *the_dev = NULL;

/*
 * Transmitted packets are fragmented, so we can copy the important headesr 
 * before checking them for validity. Avoids need for page protection.
 */
/* Ethernet + IP headers */
#define PKT_PROT_LEN (ETH_HLEN + 20)
static kmem_cache_t *net_header_cachep;

/**
 *	__dev_get_by_name	- find a device by its name 
 *	@name: name to find
 *
 *	Find an interface by name. Must be called under RTNL semaphore
 *	or @dev_base_lock. If the name is found a pointer to the device
 *	is returned. If the name is not found then %NULL is returned. The
 *	reference counters are not incremented so the caller must be
 *	careful with locks.
 */
 

struct net_device *__dev_get_by_name(const char *name)
{
    struct net_device *dev;

    for (dev = dev_base; dev != NULL; dev = dev->next) {
        if (strncmp(dev->name, name, IFNAMSIZ) == 0)
            return dev;
    }
    return NULL;
}

/**
 *	dev_get_by_name		- find a device by its name
 *	@name: name to find
 *
 *	Find an interface by name. This can be called from any 
 *	context and does its own locking. The returned handle has
 *	the usage count incremented and the caller must use dev_put() to
 *	release it when it is no longer needed. %NULL is returned if no
 *	matching device is found.
 */

struct net_device *dev_get_by_name(const char *name)
{
    struct net_device *dev;

    read_lock(&dev_base_lock);
    dev = __dev_get_by_name(name);
    if (dev)
        dev_hold(dev);
    read_unlock(&dev_base_lock);
    return dev;
}

/**
 *	dev_get	-	test if a device exists
 *	@name:	name to test for
 *
 *	Test if a name exists. Returns true if the name is found. In order
 *	to be sure the name is not allocated or removed during the test the
 *	caller must hold the rtnl semaphore.
 *
 *	This function primarily exists for back compatibility with older
 *	drivers. 
 */
 
int dev_get(const char *name)
{
    struct net_device *dev;

    read_lock(&dev_base_lock);
    dev = __dev_get_by_name(name);
    read_unlock(&dev_base_lock);
    return dev != NULL;
}

/**
 *	__dev_get_by_index - find a device by its ifindex
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns %NULL if the device
 *	is not found or a pointer to the device. The device has not
 *	had its reference counter increased so the caller must be careful
 *	about locking. The caller must hold either the RTNL semaphore
 *	or @dev_base_lock.
 */

struct net_device * __dev_get_by_index(int ifindex)
{
    struct net_device *dev;

    for (dev = dev_base; dev != NULL; dev = dev->next) {
        if (dev->ifindex == ifindex)
            return dev;
    }
    return NULL;
}


/**
 *	dev_get_by_index - find a device by its ifindex
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns NULL if the device
 *	is not found or a pointer to the device. The device returned has 
 *	had a reference added and the pointer is safe until the user calls
 *	dev_put to indicate they have finished with it.
 */

struct net_device * dev_get_by_index(int ifindex)
{
    struct net_device *dev;

    read_lock(&dev_base_lock);
    dev = __dev_get_by_index(ifindex);
    if (dev)
        dev_hold(dev);
    read_unlock(&dev_base_lock);
    return dev;
}

/**
 *	dev_getbyhwaddr - find a device by its hardware address
 *	@type: media type of device
 *	@ha: hardware address
 *
 *	Search for an interface by MAC address. Returns NULL if the device
 *	is not found or a pointer to the device. The caller must hold the
 *	rtnl semaphore. The returned device has not had its ref count increased
 *	and the caller must therefore be careful about locking
 *
 *	BUGS:
 *	If the API was consistent this would be __dev_get_by_hwaddr
 */

struct net_device *dev_getbyhwaddr(unsigned short type, char *ha)
{
    struct net_device *dev;

    for (dev = dev_base; dev != NULL; dev = dev->next) {
        if (dev->type == type &&
            memcmp(dev->dev_addr, ha, dev->addr_len) == 0)
            return dev;
    }
    return NULL;
}

/**
 *	dev_alloc_name - allocate a name for a device
 *	@dev: device 
 *	@name: name format string
 *
 *	Passed a format string - eg "lt%d" it will try and find a suitable
 *	id. Not efficient for many devices, not called a lot. The caller
 *	must hold the dev_base or rtnl lock while allocating the name and
 *	adding the device in order to avoid duplicates. Returns the number
 *	of the unit assigned or a negative errno code.
 */

int dev_alloc_name(struct net_device *dev, const char *name)
{
    int i;
    char buf[32];
    char *p;

    /*
     * Verify the string as this thing may have come from
     * the user.  There must be either one "%d" and no other "%"
     * characters, or no "%" characters at all.
     */
    p = strchr(name, '%');
    if (p && (p[1] != 'd' || strchr(p+2, '%')))
        return -EINVAL;

    /*
     * If you need over 100 please also fix the algorithm...
     */
    for (i = 0; i < 100; i++) {
        snprintf(buf,sizeof(buf),name,i);
        if (__dev_get_by_name(buf) == NULL) {
            strcpy(dev->name, buf);
            return i;
        }
    }
    return -ENFILE;	/* Over 100 of the things .. bail out! */
}

/**
 *	dev_alloc - allocate a network device and name
 *	@name: name format string
 *	@err: error return pointer
 *
 *	Passed a format string, eg. "lt%d", it will allocate a network device
 *	and space for the name. %NULL is returned if no memory is available.
 *	If the allocation succeeds then the name is assigned and the 
 *	device pointer returned. %NULL is returned if the name allocation
 *	failed. The cause of an error is returned as a negative errno code
 *	in the variable @err points to.
 *
 *	The caller must hold the @dev_base or RTNL locks when doing this in
 *	order to avoid duplicate name allocations.
 */

struct net_device *dev_alloc(const char *name, int *err)
{
    struct net_device *dev=kmalloc(sizeof(struct net_device), GFP_KERNEL);
    if (dev == NULL) {
        *err = -ENOBUFS;
        return NULL;
    }
    memset(dev, 0, sizeof(struct net_device));
    *err = dev_alloc_name(dev, name);
    if (*err < 0) {
        kfree(dev);
        return NULL;
    }
    return dev;
}

/**
 *	netdev_state_change - device changes state
 *	@dev: device to cause notification
 *
 *	Called to indicate a device has changed state. This function calls
 *	the notifier chains for netdev_chain and sends a NEWLINK message
 *	to the routing socket.
 */
 
void netdev_state_change(struct net_device *dev)
{
    if (dev->flags&IFF_UP) {
        notifier_call_chain(&netdev_chain, NETDEV_CHANGE, dev);
        rtmsg_ifinfo(RTM_NEWLINK, dev, 0);
    }
}


#ifdef CONFIG_KMOD

/**
 *	dev_load 	- load a network module
 *	@name: name of interface
 *
 *	If a network interface is not present and the process has suitable
 *	privileges this function loads the module. If module loading is not
 *	available in this kernel then it becomes a nop.
 */

void dev_load(const char *name)
{
    if (!dev_get(name) && capable(CAP_SYS_MODULE))
        request_module(name);
}

#else

extern inline void dev_load(const char *unused){;}

#endif

static int default_rebuild_header(struct sk_buff *skb)
{
    printk(KERN_DEBUG "%s: default_rebuild_header called -- BUG!\n", 
           skb->dev ? skb->dev->name : "NULL!!!");
    kfree_skb(skb);
    return 1;
}

/**
 *	dev_open	- prepare an interface for use. 
 *	@dev:	device to open
 *
 *	Takes a device from down to up state. The device's private open
 *	function is invoked and then the multicast lists are loaded. Finally
 *	the device is moved into the up state and a %NETDEV_UP message is
 *	sent to the netdev notifier chain.
 *
 *	Calling this function on an active interface is a nop. On a failure
 *	a negative errno code is returned.
 */
 
int dev_open(struct net_device *dev)
{
    int ret = 0;

    /*
     *	Is it already up?
     */

    if (dev->flags&IFF_UP)
        return 0;

    /*
     *	Is it even present?
     */
    if (!netif_device_present(dev))
        return -ENODEV;

    /*
     *	Call device private open method
     */
    if (try_inc_mod_count(dev->owner)) {
        if (dev->open) {
            ret = dev->open(dev);
            if (ret != 0 && dev->owner)
                __MOD_DEC_USE_COUNT(dev->owner);
        }
    } else {
        ret = -ENODEV;
    }

    /*
     *	If it went open OK then:
     */
	 
    if (ret == 0) 
    {
        /*
         *	Set the flags.
         */
        dev->flags |= IFF_UP;

        set_bit(__LINK_STATE_START, &dev->state);

        /*
         *	Initialize multicasting status 
         */
        dev_mc_upload(dev);

        /*
         *	Wakeup transmit queue engine
         */
        dev_activate(dev);

        /*
         *	... and announce new interface.
         */
        notifier_call_chain(&netdev_chain, NETDEV_UP, dev);
    }
    return(ret);
}


/**
 *	dev_close - shutdown an interface.
 *	@dev: device to shutdown
 *
 *	This function moves an active device into down state. A 
 *	%NETDEV_GOING_DOWN is sent to the netdev notifier chain. The device
 *	is then deactivated and finally a %NETDEV_DOWN is sent to the notifier
 *	chain.
 */
 
int dev_close(struct net_device *dev)
{
    if (!(dev->flags&IFF_UP))
        return 0;

    /*
     *	Tell people we are going down, so that they can
     *	prepare to death, when device is still operating.
     */
    notifier_call_chain(&netdev_chain, NETDEV_GOING_DOWN, dev);

    dev_deactivate(dev);

    clear_bit(__LINK_STATE_START, &dev->state);

    /*
     *	Call the device specific close. This cannot fail.
     *	Only if device is UP
     *
     *	We allow it to be called even after a DETACH hot-plug
     *	event.
     */
	 
    if (dev->stop)
        dev->stop(dev);

    /*
     *	Device is now down.
     */

    dev->flags &= ~IFF_UP;

    /*
     *	Tell people we are down
     */
    notifier_call_chain(&netdev_chain, NETDEV_DOWN, dev);

    /*
     * Drop the module refcount
     */
    if (dev->owner)
        __MOD_DEC_USE_COUNT(dev->owner);

    return(0);
}


#ifdef CONFIG_HIGHMEM
/* Actually, we should eliminate this check as soon as we know, that:
 * 1. IOMMU is present and allows to map all the memory.
 * 2. No high memory really exists on this machine.
 */

static inline int
illegal_highdma(struct net_device *dev, struct sk_buff *skb)
{
    int i;

    if (dev->features&NETIF_F_HIGHDMA)
        return 0;

    for (i=0; i<skb_shinfo(skb)->nr_frags; i++)
        if (skb_shinfo(skb)->frags[i].page >= highmem_start_page)
            return 1;

    return 0;
}
#else
#define illegal_highdma(dev, skb)	(0)
#endif


/*=======================================================================
			Receiver routines
  =======================================================================*/

struct netif_rx_stats netdev_rx_stat[NR_CPUS];

void deliver_packet(struct sk_buff *skb, net_vif_t *vif)
{
    rx_shadow_entry_t *rx;
    unsigned long *ptep, pte, new_pte; 
    struct pfn_info *old_page, *new_page, *pte_page;
    unsigned short size;
    unsigned char  offset, status = RING_STATUS_OK;
    struct task_struct *p = vif->domain;
    unsigned long spte_pfn;

    memcpy(skb->mac.ethernet->h_dest, vif->vmac, ETH_ALEN);
    if ( ntohs(skb->mac.ethernet->h_proto) == ETH_P_ARP )
        memcpy(skb->nh.raw + 18, vif->vmac, ETH_ALEN);

    spin_lock(&vif->rx_lock);

    if ( unlikely(vif->rx_cons == vif->rx_prod) )
    {
        spin_unlock(&vif->rx_lock);
        perfc_incr(net_rx_capacity_drop);
        return;
    }
    rx = &vif->rx_shadow_ring[MASK_NET_RX_IDX(vif->rx_cons++)];

    size   = (unsigned short)skb->len;
    offset = (unsigned char)((unsigned long)skb->data & ~PAGE_MASK);

    pte_page = &frame_table[rx->pte_ptr >> PAGE_SHIFT];
    old_page = &frame_table[rx->buf_pfn];
    new_page = skb->pf;
    
    skb->pf = old_page;

    ptep = map_domain_mem(rx->pte_ptr);

    new_page->u.domain = p;
    wmb(); /* make dom ptr visible before updating refcnt. */
    spin_lock(&p->page_list_lock);
    list_add(&new_page->list, &p->page_list);
    new_page->count_and_flags = PGC_allocated | 2;
    spin_unlock(&p->page_list_lock);
    get_page_type(new_page, PGT_writeable_page);
    set_bit(_PGC_tlb_flush_on_type_change, &new_page->count_and_flags);
    wmb(); /* Get type count and set flush bit before updating PTE. */

    pte = *ptep;

    new_pte = (pte & ~PAGE_MASK) | _PAGE_RW | _PAGE_PRESENT |
                          ((new_page - frame_table) << PAGE_SHIFT);

    if ( unlikely(pte & _PAGE_PRESENT) || 
         unlikely(cmpxchg(ptep, pte, new_pte)) != pte )
    {
        DPRINTK("PTE was modified or reused! %08lx %08lx\n", pte, *ptep);
        unmap_domain_mem(ptep);
        /* At some point maybe should have 'new_page' in error response. */
        put_page_and_type(new_page);
        status = RING_STATUS_BAD_PAGE;
        goto out;
    }

    machine_to_phys_mapping[new_page - frame_table] = 
	machine_to_phys_mapping[old_page - frame_table];

    if ( p->mm.shadow_mode && 
	 (spte_pfn=get_shadow_status(&p->mm, pte_page-frame_table)) )
    {
	unsigned long *sptr = map_domain_mem( (spte_pfn<<PAGE_SHIFT) |
			(((unsigned long)ptep)&~PAGE_MASK) );

        /* Avoid the fault later. */
	*sptr = new_pte;
	unmap_domain_mem(sptr);

	put_shadow_status(&p->mm);
    }
    
    unmap_domain_mem(ptep);

    /* if in shadow mode, mark the buffer as dirty */
    if( p->mm.shadow_mode == SHM_logdirty )
	mark_dirty( &p->mm, (new_page-frame_table) );

    /* Updates must happen before releasing the descriptor. */
    smp_wmb();

    perfc_incr(net_rx_delivered);

    /* record this so they can be billed */
    vif->total_packets_received++;
    vif->total_bytes_received += size;

 out:
    put_page_and_type(pte_page);
    make_rx_response(vif, rx->id, size, status, offset);
    spin_unlock(&vif->rx_lock);
}

/**
 *	netif_rx	-	post buffer to the network code
 *	@skb: buffer to post
 *
 *	This function receives a packet from a device driver and queues it for
 *	the upper (protocol) levels to process.  It always succeeds. The buffer
 *	may be dropped during processing for congestion control or by the 
 *	protocol layers.
 *      
 *	return values:
 *	NET_RX_SUCCESS	(no congestion)           
 *	NET_RX_DROP    (packet was dropped)
 */

int netif_rx(struct sk_buff *skb)
{
    int cpu = smp_processor_id();
    unsigned long flags;

    local_irq_save(flags);
    if ( unlikely(skb_queue_len(&skb_queue[cpu].rx) > 100) )
    {
        local_irq_restore(flags);
        perfc_incr(net_rx_congestion_drop);
        return NET_RX_DROP;
    }
    __skb_queue_tail(&skb_queue[cpu].rx, skb);
    local_irq_restore(flags);

    __cpu_raise_softirq(cpu, NET_RX_SOFTIRQ);

    return NET_RX_SUCCESS;
}

static void net_rx_action(struct softirq_action *h)
{
    int offset, cpu = smp_processor_id();
    struct sk_buff_head list, *q = &skb_queue[cpu].rx;
    struct sk_buff *skb;

    local_irq_disable();
    /* Code to patch to the private list header is invalid if list is empty! */
    if ( unlikely(skb_queue_len(q) == 0) )
    {
        local_irq_enable();
        return;
    }
    /* Patch the head and tail skbuffs to point at the private list header. */
    q->next->prev = (struct sk_buff *)&list;
    q->prev->next = (struct sk_buff *)&list;
    /* Move the list to our private header. The public header is reinit'ed. */
    list = *q;
    skb_queue_head_init(q);
    local_irq_enable();

    while ( (skb = __skb_dequeue(&list)) != NULL )
    {
        ASSERT(skb->skb_type == SKB_ZERO_COPY);

        /*
         * Offset will include 16 bytes padding from dev_alloc_skb, 14 bytes
         * for ethernet header, plus any other alignment padding added by the
         * driver.
         */
        offset = (int)(long)skb->data & ~PAGE_MASK; 
        skb->head = (u8 *)map_domain_mem(((skb->pf - frame_table) << 
                                          PAGE_SHIFT));
        skb->data = skb->nh.raw = skb->head + offset;
        skb->tail = skb->data + skb->len;
        skb_push(skb, ETH_HLEN);
        skb->mac.raw = skb->data;
        
        netdev_rx_stat[cpu].total++;
        
        if ( skb->dst_vif == NULL )
            skb->dst_vif = net_get_target_vif(
                skb->data, skb->len, skb->src_vif);
        
        if ( !VIF_LOCAL(skb->dst_vif) )
            skb->dst_vif = find_net_vif(0, 0);
        
        if ( skb->dst_vif != NULL )
        {
            deliver_packet(skb, skb->dst_vif);
            put_vif(skb->dst_vif);
        }

        unmap_domain_mem(skb->head);

        kfree_skb(skb);
    }
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

static int __on_net_schedule_list(net_vif_t *vif)
{
    return vif->list.next != NULL;
}

static void remove_from_net_schedule_list(net_vif_t *vif)
{
    spin_lock(&net_schedule_list_lock);
    ASSERT(__on_net_schedule_list(vif));
    list_del(&vif->list);
    vif->list.next = NULL;
    put_vif(vif);
    spin_unlock(&net_schedule_list_lock);
}

static void add_to_net_schedule_list_tail(net_vif_t *vif)
{
    if ( __on_net_schedule_list(vif) )
        return;

    spin_lock(&net_schedule_list_lock);
    if ( likely(!__on_net_schedule_list(vif)) )
    {
        list_add_tail(&vif->list, &net_schedule_list);
        get_vif(vif);
    }
    spin_unlock(&net_schedule_list_lock);
}


static void tx_skb_release(struct sk_buff *skb);
    
static void net_tx_action(unsigned long unused)
{
    struct net_device *dev = the_dev;
    struct list_head *ent;
    struct sk_buff *skb, *nskb;
    net_vif_t *vif;
    tx_shadow_entry_t *tx;

    spin_lock(&dev->xmit_lock);
    while ( !netif_queue_stopped(dev) &&
            !list_empty(&net_schedule_list) )
    {
        /* Get a vif from the list with work to do. */
        ent = net_schedule_list.next;
        vif = list_entry(ent, net_vif_t, list);
        get_vif(vif);
        remove_from_net_schedule_list(vif);

        /* Check whether there are packets to be transmitted. */
        if ( (vif->tx_cons == vif->tx_prod) && !get_tx_bufs(vif) )
        {
            put_vif(vif);
            continue;
        }

        add_to_net_schedule_list_tail(vif);

        if ( unlikely((skb = alloc_skb_nodata(GFP_ATOMIC)) == NULL) )
        {
            printk("Out of memory in net_tx_action()!\n");
            add_to_net_schedule_list_tail(vif);
            put_vif(vif);
            break;
        }
        
        /* Pick an entry from the transmit queue. */
        tx = &vif->tx_shadow_ring[MASK_NET_TX_IDX(vif->tx_cons++)];

        skb->destructor = tx_skb_release;

        skb->head = skb->data = tx->header;
        skb->end  = skb->tail = skb->head + PKT_PROT_LEN;
        
        skb->dev      = the_dev;
        skb->src_vif  = vif;
        skb->dst_vif  = NULL;
        skb->mac.raw  = skb->data; 
        skb->guest_id = tx->id;
        
        skb_shinfo(skb)->frags[0].page        = 
            &frame_table[tx->payload >> PAGE_SHIFT];
        skb_shinfo(skb)->frags[0].size        = tx->size - PKT_PROT_LEN;
        skb_shinfo(skb)->frags[0].page_offset = tx->payload & ~PAGE_MASK;
        skb_shinfo(skb)->nr_frags = 1;

        skb->data_len = tx->size - PKT_PROT_LEN;
        skb->len      = tx->size;

        /* record the transmission so they can be billed */
        vif->total_packets_sent++;
        vif->total_bytes_sent += tx->size;

        /* Is the NIC crap? */
        if ( unlikely(!(dev->features & NETIF_F_SG)) )
        {
            nskb = skb_copy(skb, GFP_KERNEL);
            kfree_skb(skb);
            skb = nskb;
        }

        /* Transmit should always work, or the queue would be stopped. */
        if ( unlikely(dev->hard_start_xmit(skb, dev) != 0) )
        {
            printk("Weird failure in hard_start_xmit!\n");
            kfree_skb(skb);
            break;
        }

        perfc_incr(net_tx_transmitted);
    }
    spin_unlock(&dev->xmit_lock);
}

DECLARE_TASKLET_DISABLED(net_tx_tasklet, net_tx_action, 0);

static inline void maybe_schedule_tx_action(void)
{
    smp_mb();
    if ( !netif_queue_stopped(the_dev) &&
         !list_empty(&net_schedule_list) )
        tasklet_schedule(&net_tx_tasklet);
}


static void net_tx_gc(struct softirq_action *h)
{
    int cpu = smp_processor_id();
    struct sk_buff *skb, *nskb;

    local_irq_disable();
    skb = skb_queue[cpu].tx;
    skb_queue[cpu].tx = NULL;
    local_irq_enable();

    while ( skb != NULL )
    {
        nskb = skb->next;
        __kfree_skb(skb);
        skb = nskb;
    }
}

/* Destructor function for tx skbs. */
static void tx_skb_release(struct sk_buff *skb)
{
    int i;
    net_vif_t *vif;

    vif = skb->src_vif;
    
    for ( i = 0; i < skb_shinfo(skb)->nr_frags; i++ )
        put_page(skb_shinfo(skb)->frags[i].page);
    
    if ( skb->skb_type == SKB_NODATA )
        kmem_cache_free(net_header_cachep, skb->head);
    
    skb_shinfo(skb)->nr_frags = 0; 
    
    spin_lock(&vif->tx_lock);
    make_tx_response(vif, skb->guest_id, RING_STATUS_OK);
    spin_unlock(&vif->tx_lock);
    
    /*
     * Checks below must happen after the above response is posted. This avoids
     * a possible race with a guest OS on another CPU.
     */
    smp_mb();
    
    if ( (vif->tx_cons == vif->tx_prod) && get_tx_bufs(vif) )
    {
        add_to_net_schedule_list_tail(vif);
        maybe_schedule_tx_action();        
    }
    
    put_vif(vif);
}


/*
 *	We need this ioctl for efficient implementation of the
 *	if_indextoname() function required by the IPv6 API.  Without
 *	it, we would have to search all the interfaces to find a
 *	match.  --pb
 */

static int dev_ifname(struct ifreq *arg)
{
    struct net_device *dev;
    struct ifreq ifr;

    /*
     *	Fetch the caller's info block. 
     */
	
    if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
        return -EFAULT;

    read_lock(&dev_base_lock);
    dev = __dev_get_by_index(ifr.ifr_ifindex);
    if (!dev) {
        read_unlock(&dev_base_lock);
        return -ENODEV;
    }

    strcpy(ifr.ifr_name, dev->name);
    read_unlock(&dev_base_lock);

    if (copy_to_user(arg, &ifr, sizeof(struct ifreq)))
        return -EFAULT;
    return 0;
}


/**
 *	netdev_set_master	-	set up master/slave pair
 *	@slave: slave device
 *	@master: new master device
 *
 *	Changes the master device of the slave. Pass %NULL to break the
 *	bonding. The caller must hold the RTNL semaphore. On a failure
 *	a negative errno code is returned. On success the reference counts
 *	are adjusted, %RTM_NEWLINK is sent to the routing socket and the
 *	function returns zero.
 */
 
int netdev_set_master(struct net_device *slave, struct net_device *master)
{
    struct net_device *old = slave->master;

    if (master) {
        if (old)
            return -EBUSY;
        dev_hold(master);
    }

    br_write_lock_bh(BR_NETPROTO_LOCK);
    slave->master = master;
    br_write_unlock_bh(BR_NETPROTO_LOCK);

    if (old)
        dev_put(old);

    if (master)
        slave->flags |= IFF_SLAVE;
    else
        slave->flags &= ~IFF_SLAVE;

    rtmsg_ifinfo(RTM_NEWLINK, slave, IFF_SLAVE);
    return 0;
}

/**
 *	dev_set_promiscuity	- update promiscuity count on a device
 *	@dev: device
 *	@inc: modifier
 *
 *	Add or remove promsicuity from a device. While the count in the device
 *	remains above zero the interface remains promiscuous. Once it hits zero
 *	the device reverts back to normal filtering operation. A negative inc
 *	value is used to drop promiscuity on the device.
 */
 
void dev_set_promiscuity(struct net_device *dev, int inc)
{
    unsigned short old_flags = dev->flags;

    dev->flags |= IFF_PROMISC;
    if ((dev->promiscuity += inc) == 0)
        dev->flags &= ~IFF_PROMISC;
    if (dev->flags^old_flags) {
#ifdef CONFIG_NET_FASTROUTE
        if (dev->flags&IFF_PROMISC) {
            netdev_fastroute_obstacles++;
            dev_clear_fastroute(dev);
        } else
            netdev_fastroute_obstacles--;
#endif
        dev_mc_upload(dev);
        printk(KERN_INFO "device %s %s promiscuous mode\n",
               dev->name, (dev->flags&IFF_PROMISC) ? "entered" : "left");
    }
}

/**
 *	dev_set_allmulti	- update allmulti count on a device
 *	@dev: device
 *	@inc: modifier
 *
 *	Add or remove reception of all multicast frames to a device. While the
 *	count in the device remains above zero the interface remains listening
 *	to all interfaces. Once it hits zero the device reverts back to normal
 *	filtering operation. A negative @inc value is used to drop the counter
 *	when releasing a resource needing all multicasts.
 */

void dev_set_allmulti(struct net_device *dev, int inc)
{
    unsigned short old_flags = dev->flags;

    dev->flags |= IFF_ALLMULTI;
    if ((dev->allmulti += inc) == 0)
        dev->flags &= ~IFF_ALLMULTI;
    if (dev->flags^old_flags)
        dev_mc_upload(dev);
}

int dev_change_flags(struct net_device *dev, unsigned flags)
{
    int ret;
    int old_flags = dev->flags;

    /*
     *	Set the flags on our device.
     */

    dev->flags = (flags & (IFF_DEBUG|IFF_NOTRAILERS|IFF_NOARP|IFF_DYNAMIC|
                           IFF_MULTICAST|IFF_PORTSEL|IFF_AUTOMEDIA)) |
        (dev->flags & (IFF_UP|IFF_VOLATILE|IFF_PROMISC|IFF_ALLMULTI));

    /*
     *	Load in the correct multicast list now the flags have changed.
     */				

    dev_mc_upload(dev);

    /*
     *	Have we downed the interface. We handle IFF_UP ourselves
     *	according to user attempts to set it, rather than blindly
     *	setting it.
     */

    ret = 0;
    if ((old_flags^flags)&IFF_UP)	/* Bit is different  ? */
    {
        ret = ((old_flags & IFF_UP) ? dev_close : dev_open)(dev);

        if (ret == 0) 
            dev_mc_upload(dev);
    }

    if (dev->flags&IFF_UP &&
        ((old_flags^dev->flags)&
         ~(IFF_UP|IFF_PROMISC|IFF_ALLMULTI|IFF_VOLATILE)))
        notifier_call_chain(&netdev_chain, NETDEV_CHANGE, dev);

    if ((flags^dev->gflags)&IFF_PROMISC) {
        int inc = (flags&IFF_PROMISC) ? +1 : -1;
        dev->gflags ^= IFF_PROMISC;
        dev_set_promiscuity(dev, inc);
    }

    /* NOTE: order of synchronization of IFF_PROMISC and IFF_ALLMULTI
       is important. Some (broken) drivers set IFF_PROMISC, when
       IFF_ALLMULTI is requested not asking us and not reporting.
    */
    if ((flags^dev->gflags)&IFF_ALLMULTI) {
        int inc = (flags&IFF_ALLMULTI) ? +1 : -1;
        dev->gflags ^= IFF_ALLMULTI;
        dev_set_allmulti(dev, inc);
    }

    if (old_flags^dev->flags)
        rtmsg_ifinfo(RTM_NEWLINK, dev, old_flags^dev->flags);

    return ret;
}

/*
 *	Perform the SIOCxIFxxx calls. 
 */
 
static int dev_ifsioc(struct ifreq *ifr, unsigned int cmd)
{
    struct net_device *dev;
    int err;

    if ((dev = __dev_get_by_name(ifr->ifr_name)) == NULL)
        return -ENODEV;

    switch(cmd) 
    {
    case SIOCGIFFLAGS:	/* Get interface flags */
        ifr->ifr_flags = (dev->flags&~(IFF_PROMISC|IFF_ALLMULTI|IFF_RUNNING))
            |(dev->gflags&(IFF_PROMISC|IFF_ALLMULTI));
        if (netif_running(dev) && netif_carrier_ok(dev))
            ifr->ifr_flags |= IFF_RUNNING;
        return 0;

    case SIOCSIFFLAGS:	/* Set interface flags */
        return dev_change_flags(dev, ifr->ifr_flags);
		
    case SIOCGIFMETRIC:	/* Get the metric on the interface */
        ifr->ifr_metric = 0;
        return 0;
			
    case SIOCSIFMETRIC:	/* Set the metric on the interface */
        return -EOPNOTSUPP;
	
    case SIOCGIFMTU:	/* Get the MTU of a device */
        ifr->ifr_mtu = dev->mtu;
        return 0;
	
    case SIOCSIFMTU:	/* Set the MTU of a device */
        if (ifr->ifr_mtu == dev->mtu)
            return 0;

        /*
         *	MTU must be positive.
         */
			 
        if (ifr->ifr_mtu<0)
            return -EINVAL;

        if (!netif_device_present(dev))
            return -ENODEV;

        if (dev->change_mtu)
            err = dev->change_mtu(dev, ifr->ifr_mtu);
        else {
            dev->mtu = ifr->ifr_mtu;
            err = 0;
        }
        if (!err && dev->flags&IFF_UP)
            notifier_call_chain(&netdev_chain, NETDEV_CHANGEMTU, dev);
        return err;

    case SIOCGIFHWADDR:
        memcpy(ifr->ifr_hwaddr.sa_data,dev->dev_addr, MAX_ADDR_LEN);
        ifr->ifr_hwaddr.sa_family=dev->type;
        return 0;
				
    case SIOCSIFHWADDR:
        if (dev->set_mac_address == NULL)
            return -EOPNOTSUPP;
        if (ifr->ifr_hwaddr.sa_family!=dev->type)
            return -EINVAL;
        if (!netif_device_present(dev))
            return -ENODEV;
        err = dev->set_mac_address(dev, &ifr->ifr_hwaddr);
        if (!err)
            notifier_call_chain(&netdev_chain, NETDEV_CHANGEADDR, dev);
        return err;
			
    case SIOCSIFHWBROADCAST:
        if (ifr->ifr_hwaddr.sa_family!=dev->type)
            return -EINVAL;
        memcpy(dev->broadcast, ifr->ifr_hwaddr.sa_data, MAX_ADDR_LEN);
        notifier_call_chain(&netdev_chain, NETDEV_CHANGEADDR, dev);
        return 0;

    case SIOCGIFMAP:
        ifr->ifr_map.mem_start=dev->mem_start;
        ifr->ifr_map.mem_end=dev->mem_end;
        ifr->ifr_map.base_addr=dev->base_addr;
        ifr->ifr_map.irq=dev->irq;
        ifr->ifr_map.dma=dev->dma;
        ifr->ifr_map.port=dev->if_port;
        return 0;
			
    case SIOCSIFMAP:
        if (dev->set_config) {
            if (!netif_device_present(dev))
                return -ENODEV;
            return dev->set_config(dev,&ifr->ifr_map);
        }
        return -EOPNOTSUPP;
			
    case SIOCADDMULTI:
        if (dev->set_multicast_list == NULL ||
            ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
            return -EINVAL;
        if (!netif_device_present(dev))
            return -ENODEV;
        dev_mc_add(dev,ifr->ifr_hwaddr.sa_data, dev->addr_len, 1);
        return 0;

    case SIOCDELMULTI:
        if (dev->set_multicast_list == NULL ||
            ifr->ifr_hwaddr.sa_family!=AF_UNSPEC)
            return -EINVAL;
        if (!netif_device_present(dev))
            return -ENODEV;
        dev_mc_delete(dev,ifr->ifr_hwaddr.sa_data,dev->addr_len, 1);
        return 0;

    case SIOCGIFINDEX:
        ifr->ifr_ifindex = dev->ifindex;
        return 0;

    case SIOCSIFNAME:
        if (dev->flags&IFF_UP)
            return -EBUSY;
        if (__dev_get_by_name(ifr->ifr_newname))
            return -EEXIST;
        memcpy(dev->name, ifr->ifr_newname, IFNAMSIZ);
        dev->name[IFNAMSIZ-1] = 0;
        notifier_call_chain(&netdev_chain, NETDEV_CHANGENAME, dev);
        return 0;

#ifdef WIRELESS_EXT
    case SIOCGIWSTATS:
        return dev_iwstats(dev, ifr);
#endif	/* WIRELESS_EXT */

        /*
         *	Unknown or private ioctl
         */

    default:
        if ((cmd >= SIOCDEVPRIVATE &&
             cmd <= SIOCDEVPRIVATE + 15) ||
            cmd == SIOCBONDENSLAVE ||
            cmd == SIOCBONDRELEASE ||
            cmd == SIOCBONDSETHWADDR ||
            cmd == SIOCBONDSLAVEINFOQUERY ||
            cmd == SIOCBONDINFOQUERY ||
            cmd == SIOCBONDCHANGEACTIVE ||
            cmd == SIOCETHTOOL ||
            cmd == SIOCGMIIPHY ||
            cmd == SIOCGMIIREG ||
            cmd == SIOCSMIIREG) {
            if (dev->do_ioctl) {
                if (!netif_device_present(dev))
                    return -ENODEV;
                return dev->do_ioctl(dev, ifr, cmd);
            }
            return -EOPNOTSUPP;
        }

#ifdef WIRELESS_EXT
        if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST) {
            if (dev->do_ioctl) {
                if (!netif_device_present(dev))
                    return -ENODEV;
                return dev->do_ioctl(dev, ifr, cmd);
            }
            return -EOPNOTSUPP;
        }
#endif	/* WIRELESS_EXT */

    }
    return -EINVAL;
}

/*
 * This function handles all "interface"-type I/O control requests. The actual
 * 'doing' part of this is dev_ifsioc above.
 */

/**
 *	dev_ioctl	-	network device ioctl
 *	@cmd: command to issue
 *	@arg: pointer to a struct ifreq in user space
 *
 *	Issue ioctl functions to devices. This is normally called by the
 *	user space syscall interfaces but can sometimes be useful for 
 *	other purposes. The return value is the return from the syscall if
 *	positive or a negative errno code on error.
 */

int dev_ioctl(unsigned int cmd, void *arg)
{
    struct ifreq ifr;
    int ret;
    char *colon;

    /* One special case: SIOCGIFCONF takes ifconf argument
       and requires shared lock, because it sleeps writing
       to user space.
    */
	   
    if (cmd == SIOCGIFCONF) {
        return -ENOSYS;
    }
    if (cmd == SIOCGIFNAME) {
        return dev_ifname((struct ifreq *)arg);
    }

    if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
        return -EFAULT;

    ifr.ifr_name[IFNAMSIZ-1] = 0;

    colon = strchr(ifr.ifr_name, ':');
    if (colon)
        *colon = 0;

    /*
     *	See which interface the caller is talking about. 
     */
	 
    switch(cmd) 
    {
        /*
         *	These ioctl calls:
         *	- can be done by all.
         *	- atomic and do not require locking.
         *	- return a value
         */
		 
    case SIOCGIFFLAGS:
    case SIOCGIFMETRIC:
    case SIOCGIFMTU:
    case SIOCGIFHWADDR:
    case SIOCGIFSLAVE:
    case SIOCGIFMAP:
    case SIOCGIFINDEX:
        dev_load(ifr.ifr_name);
        read_lock(&dev_base_lock);
        ret = dev_ifsioc(&ifr, cmd);
        read_unlock(&dev_base_lock);
        if (!ret) {
            if (colon)
                *colon = ':';
            if (copy_to_user(arg, &ifr, sizeof(struct ifreq)))
                return -EFAULT;
        }
        return ret;

        /*
         *	These ioctl calls:
         *	- require superuser power.
         *	- require strict serialization.
         *	- return a value
         */
		 
    case SIOCETHTOOL:
    case SIOCGMIIPHY:
    case SIOCGMIIREG:
        if (!capable(CAP_NET_ADMIN))
            return -EPERM;
        dev_load(ifr.ifr_name);
        dev_probe_lock();
        rtnl_lock();
        ret = dev_ifsioc(&ifr, cmd);
        rtnl_unlock();
        dev_probe_unlock();
        if (!ret) {
            if (colon)
                *colon = ':';
            if (copy_to_user(arg, &ifr, sizeof(struct ifreq)))
                return -EFAULT;
        }
        return ret;

        /*
         *	These ioctl calls:
         *	- require superuser power.
         *	- require strict serialization.
         *	- do not return a value
         */
		 
    case SIOCSIFFLAGS:
    case SIOCSIFMETRIC:
    case SIOCSIFMTU:
    case SIOCSIFMAP:
    case SIOCSIFHWADDR:
    case SIOCSIFSLAVE:
    case SIOCADDMULTI:
    case SIOCDELMULTI:
    case SIOCSIFHWBROADCAST:
    case SIOCSIFNAME:
    case SIOCSMIIREG:
    case SIOCBONDENSLAVE:
    case SIOCBONDRELEASE:
    case SIOCBONDSETHWADDR:
    case SIOCBONDSLAVEINFOQUERY:
    case SIOCBONDINFOQUERY:
    case SIOCBONDCHANGEACTIVE:
        if (!capable(CAP_NET_ADMIN))
            return -EPERM;
        dev_load(ifr.ifr_name);
        dev_probe_lock();
        rtnl_lock();
        ret = dev_ifsioc(&ifr, cmd);
        rtnl_unlock();
        dev_probe_unlock();
        return ret;
	
    case SIOCGIFMEM:
        /* Get the per device memory space. We can add this but currently
           do not support it */
    case SIOCSIFMEM:
        /* Set the per device memory buffer space. */
    case SIOCSIFLINK:
        return -EINVAL;

        /*
         *	Unknown or private ioctl.
         */	
		 
    default:
        if (cmd >= SIOCDEVPRIVATE &&
            cmd <= SIOCDEVPRIVATE + 15) {
            dev_load(ifr.ifr_name);
            dev_probe_lock();
            rtnl_lock();
            ret = dev_ifsioc(&ifr, cmd);
            rtnl_unlock();
            dev_probe_unlock();
            if (!ret && copy_to_user(arg, &ifr, sizeof(struct ifreq)))
                return -EFAULT;
            return ret;
        }
#ifdef WIRELESS_EXT
        /* Take care of Wireless Extensions */
        if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST) {
				/* If command is `set a parameter', or
				 * `get the encoding parameters', check if
				 * the user has the right to do it */
            if (IW_IS_SET(cmd) || (cmd == SIOCGIWENCODE)) {
                if(!capable(CAP_NET_ADMIN))
                    return -EPERM;
            }
            dev_load(ifr.ifr_name);
            rtnl_lock();
            ret = dev_ifsioc(&ifr, cmd);
            rtnl_unlock();
            if (!ret && IW_IS_GET(cmd) &&
                copy_to_user(arg, &ifr, 
                             sizeof(struct ifreq)))
                return -EFAULT;
            return ret;
        }
#endif	/* WIRELESS_EXT */
        return -EINVAL;
    }
}


/**
 *	dev_new_index	-	allocate an ifindex
 *
 *	Returns a suitable unique value for a new device interface
 *	number.  The caller must hold the rtnl semaphore or the
 *	dev_base_lock to be sure it remains unique.
 */
 
int dev_new_index(void)
{
    static int ifindex;
    for (;;) {
        if (++ifindex <= 0)
            ifindex=1;
        if (__dev_get_by_index(ifindex) == NULL)
            return ifindex;
    }
}

static int dev_boot_phase = 1;

/**
 *	register_netdevice	- register a network device
 *	@dev: device to register
 *	
 *	Take a completed network device structure and add it to the kernel
 *	interfaces. A %NETDEV_REGISTER message is sent to the netdev notifier
 *	chain. 0 is returned on success. A negative errno code is returned
 *	on a failure to set up the device, or if the name is a duplicate.
 *
 *	Callers must hold the rtnl semaphore.  See the comment at the
 *	end of Space.c for details about the locking.  You may want
 *	register_netdev() instead of this.
 *
 *	BUGS:
 *	The locking appears insufficient to guarantee two parallel registers
 *	will not get the same name.
 */

int net_dev_init(void);

int register_netdevice(struct net_device *dev)
{
    struct net_device *d, **dp;
#ifdef CONFIG_NET_DIVERT
    int ret;
#endif

    spin_lock_init(&dev->queue_lock);
    spin_lock_init(&dev->xmit_lock);
    dev->xmit_lock_owner = -1;
#ifdef CONFIG_NET_FASTROUTE
    dev->fastpath_lock=RW_LOCK_UNLOCKED;
#endif

    if (dev_boot_phase)
        net_dev_init();

#ifdef CONFIG_NET_DIVERT
    ret = alloc_divert_blk(dev);
    if (ret)
        return ret;
#endif /* CONFIG_NET_DIVERT */
	
    dev->iflink = -1;

    /* Init, if this function is available */
    if (dev->init && dev->init(dev) != 0) {
#ifdef CONFIG_NET_DIVERT
        free_divert_blk(dev);
#endif
        return -EIO;
    }

    dev->ifindex = dev_new_index();
    if (dev->iflink == -1)
        dev->iflink = dev->ifindex;

    /* Check for existence, and append to tail of chain */
    for (dp=&dev_base; (d=*dp) != NULL; dp=&d->next) {
        if (d == dev || strcmp(d->name, dev->name) == 0) {
#ifdef CONFIG_NET_DIVERT
            free_divert_blk(dev);
#endif
            return -EEXIST;
        }
    }
    /*
     *	nil rebuild_header routine,
     *	that should be never called and used as just bug trap.
     */

    if (dev->rebuild_header == NULL)
        dev->rebuild_header = default_rebuild_header;

    /*
     *	Default initial state at registry is that the
     *	device is present.
     */

    set_bit(__LINK_STATE_PRESENT, &dev->state);

    dev->next = NULL;
    dev_init_scheduler(dev);
    write_lock_bh(&dev_base_lock);
    *dp = dev;
    dev_hold(dev);
    dev->deadbeaf = 0;
    write_unlock_bh(&dev_base_lock);

    /* Notify protocols, that a new device appeared. */
    notifier_call_chain(&netdev_chain, NETDEV_REGISTER, dev);

    return 0;
}

/**
 *	netdev_finish_unregister - complete unregistration
 *	@dev: device
 *
 *	Destroy and free a dead device. A value of zero is returned on
 *	success.
 */
 
int netdev_finish_unregister(struct net_device *dev)
{
    BUG_TRAP(dev->ip_ptr==NULL);
    BUG_TRAP(dev->ip6_ptr==NULL);
    BUG_TRAP(dev->dn_ptr==NULL);

    if (!dev->deadbeaf) {
        printk(KERN_ERR "Freeing alive device %p, %s\n",
               dev, dev->name);
        return 0;
    }
#ifdef NET_REFCNT_DEBUG
    printk(KERN_DEBUG "netdev_finish_unregister: %s%s.\n", dev->name,
           (dev->features & NETIF_F_DYNALLOC)?"":", old style");
#endif
    if (dev->destructor)
        dev->destructor(dev);
    if (dev->features & NETIF_F_DYNALLOC)
        kfree(dev);
    return 0;
}

/**
 *	unregister_netdevice - remove device from the kernel
 *	@dev: device
 *
 *	This function shuts down a device interface and removes it
 *	from the kernel tables. On success 0 is returned, on a failure
 *	a negative errno code is returned.
 *
 *	Callers must hold the rtnl semaphore.  See the comment at the
 *	end of Space.c for details about the locking.  You may want
 *	unregister_netdev() instead of this.
 */

int unregister_netdevice(struct net_device *dev)
{
    unsigned long now, warning_time;
    struct net_device *d, **dp;

    /* If device is running, close it first. */
    if (dev->flags & IFF_UP)
        dev_close(dev);

    BUG_TRAP(dev->deadbeaf==0);
    dev->deadbeaf = 1;

    /* And unlink it from device chain. */
    for (dp = &dev_base; (d=*dp) != NULL; dp=&d->next) {
        if (d == dev) {
            write_lock_bh(&dev_base_lock);
            *dp = d->next;
            write_unlock_bh(&dev_base_lock);
            break;
        }
    }
    if (d == NULL) {
        printk(KERN_DEBUG "unregister_netdevice: device %s/%p"
               " not registered\n", dev->name, dev);
        return -ENODEV;
    }

    /* Synchronize to net_rx_action. */
    br_write_lock_bh(BR_NETPROTO_LOCK);
    br_write_unlock_bh(BR_NETPROTO_LOCK);

    if (dev_boot_phase == 0) {

        /* Shutdown queueing discipline. */
        dev_shutdown(dev);

        /* Notify protocols, that we are about to destroy
           this device. They should clean all the things.
        */
        notifier_call_chain(&netdev_chain, NETDEV_UNREGISTER, dev);

        /*
         *	Flush the multicast chain
         */
        dev_mc_discard(dev);
    }

    if (dev->uninit)
        dev->uninit(dev);

    /* Notifier chain MUST detach us from master device. */
    BUG_TRAP(dev->master==NULL);

#ifdef CONFIG_NET_DIVERT
    free_divert_blk(dev);
#endif

    if (dev->features & NETIF_F_DYNALLOC) {
#ifdef NET_REFCNT_DEBUG
        if (atomic_read(&dev->refcnt) != 1)
            printk(KERN_DEBUG "unregister_netdevice: holding %s refcnt=%d\n",
                   dev->name, atomic_read(&dev->refcnt)-1);
#endif
        dev_put(dev);
        return 0;
    }

    /* Last reference is our one */
    if (atomic_read(&dev->refcnt) == 1) {
        dev_put(dev);
        return 0;
    }

#ifdef NET_REFCNT_DEBUG
    printk("unregister_netdevice: waiting %s refcnt=%d\n",
           dev->name, atomic_read(&dev->refcnt));
#endif

    /* EXPLANATION. If dev->refcnt is not now 1 (our own reference)
       it means that someone in the kernel still has a reference
       to this device and we cannot release it.

       "New style" devices have destructors, hence we can return from this
       function and destructor will do all the work later.  As of kernel 2.4.0
       there are very few "New Style" devices.

       "Old style" devices expect that the device is free of any references
       upon exit from this function.
       We cannot return from this function until all such references have
       fallen away.  This is because the caller of this function will probably
       immediately kfree(*dev) and then be unloaded via sys_delete_module.

       So, we linger until all references fall away.  The duration of the
       linger is basically unbounded! It is driven by, for example, the
       current setting of sysctl_ipfrag_time.

       After 1 second, we start to rebroadcast unregister notifications
       in hope that careless clients will release the device.

    */

    now = warning_time = jiffies;
    while (atomic_read(&dev->refcnt) != 1) {
        if ((jiffies - now) > 1*HZ) {
            /* Rebroadcast unregister notification */
            notifier_call_chain(&netdev_chain, NETDEV_UNREGISTER, dev);
        }
        mdelay(250);
        if ((jiffies - warning_time) > 10*HZ) {
            printk(KERN_EMERG "unregister_netdevice: waiting for %s to "
                   "become free. Usage count = %d\n",
                   dev->name, atomic_read(&dev->refcnt));
            warning_time = jiffies;
        }
    }
    dev_put(dev);
    return 0;
}


/*
 *	Initialize the DEV module. At boot time this walks the device list and
 *	unhooks any devices that fail to initialise (normally hardware not 
 *	present) and leaves us with a valid list of present and active devices.
 *
 */

extern void net_device_init(void);
extern void ip_auto_config(void);
#ifdef CONFIG_NET_DIVERT
extern void dv_init(void);
#endif /* CONFIG_NET_DIVERT */


/*
 *       Callers must hold the rtnl semaphore.  See the comment at the
 *       end of Space.c for details about the locking.
 */
int __init net_dev_init(void)
{
    struct net_device *dev, **dp;

    if ( !dev_boot_phase )
        return 0;

    skb_init();

    net_header_cachep = kmem_cache_create(
        "net_header_cache", 
        (PKT_PROT_LEN + sizeof(void *) - 1) & ~(sizeof(void *) - 1),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);

    spin_lock_init(&net_schedule_list_lock);
    INIT_LIST_HEAD(&net_schedule_list);

    /*
     *	Add the devices.
     *	If the call to dev->init fails, the dev is removed
     *	from the chain disconnecting the device until the
     *	next reboot.
     *
     *	NB At boot phase networking is dead. No locking is required.
     *	But we still preserve dev_base_lock for sanity.
     */
    dp = &dev_base;
    while ((dev = *dp) != NULL) {
        spin_lock_init(&dev->queue_lock);
        spin_lock_init(&dev->xmit_lock);

        dev->xmit_lock_owner = -1;
        dev->iflink = -1;
        dev_hold(dev);

        /*
         * Allocate name. If the init() fails
         * the name will be reissued correctly.
         */
        if (strchr(dev->name, '%'))
            dev_alloc_name(dev, dev->name);

        if (dev->init && dev->init(dev)) {
            /*
             * It failed to come up. It will be unhooked later.
             * dev_alloc_name can now advance to next suitable
             * name that is checked next.
             */
            dev->deadbeaf = 1;
            dp = &dev->next;
        } else {
            dp = &dev->next;
            dev->ifindex = dev_new_index();
            if (dev->iflink == -1)
                dev->iflink = dev->ifindex;
            if (dev->rebuild_header == NULL)
                dev->rebuild_header = default_rebuild_header;
            dev_init_scheduler(dev);
            set_bit(__LINK_STATE_PRESENT, &dev->state);
        }
    }

    /*
     * Unhook devices that failed to come up
     */
    dp = &dev_base;
    while ((dev = *dp) != NULL) {
        if (dev->deadbeaf) {
            write_lock_bh(&dev_base_lock);
            *dp = dev->next;
            write_unlock_bh(&dev_base_lock);
            dev_put(dev);
        } else {
            dp = &dev->next;
        }
    }

    dev_boot_phase = 0;

    dev_mcast_init();

    /*
     *	Initialise network devices
     */
	 
    net_device_init();

    return 0;
}

inline int init_tx_header(net_vif_t *vif, u8 *data, 
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
        /* Unsupported protocols are onyl allowed to/from VIF0/0. */
        if ( (vif->domain->domain != 0) || (vif->idx != 0) )
            proto = 0;
        break;
    }
    return proto;
}

static void tx_credit_callback(unsigned long data)
{
    net_vif_t *vif = (net_vif_t *)data;

    vif->remaining_credit = vif->credit_bytes;

    if ( get_tx_bufs(vif) )
    {
        add_to_net_schedule_list_tail(vif);
        maybe_schedule_tx_action();
    }    
}

static int get_tx_bufs(net_vif_t *vif)
{
    struct task_struct *p = vif->domain;
    net_idx_t          *shared_idxs  = vif->shared_idxs;
    net_ring_t         *shared_rings = vif->shared_rings;
    net_vif_t          *target;
    unsigned long       buf_pfn;
    struct pfn_info    *buf_page;
    u8                 *g_data;
    unsigned short      protocol;
    struct sk_buff     *skb;
    tx_req_entry_t      tx;
    tx_shadow_entry_t  *stx;
    NET_RING_IDX        i, j;
    int                 ret = 0;

    if ( vif->tx_req_cons == shared_idxs->tx_req_prod )
        return 0;

    spin_lock(&vif->tx_lock);

    /* Currently waiting for more credit? */
    if ( vif->remaining_credit == 0 )
        goto out;

    j = vif->tx_prod;

    /*
     * Collect up new transmit buffers. We collect up to the guest OS's new 
     * producer index, but take care not to catch up with our own consumer 
     * index.
     */
 again:
    for ( i = vif->tx_req_cons; 
          (i != shared_idxs->tx_req_prod) && 
              ((i-vif->tx_resp_prod) != XENNET_TX_RING_SIZE);
          i++ )
    {
        tx     = shared_rings->tx_ring[MASK_NET_TX_IDX(i)].req;
        target = VIF_DROP;

        if ( unlikely(tx.size <= PKT_PROT_LEN) || 
             unlikely(tx.size > ETH_FRAME_LEN) )
        {
            DPRINTK("Bad packet size: %d\n", tx.size);
            make_tx_response(vif, tx.id, RING_STATUS_BAD_PAGE);
            continue; 
        }

        /* Credit-based scheduling. */
        if ( tx.size > vif->remaining_credit )
        {
            s_time_t now = NOW(), next_credit = 
                vif->credit_timeout.expires + MICROSECS(vif->credit_usec);
            if ( next_credit <= now )
            {
                vif->credit_timeout.expires = now;
                vif->remaining_credit = vif->credit_bytes;
            }
            else
            {
                vif->remaining_credit = 0;
                vif->credit_timeout.expires  = next_credit;
                vif->credit_timeout.data     = (unsigned long)vif;
                vif->credit_timeout.function = tx_credit_callback;
                vif->credit_timeout.cpu      = smp_processor_id();
                add_ac_timer(&vif->credit_timeout);
                break;
            }
        }
        vif->remaining_credit -= tx.size;

        /* No crossing a page boundary as the payload mustn't fragment. */
        if ( unlikely(((tx.addr & ~PAGE_MASK) + tx.size) >= PAGE_SIZE) ) 
        {
            DPRINTK("tx.addr: %lx, size: %u, end: %lu\n", 
                    tx.addr, tx.size, (tx.addr &~PAGE_MASK) + tx.size);
            make_tx_response(vif, tx.id, RING_STATUS_BAD_PAGE);
            continue;
        }

        buf_pfn  = tx.addr >> PAGE_SHIFT;
        buf_page = frame_table + buf_pfn;
        if ( unlikely(buf_pfn >= max_page) || 
             unlikely(!get_page(buf_page, p)) )
        {
            DPRINTK("Bad page frame\n");
            make_tx_response(vif, tx.id, RING_STATUS_BAD_PAGE);
            continue;
        }
            
        g_data = map_domain_mem(tx.addr);

        protocol = __constant_htons(
            init_tx_header(vif, g_data, tx.size, the_dev));
        if ( protocol == 0 )
        {
            make_tx_response(vif, tx.id, RING_STATUS_BAD_PAGE);
            goto cleanup_and_continue;
        }

        target = net_get_target_vif(g_data, tx.size, vif);

        if ( VIF_LOCAL(target) )
        {
            /* Local delivery */
            if ( unlikely((skb = dev_alloc_skb(ETH_FRAME_LEN + 32)) == NULL) )
            {
                make_tx_response(vif, tx.id, RING_STATUS_BAD_PAGE);
                put_vif(target);
                goto cleanup_and_continue;
            }

            skb->src_vif = vif;
            skb->dst_vif = target;
            skb->protocol = protocol;                

            /*
             * We don't need a well-formed skb as netif_rx will fill these
             * fields in as necessary. All we actually need is the right
             * page offset in skb->data, and the right length in skb->len.
             * Note that the correct address/length *excludes* link header.
             */
            skb->head = (u8 *)map_domain_mem(
                ((skb->pf - frame_table) << PAGE_SHIFT));
            skb->data = skb->head + 18;
            memcpy(skb->data, g_data, tx.size);
            skb->data += ETH_HLEN;
            skb->len = tx.size - ETH_HLEN;
            unmap_domain_mem(skb->head);

            if ( netif_rx(skb) == NET_RX_DROP )
                kfree_skb(skb);

            make_tx_response(vif, tx.id, RING_STATUS_OK);
        }
        else if ( (target == VIF_PHYS) || IS_PRIV(p) )
        {
            /*
             * XXX HACK XXX: Our wildcard rule for domain-0 incorrectly puts 
             * some 169.254.* (ie. link-local) packets on the wire unless we 
             * include this explicit test. :-(
             */
            switch ( ntohs(*(unsigned short *)(g_data + 12)) )
            {
            case ETH_P_ARP:
                if ( ((ntohl(*(unsigned long *)(g_data + 28)) & 0xFFFF0000) == 
                      0xA9FE0000) )
                    goto disallow_linklocal_packets;
                break;
            case ETH_P_IP:
                if ( ((ntohl(*(unsigned long *)(g_data + 26)) & 0xFFFF0000) == 
                      0xA9FE0000) )
                    goto disallow_linklocal_packets;
                break;
            }

            stx = &vif->tx_shadow_ring[MASK_NET_TX_IDX(j)];
            stx->id     = tx.id;
            stx->size   = tx.size;
            stx->header = kmem_cache_alloc(net_header_cachep, GFP_KERNEL);
            if ( unlikely(stx->header == NULL) )
            { 
                make_tx_response(vif, tx.id, RING_STATUS_OK);
                goto cleanup_and_continue;
            }

            memcpy(stx->header, g_data, PKT_PROT_LEN);
            stx->payload = tx.addr + PKT_PROT_LEN;

            j++;
            buf_page = NULL; /* hand off our page reference */
        }
        else
        {
        disallow_linklocal_packets:
            make_tx_response(vif, tx.id, RING_STATUS_DROPPED);
        }

    cleanup_and_continue:
        if ( buf_page != NULL )
            put_page(buf_page);
        unmap_domain_mem(g_data);
    }

    /*
     * Needed as a final check for req_prod updates on another CPU.
     * Also ensures that other CPUs see shadow ring updates.
     */
    smp_mb();

    if ( ((vif->tx_req_cons = i) != shared_idxs->tx_req_prod) &&
         (vif->remaining_credit != 0) )
        goto again;

    if ( (ret = (vif->tx_prod != j)) )
        vif->tx_prod = j;

 out:
    spin_unlock(&vif->tx_lock);

    return ret;
}


static void get_rx_bufs(net_vif_t *vif)
{
    struct task_struct *p = vif->domain;
    net_ring_t *shared_rings = vif->shared_rings;
    net_idx_t *shared_idxs = vif->shared_idxs;
    NET_RING_IDX i, j;
    rx_req_entry_t rx;
    rx_shadow_entry_t *srx;
    unsigned long  pte_pfn, buf_pfn;
    struct pfn_info *pte_page, *buf_page;
    unsigned long *ptep, pte, spfn;

    spin_lock(&vif->rx_lock);

    /*
     * Collect up new receive buffers. We collect up to the guest OS's new
     * producer index, but take care not to catch up with our own consumer
     * index.
     */
    j = vif->rx_prod;
    for ( i = vif->rx_req_cons; 
          (i != shared_idxs->rx_req_prod) && 
              ((i-vif->rx_resp_prod) != XENNET_RX_RING_SIZE);
          i++ )
    {
        rx = shared_rings->rx_ring[MASK_NET_RX_IDX(i)].req;

        pte_pfn  = rx.addr >> PAGE_SHIFT;
        pte_page = &frame_table[pte_pfn];

        /* The address passed down must be to a valid PTE. */
        if ( unlikely(pte_pfn >= max_page) ||
             unlikely(!get_page_and_type(pte_page, p, PGT_l1_page_table)) )
        {
            DPRINTK("Bad page frame for ppte %u,%08lx,%08lx,%08x\n",
                    p->domain, pte_pfn, max_page, pte_page->type_and_flags);
            make_rx_response(vif, rx.id, 0, RING_STATUS_BAD_PAGE, 0);
            continue;
        }
        
        ptep = map_domain_mem(rx.addr);
        pte  = *ptep;

        /* We must be passed a valid writeable mapping to swizzle. */
        if ( unlikely((pte & (_PAGE_PRESENT|_PAGE_RW)) != 
                      (_PAGE_PRESENT|_PAGE_RW)) ||
             unlikely(cmpxchg(ptep, pte, pte & ~_PAGE_PRESENT) != pte) )
        {
            DPRINTK("Invalid PTE passed down (not present or changing)\n");
            put_page_and_type(pte_page);
            make_rx_response(vif, rx.id, 0, RING_STATUS_BAD_PAGE, 0);
            goto rx_unmap_and_continue;
        }

	if ( p->mm.shadow_mode && 
	     (spfn=get_shadow_status(&p->mm, rx.addr>>PAGE_SHIFT)) )
	  {
	    unsigned long * sptr = 
	      map_domain_mem( (spfn<<PAGE_SHIFT) | (rx.addr&~PAGE_MASK) );

	    *sptr = 0;
	    unmap_domain_mem( sptr );
	    put_shadow_status(&p->mm);
	  }
        
        buf_pfn  = pte >> PAGE_SHIFT;
        buf_page = &frame_table[buf_pfn];

        /*
         * The page must belong to the correct domain, and must be mapped
         * just once as a writeable page.
         */
        if ( unlikely(buf_page->u.domain != p) ||
             unlikely(cmpxchg(&buf_page->type_and_flags, 
                              PGT_writeable_page|PGT_validated|1,
                              0) != (PGT_writeable_page|PGT_validated|1)) )
        {
            DPRINTK("Bad domain or page mapped writeable more than once.\n");
            if ( cmpxchg(ptep, pte & ~_PAGE_PRESENT, pte) != 
                 (pte & ~_PAGE_PRESENT) )
                put_page_and_type(buf_page);
            put_page_and_type(pte_page);
            make_rx_response(vif, rx.id, 0, RING_STATUS_BAD_PAGE, 0);
            goto rx_unmap_and_continue;
        }

        /*
         * Now ensure that we can take the last references to this page.
         * The final count should be 2, because of PGC_allocated.
         */
        if ( unlikely(cmpxchg(&buf_page->count_and_flags, 
                              PGC_allocated | PGC_tlb_flush_on_type_change | 2,
                              0) != 
                      (PGC_allocated | PGC_tlb_flush_on_type_change | 2)) )
        {
            DPRINTK("Page held more than once mfn=%x %08x %s\n", 
		    buf_page-frame_table,
                    buf_page->count_and_flags,
		    (buf_page->u.domain)?buf_page->u.domain->name:"None");

            if ( !get_page_type(buf_page, PGT_writeable_page) )
                put_page(buf_page);
            else if ( cmpxchg(ptep, pte & ~_PAGE_PRESENT, pte) !=
                      (pte & ~_PAGE_PRESENT) )
                put_page_and_type(buf_page);
            put_page_and_type(pte_page);
            /* NB. If we fail to remap the page, we should probably flag it. */
            make_rx_response(vif, rx.id, 0, RING_STATUS_BAD_PAGE, 0);
            goto rx_unmap_and_continue;
        }
            
        buf_page->tlbflush_timestamp = tlbflush_clock;
        buf_page->u.cpu_mask = 1 << p->processor;

        /* Remove from the domain's allocation list. */
        spin_lock(&p->page_list_lock);
        list_del(&buf_page->list);
        spin_unlock(&p->page_list_lock);

        srx = &vif->rx_shadow_ring[MASK_NET_RX_IDX(j++)];
        srx->id      = rx.id;
        srx->pte_ptr = rx.addr;
        srx->buf_pfn = buf_pfn;
            
    rx_unmap_and_continue:
        unmap_domain_mem(ptep);
    }

    vif->rx_req_cons = i;

    if ( vif->rx_prod != j )
    {
        smp_mb(); /* Let other CPUs see new descriptors first. */
        vif->rx_prod = j;
    }

    spin_unlock(&vif->rx_lock);
}


static long get_bufs_from_vif(net_vif_t *vif)
{
    if ( get_tx_bufs(vif) )
    {
        add_to_net_schedule_list_tail(vif);
        maybe_schedule_tx_action();
    }

    get_rx_bufs(vif);

    return 0;
}


long flush_bufs_for_vif(net_vif_t *vif)
{
    NET_RING_IDX i;
    unsigned long *ptep, pte;
    struct pfn_info *page;
    struct task_struct *p = vif->domain;
    rx_shadow_entry_t *rx;
    net_ring_t *shared_rings = vif->shared_rings;
    net_idx_t *shared_idxs = vif->shared_idxs;

    /* Return any outstanding receive buffers to the guest OS. */
    spin_lock(&vif->rx_lock);
    for ( i = vif->rx_req_cons; 
          (i != shared_idxs->rx_req_prod) &&
              ((i-vif->rx_resp_prod) != XENNET_RX_RING_SIZE);
          i++ )
    {
        make_rx_response(vif, shared_rings->rx_ring[MASK_NET_RX_IDX(i)].req.id,
                         0, RING_STATUS_DROPPED, 0);
    }
    vif->rx_req_cons = i;
    for ( i = vif->rx_cons; i != vif->rx_prod; i++ )
    {
        rx = &vif->rx_shadow_ring[MASK_NET_RX_IDX(i)];

        /* Give the buffer page back to the domain. */
        page = &frame_table[rx->buf_pfn];
        page->u.domain = p;
        spin_lock(&p->page_list_lock);
        list_add(&page->list, &p->page_list);
        page->count_and_flags = PGC_allocated | 2;
        spin_unlock(&p->page_list_lock);
        get_page_type(page, PGT_writeable_page);
        set_bit(_PGC_tlb_flush_on_type_change, &page->count_and_flags);
        wmb();

        /* Patch up the PTE if it hasn't changed under our feet. */
        ptep = map_domain_mem(rx->pte_ptr);
        pte  = *ptep;
        if ( unlikely(pte & _PAGE_PRESENT) ||
             unlikely(cmpxchg(ptep, pte, (rx->buf_pfn<<PAGE_SHIFT) | 
                              (pte & ~PAGE_MASK) | _PAGE_RW | _PAGE_PRESENT)
                      != pte) )
        {
            DPRINTK("PTE was modified or reused! %08lx %08lx\n", pte, *ptep);
            put_page_and_type(page);
        }
        unmap_domain_mem(ptep);

        put_page_and_type(&frame_table[rx->pte_ptr >> PAGE_SHIFT]);

	/*
         * If in shadow mode, mark the PTE as dirty.
         * (We assume the shadow page table is about to be blown away,
         * and so it's not worth marking the buffer as dirty.)
         */
	if ( p->mm.shadow_mode == SHM_logdirty )
	    mark_dirty(&p->mm, rx->pte_ptr>>PAGE_SHIFT);

        make_rx_response(vif, rx->id, 0, RING_STATUS_DROPPED, 0);
    }
    vif->rx_cons = i;
    spin_unlock(&vif->rx_lock);

    /*
     * Flush pending transmit buffers. The guest may still have to wait for
     * buffers that are queued at a physical NIC.
     */
    spin_lock(&vif->tx_lock);
    for ( i = vif->tx_req_cons; 
          (i != shared_idxs->tx_req_prod) &&
              ((i-vif->tx_resp_prod) != XENNET_TX_RING_SIZE);
          i++ )
    {
        make_tx_response(vif, shared_rings->tx_ring[MASK_NET_TX_IDX(i)].req.id,
                         RING_STATUS_DROPPED);
    }
    vif->tx_req_cons = i;
    spin_unlock(&vif->tx_lock);

    return 0;
}


/*
 * do_net_io_op:
 * 
 * Called from guest OS to notify updates to its transmit and/or receive
 * descriptor rings.
 */
long do_net_io_op(netop_t *uop)
{
    netop_t op;
    net_vif_t *vif;
    long ret;

    perfc_incr(net_hypercalls);

    if ( unlikely(copy_from_user(&op, uop, sizeof(op)) != 0) )
        return -EFAULT;

    if ( unlikely(op.vif >= MAX_DOMAIN_VIFS) || 
         unlikely((vif = current->net_vif_list[op.vif]) == NULL) )
        return -EINVAL;

    switch ( op.cmd )
    {
    case NETOP_PUSH_BUFFERS:
        ret = get_bufs_from_vif(vif);
        break;

    case NETOP_FLUSH_BUFFERS:
        ret = flush_bufs_for_vif(vif);
        break;

    case NETOP_RESET_RINGS:
        /* We take the tx_lock to avoid a race with get_tx_bufs. */
        spin_lock(&vif->tx_lock);
        if ( (vif->rx_req_cons != vif->rx_resp_prod) || 
             (vif->tx_req_cons != vif->tx_resp_prod) )
        {
            /* The interface isn't quiescent. */
            ret = -EINVAL; 
        }
        else
        {
            vif->rx_req_cons = vif->rx_resp_prod = 0;
            vif->tx_req_cons = vif->tx_resp_prod = 0;
            ret = 0;
        }
        spin_unlock(&vif->tx_lock);
        break;

    case NETOP_GET_VIF_INFO:
        op.u.get_vif_info.ring_mfn = 
            virt_to_phys(vif->shared_rings) >> PAGE_SHIFT;
        memcpy(op.u.get_vif_info.vmac, vif->vmac, ETH_ALEN);
        ret = copy_to_user(uop, &op, sizeof(op)) ? -EFAULT: 0;
        break;

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}


static void make_tx_response(net_vif_t     *vif, 
                             unsigned short id, 
                             unsigned char  st)
{
    NET_RING_IDX i = vif->tx_resp_prod;
    tx_resp_entry_t *resp;

    resp = &vif->shared_rings->tx_ring[MASK_NET_TX_IDX(i)].resp;
    resp->id     = id;
    resp->status = st;
    wmb();
    vif->shared_idxs->tx_resp_prod = vif->tx_resp_prod = ++i;

    smp_mb(); /* Update producer before checking event threshold. */
    if ( i == vif->shared_idxs->tx_event )
        send_guest_virq(vif->domain, VIRQ_NET);
}


static void make_rx_response(net_vif_t     *vif, 
                             unsigned short id, 
                             unsigned short size,
                             unsigned char  st,
                             unsigned char  off)
{
    NET_RING_IDX i = vif->rx_resp_prod;
    rx_resp_entry_t *resp;

    resp = &vif->shared_rings->rx_ring[MASK_NET_RX_IDX(i)].resp;
    resp->id     = id;
    resp->size   = size;
    resp->status = st;
    resp->offset = off;
    wmb();
    vif->shared_idxs->rx_resp_prod = vif->rx_resp_prod = ++i;

    smp_mb(); /* Update producer before checking event threshold. */
    if ( i == vif->shared_idxs->rx_event )
        send_guest_virq(vif->domain, VIRQ_NET);
}


int setup_network_devices(void)
{
    int i, ret;
    extern char opt_ifname[];

    memset(skb_queue, 0, sizeof(skb_queue));
    for ( i = 0; i < smp_num_cpus; i++ )
        skb_queue_head_init(&skb_queue[i].rx);

    /* Actual receive processing happens in softirq context. */
    open_softirq(NET_RX_SOFTIRQ, net_rx_action, NULL);

    /* Processing of defunct transmit buffers happens in softirq context. */
    open_softirq(NET_TX_SOFTIRQ, net_tx_gc, NULL);

    /* Tranmit scheduling happens in a tasklet to exclude other processors. */
    tasklet_enable(&net_tx_tasklet);

    if ( (the_dev = dev_get_by_name(opt_ifname)) == NULL ) 
    {
        printk("Could not find device %s: using dummy device\n", opt_ifname);
        strcpy(opt_ifname, "dummy");
        if ( (the_dev = dev_get_by_name(opt_ifname)) == NULL )
        {
            printk("Failed to find the dummy device!\n");
            return 0;
        }
    }

    if ( (ret = dev_open(the_dev)) != 0 )
    {
        printk("Error opening device %s for use (%d)\n", opt_ifname, ret);
        the_dev = NULL;
        return 0;
    }

    printk("Device %s opened and ready for use.\n", opt_ifname);

    return 1;
}

