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
#include <linux/config.h>
#include <linux/delay.h>
#include <linux/lib.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/brlock.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pkt_sched.h>

#include <linux/event.h>
#include <asm/domain_page.h>
#include <asm/pgalloc.h>

#define BUG_TRAP ASSERT
#define notifier_call_chain(_a,_b,_c) ((void)0)
#define rtmsg_ifinfo(_a,_b,_c) ((void)0)
#define rtnl_lock() ((void)0)
#define rtnl_unlock() ((void)0)
#define dst_init() ((void)0)

// Ring defines:
#define TX_RING_INC(_i)    (((_i)+1) & (TX_RING_SIZE-1))
#define RX_RING_INC(_i)    (((_i)+1) & (RX_RING_SIZE-1))
#define TX_RING_ADD(_i,_j) (((_i)+(_j)) & (TX_RING_SIZE-1))
#define RX_RING_ADD(_i,_j) (((_i)+(_j)) & (RX_RING_SIZE-1))

struct net_device *the_dev = NULL;

/*
 *	Device drivers call our routines to queue packets here. We empty the
 *	queue in the local softnet handler.
 */
struct softnet_data softnet_data[NR_CPUS] __cacheline_aligned;


/*********************************************************************************

			    Device Interface Subroutines

**********************************************************************************/

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

/* 
   Return value is changed to int to prevent illegal usage in future.
   It is still legal to use to check for device existance.

   User should understand, that the result returned by this function
   is meaningless, if it was not issued under rtnl semaphore.
 */

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
	printk(KERN_DEBUG "%s: default_rebuild_header called -- BUG!\n", skb->dev ? skb->dev->name : "NULL!!!");
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

/**
 *	dev_queue_xmit - transmit a buffer
 *	@skb: buffer to transmit
 *	
 *	Queue a buffer for transmission to a network device. The caller must
 *	have set the device and priority and built the buffer before calling this 
 *	function. The function can be called from an interrupt.
 *
 *	A negative errno code is returned on a failure. A success does not
 *	guarantee the frame will be transmitted as it may be dropped due
 *	to congestion or traffic shaping.
 */

int dev_queue_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct Qdisc  *q;
if (!(dev->features&NETIF_F_SG)) printk("NIC doesn't do SG!!!\n");
	if (skb_shinfo(skb)->frag_list &&
	    !(dev->features&NETIF_F_FRAGLIST) &&
	    skb_linearize(skb, GFP_ATOMIC) != 0) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	/* Fragmented skb is linearized if device does not support SG,
	 * or if at least one of fragments is in highmem and device
	 * does not support DMA from it.
	 */
	if (skb_shinfo(skb)->nr_frags &&
	    (!(dev->features&NETIF_F_SG) || illegal_highdma(dev, skb)) &&
	    skb_linearize(skb, GFP_ATOMIC) != 0) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	/* Grab device queue */
	spin_lock_bh(&dev->queue_lock);
	q = dev->qdisc;
	if (q->enqueue) {
		int ret = q->enqueue(skb, q);

		qdisc_run(dev);

		spin_unlock_bh(&dev->queue_lock);
		return ret == NET_XMIT_BYPASS ? NET_XMIT_SUCCESS : ret;
	}

	/* The device has no queue. Common case for software devices:
	   loopback, all the sorts of tunnels...

	   Really, it is unlikely that xmit_lock protection is necessary here.
	   (f.e. loopback and IP tunnels are clean ignoring statistics counters.)
	   However, it is possible, that they rely on protection
	   made by us here.

	   Check this and shot the lock. It is not prone from deadlocks.
	   Either shot noqueue qdisc, it is even simpler 8)
	 */
	if (dev->flags&IFF_UP) {
		int cpu = smp_processor_id();

		if (dev->xmit_lock_owner != cpu) {
			spin_unlock(&dev->queue_lock);
			spin_lock(&dev->xmit_lock);
			dev->xmit_lock_owner = cpu;

			if (!netif_queue_stopped(dev)) {
				if (dev->hard_start_xmit(skb, dev) == 0) {
					dev->xmit_lock_owner = -1;
					spin_unlock_bh(&dev->xmit_lock);
					return 0;
				}
			}
			dev->xmit_lock_owner = -1;
			spin_unlock_bh(&dev->xmit_lock);
			kfree_skb(skb);
			return -ENETDOWN;
		} else {
			/* Recursion is detected! It is possible, unfortunately */
		}
	}
	spin_unlock_bh(&dev->queue_lock);

	kfree_skb(skb);
	return -ENETDOWN;
}


/*=======================================================================
			Receiver routines
  =======================================================================*/

int netdev_max_backlog = 300;
/* These numbers are selected based on intuition and some
 * experimentatiom, if you have more scientific way of doing this
 * please go ahead and fix things.
 */
int no_cong_thresh = 10;
int no_cong = 20;
int lo_cong = 100;
int mod_cong = 290;

struct netif_rx_stats netdev_rx_stat[NR_CPUS];


#ifdef CONFIG_NET_HW_FLOWCONTROL
atomic_t netdev_dropping = ATOMIC_INIT(0);
static unsigned long netdev_fc_mask = 1;
unsigned long netdev_fc_xoff = 0;
spinlock_t netdev_fc_lock = SPIN_LOCK_UNLOCKED;

static struct
{
	void (*stimul)(struct net_device *);
	struct net_device *dev;
} netdev_fc_slots[BITS_PER_LONG];

int netdev_register_fc(struct net_device *dev, void (*stimul)(struct net_device *dev))
{
	int bit = 0;
	unsigned long flags;

	spin_lock_irqsave(&netdev_fc_lock, flags);
	if (netdev_fc_mask != ~0UL) {
		bit = ffz(netdev_fc_mask);
		netdev_fc_slots[bit].stimul = stimul;
		netdev_fc_slots[bit].dev = dev;
		set_bit(bit, &netdev_fc_mask);
		clear_bit(bit, &netdev_fc_xoff);
	}
	spin_unlock_irqrestore(&netdev_fc_lock, flags);
	return bit;
}

void netdev_unregister_fc(int bit)
{
	unsigned long flags;

	spin_lock_irqsave(&netdev_fc_lock, flags);
	if (bit > 0) {
		netdev_fc_slots[bit].stimul = NULL;
		netdev_fc_slots[bit].dev = NULL;
		clear_bit(bit, &netdev_fc_mask);
		clear_bit(bit, &netdev_fc_xoff);
	}
	spin_unlock_irqrestore(&netdev_fc_lock, flags);
}

static void netdev_wakeup(void)
{
	unsigned long xoff;

	spin_lock(&netdev_fc_lock);
	xoff = netdev_fc_xoff;
	netdev_fc_xoff = 0;
	while (xoff) {
		int i = ffz(~xoff);
		xoff &= ~(1<<i);
		netdev_fc_slots[i].stimul(netdev_fc_slots[i].dev);
	}
	spin_unlock(&netdev_fc_lock);
}
#endif

static void get_sample_stats(int cpu)
{
	int blog = softnet_data[cpu].input_pkt_queue.qlen;
	int avg_blog = softnet_data[cpu].avg_blog;

	avg_blog = (avg_blog >> 1)+ (blog >> 1);

	if (avg_blog > mod_cong) {
		/* Above moderate congestion levels. */
		softnet_data[cpu].cng_level = NET_RX_CN_HIGH;
	} else if (avg_blog > lo_cong) {
		softnet_data[cpu].cng_level = NET_RX_CN_MOD;
	} else if (avg_blog > no_cong) 
		softnet_data[cpu].cng_level = NET_RX_CN_LOW;
	else  /* no congestion */
		softnet_data[cpu].cng_level = NET_RX_SUCCESS;

	softnet_data[cpu].avg_blog = avg_blog;
}

void deliver_packet(struct sk_buff *skb, net_vif_t *vif)
{
        net_shadow_ring_t *shadow_ring;
        rx_shadow_entry_t *rx;
        unsigned long *g_pte; //tmp
        struct pfn_info *g_pfn, *h_pfn;
        unsigned int i; //, nvif;

        
        
        /*
         * Write the virtual MAC address into the destination field
         * of the ethernet packet. Furthermore, do the same for ARP
         * reply packets. This is easy because the virtual MAC address
         * is always 00-[nn]-00-00-00-00, where the second sixteen bits 
         * of the MAC are the vif's id.  This is to differentiate between
         * vifs on guests that have more than one.
         *
         * In zero copy, the data pointers for the packet have to have been 
         * mapped in by the caller.
         */

        memset(skb->mac.ethernet->h_dest, 0, ETH_ALEN);
//        *(unsigned int *)(skb->mac.ethernet->h_dest + 1) = nvif;
        if ( ntohs(skb->mac.ethernet->h_proto) == ETH_P_ARP )
        {
            memset(skb->nh.raw + 18, 0, ETH_ALEN);
//            *(unsigned int *)(skb->nh.raw + 18 + 1) = nvif;
        }
        shadow_ring = vif->shadow_ring;

        //Advance to next good buffer.
        for (i = shadow_ring->rx_cons; 
             (i != shadow_ring->rx_prod) 
             && ( shadow_ring->rx_ring[i].status != RING_STATUS_OK );
             i = RX_RING_INC(i));
            
        if (( i != shadow_ring->rx_prod ) &&
            ( shadow_ring->rx_ring[i].status == RING_STATUS_OK ))
        {
            rx = shadow_ring->rx_ring+i;
            if ( (skb->len + ETH_HLEN) < rx->size )
                rx->size = skb->len + ETH_HLEN;
            
            g_pte = map_domain_mem(rx->addr);

            g_pfn =  frame_table + (*g_pte >> PAGE_SHIFT);
            h_pfn = skb->pf;

            h_pfn->tot_count = h_pfn->type_count = 1;
            g_pfn->tot_count = g_pfn->type_count = 0;
            h_pfn->flags = g_pfn->flags & (~PG_type_mask);

            if (*g_pte & _PAGE_RW) h_pfn->flags |= PGT_writeable_page;
            g_pfn->flags = 0;
            
            //point guest pte at the new page:
            machine_to_phys_mapping[h_pfn - frame_table] 
                    = machine_to_phys_mapping[g_pfn - frame_table];

            *g_pte = (*g_pte & ~PAGE_MASK) 
                | (((h_pfn - frame_table) << PAGE_SHIFT) & PAGE_MASK);
            *g_pte |= _PAGE_PRESENT;
                
            unmap_domain_mem(g_pte);
            skb->pf = g_pfn; // return the guest pfn to be put on the free list
                
            shadow_ring->rx_cons = RX_RING_INC(i);
        }
}

/* Deliver skb to an old protocol, which is not threaded well
   or which do not understand shared skbs.
 */
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
 *	NET_RX_CN_LOW     (low congestion) 
 *	NET_RX_CN_MOD     (moderate congestion)
 *	NET_RX_CN_HIGH    (high congestion) 
 *	NET_RX_DROP    (packet was dropped)
 *      
 *      
 */

int netif_rx(struct sk_buff *skb)
{
#ifdef CONFIG_SMP
        unsigned long cpu_mask;
#endif
        
        struct task_struct *p;
	int this_cpu = smp_processor_id();
	struct softnet_data *queue;
	unsigned long flags;
        net_vif_t *vif;

	local_irq_save(flags);

        if (skb->skb_type != SKB_ZERO_COPY) 
            BUG();
                
	if (skb->stamp.tv_sec == 0)
	    get_fast_time(&skb->stamp);

        if ( (skb->data - skb->head) != (18 + ETH_HLEN) )
            printk("headroom was %lu!\n", (unsigned long)skb->data - (unsigned long)skb->head);
        //    BUG();
        
        skb->head = (u8 *)map_domain_mem(((skb->pf - frame_table) << PAGE_SHIFT));

        /* remapping this address really screws up all the skb pointers.  We need 
        * to map them all here sufficiently to get the packet demultiplexed.
        */
                
        skb->data = skb->head;
        skb_reserve(skb,18); // 18 is the 16 from dev_alloc_skb plus 2 for #
                             // IP header alignment. 
        skb->mac.raw = skb->data;
        skb->data += ETH_HLEN;
        skb->nh.raw = skb->data;
        
	/* The code is rearranged so that the path is the most
	   short when CPU is congested, but is still operating.
	 */
	queue = &softnet_data[this_cpu];
        
	netdev_rx_stat[this_cpu].total++;

        if ( skb->src_vif == VIF_UNKNOWN_INTERFACE )
            skb->src_vif = VIF_PHYSICAL_INTERFACE;
                
        if ( skb->dst_vif == VIF_UNKNOWN_INTERFACE )
            skb->dst_vif = __net_get_target_vif(skb->mac.raw, skb->len, skb->src_vif);
//if (skb->dst_vif == VIF_DROP)
//printk("netif_rx target: %d (sec: %u)\n", skb->dst_vif, skb->security);
        
        if ( (vif = sys_vif_list[skb->dst_vif]) == NULL )
        {
//printk("No such vif! (%d).\n", skb->dst_vif);
            // the target vif does not exist.
            goto drop;
        }

        /* This lock-and-walk of the task list isn't really necessary, and is an
         * artifact of the old code.  The vif contains a pointer to the skb list 
         * we are going to queue the packet in, so the lock and the inner loop
         * could be removed.
         *
         * The argument against this is a possible race in which a domain is killed
         * as packets are being delivered to it.  This would result in the dest vif
         * vanishing before we can deliver to it.
         */
        
        if ( skb->dst_vif >= VIF_PHYSICAL_INTERFACE )
        {
            read_lock(&tasklist_lock);
            p = &idle0_task;
            do {
                if ( p->domain != vif->domain ) continue;
                if ( vif->skb_list.qlen > 100 ) break;
                deliver_packet(skb, vif);
                cpu_mask = mark_hyp_event(p, _HYP_EVENT_NET_RX);
                read_unlock(&tasklist_lock);
                goto found;
            }
            while ( (p = p->next_task) != &idle0_task );
            read_unlock(&tasklist_lock); 
            goto drop;
        }

drop:
	netdev_rx_stat[this_cpu].dropped++;
        unmap_domain_mem(skb->head);
	kfree_skb(skb);
        local_irq_restore(flags);
	return NET_RX_DROP;

found:
        unmap_domain_mem(skb->head);
        skb->head = skb->data = skb->tail = (void *)0xdeadbeef;
        kfree_skb(skb);
        hyp_event_notify(cpu_mask);
        local_irq_restore(flags);
        return 0;
}


static int deliver_to_old_ones(struct packet_type *pt, struct sk_buff *skb, int last)
{
	static spinlock_t net_bh_lock = SPIN_LOCK_UNLOCKED;
	int ret = NET_RX_DROP;


	if (!last) {
		skb = skb_clone(skb, GFP_ATOMIC);
		if (skb == NULL)
			return ret;
	}
	if (skb_is_nonlinear(skb) && skb_linearize(skb, GFP_ATOMIC) != 0) {
		kfree_skb(skb);
		return ret;
	}

	/* The assumption (correct one) is that old protocols
	   did not depened on BHs different of NET_BH and TIMER_BH.
	 */

	/* Emulate NET_BH with special spinlock */
	spin_lock(&net_bh_lock);

	/* Disable timers and wait for all timers completion */
	tasklet_disable(bh_task_vec+TIMER_BH);

	ret = pt->func(skb, skb->dev, pt);

	tasklet_hi_enable(bh_task_vec+TIMER_BH);
	spin_unlock(&net_bh_lock);
	return ret;
}

static void net_tx_action(struct softirq_action *h)
{
	int cpu = smp_processor_id();

	if (softnet_data[cpu].completion_queue) {
		struct sk_buff *clist;

		local_irq_disable();
		clist = softnet_data[cpu].completion_queue;
		softnet_data[cpu].completion_queue = NULL;
		local_irq_enable();

		while (clist != NULL) {
			struct sk_buff *skb = clist;
			clist = clist->next;

			BUG_TRAP(atomic_read(&skb->users) == 0);
			__kfree_skb(skb);
		}
	}

	if (softnet_data[cpu].output_queue) {
		struct net_device *head;

		local_irq_disable();
		head = softnet_data[cpu].output_queue;
		softnet_data[cpu].output_queue = NULL;
		local_irq_enable();

		while (head != NULL) {
			struct net_device *dev = head;
			head = head->next_sched;

			smp_mb__before_clear_bit();
			clear_bit(__LINK_STATE_SCHED, &dev->state);

			if (spin_trylock(&dev->queue_lock)) {
				qdisc_run(dev);
				spin_unlock(&dev->queue_lock);
			} else {
				netif_schedule(dev);
			}
		}
	}
}


#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
void (*br_handle_frame_hook)(struct sk_buff *skb) = NULL;
#endif

static __inline__ int handle_bridge(struct sk_buff *skb,
				     struct packet_type *pt_prev)
{
	int ret = NET_RX_DROP;

	if (pt_prev) {
		if (!pt_prev->data)
			ret = deliver_to_old_ones(pt_prev, skb, 0);
		else {
			atomic_inc(&skb->users);
			ret = pt_prev->func(skb, skb->dev, pt_prev);
		}
	}

#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
	br_handle_frame_hook(skb);
#endif
	return ret;
}


#ifdef CONFIG_NET_DIVERT
static inline void handle_diverter(struct sk_buff *skb)
{
	/* if diversion is supported on device, then divert */
	if (skb->dev->divert && skb->dev->divert->divert)
		divert_frame(skb);
}
#endif   /* CONFIG_NET_DIVERT */

void update_shared_ring(void)
{
    rx_shadow_entry_t *rx;
    shared_info_t *s = current->shared_info;
    net_ring_t *net_ring;
    net_shadow_ring_t *shadow_ring;
    unsigned int nvif;
    
    clear_bit(_HYP_EVENT_NET_RX, &current->hyp_events);
    for (nvif = 0; nvif < current->num_net_vifs; nvif++)
    {
        net_ring = current->net_vif_list[nvif]->net_ring;
        shadow_ring = current->net_vif_list[nvif]->shadow_ring;
        while ((shadow_ring->rx_idx != shadow_ring->rx_cons) 
                && (net_ring->rx_cons != net_ring->rx_prod))
        {
            rx = shadow_ring->rx_ring+shadow_ring->rx_idx;
            copy_to_user(net_ring->rx_ring + net_ring->rx_cons, rx, sizeof(rx_entry_t));

            shadow_ring->rx_idx = RX_RING_INC(shadow_ring->rx_idx);
            net_ring->rx_cons   = RX_RING_INC(net_ring->rx_cons);
            
            if (rx->flush_count == tlb_flush_count[smp_processor_id()])
                __flush_tlb();

            if ( net_ring->rx_cons == net_ring->rx_event )
                set_bit(_EVENT_NET_RX_FOR_VIF(nvif), &s->events);
            
        }
    }
}
            
void flush_rx_queue(void)
{
    struct sk_buff *skb;
    shared_info_t *s = current->shared_info;
    net_ring_t *net_ring;
    net_shadow_ring_t *shadow_ring;
    unsigned int i, nvif;
    rx_shadow_entry_t *rx;
    unsigned long *g_pte, tmp;
    struct pfn_info *g_pfn, *h_pfn;
    
    /* I have changed this to batch flush all vifs for a guest
     * at once, whenever this is called.  Since the guest is about to be
     * scheduled and issued an RX interrupt for one nic, it might as well
     * receive all pending traffic  although it will still only get
     * interrupts about rings that pass the event marker.  
     *
     * If this doesn't make sense, _HYP_EVENT_NET_RX can be modified to
     * represent individual interrups as _EVENT_NET_RX and the outer for
     * loop can be replaced with a translation to the specific NET 
     * interrupt to serve. --akw
     */
    clear_bit(_HYP_EVENT_NET_RX, &current->hyp_events);

    for (nvif = 0; nvif < current->num_net_vifs; nvif++)
    {
        net_ring = current->net_vif_list[nvif]->net_ring;
        shadow_ring = current->net_vif_list[nvif]->shadow_ring;
        while ( (skb = skb_dequeue(&current->net_vif_list[nvif]->skb_list)) 
                        != NULL )
        {
            //temporary hack to stop processing non-zc skbs.
            if (skb->skb_type == SKB_NORMAL) continue;
            /*
             * Write the virtual MAC address into the destination field
             * of the ethernet packet. Furthermore, do the same for ARP
             * reply packets. This is easy because the virtual MAC address
             * is always 00-00-00-00-00-00.
             *
             * Actually, the MAC address is now all zeros, except for the
             * second sixteen bits, which are the per-host vif id.
             * (so eth0 should be 00-00-..., eth1 is 00-01-...)
             */
            
            if (skb->skb_type == SKB_ZERO_COPY)
            {
                skb->head = (u8 *)map_domain_mem(((skb->pf - frame_table) << PAGE_SHIFT));
                skb->data = skb->head;
                skb_reserve(skb,16); 
                skb->mac.raw = skb->data;
                skb->data += ETH_HLEN;
            }
            
            memset(skb->mac.ethernet->h_dest, 0, ETH_ALEN);
            *(unsigned int *)(skb->mac.ethernet->h_dest + 1) = nvif;
            if ( ntohs(skb->mac.ethernet->h_proto) == ETH_P_ARP )
            {
                memset(skb->nh.raw + 18, 0, ETH_ALEN);
                *(unsigned int *)(skb->nh.raw + 18 + 1) = nvif;
            }

            if (skb->skb_type == SKB_ZERO_COPY)
            {
                unmap_domain_mem(skb->head);
            }

            i = net_ring->rx_cons;
            if ( i != net_ring->rx_prod )
            {
                net_ring->rx_ring[i].status = shadow_ring->rx_ring[i].status;
                if ( shadow_ring->rx_ring[i].status == RING_STATUS_OK)
                {
                    rx = shadow_ring->rx_ring+i;
                    if ( (skb->len + ETH_HLEN) < rx->size )
                        rx->size = skb->len + ETH_HLEN;

                    /* remap the packet again.  This is very temporary and will shortly be
                     * replaced with a page swizzle.
                     */

                    /*if (skb->skb_type == SKB_ZERO_COPY)
                    {
                        skb->head = (u8 *)map_domain_mem(((skb->pf - frame_table) << PAGE_SHIFT));
                        skb->data = skb->head;
                        skb_reserve(skb,16); 
                        skb->mac.raw = skb->data;
                        skb->data += ETH_HLEN;
                    }
                                                                        
                    copy_to_user((void *)rx->addr, skb->mac.raw, rx->size);
                    copy_to_user(net_ring->rx_ring+i, rx, sizeof(rx));
                    
                    if (skb->skb_type == SKB_ZERO_COPY)
                    {
                        unmap_domain_mem(skb->head);
                        skb->head = skb->data = skb->tail = (void *)0xdeadbeef;
                    }*/

                    //presumably I don't need to rewalk the guest page table
                    //here.
                    if (skb->skb_type == SKB_ZERO_COPY) 
                    {
                        // g_pfn is the frame FROM the guest being given up
                        // h_pfn is the frame FROM the hypervisor, passing up.
                        
                        if (rx->flush_count == tlb_flush_count[smp_processor_id()])
                        {
                            flush_tlb_all();
                        }
                        
                        g_pte = map_domain_mem(rx->addr);
                        
                        //g_pfn = frame_table + (rx->addr >> PAGE_SHIFT);
                        g_pfn =  frame_table + (*g_pte >> PAGE_SHIFT);
                        h_pfn = skb->pf;


                        //tmp = g_pfn->next; g_pfn->next = h_pfn->next; h_pfn->next = tmp;
                        //tmp = g_pfn->prev; g_pfn->prev = h_pfn->prev; h_pfn->prev = tmp;
                        tmp = g_pfn->flags; g_pfn->flags = h_pfn->flags; h_pfn->flags = tmp;
                        
                        h_pfn->tot_count = 1;
                        h_pfn->type_count = g_pfn->type_count;
                        g_pfn->tot_count = g_pfn->type_count = 0;
                        
                        h_pfn->flags = current->domain | PGT_l1_page_table;
                        g_pfn->flags = PGT_l1_page_table;


                        *g_pte = (*g_pte & ~PAGE_MASK) | (((h_pfn - frame_table) << PAGE_SHIFT) & PAGE_MASK);

                        *g_pte |= _PAGE_PRESENT;
                        unmap_domain_mem(g_pte);

                        skb->pf = g_pfn; // return the guest pfn to be put on the free list
                    } else {
                        BUG(); //got a non-zero copy skb.  which is not good.
                    }
                    
                }
                net_ring->rx_cons = (i+1) & (RX_RING_SIZE-1);
                if ( net_ring->rx_cons == net_ring->rx_event )
                    set_bit(_EVENT_NET_RX_FOR_VIF(nvif), &s->events);
            }
            kfree_skb(skb);
        }
    }
}


/*
 *	Map an interface index to its name (SIOCGIFNAME)
 */

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
	    ((old_flags^dev->flags)&~(IFF_UP|IFF_PROMISC|IFF_ALLMULTI|IFF_VOLATILE)))
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
		
		case SIOCGIFMETRIC:	/* Get the metric on the interface (currently unused) */
			ifr->ifr_metric = 0;
			return 0;
			
		case SIOCSIFMETRIC:	/* Set the metric on the interface (currently unused) */
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

		case SIOCGIFTXQLEN:
			ifr->ifr_qlen = dev->tx_queue_len;
			return 0;

		case SIOCSIFTXQLEN:
			if (ifr->ifr_qlen<0)
				return -EINVAL;
			dev->tx_queue_len = ifr->ifr_qlen;
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
 *	This function handles all "interface"-type I/O control requests. The actual
 *	'doing' part of this is dev_ifsioc above.
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
		case SIOCGIFTXQLEN:
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
		case SIOCSIFTXQLEN:
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
			/* Set the per device memory buffer space. Not applicable in our case */
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
				    copy_to_user(arg, &ifr, sizeof(struct ifreq)))
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
		printk(KERN_ERR "Freeing alive device %p, %s\n", dev, dev->name);
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
		printk(KERN_DEBUG "unregister_netdevice: device %s/%p never was registered\n", dev->name, dev);
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
			printk(KERN_DEBUG "unregister_netdevice: holding %s refcnt=%d\n", dev->name, atomic_read(&dev->refcnt)-1);
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
	printk("unregister_netdevice: waiting %s refcnt=%d\n", dev->name, atomic_read(&dev->refcnt));
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
	int i;

	if (!dev_boot_phase)
		return 0;

        /*
         * KAF: was sone in socket_init, but that top-half stuff is gone.
         */
        skb_init();

	/*
	 *	Initialise the packet receive queues.
	 */

	for (i = 0; i < NR_CPUS; i++) {
		struct softnet_data *queue;

		queue = &softnet_data[i];
                skb_queue_head_init(&queue->input_pkt_queue);
		queue->throttle = 0;
		queue->cng_level = 0;
		queue->avg_blog = 10; /* arbitrary non-zero */
		queue->completion_queue = NULL;
	}
	
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

	open_softirq(NET_TX_SOFTIRQ, net_tx_action, NULL);
	//open_softirq(NET_RX_SOFTIRQ, net_rx_action, NULL);

	dst_init();
	dev_mcast_init();

#ifdef CONFIG_NET_SCHED
	pktsched_init();
#endif

	/*
	 *	Initialise network devices
	 */
	 
	net_device_init();

	return 0;
}

inline int init_tx_header(u8 *data, unsigned int len, struct net_device *dev)
{
        memcpy(data + ETH_ALEN, dev->dev_addr, ETH_ALEN);
        
        switch ( ntohs(*(unsigned short *)(data + 12)) )
        {
        case ETH_P_ARP:
            if ( len < 42 ) break;
            memcpy(data + 22, dev->dev_addr, 6);
            return ETH_P_ARP;
        case ETH_P_IP:
            return ETH_P_IP;
        }
        return 0;
}

/* 
 * tx_skb_release
 *
 * skb destructor function that is attached to zero-copy tx skbs before 
 * they are passed to the device driver for transmission.  The destructor 
 * is responsible for unlinking the fragment pointer to the skb data that 
 * is in guest memory, and decrementing the tot_count on the packet pages 
 * pfn_info.
 */

void tx_skb_release(struct sk_buff *skb)
{
    int i;
    
    for (i= 0; i < skb_shinfo(skb)->nr_frags; i++)
        skb_shinfo(skb)->frags[i].page->tot_count--;
    
    skb_shinfo(skb)->nr_frags = 0; 
}
    
/*
 * do_net_update:
 * 
 * Called from guest OS to notify updates to its transmit and/or receive
 * descriptor rings.
 */
#define PKT_PROT_LEN (ETH_HLEN + 8)

void print_range2(u8 *start, unsigned int len)
{
    int i=0;
    while (i++ < len)
    {
        printk("%x:",start[i]);
    }
    printk("\n");
}

long do_net_update(void)
{
    shared_info_t *shared = current->shared_info;    
    net_ring_t *net_ring;
    net_shadow_ring_t *shadow_ring;
    net_vif_t *current_vif;
    unsigned int i, j;
    struct sk_buff *skb;
    tx_entry_t tx;
    rx_shadow_entry_t *rx;
    unsigned long pfn;
    struct pfn_info *page;
    unsigned long *g_pte;
    
    
    for ( j = 0; j < current->num_net_vifs; j++)
    {
        current_vif = current->net_vif_list[j];
        net_ring = current_vif->net_ring;
        int target;
        u8 *g_data;
        unsigned short protocol;

        /* First, we send out pending TX descriptors if they exist on this ring.
         */
        
        for ( i = net_ring->tx_cons; i != net_ring->tx_prod; i = TX_RING_INC(i) )
        {
            if ( copy_from_user(&tx, net_ring->tx_ring+i, sizeof(tx)) )
                continue;

            if ( tx.size < PKT_PROT_LEN ) continue; // This should be reasonable.
            
            // Packets must not cross page boundaries.  For now, this is a 
            // kernel panic, later it may become a continue -- silent fail.
            
            if ( ((tx.addr & ~PAGE_MASK) + tx.size) >= PAGE_SIZE ) 
            {
                printk("tx.addr: %lx, size: %lu, end: %lu\n", tx.addr, tx.size,
                    (tx.addr &~PAGE_MASK) + tx.size);
                continue;
                //BUG();
            }
            
            if ( TX_RING_INC(i) == net_ring->tx_event )
                set_bit(_EVENT_NET_TX_FOR_VIF(j), &shared->events);

            /* Map the skb in from the guest, and get it's delivery target.
             * We need this to know whether the packet is to be sent locally
             * or remotely.
             */
            
            g_data = map_domain_mem(tx.addr);

//print_range2(g_data, PKT_PROT_LEN);                
            protocol = __constant_htons(init_tx_header(g_data, tx.size, the_dev));
            if ( protocol == 0 )
            {
                unmap_domain_mem(g_data);
                continue;
            }

            target = __net_get_target_vif(g_data, tx.size, current_vif->id);
//printk("Send to target: %d\n", target); 
            if (target > VIF_PHYSICAL_INTERFACE )
            {
                // Local delivery: Allocate an skb off the domain free list
                // fil it, and pass it to netif_rx as if it came off the NIC.
//printk("LOCAL! (%d) \n", target);
                skb = dev_alloc_skb(tx.size);
                if (skb == NULL) 
                {
                    unmap_domain_mem(g_data);
                    continue;
                }
                
                skb->src_vif = current_vif->id;
                skb->dst_vif = target;
                skb->protocol = protocol;

                skb->head = (u8 *)map_domain_mem(((skb->pf - frame_table) << PAGE_SHIFT));
                skb->data = skb->head + 16;
                skb_reserve(skb,2);
                memcpy(skb->data, g_data, tx.size);
                skb->len = tx.size;
                unmap_domain_mem(skb->head);
                skb->data += ETH_HLEN; // so the assertion in netif_RX doesn't freak out.
                
                (void)netif_rx(skb);

                unmap_domain_mem(g_data);
            }
            else if ( target == VIF_PHYSICAL_INTERFACE )
            {
                // External delivery: Allocate a small skb to hold protected header info
                // and copy the eth header and IP address fields into that.
                // Set a frag link to the remaining data, and we will scatter-gather
                // in the device driver to send the two bits later.
                
                /*unmap_domain_mem(g_data);*/
                    
                skb = alloc_skb(PKT_PROT_LEN, GFP_KERNEL); // Eth header + two IP addrs.
                if (skb == NULL) 
                {
printk("Alloc skb failed!\n");
                    continue;
                }
            
                skb_put(skb, PKT_PROT_LEN);
                /*if ( copy_from_user(skb->data, (void *)tx.addr, PKT_PROT_LEN) )
                {
printk("Copy from user failed!\n");
                    kfree_skb(skb);
                    continue;
                }
                */
                memcpy(skb->data, g_data, PKT_PROT_LEN);
                unmap_domain_mem(g_data);
//print_range2(g_data, PKT_PROT_LEN);                
                skb->dev = the_dev;
                skb->src_vif = current_vif->id;
                skb->dst_vif = target;
                skb->protocol = protocol; // These next two lines abbreviate the call 
                                          // to eth_type_trans as we already have our
                                          // protocol.
                //skb_pull(skb, skb->dev->hard_header_len);
                skb->mac.raw=skb->data; 

                // set tot_count++ in the guest data pfn.
                page = (tx.addr >> PAGE_SHIFT) + frame_table;
                page->tot_count++;

                // place the remainder of the packet (which is in guest memory) into an
                // skb frag.
                skb_shinfo(skb)->frags[0].page = page;
                skb_shinfo(skb)->frags[0].size = tx.size - PKT_PROT_LEN;
                skb_shinfo(skb)->frags[0].page_offset 
                    = (tx.addr & ~PAGE_MASK) + PKT_PROT_LEN;
                skb_shinfo(skb)->nr_frags = 1;
                skb->data_len = tx.size - skb->len;
                skb->len = tx.size;
                
                // assign a destructor to the skb that will unlink and dec the tot_count
                skb->destructor = &tx_skb_release;
                //skb_push(skb, skb->dev->hard_header_len);
//printk("calling dev_queue_xmit!\n");
                dev_queue_xmit(skb);
            }
            else
            {
                unmap_domain_mem(g_data);
            }
        }
        net_ring->tx_cons = i;

        /* Next, pull any new RX descriptors across to the shadow ring.
         */
    
        shadow_ring = current_vif->shadow_ring;

        for (i = shadow_ring->rx_prod; i != net_ring->rx_prod; i = RX_RING_INC(i))
        {
            /* This copy assumes that rx_shadow_entry_t is an extension of 
             * rx_net_entry_t extra fields must be tacked on to the end.
             */
            if ( copy_from_user( shadow_ring->rx_ring+i, net_ring->rx_ring+i, 
                                 sizeof (rx_entry_t) ) )
            {
                shadow_ring->rx_ring[i].status = RING_STATUS_ERR_CFU;
                continue;
            } else {
                    
                rx = shadow_ring->rx_ring + i;
                pfn = rx->addr >> PAGE_SHIFT;
                page = frame_table + pfn;
                
                shadow_ring->rx_ring[i].status = RING_STATUS_BAD_PAGE;

                if  ( page->flags != (PGT_l1_page_table | current->domain) ) 
                {
BUG();
                       continue;
                }


                g_pte = map_domain_mem(rx->addr);

                if (!(*g_pte & _PAGE_PRESENT))
                {
BUG();
                        unmap_domain_mem(g_pte);
                        continue;
                }
                
                page = (*g_pte >> PAGE_SHIFT) + frame_table;
                
                if (page->tot_count != 1) 
                {
printk("!\n");
                        unmap_domain_mem(g_pte);
                        continue;
                }
                
                // The pte they passed was good, so we take it away from them.
                shadow_ring->rx_ring[i].status = RING_STATUS_OK;
                *g_pte &= ~_PAGE_PRESENT;
                page->flags = (page->flags & ~PG_type_mask) | PGT_net_rx_buf;
                rx->flush_count = tlb_flush_count[smp_processor_id()];

                unmap_domain_mem(g_pte);
            }
        }
        shadow_ring->rx_prod = net_ring->rx_prod;
    }
    return 0;
}


int setup_network_devices(void)
{
    int ret;
    struct net_device *dev = dev_get_by_name("eth0");

    if ( dev == NULL ) 
    {
        printk("Could not find device eth0\n");
        return 0;
    }

    ret = dev_open(dev);
    if ( ret != 0 )
    {
        printk("Error opening device eth0 for use (%d)\n", ret);
        return 0;
    }
    printk("Device eth0 opened and ready for use\n");
    the_dev = dev;

    return 1;
}

