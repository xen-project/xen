/*
 * VLAN		An implementation of 802.1Q VLAN tagging.
 *
 * Authors:	Ben Greear <greearb@candelatech.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */

#ifndef _LINUX_IF_VLAN_H_
#define _LINUX_IF_VLAN_H_

#ifdef __KERNEL__

/* externally defined structs */
struct vlan_group;
struct net_device;
struct sk_buff;
struct packet_type;
struct vlan_collection;
struct vlan_dev_info;

//#include <xeno/proc_fs.h> /* for proc_dir_entry */
#include <xeno/netdevice.h>

#define VLAN_HLEN	4		/* The additional bytes (on top of the Ethernet header)
					 * that VLAN requires.
					 */
#define VLAN_ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define VLAN_ETH_HLEN	18		/* Total octets in header.	 */
#define VLAN_ETH_ZLEN	64		/* Min. octets in frame sans FCS */

/*
 * According to 802.3ac, the packet can be 4 bytes longer. --Klika Jan
 */
#define VLAN_ETH_DATA_LEN	1500	/* Max. octets in payload	 */
#define VLAN_ETH_FRAME_LEN	1518	/* Max. octets in frame sans FCS */

struct vlan_ethhdr {
   unsigned char	h_dest[ETH_ALEN];	   /* destination eth addr	*/
   unsigned char	h_source[ETH_ALEN];	   /* source ether addr	*/
   unsigned short       h_vlan_proto;              /* Should always be 0x8100 */
   unsigned short       h_vlan_TCI;                /* Encapsulates priority and VLAN ID */
   unsigned short	h_vlan_encapsulated_proto; /* packet type ID field (or len) */
};

struct vlan_hdr {
   unsigned short       h_vlan_TCI;                /* Encapsulates priority and VLAN ID */
   unsigned short       h_vlan_encapsulated_proto; /* packet type ID field (or len) */
};

#define VLAN_VID_MASK	0xfff

/* found in af_inet.c */
extern int (*vlan_ioctl_hook)(unsigned long arg);

#define VLAN_NAME "vlan"

/* if this changes, algorithm will have to be reworked because this
 * depends on completely exhausting the VLAN identifier space.  Thus
 * it gives constant time look-up, but in many cases it wastes memory.
 */
#define VLAN_GROUP_ARRAY_LEN 4096

struct vlan_group {
	int real_dev_ifindex; /* The ifindex of the ethernet(like) device the vlan is attached to. */
	struct net_device *vlan_devices[VLAN_GROUP_ARRAY_LEN];

	struct vlan_group *next; /* the next in the list */
};

struct vlan_priority_tci_mapping {
	unsigned long priority;
	unsigned short vlan_qos; /* This should be shifted when first set, so we only do it
				  * at provisioning time.
				  * ((skb->priority << 13) & 0xE000)
				  */
	struct vlan_priority_tci_mapping *next;
};

/* Holds information that makes sense if this device is a VLAN device. */
struct vlan_dev_info {
	/** This will be the mapping that correlates skb->priority to
	 * 3 bits of VLAN QOS tags...
	 */
	unsigned long ingress_priority_map[8];
	struct vlan_priority_tci_mapping *egress_priority_map[16]; /* hash table */

	unsigned short vlan_id;        /*  The VLAN Identifier for this interface. */
	unsigned short flags;          /* (1 << 0) re_order_header   This option will cause the
                                        *   VLAN code to move around the ethernet header on
                                        *   ingress to make the skb look **exactly** like it
                                        *   came in from an ethernet port.  This destroys some of
                                        *   the VLAN information in the skb, but it fixes programs
                                        *   like DHCP that use packet-filtering and don't understand
                                        *   802.1Q
                                        */
	struct dev_mc_list *old_mc_list;  /* old multi-cast list for the VLAN interface..
                                           * we save this so we can tell what changes were
                                           * made, in order to feed the right changes down
                                           * to the real hardware...
                                           */
	int old_allmulti;               /* similar to above. */
	int old_promiscuity;            /* similar to above. */
	struct net_device *real_dev;    /* the underlying device/interface */
	struct proc_dir_entry *dent;    /* Holds the proc data */
	unsigned long cnt_inc_headroom_on_tx; /* How many times did we have to grow the skb on TX. */
	unsigned long cnt_encap_on_xmit;      /* How many times did we have to encapsulate the skb on TX. */
	struct net_device_stats dev_stats; /* Device stats (rx-bytes, tx-pkts, etc...) */
};

#define VLAN_DEV_INFO(x) ((struct vlan_dev_info *)(x->priv))

/* inline functions */

static inline struct net_device_stats *vlan_dev_get_stats(struct net_device *dev)
{
	return &(VLAN_DEV_INFO(dev)->dev_stats);
}

static inline __u32 vlan_get_ingress_priority(struct net_device *dev,
					      unsigned short vlan_tag)
{
	struct vlan_dev_info *vip = VLAN_DEV_INFO(dev);

	return vip->ingress_priority_map[(vlan_tag >> 13) & 0x7];
}

/* VLAN tx hw acceleration helpers. */
struct vlan_skb_tx_cookie {
	u32	magic;
	u32	vlan_tag;
};

#if 0
#define VLAN_TX_COOKIE_MAGIC	0x564c414e	/* "VLAN" in ascii. */
#define VLAN_TX_SKB_CB(__skb)	((struct vlan_skb_tx_cookie *)&((__skb)->cb[0]))
#define vlan_tx_tag_present(__skb) \
	(VLAN_TX_SKB_CB(__skb)->magic == VLAN_TX_COOKIE_MAGIC)
#define vlan_tx_tag_get(__skb)	(VLAN_TX_SKB_CB(__skb)->vlan_tag)
#else /* XXX KAF: We don't support vlan tagging at the moment. */
#define VLAN_TX_SKB_CB(__skb)	   NULL
#define vlan_tx_tag_present(__skb) 0
#define vlan_tx_tag_get(__skb)	   0
#endif

#if 0
/* VLAN rx hw acceleration helper.  This acts like netif_{rx,receive_skb}(). */
static inline int __vlan_hwaccel_rx(struct sk_buff *skb,
				    struct vlan_group *grp,
				    unsigned short vlan_tag, int polling)
{
	struct net_device_stats *stats;

	skb->dev = grp->vlan_devices[vlan_tag & VLAN_VID_MASK];
	if (skb->dev == NULL) {
		kfree_skb(skb);

		/* Not NET_RX_DROP, this is not being dropped
		 * due to congestion.
		 */
		return 0;
	}

	skb->dev->last_rx = jiffies;

	stats = vlan_dev_get_stats(skb->dev);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;

	skb->priority = vlan_get_ingress_priority(skb->dev, vlan_tag);
	switch (skb->pkt_type) {
	case PACKET_BROADCAST:
		break;

	case PACKET_MULTICAST:
		stats->multicast++;
		break;

	case PACKET_OTHERHOST:
		/* Our lower layer thinks this is not local, let's make sure.
		 * This allows the VLAN to have a different MAC than the underlying
		 * device, and still route correctly.
		 */
		if (!memcmp(skb->mac.ethernet->h_dest, skb->dev->dev_addr, ETH_ALEN))
			skb->pkt_type = PACKET_HOST;
		break;
	};

#ifdef NAPI
	return (polling ? netif_receive_skb(skb) : netif_rx(skb));
#else
        return netif_rx(skb);
#endif
}

static inline int vlan_hwaccel_rx(struct sk_buff *skb,
				  struct vlan_group *grp,
				  unsigned short vlan_tag)
{
	return __vlan_hwaccel_rx(skb, grp, vlan_tag, 0);
}

static inline int vlan_hwaccel_receive_skb(struct sk_buff *skb,
					   struct vlan_group *grp,
					   unsigned short vlan_tag)
{
	return __vlan_hwaccel_rx(skb, grp, vlan_tag, 1);
}
#else
#define vlan_hwaccel_rx(_skb, _grp, _tag) (netif_rx(_skb))
#endif
#endif /* __KERNEL__ */

/* VLAN IOCTLs are found in sockios.h */

/* Passed in vlan_ioctl_args structure to determine behaviour. */
enum vlan_ioctl_cmds {
	ADD_VLAN_CMD,
	DEL_VLAN_CMD,
	SET_VLAN_INGRESS_PRIORITY_CMD,
	SET_VLAN_EGRESS_PRIORITY_CMD,
	GET_VLAN_INGRESS_PRIORITY_CMD,
	GET_VLAN_EGRESS_PRIORITY_CMD,
	SET_VLAN_NAME_TYPE_CMD,
	SET_VLAN_FLAG_CMD
};

enum vlan_name_types {
	VLAN_NAME_TYPE_PLUS_VID, /* Name will look like:  vlan0005 */
	VLAN_NAME_TYPE_RAW_PLUS_VID, /* name will look like:  eth1.0005 */
	VLAN_NAME_TYPE_PLUS_VID_NO_PAD, /* Name will look like:  vlan5 */
	VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD, /* Name will look like:  eth0.5 */
	VLAN_NAME_TYPE_HIGHEST
};

struct vlan_ioctl_args {
	int cmd; /* Should be one of the vlan_ioctl_cmds enum above. */
	char device1[24];

        union {
		char device2[24];
		int VID;
		unsigned int skb_priority;
		unsigned int name_type;
		unsigned int bind_type;
		unsigned int flag; /* Matches vlan_dev_info flags */
        } u;

	short vlan_qos;   
};

#endif /* !(_LINUX_IF_VLAN_H_) */
