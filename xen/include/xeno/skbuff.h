/*
 *	Definitions for the 'struct sk_buff' memory handlers.
 *
 *	Authors:
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Florian La Roche, <rzsfl@rz.uni-sb.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
 
#ifndef _LINUX_SKBUFF_H
#define _LINUX_SKBUFF_H

#include <linux/config.h>
#include <linux/lib.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <asm/system.h>
#include <asm/atomic.h>
#include <asm/types.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <xeno/vif.h>

/* skb_type values */
#define SKB_NORMAL               0 /* A Linux-style skbuff: no strangeness */
#define SKB_ZERO_COPY            1 /* Zero copy skbs are used for receive  */
#define SKB_NODATA               2 /* Data allocation not handled by us    */

#define HAVE_ALLOC_SKB		/* For the drivers to know */
#define HAVE_ALIGNABLE_SKB	/* Ditto 8)		   */
#define SLAB_SKB 		/* Slabified skbuffs 	   */

#define CHECKSUM_NONE 0
#define CHECKSUM_HW 1
#define CHECKSUM_UNNECESSARY 2

#define SKB_DATA_ALIGN(X)	(((X) + (SMP_CACHE_BYTES-1)) & ~(SMP_CACHE_BYTES-1))

/* A. Checksumming of received packets by device.
 *
 *	NONE: device failed to checksum this packet.
 *		skb->csum is undefined.
 *
 *	UNNECESSARY: device parsed packet and wouldbe verified checksum.
 *		skb->csum is undefined.
 *	      It is bad option, but, unfortunately, many of vendors do this.
 *	      Apparently with secret goal to sell you new device, when you
 *	      will add new protocol to your host. F.e. IPv6. 8)
 *
 *	HW: the most generic way. Device supplied checksum of _all_
 *	    the packet as seen by netif_rx in skb->csum.
 *	    NOTE: Even if device supports only some protocols, but
 *	    is able to produce some skb->csum, it MUST use HW,
 *	    not UNNECESSARY.
 *
 * B. Checksumming on output.
 *
 *	NONE: skb is checksummed by protocol or csum is not required.
 *
 *	HW: device is required to csum packet as seen by hard_start_xmit
 *	from skb->h.raw to the end and to record the checksum
 *	at skb->h.raw+skb->csum.
 *
 *	Device must show its capabilities in dev->features, set
 *	at device setup time.
 *	NETIF_F_HW_CSUM	- it is clever device, it is able to checksum
 *			  everything.
 *	NETIF_F_NO_CSUM - loopback or reliable single hop media.
 *	NETIF_F_IP_CSUM - device is dumb. It is able to csum only
 *			  TCP/UDP over IPv4. Sigh. Vendors like this
 *			  way by an unknown reason. Though, see comment above
 *			  about CHECKSUM_UNNECESSARY. 8)
 */

#ifdef __i386__
#define NET_CALLER(arg) (*(((void**)&arg)-1))
#else
#define NET_CALLER(arg) __builtin_return_address(0)
#endif

struct sk_buff_head {
    /* These two members must be first. */
    struct sk_buff	* next;
    struct sk_buff	* prev;

    __u32		qlen;
    spinlock_t	lock;
};

#define MAX_SKB_FRAGS 1 /* KAF: was 6 */

typedef struct skb_frag_struct {
    struct pfn_info *page;
    __u16 page_offset;
    __u16 size;
} skb_frag_t;

struct skb_shared_info {
    unsigned int nr_frags;
    skb_frag_t	frags[MAX_SKB_FRAGS];
};

struct sk_buff {
    /* These two members must be first. */
    struct sk_buff	* next;			/* Next buffer in list 				*/
    struct sk_buff	* prev;			/* Previous buffer in list 			*/

    struct sk_buff_head * list;		/* List we are on				*/
    struct net_device	*dev;		/* Device we arrived on/are leaving by		*/

    /* Transport layer header */
    union
    {
        struct tcphdr	*th;
        struct udphdr	*uh;
        struct icmphdr	*icmph;
        struct igmphdr	*igmph;
        struct iphdr	*ipiph;
        struct spxhdr	*spxh;
        unsigned char	*raw;
    } h;

    /* Network layer header */
    union
    {
        struct iphdr	*iph;
        struct ipv6hdr	*ipv6h;
        struct arphdr	*arph;
        struct ipxhdr	*ipxh;
        unsigned char	*raw;
    } nh;
  
    /* Link layer header */
    union 
    {	
        struct ethhdr	*ethernet;
        unsigned char 	*raw;
    } mac;

    unsigned int 	len;			/* Length of actual data			*/
    unsigned int 	data_len;
    unsigned int	csum;			/* Checksum 					*/
    unsigned char 	skb_type,
        pkt_type,		/* Packet class					*/
        ip_summed;		/* Driver fed us an IP checksum			*/
    unsigned short	protocol;		/* Packet protocol from driver. 		*/
    unsigned char	*head;			/* Head of buffer 				*/
    unsigned char	*data;			/* Data head pointer				*/
    unsigned char	*tail;			/* Tail pointer					*/
    unsigned char 	*end;			/* End pointer					*/

    void 		(*destructor)(struct sk_buff *);	/* Destruct function		*/

    unsigned short guest_id;  /* guest-OS's id for this packet (tx only!)   */
    struct pfn_info *pf;      /* record of physical pf address for freeing  */
    net_vif_t *src_vif;       /* vif we came from                           */
    net_vif_t *dst_vif;       /* vif we are bound for                       */
    struct skb_shared_info shinfo; /* shared info not shared in Xen.        */
};

extern void	       __kfree_skb(struct sk_buff *skb);
extern struct sk_buff *alloc_skb(unsigned int size, int priority);
extern struct sk_buff *alloc_skb_nodata(int priority);
extern struct sk_buff *alloc_zc_skb(unsigned int size, int priority);
extern void	       kfree_skbmem(struct sk_buff *skb);
extern struct sk_buff *skb_copy(const struct sk_buff *skb, int priority);
#define dev_kfree_skb(a)	kfree_skb(a)
extern void	skb_over_panic(struct sk_buff *skb, int len, void *here);
extern void	skb_under_panic(struct sk_buff *skb, int len, void *here);

/* In Xen, we don't clone skbs, so shared data can go in the sk_buff struct. */
#define skb_shinfo(SKB)     ((struct skb_shared_info *)(&(SKB)->shinfo))

/**
 *	kfree_skb - free an sk_buff
 *	@skb: buffer to free
 *
 *	Drop a reference to the buffer and free it if the usage count has
 *	hit zero.
 */
 
static inline void kfree_skb(struct sk_buff *skb)
{
    __kfree_skb(skb);
}

/**
 *	skb_queue_len	- get queue length
 *	@list_: list to measure
 *
 *	Return the length of an &sk_buff queue. 
 */
 
static inline __u32 skb_queue_len(struct sk_buff_head *list_)
{
    return(list_->qlen);
}

static inline void skb_queue_head_init(struct sk_buff_head *list)
{
    spin_lock_init(&list->lock);
    list->prev = (struct sk_buff *)list;
    list->next = (struct sk_buff *)list;
    list->qlen = 0;
}

/**
 *	__skb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 
static inline void __skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk)
{
    struct sk_buff *prev, *next;

    newsk->list = list;
    list->qlen++;
    prev = (struct sk_buff *)list;
    next = prev->next;
    newsk->next = next;
    newsk->prev = prev;
    next->prev = newsk;
    prev->next = newsk;
}

/**
 *	__skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The head item is
 *	returned or %NULL if the list is empty.
 */

static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *list)
{
    struct sk_buff *next, *prev, *result;

    prev = (struct sk_buff *) list;
    next = prev->next;
    result = NULL;
    if (next != prev) {
        result = next;
        next = next->next;
        list->qlen--;
        next->prev = prev;
        prev->next = next;
        result->next = NULL;
        result->prev = NULL;
        result->list = NULL;
    }
    return result;
}

static inline int skb_is_nonlinear(const struct sk_buff *skb)
{
    return skb->data_len;
}

#define SKB_LINEAR_ASSERT(skb) do { if (skb_is_nonlinear(skb)) BUG(); } while (0)

/*
 *	Add data to an sk_buff
 */
 
static inline unsigned char *__skb_put(struct sk_buff *skb, unsigned int len)
{
    unsigned char *tmp=skb->tail;
    SKB_LINEAR_ASSERT(skb);
    skb->tail+=len;
    skb->len+=len;
    return tmp;
}

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
 
static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
    unsigned char *tmp=skb->tail;
    SKB_LINEAR_ASSERT(skb);
    skb->tail+=len;
    skb->len+=len;
    if(skb->tail>skb->end) {
        skb_over_panic(skb, len, current_text_addr());
    }
    return tmp;
}

static inline unsigned char *__skb_push(struct sk_buff *skb, unsigned int len)
{
    skb->data-=len;
    skb->len+=len;
    return skb->data;
}

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
    skb->data-=len;
    skb->len+=len;
    if(skb->data<skb->head) {
        skb_under_panic(skb, len, current_text_addr());
    }
    return skb->data;
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
    skb->len-=len;
    if (skb->len < skb->data_len)
        BUG();
    return 	skb->data+=len;
}

/**
 *	skb_pull - remove data from the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to remove
 *
 *	This function removes data from the start of a buffer, returning
 *	the memory to the headroom. A pointer to the next data in the buffer
 *	is returned. Once the data has been pulled future pushes will overwrite
 *	the old data.
 */

static inline unsigned char * skb_pull(struct sk_buff *skb, unsigned int len)
{	
    if (len > skb->len)
        return NULL;
    return __skb_pull(skb,len);
}

/**
 *	skb_reserve - adjust headroom
 *	@skb: buffer to alter
 *	@len: bytes to move
 *
 *	Increase the headroom of an empty &sk_buff by reducing the tail
 *	room. This is only allowed for an empty buffer.
 */

static inline void skb_reserve(struct sk_buff *skb, unsigned int len)
{
    skb->data+=len;
    skb->tail+=len;
}

/**
 *	__dev_alloc_skb - allocate an skbuff for sending
 *	@length: length to allocate
 *	@gfp_mask: get_free_pages mask, passed to alloc_skb
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned in there is no free memory.
 */
 
static inline struct sk_buff *__dev_alloc_skb(unsigned int length,
					      int gfp_mask)
{
    struct sk_buff *skb;
    skb = alloc_zc_skb(length+16, gfp_mask);
    if (skb)
        skb_reserve(skb,16);
    return skb;
}

/**
 *	dev_alloc_skb - allocate an skbuff for sending
 *	@length: length to allocate
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned in there is no free memory. Although this function
 *	allocates memory it can be called from an interrupt.
 */
 
static inline struct sk_buff *dev_alloc_skb(unsigned int length)
{
    return __dev_alloc_skb(length, GFP_ATOMIC);
}

static inline void *kmap_skb_frag(const skb_frag_t *frag)
{
    return page_address(frag->page);
}

static inline void kunmap_skb_frag(void *vaddr)
{
}

extern int skb_copy_bits(const struct sk_buff *skb, 
                         int offset, void *to, int len);
extern void skb_init(void);

extern int skb_linearize(struct sk_buff *skn, int gfp_mask);

#endif	/* _LINUX_SKBUFF_H */
