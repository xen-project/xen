/*
 *	Routines having to do with the 'struct sk_buff' memory handlers.
 *
 *	Authors:	Alan Cox <iiitac@pyr.swan.ac.uk>
 *			Florian La Roche <rzsfl@rz.uni-sb.de>
 *
 *	Version:	$Id: skbuff.c,v 1.89 2001/08/06 13:25:02 davem Exp $
 *
 *	Fixes:	
 *		Alan Cox	:	Fixed the worst of the load balancer bugs.
 *		Dave Platt	:	Interrupt stacking fix.
 *	Richard Kooijman	:	Timestamp fixes.
 *		Alan Cox	:	Changed buffer format.
 *		Alan Cox	:	destructor hook for AF_UNIX etc.
 *		Linus Torvalds	:	Better skb_clone.
 *		Alan Cox	:	Added skb_copy.
 *		Alan Cox	:	Added all the changed routines Linus
 *					only put in the headers
 *		Ray VanTassle	:	Fixed --skb->lock in free
 *		Alan Cox	:	skb_copy copy arp field
 *		Andi Kleen	:	slabified it.
 *
 *	NOTE:
 *		The __skb_ routines should be called with interrupts 
 *	disabled, or you better be *real* sure that the operation is atomic 
 *	with respect to whatever list is being frobbed (e.g. via lock_sock()
 *	or via disabling bottom half handlers, etc).
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/lib.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/cache.h>
#include <linux/init.h>

#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/io.h>

#define BUG_TRAP ASSERT

int sysctl_hot_list_len = 128;

static kmem_cache_t *skbuff_head_cache;

static union {
    struct sk_buff_head	list;
    char			pad[SMP_CACHE_BYTES];
} skb_head_pool[NR_CPUS];

/*
 *	Keep out-of-line to prevent kernel bloat.
 *	__builtin_return_address is not used because it is not always
 *	reliable. 
 */

/**
 *	skb_over_panic	- 	private function
 *	@skb: buffer
 *	@sz: size
 *	@here: address
 *
 *	Out of line support code for skb_put(). Not user callable.
 */
 
void skb_over_panic(struct sk_buff *skb, int sz, void *here)
{
    printk("skput:over: %p:%d put:%d dev:%s", 
           here, skb->len, sz, skb->dev ? skb->dev->name : "<NULL>");
    BUG();
}

/**
 *	skb_under_panic	- 	private function
 *	@skb: buffer
 *	@sz: size
 *	@here: address
 *
 *	Out of line support code for skb_push(). Not user callable.
 */
 

void skb_under_panic(struct sk_buff *skb, int sz, void *here)
{
    printk("skput:under: %p:%d put:%d dev:%s",
           here, skb->len, sz, skb->dev ? skb->dev->name : "<NULL>");
    BUG();
}

static __inline__ struct sk_buff *skb_head_from_pool(void)
{
    struct sk_buff_head *list = &skb_head_pool[smp_processor_id()].list;

    if (skb_queue_len(list)) {
        struct sk_buff *skb;
        unsigned long flags;

        local_irq_save(flags);
        skb = __skb_dequeue(list);
        local_irq_restore(flags);
        return skb;
    }
    return NULL;
}

static __inline__ void skb_head_to_pool(struct sk_buff *skb)
{
    struct sk_buff_head *list = &skb_head_pool[smp_processor_id()].list;

    if (skb_queue_len(list) < sysctl_hot_list_len) {
        unsigned long flags;

        local_irq_save(flags);
        __skb_queue_head(list, skb);
        local_irq_restore(flags);

        return;
    }
    kmem_cache_free(skbuff_head_cache, skb);
}

static inline u8 *alloc_skb_data_page(struct sk_buff *skb)
{
    struct list_head *list_ptr;
    struct pfn_info  *pf;
    unsigned long flags;
        
    spin_lock_irqsave(&free_list_lock, flags);

    if (!free_pfns) return NULL;

    list_ptr = free_list.next;
    pf = list_entry(list_ptr, struct pfn_info, list);
    pf->flags = 0;
    list_del(&pf->list);
    free_pfns--;

    spin_unlock_irqrestore(&free_list_lock, flags);

    skb->pf = pf;
    return (u8 *)((pf - frame_table) << PAGE_SHIFT);
}

static inline void dealloc_skb_data_page(struct sk_buff *skb)
{
    struct pfn_info  *pf;
    unsigned long flags;

    pf = skb->pf;

    spin_lock_irqsave(&free_list_lock, flags);
        
    pf->flags = pf->type_count = pf->tot_count = 0;
    list_add(&pf->list, &free_list);
    free_pfns++;

    spin_unlock_irqrestore(&free_list_lock, flags);

}

static inline void INTERRUPT_CHECK(int gfp_mask)
{
    if (in_interrupt() && (gfp_mask & __GFP_WAIT)) {
        printk(KERN_ERR "alloc_skb called nonatomically\n");
        BUG();
    }
}


/**
 *	alloc_skb	-	allocate a network buffer
 *	@size: size to allocate
 *	@gfp_mask: allocation mask
 *
 *	Allocate a new &sk_buff. The returned buffer has no headroom and a
 *	tail room of size bytes. The object has a reference count of one.
 *	The return is the buffer. On a failure the return is %NULL.
 *
 *	Buffers may only be allocated from interrupts using a @gfp_mask of
 *	%GFP_ATOMIC.
 */
 
struct sk_buff *alloc_skb(unsigned int size,int gfp_mask)
{
    struct sk_buff *skb;
    u8 *data;

    INTERRUPT_CHECK(gfp_mask);

    /* Get the HEAD */
    skb = skb_head_from_pool();
    if (skb == NULL) {
        skb = kmem_cache_alloc(skbuff_head_cache, gfp_mask & ~__GFP_DMA);
        if (skb == NULL)
            goto nohead;
    }

    /* Get the DATA. Size must match skb_add_mtu(). */
    size = SKB_DATA_ALIGN(size);
    data = kmalloc(size + sizeof(struct skb_shared_info), gfp_mask);
    if (data == NULL)
        goto nodata;

    /* Load the data pointers. */
    skb->head = data;
    skb->data = data;
    skb->tail = data;
    skb->end = data + size;

    /* Set up other state */
    skb->len = 0;
    skb->data_len = 0;
    skb->src_vif = VIF_UNKNOWN_INTERFACE;
    skb->dst_vif = VIF_UNKNOWN_INTERFACE;
    skb->skb_type = SKB_NORMAL;

    skb_shinfo(skb)->nr_frags = 0;
    return skb;

 nodata:
    skb_head_to_pool(skb);
 nohead:
    return NULL;
}


struct sk_buff *alloc_zc_skb(unsigned int size,int gfp_mask)
{
    struct sk_buff *skb;
    u8 *data;

    INTERRUPT_CHECK(gfp_mask);

    /* Get the HEAD */
    skb = skb_head_from_pool();
    if (skb == NULL) {
        skb = kmem_cache_alloc(skbuff_head_cache, gfp_mask & ~__GFP_DMA);
        if (skb == NULL)
            goto nohead;
    }

    /* Get the DATA. Size must match skb_add_mtu(). */
    size = SKB_DATA_ALIGN(size);
    data = alloc_skb_data_page(skb);

    if (data == NULL)
        goto nodata;

    /* A FAKE virtual address, so that pci_map_xxx dor the right thing. */
    data = phys_to_virt((unsigned long)data); 
        
    /* Load the data pointers. */
    skb->head = data;
    skb->data = data;
    skb->tail = data;
    skb->end = data + size;

    /* Set up other state */
    skb->len = 0;
    skb->data_len = 0;
    skb->src_vif = VIF_UNKNOWN_INTERFACE;
    skb->dst_vif = VIF_UNKNOWN_INTERFACE;
    skb->skb_type = SKB_ZERO_COPY;

    skb_shinfo(skb)->nr_frags = 0;

    return skb;

 nodata:
    skb_head_to_pool(skb);
 nohead:
    return NULL;
}


struct sk_buff *alloc_skb_nodata(int gfp_mask)
{
    struct sk_buff *skb;

    INTERRUPT_CHECK(gfp_mask);

    /* Get the HEAD */
    skb = skb_head_from_pool();
    if (skb == NULL) {
        skb = kmem_cache_alloc(skbuff_head_cache, gfp_mask & ~__GFP_DMA);
        if (skb == NULL)
            return NULL;
    }

    skb->skb_type = SKB_NODATA;
    return skb;
}


/*
 *	Slab constructor for a skb head. 
 */ 
static inline void skb_headerinit(void *p, kmem_cache_t *cache, 
				  unsigned long flags)
{
    struct sk_buff *skb = p;

    skb->next = NULL;
    skb->prev = NULL;
    skb->list = NULL;
    skb->dev = NULL;
    skb->pkt_type = PACKET_HOST;	/* Default type */
    skb->ip_summed = 0;
    skb->destructor = NULL;
}

static void skb_release_data(struct sk_buff *skb)
{
    if (skb_shinfo(skb)->nr_frags) BUG();

    switch ( skb->skb_type )
    {
    case SKB_NORMAL:
        kfree(skb->head);
        break;
    case SKB_ZERO_COPY:
        dealloc_skb_data_page(skb);
        break;
    case SKB_NODATA:
        break;
    default:
        BUG();
    }
}

/*
 *	Free an skbuff by memory without cleaning the state. 
 */
void kfree_skbmem(struct sk_buff *skb)
{
    skb_release_data(skb);
    skb_head_to_pool(skb);
}

/**
 *	__kfree_skb - private function 
 *	@skb: buffer
 *
 *	Free an sk_buff. Release anything attached to the buffer. 
 *	Clean the state. This is an internal helper function. Users should
 *	always call kfree_skb
 */

void __kfree_skb(struct sk_buff *skb)
{
    if ( skb->list )
        panic(KERN_WARNING "Warning: kfree_skb passed an skb still "
              "on a list (from %p).\n", NET_CALLER(skb));

    if ( skb->destructor )
        skb->destructor(skb);

    skb_headerinit(skb, NULL, 0);  /* clean state */
    kfree_skbmem(skb);
}

static void copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
    /*
     *	Shift between the two data areas in bytes
     */
    unsigned long offset = new->data - old->data;

    new->list=NULL;
    new->dev=old->dev;
    new->protocol=old->protocol;
    new->h.raw=old->h.raw+offset;
    new->nh.raw=old->nh.raw+offset;
    new->mac.raw=old->mac.raw+offset;
    new->pkt_type=old->pkt_type;
    new->destructor = NULL;
}

/**
 *	skb_copy	-	create private copy of an sk_buff
 *	@skb: buffer to copy
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and its data. This is used when the
 *	caller wishes to modify the data and needs a private copy of the 
 *	data to alter. Returns %NULL on failure or the pointer to the buffer
 *	on success. The returned buffer has a reference count of 1.
 *
 *	As by-product this function converts non-linear &sk_buff to linear
 *	one, so that &sk_buff becomes completely private and caller is allowed
 *	to modify all the data of returned buffer. This means that this
 *	function is not recommended for use in circumstances when only
 *	header is going to be modified. Use pskb_copy() instead.
 */
 
struct sk_buff *skb_copy(const struct sk_buff *skb, int gfp_mask)
{
    struct sk_buff *n;
    int headerlen = skb->data-skb->head;

    /*
     *	Allocate the copy buffer
     */
    n=alloc_skb(skb->end - skb->head + skb->data_len, gfp_mask);
    if(n==NULL)
        return NULL;

    /* Set the data pointer */
    skb_reserve(n,headerlen);
    /* Set the tail pointer and length */
    skb_put(n,skb->len);
    n->csum = skb->csum;
    n->ip_summed = skb->ip_summed;

    if (skb_copy_bits(skb, -headerlen, n->head, headerlen+skb->len))
        BUG();

    copy_skb_header(n, skb);

    return n;
}

/* Copy some data bits from skb to kernel buffer. */

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
    int i, copy;
    int start = skb->len - skb->data_len;

    if (offset > (int)skb->len-len)
        goto fault;

    /* Copy header. */
    if ((copy = start-offset) > 0) {
        if (copy > len)
            copy = len;
        memcpy(to, skb->data + offset, copy);
        if ((len -= copy) == 0)
            return 0;
        offset += copy;
        to += copy;
    }

    for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
        int end;

        BUG_TRAP(start <= offset+len);

        end = start + skb_shinfo(skb)->frags[i].size;
        if ((copy = end-offset) > 0) {
            u8 *vaddr;

            if (copy > len)
                copy = len;

            vaddr = kmap_skb_frag(&skb_shinfo(skb)->frags[i]);
            memcpy(to, vaddr+skb_shinfo(skb)->frags[i].page_offset+
                   offset-start, copy);
            kunmap_skb_frag(vaddr);

            if ((len -= copy) == 0)
                return 0;
            offset += copy;
            to += copy;
        }
        start = end;
    }

    if (len == 0)
        return 0;

 fault:
    return -EFAULT;
}

void __init skb_init(void)
{
    int i;

    skbuff_head_cache = kmem_cache_create("skbuff_head_cache",
                                          sizeof(struct sk_buff),
                                          0,
                                          SLAB_HWCACHE_ALIGN,
                                          skb_headerinit, NULL);
    if (!skbuff_head_cache)
        panic("cannot create skbuff cache");

    for (i=0; i<NR_CPUS; i++)
        skb_queue_head_init(&skb_head_pool[i].list);
}
