
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/page.h>

EXPORT_SYMBOL(__dev_alloc_skb);

/* Referenced in netback.c. */
/*static*/ kmem_cache_t *skbuff_cachep;

struct sk_buff *__dev_alloc_skb(unsigned int length, int gfp_mask)
{
    struct sk_buff *skb;
    u8             *new_data, *new_shinfo; 

    /*
     * Yuk! There is no way to get a skbuff head without allocating the
     * data area using kmalloc(). So we do that and then replace the default
     * data area with our own.
     */
    skb = alloc_skb(0, gfp_mask);
    if ( unlikely(skb == NULL) )
        return NULL;

    new_data = kmem_cache_alloc(skbuff_cachep, gfp_mask);
    if ( new_data == NULL )
    {
        dev_kfree_skb(skb);
        return NULL;
    }

    new_shinfo = 
        new_data + PAGE_SIZE - sizeof(struct skb_shared_info);
    memcpy(new_shinfo, skb_shinfo(skb), sizeof(struct skb_shared_info));

    kfree(skb->head);

    skb->head = new_data;
    skb->data = skb->tail = new_data + 16; /* __dev_alloc_skb does this */
    skb->end  = new_shinfo;
    skb->truesize = 1500;                  /* is this important? */

    return skb;
}

static void skbuff_ctor(void *buf, kmem_cache_t *cachep, unsigned long unused)
{
    scrub_pages(buf, 1);
}

static int __init skbuff_init(void)
{
    skbuff_cachep = kmem_cache_create(
        "xen-skb", PAGE_SIZE, PAGE_SIZE, 0, skbuff_ctor, NULL);
    return 0;
}
__initcall(skbuff_init);
