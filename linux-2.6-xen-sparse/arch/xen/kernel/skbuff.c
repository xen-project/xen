
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

/* Size must be cacheline-aligned (alloc_skb uses SKB_DATA_ALIGN). */
#define XEN_SKB_SIZE \
    ((PAGE_SIZE - sizeof(struct skb_shared_info)) & ~(SMP_CACHE_BYTES - 1))

struct sk_buff *__dev_alloc_skb(unsigned int length, int gfp_mask)
{
    struct sk_buff *skb;
    skb = alloc_skb_from_cache(skbuff_cachep, length + 16, gfp_mask);
    if ( likely(skb != NULL) )
        skb_reserve(skb, 16);
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
