
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm-xen/hypervisor.h>

/* Referenced in netback.c. */
/*static*/ kmem_cache_t *skbuff_cachep;

#define MAX_SKBUFF_ORDER 2
static kmem_cache_t *skbuff_order_cachep[MAX_SKBUFF_ORDER + 1];

struct sk_buff *__dev_alloc_skb(unsigned int length, int gfp_mask)
{
	struct sk_buff *skb;
	int order;

	length = SKB_DATA_ALIGN(length + 16);
	order = get_order(length + sizeof(struct skb_shared_info));
	if (order > MAX_SKBUFF_ORDER) {
		printk(KERN_ALERT "Attempt to allocate order %d skbuff. "
		       "Increase MAX_SKBUFF_ORDER.\n", order);
		return NULL;
	}

	skb = alloc_skb_from_cache(
		skbuff_order_cachep[order], length, gfp_mask);
	if (skb != NULL)
		skb_reserve(skb, 16);

	return skb;
}

static void skbuff_ctor(void *buf, kmem_cache_t *cachep, unsigned long unused)
{
	int order = 0;

	while (skbuff_order_cachep[order] != cachep)
		order++;

	if (order != 0)
		xen_create_contiguous_region((unsigned long)buf, order);

	scrub_pages(buf, 1 << order);
}

static void skbuff_dtor(void *buf, kmem_cache_t *cachep, unsigned long unused)
{
	int order = 0;

	while (skbuff_order_cachep[order] != cachep)
		order++;

	if (order != 0)
		xen_destroy_contiguous_region((unsigned long)buf, order);
}

static int __init skbuff_init(void)
{
	static char name[MAX_SKBUFF_ORDER + 1][20];
	unsigned long size;
	int order;

	for (order = 0; order <= MAX_SKBUFF_ORDER; order++) {
		size = PAGE_SIZE << order;
		sprintf(name[order], "xen-skb-%lu", size);
		skbuff_order_cachep[order] = kmem_cache_create(
			name[order], size, size, 0, skbuff_ctor, skbuff_dtor);
	}

	skbuff_cachep = skbuff_order_cachep[0];

	return 0;
}
__initcall(skbuff_init);

EXPORT_SYMBOL(__dev_alloc_skb);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
