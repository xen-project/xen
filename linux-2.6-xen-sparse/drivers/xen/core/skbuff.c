
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
#include <asm/hypervisor.h>

/* Referenced in netback.c. */
/*static*/ kmem_cache_t *skbuff_cachep;
EXPORT_SYMBOL(skbuff_cachep);

#define MAX_SKBUFF_ORDER 4
static kmem_cache_t *skbuff_order_cachep[MAX_SKBUFF_ORDER + 1];

static struct {
	int size;
	kmem_cache_t *cachep;
} skbuff_small[] = { { 512, NULL }, { 2048, NULL } };

struct sk_buff *__alloc_skb(unsigned int length, gfp_t gfp_mask,
			    int fclone)
{
	int order, i;
	kmem_cache_t *cachep;

	length = SKB_DATA_ALIGN(length) + sizeof(struct skb_shared_info);

	if (length <= skbuff_small[ARRAY_SIZE(skbuff_small)-1].size) {
		for (i = 0; skbuff_small[i].size < length; i++)
			continue;
		cachep = skbuff_small[i].cachep;
	} else {
		order = get_order(length);
		if (order > MAX_SKBUFF_ORDER) {
			printk(KERN_ALERT "Attempt to allocate order %d "
			       "skbuff. Increase MAX_SKBUFF_ORDER.\n", order);
			return NULL;
		}
		cachep = skbuff_order_cachep[order];
	}

	length -= sizeof(struct skb_shared_info);

	return alloc_skb_from_cache(cachep, length, gfp_mask, fclone);
}

struct sk_buff *__dev_alloc_skb(unsigned int length, gfp_t gfp_mask)
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
		skbuff_order_cachep[order], length, gfp_mask, 0);
	if (skb != NULL)
		skb_reserve(skb, 16);

	return skb;
}

static void skbuff_ctor(void *buf, kmem_cache_t *cachep, unsigned long unused)
{
	int order = 0;

	while (skbuff_order_cachep[order] != cachep)
		order++;

	/* Do our best to allocate contiguous memory but fall back to IOMMU. */
	if (order != 0)
		(void)xen_create_contiguous_region(
			(unsigned long)buf, order, 0);

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
	static char small_name[ARRAY_SIZE(skbuff_small)][20];
	unsigned long size;
	int i, order;

	for (i = 0; i < ARRAY_SIZE(skbuff_small); i++) {
		size = skbuff_small[i].size;
		sprintf(small_name[i], "xen-skb-%lu", size);
		/*
		 * No ctor/dtor: objects do not span page boundaries, and they
		 * are only used on transmit path so no need for scrubbing.
		 */
		skbuff_small[i].cachep = kmem_cache_create(
			small_name[i], size, size, 0, NULL, NULL);
	}

	for (order = 0; order <= MAX_SKBUFF_ORDER; order++) {
		size = PAGE_SIZE << order;
		sprintf(name[order], "xen-skb-%lu", size);
		skbuff_order_cachep[order] = kmem_cache_create(
			name[order], size, size, 0, skbuff_ctor, skbuff_dtor);
	}

	skbuff_cachep = skbuff_order_cachep[0];

	return 0;
}
core_initcall(skbuff_init);

EXPORT_SYMBOL(__dev_alloc_skb);
