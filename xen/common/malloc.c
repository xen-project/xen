/* Simple allocator for Xen.  If larger than a page, simply use the
 * page-order allocator.
 *
 * Copyright (C) 2005 Rusty Russell IBM Corporation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <xen/mm.h>
#include <xen/spinlock.h>
#include <xen/ac_timer.h>

#define BUG_ON(x) do { if (x) BUG(); }while(0)

static LIST_HEAD(freelist);
static spinlock_t freelist_lock = SPIN_LOCK_UNLOCKED;

struct xmalloc_hdr
{
	/* Total including this hdr: negative means allocated. */
	long size;
	union {
		struct list_head freelist;
		char data[0];
	} u;
};

static void maybe_split(struct xmalloc_hdr *hdr, size_t size, size_t block)
{
	size_t leftover = block - size;

	/* If enough left to make a block, put it on free list. */
	if (leftover >= sizeof(struct xmalloc_hdr)) {
		struct xmalloc_hdr *extra;

		extra = (void *)hdr + size;
		extra->size = leftover;
		list_add(&extra->u.freelist, &freelist);
	} else
		size = block;

	hdr->size = -size;
}

static void *xmalloc_new_page(size_t size)
{
	struct xmalloc_hdr *hdr;
	unsigned long flags;

	hdr = (void *)alloc_xenheap_pages(0);
	if (!hdr)
		return NULL;

	spin_lock_irqsave(&freelist_lock, flags);
	maybe_split(hdr, size, PAGE_SIZE);
	spin_unlock_irqrestore(&freelist_lock, flags);
	return hdr->u.data;
}

/* Big object?  Just use page allocator. */
static void *xmalloc_whole_pages(size_t size)
{
	struct xmalloc_hdr *hdr;
	unsigned int pageorder = get_order(size);

	hdr = (void *)alloc_xenheap_pages(pageorder);
	if (!hdr)
		return NULL;

	hdr->size = -(1 << (pageorder + PAGE_SHIFT));
	return hdr->u.data;
}

void *__xmalloc(size_t size, const char *file, unsigned int line)
{
	struct xmalloc_hdr *i;
	unsigned long flags;

	/* Add room for header, align to unsigned long. */
	size += offsetof(struct xmalloc_hdr, u.data);
	size = ((size + sizeof(unsigned long)-1)&~(sizeof(unsigned long)-1));

	/* Minimum size is size of freelist entry. */
	if (size < sizeof(*i))
		size = sizeof(*i);

	/* For big allocs, give them whole pages. */
	if (size >= PAGE_SIZE)
		return xmalloc_whole_pages(size);

	/* Search free list */
	spin_lock_irqsave(&freelist_lock, flags);
	list_for_each_entry(i, &freelist, u.freelist) {
		if (i->size >= size) {
			list_del(&i->u.freelist);
			maybe_split(i, size, i->size);
			spin_unlock_irqrestore(&freelist_lock, flags);
			return i->u.data;
		}
	}
	spin_unlock_irqrestore(&freelist_lock, flags);

	/* Alloc a new page and return from that. */
	return xmalloc_new_page(size);
}

void __xfree(const void *p, const char *file, unsigned int line)
{
	unsigned long flags;
	struct xmalloc_hdr *i, *tmp, *hdr;

	if (!p)
		return;

	hdr = container_of((void *)p, struct xmalloc_hdr, u.data);

	/* We know hdr will be on same page. */
	BUG_ON(((long)p & PAGE_MASK) != ((long)hdr & PAGE_MASK));

	/* Not previously freed. */
	BUG_ON(hdr->size > 0);
	hdr->size = -hdr->size;

	/* Big allocs free directly. */
	if (hdr->size >= PAGE_SIZE) {
		free_xenheap_pages((unsigned long)hdr, get_order(hdr->size));
		return;
	}

	/* Merge with other free block, or put in list. */
	spin_lock_irqsave(&freelist_lock, flags);
	list_for_each_entry_safe(i, tmp, &freelist, u.freelist) {
		/* We follow this block?  Swallow it. */
		if ((void *)i + i->size == (void *)hdr) {
			list_del(&i->u.freelist);
			i->size += hdr->size;
			hdr = i;
		}
		/* It follows us?  Delete it and add it to us. */
		if ((void *)hdr + hdr->size == (void *)i) {
			list_del(&i->u.freelist);
			hdr->size += i->size;
		}
	}

	/* Did we free entire page? */
	if (hdr->size == PAGE_SIZE) {
		BUG_ON((((unsigned long)hdr) & (PAGE_SIZE-1)) != 0);
		free_xenheap_pages((unsigned long)hdr, 0);
	} else
		list_add(&hdr->u.freelist, &freelist);
	spin_unlock_irqrestore(&freelist_lock, flags);
}
