/*
 *	linux/kernel/resource.c
 *
 * Copyright (C) 1999	Linus Torvalds
 * Copyright (C) 1999	Martin Mares <mj@ucw.cz>
 *
 * Arbitrary resource management.
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/ioport.h>
#include <xen/init.h>
#include <xen/slab.h>
#include <xen/spinlock.h>
#include <asm/io.h>

struct resource ioport_resource = { "PCI IO", 0x0000, IO_SPACE_LIMIT, IORESOURCE_IO };
struct resource iomem_resource = { "PCI mem", 0x00000000, 0xffffffff, IORESOURCE_MEM };

static rwlock_t resource_lock = RW_LOCK_UNLOCKED;

/*
 * This generates reports for /proc/ioports and /proc/iomem
 */
static char * do_resource_list(struct resource *entry, const char *fmt, int offset, char *buf, char *end)
{
	if (offset < 0)
		offset = 0;

	while (entry) {
		const char *name = entry->name;
		unsigned long from, to;

		if ((int) (end-buf) < 80)
			return buf;

		from = entry->start;
		to = entry->end;
		if (!name)
			name = "<BAD>";

		buf += sprintf(buf, fmt + offset, from, to, name);
		if (entry->child)
			buf = do_resource_list(entry->child, fmt, offset-2, buf, end);
		entry = entry->sibling;
	}

	return buf;
}

int get_resource_list(struct resource *root, char *buf, int size)
{
	char *fmt;
	int retval;

	fmt = "        %08lx-%08lx : %s\n";
	if (root->end < 0x10000)
		fmt = "        %04lx-%04lx : %s\n";
	read_lock(&resource_lock);
	retval = do_resource_list(root->child, fmt, 8, buf, buf + size) - buf;
	read_unlock(&resource_lock);
	return retval;
}	

/* Return the conflict entry if you can't request it */
static struct resource * __request_resource(struct resource *root, struct resource *new)
{
	unsigned long start = new->start;
	unsigned long end = new->end;
	struct resource *tmp, **p;

	if (end < start)
		return root;
	if (start < root->start)
		return root;
	if (end > root->end)
		return root;
	p = &root->child;
	for (;;) {
		tmp = *p;
		if (!tmp || tmp->start > end) {
			new->sibling = tmp;
			*p = new;
			new->parent = root;
			return NULL;
		}
		p = &tmp->sibling;
		if (tmp->end < start)
			continue;
		return tmp;
	}
}

static int __release_resource(struct resource *old)
{
	struct resource *tmp, **p;

	p = &old->parent->child;
	for (;;) {
		tmp = *p;
		if (!tmp)
			break;
		if (tmp == old) {
			*p = tmp->sibling;
			old->parent = NULL;
			return 0;
		}
		p = &tmp->sibling;
	}
	return -EINVAL;
}

int request_resource(struct resource *root, struct resource *new)
{
	struct resource *conflict;

	write_lock(&resource_lock);
	conflict = __request_resource(root, new);
	write_unlock(&resource_lock);
	return conflict ? -EBUSY : 0;
}

int release_resource(struct resource *old)
{
	int retval;

	write_lock(&resource_lock);
	retval = __release_resource(old);
	write_unlock(&resource_lock);
	return retval;
}

int check_resource(struct resource *root, unsigned long start, unsigned long len)
{
	struct resource *conflict, tmp;

	tmp.start = start;
	tmp.end = start + len - 1;
	write_lock(&resource_lock);
	conflict = __request_resource(root, &tmp);
	if (!conflict)
		__release_resource(&tmp);
	write_unlock(&resource_lock);
	return conflict ? -EBUSY : 0;
}

/*
 * Find empty slot in the resource tree given range and alignment.
 */
static int find_resource(struct resource *root, struct resource *new,
			 unsigned long size,
			 unsigned long min, unsigned long max,
			 unsigned long align,
			 void (*alignf)(void *, struct resource *,
					unsigned long, unsigned long),
			 void *alignf_data)
{
	struct resource *this = root->child;

	new->start = root->start;
	for(;;) {
		if (this)
			new->end = this->start;
		else
			new->end = root->end;
		if (new->start < min)
			new->start = min;
		if (new->end > max)
			new->end = max;
		new->start = (new->start + align - 1) & ~(align - 1);
		if (alignf)
			alignf(alignf_data, new, size, align);
		if (new->start < new->end && new->end - new->start + 1 >= size) {
			new->end = new->start + size - 1;
			return 0;
		}
		if (!this)
			break;
		new->start = this->end + 1;
		this = this->sibling;
	}
	return -EBUSY;
}

/*
 * Allocate empty slot in the resource tree given range and alignment.
 */
int allocate_resource(struct resource *root, struct resource *new,
		      unsigned long size,
		      unsigned long min, unsigned long max,
		      unsigned long align,
		      void (*alignf)(void *, struct resource *,
				     unsigned long, unsigned long),
		      void *alignf_data)
{
	int err;

	write_lock(&resource_lock);
	err = find_resource(root, new, size, min, max, align, alignf, alignf_data);
	if (err >= 0 && __request_resource(root, new))
		err = -EBUSY;
	write_unlock(&resource_lock);
	return err;
}

/*
 * This is compatibility stuff for IO resources.
 *
 * Note how this, unlike the above, knows about
 * the IO flag meanings (busy etc).
 *
 * Request-region creates a new busy region.
 *
 * Check-region returns non-zero if the area is already busy
 *
 * Release-region releases a matching busy region.
 */
struct resource * __request_region(struct resource *parent, unsigned long start, unsigned long n, const char *name)
{
	struct resource *res = xmalloc(struct resource);

	if (res) {
		memset(res, 0, sizeof(*res));
		res->name = name;
		res->start = start;
		res->end = start + n - 1;
		res->flags = IORESOURCE_BUSY;

		write_lock(&resource_lock);

		for (;;) {
			struct resource *conflict;

			conflict = __request_resource(parent, res);
			if (!conflict)
				break;
			if (conflict != parent) {
				parent = conflict;
				if (!(conflict->flags & IORESOURCE_BUSY))
					continue;
			}

			/* Uhhuh, that didn't work out.. */
			xfree(res);
			res = NULL;
			break;
		}
		write_unlock(&resource_lock);
	}
	return res;
}

void __release_region(struct resource *parent, unsigned long start, unsigned long n)
{
	struct resource **p;
	unsigned long end;

	p = &parent->child;
	end = start + n - 1;

	for (;;) {
		struct resource *res = *p;

		if (!res)
			break;
		if (res->start <= start && res->end >= end) {
			if (!(res->flags & IORESOURCE_BUSY)) {
				p = &res->child;
				continue;
			}
			if (res->start != start || res->end != end)
				break;
			*p = res->sibling;
			xfree(res);
			return;
		}
		p = &res->sibling;
	}
	printk("Trying to free nonexistent resource <%08lx-%08lx>\n", start, end);
}


#if 0
/*
 * Called from init/main.c to reserve IO ports.
 */
#define MAXRESERVE 4
static int __init reserve_setup(char *str)
{
	static int reserved = 0;
	static struct resource reserve[MAXRESERVE];

	for (;;) {
		int io_start, io_num;
		int x = reserved;

		if (get_option (&str, &io_start) != 2)
			break;
		if (get_option (&str, &io_num)   == 0)
			break;
		if (x < MAXRESERVE) {
			struct resource *res = reserve + x;
			res->name = "reserved";
			res->start = io_start;
			res->end = io_start + io_num - 1;
			res->flags = IORESOURCE_BUSY;
			res->child = NULL;
			if (request_resource(res->start >= 0x10000 ? &iomem_resource : &ioport_resource, res) == 0)
				reserved = x+1;
		}
	}
	return 1;
}

__setup("reserve=", reserve_setup);
#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
