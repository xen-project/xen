/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2006 Nick Piggin
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef _XEN_RADIX_TREE_H
#define _XEN_RADIX_TREE_H

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/rcupdate.h>

/*
 * An indirect pointer (root->rnode pointing to a radix_tree_node, rather
 * than a data item) is signalled by the low bit set in the root->rnode
 * pointer.
 *
 * In this case root->height is > 0, but the indirect pointer tests are
 * needed for RCU lookups (because root->height is unreliable). The only
 * time callers need worry about this is when doing a lookup_slot under
 * RCU.
 *
 * Indirect pointer in fact is also used to tag the last pointer of a node
 * when it is shrunk, before we rcu free the node. See shrink code for
 * details.
 */
#define RADIX_TREE_INDIRECT_PTR	1

static inline int radix_tree_is_indirect_ptr(void *ptr)
{
	return (int)((unsigned long)ptr & RADIX_TREE_INDIRECT_PTR);
}

/*
 *** Radix tree structure definitions.
 *** These are public to allow users to allocate instances of them.
 *** However all fields are absolutely private.
 */

#define RADIX_TREE_MAP_SHIFT	6
#define RADIX_TREE_MAP_SIZE	(1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK	(RADIX_TREE_MAP_SIZE-1)

struct radix_tree_node {
	unsigned int	height;		/* Height from the bottom */
	unsigned int	count;
	void __rcu	*slots[RADIX_TREE_MAP_SIZE];
};

typedef struct radix_tree_node *radix_tree_alloc_fn_t(void *);
typedef void radix_tree_free_fn_t(struct radix_tree_node *, void *);

struct radix_tree_root {
	unsigned int		height;
	struct radix_tree_node	__rcu *rnode;

	/* Allow to specify custom node alloc/dealloc routines. */
	radix_tree_alloc_fn_t *node_alloc;
	radix_tree_free_fn_t *node_free;
	void *node_alloc_free_arg;
};

/*
 *** radix-tree API starts here **
 */

void radix_tree_init(struct radix_tree_root *root);
void radix_tree_set_alloc_callbacks(
	struct radix_tree_root *root,
	radix_tree_alloc_fn_t *node_alloc,
	radix_tree_free_fn_t *node_free,
	void *node_alloc_free_arg);

void radix_tree_destroy(
	struct radix_tree_root *root,
	void (*slot_free)(void *));

/**
 * Radix-tree synchronization
 *
 * The radix-tree API requires that users provide all synchronisation (with
 * specific exceptions, noted below).
 *
 * Synchronization of access to the data items being stored in the tree, and
 * management of their lifetimes must be completely managed by API users.
 *
 * For API usage, in general,
 * - any function _modifying_ the tree (inserting or deleting items) must
 *   exclude other modifications, and exclude any functions reading the tree.
 * - any function _reading_ the tree (looking up items) must exclude
 *   modifications to the tree, but may occur concurrently with other readers.
 *
 * The notable exceptions to this rule are the following functions:
 * radix_tree_lookup
 * radix_tree_lookup_slot
 * radix_tree_gang_lookup
 * radix_tree_gang_lookup_slot
 *
 * The first 7 functions are able to be called locklessly, using RCU. The
 * caller must ensure calls to these functions are made within rcu_read_lock()
 * regions. Other readers (lock-free or otherwise) and modifications may be
 * running concurrently.
 *
 * It is still required that the caller manage the synchronization and lifetimes
 * of the items. So if RCU lock-free lookups are used, typically this would mean
 * that the items have their own locks, or are amenable to lock-free access; and
 * that the items are freed by RCU (or only freed after having been deleted from
 * the radix tree *and* a synchronize_rcu() grace period).
 *
 * (Note, rcu_assign_pointer and rcu_dereference are not needed to control
 * access to data items when inserting into or looking up from the radix tree)
 */

/**
 * radix_tree_deref_slot	- dereference a slot
 * @pslot:	pointer to slot, returned by radix_tree_lookup_slot
 * Returns:	item that was stored in that slot with any direct pointer flag
 *		removed.
 *
 * For use with radix_tree_lookup_slot().  Caller must hold tree at least read
 * locked across slot lookup and dereference. Not required if write lock is
 * held (ie. items cannot be concurrently inserted).
 *
 * radix_tree_deref_retry must be used to confirm validity of the pointer if
 * only the read lock is held.
 */
static inline void *radix_tree_deref_slot(void **pslot)
{
	return rcu_dereference(*pslot);
}

/**
 * radix_tree_deref_retry	- check radix_tree_deref_slot
 * @arg:	pointer returned by radix_tree_deref_slot
 * Returns:	0 if retry is not required, otherwise retry is required
 *
 * radix_tree_deref_retry must be used with radix_tree_deref_slot.
 */
static inline int radix_tree_deref_retry(void *arg)
{
	return unlikely((unsigned long)arg & RADIX_TREE_INDIRECT_PTR);
}

/**
 * radix_tree_replace_slot	- replace item in a slot
 * @pslot:	pointer to slot, returned by radix_tree_lookup_slot
 * @item:	new item to store in the slot.
 *
 * For use with radix_tree_lookup_slot().  Caller must hold tree write locked
 * across slot lookup and replacement.
 */
static inline void radix_tree_replace_slot(void **pslot, void *item)
{
	BUG_ON(radix_tree_is_indirect_ptr(item));
	rcu_assign_pointer(*pslot, item);
}


/**
 * radix_tree_{int_to_ptr,ptr_to_int}:
 * 
 * Allow storage of signed integers in radix-tree slots. We use an encoding
 * in which the bottom two bits of the slot pointer are reserved (bit 0 for
 * the indirect-pointer tag; bit 1 always set to prevent an in-use
 * integer-valued slot from being NULL and thus mistakenly being reaped).
 */
static inline void *radix_tree_int_to_ptr(int val)
{
    long _ptr = ((long)val << 2) | 0x2l;
    ASSERT((_ptr >> 2) == val);
    return (void *)_ptr;
}

static inline int radix_tree_ptr_to_int(void *ptr)
{
    ASSERT(((long)ptr & 0x3) == 0x2);
    return (int)((long)ptr >> 2);
}

int radix_tree_insert(struct radix_tree_root *, unsigned long, void *);
void *radix_tree_lookup(struct radix_tree_root *, unsigned long);
void **radix_tree_lookup_slot(struct radix_tree_root *, unsigned long);
void *radix_tree_delete(struct radix_tree_root *, unsigned long);
unsigned int
radix_tree_gang_lookup(struct radix_tree_root *root, void **results,
			unsigned long first_index, unsigned int max_items);
unsigned int
radix_tree_gang_lookup_slot(struct radix_tree_root *root, void ***results,
			unsigned long first_index, unsigned int max_items);
unsigned long radix_tree_next_hole(struct radix_tree_root *root,
				unsigned long index, unsigned long max_scan);
unsigned long radix_tree_prev_hole(struct radix_tree_root *root,
				unsigned long index, unsigned long max_scan);

#endif /* _XEN_RADIX_TREE_H */
