/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2005 SGI, Christoph Lameter <clameter@sgi.com>
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

/*
 * Copyright (C) 2009 adaption for Xen tmem by Dan Magenheimer, Oracle Corp.
 * Changed:
 * o Linux 2.6.18 source used (prior to read-copy-update addition)
 * o constants and data structures moved out to radix-tree.h header
 * o tagging code removed
 * o radix_tree_insert has func parameter for dynamic data struct allocation
 * o radix_tree_destroy added (including recursive helper function)
 * o __init functions must be called explicitly
 * o other include files adapted to Xen
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/radix-tree.h>
#include <asm/cache.h>

static unsigned long height_to_maxindex[RADIX_TREE_MAX_PATH + 1] __read_mostly;

/*
 * Return the maximum key which can be store into a
 * radix tree with height HEIGHT.
 */
static inline unsigned long radix_tree_maxindex(unsigned int height)
{
    return height_to_maxindex[height];
}

/*
 * Extend a radix tree so it can store key @index.
 */
static int radix_tree_extend(struct radix_tree_root *root, unsigned long index,
                             struct radix_tree_node *(*node_alloc)(void *), void *arg)
{
    struct radix_tree_node *node;
    unsigned int height;

    /* Figure out what the height should be.  */
    height = root->height + 1;
    if (index > radix_tree_maxindex(height))
        while (index > radix_tree_maxindex(height))
            height++;

    if (root->rnode == NULL) {
        root->height = height;
        goto out;
    }

    do {
        if (!(node = node_alloc(arg)))
            return -ENOMEM;

        /* Increase the height.  */
        node->slots[0] = root->rnode;

        node->count = 1;
        root->rnode = node;
        root->height++;
    } while (height > root->height);
 out:
    return 0;
}

/**
 * radix_tree_insert    -    insert into a radix tree
 * @root:  radix tree root
 * @index:  index key
 * @item:  item to insert
 *
 * Insert an item into the radix tree at position @index.
 */
int radix_tree_insert(struct radix_tree_root *root, unsigned long index,
                      void *item, struct radix_tree_node *(*node_alloc)(void *), void *arg)
{
    struct radix_tree_node *node = NULL, *slot;
    unsigned int height, shift;
    int offset;
    int error;

    /* Make sure the tree is high enough.  */
    if (index > radix_tree_maxindex(root->height)) {
        error = radix_tree_extend(root, index, node_alloc, arg);
        if (error)
            return error;
    }

    slot = root->rnode;
    height = root->height;
    shift = (height-1) * RADIX_TREE_MAP_SHIFT;

    offset = 0;   /* uninitialised var warning */
    while (height > 0) {
        if (slot == NULL) {
            /* Have to add a child node.  */
            if (!(slot = node_alloc(arg)))
                return -ENOMEM;
            if (node) {

                node->slots[offset] = slot;
                node->count++;
            } else
                root->rnode = slot;
        }

        /* Go a level down */
        offset = (index >> shift) & RADIX_TREE_MAP_MASK;
        node = slot;
        slot = node->slots[offset];
        shift -= RADIX_TREE_MAP_SHIFT;
        height--;
    }

    if (slot != NULL)
        return -EEXIST;

    if (node) {
        node->count++;
        node->slots[offset] = item;
    } else {
        root->rnode = item;
    }

    return 0;
}
EXPORT_SYMBOL(radix_tree_insert);

static inline void **__lookup_slot(struct radix_tree_root *root,
                                   unsigned long index)
{
    unsigned int height, shift;
    struct radix_tree_node **slot;

    height = root->height;

    if (index > radix_tree_maxindex(height))
        return NULL;

    if (height == 0 && root->rnode)
        return (void **)&root->rnode;

    shift = (height-1) * RADIX_TREE_MAP_SHIFT;
    slot = &root->rnode;

    while (height > 0) {
        if (*slot == NULL)
            return NULL;

        slot = (struct radix_tree_node **)
            ((*slot)->slots +
             ((index >> shift) & RADIX_TREE_MAP_MASK));
        shift -= RADIX_TREE_MAP_SHIFT;
        height--;
    }

    return (void **)slot;
}

/**
 * radix_tree_lookup_slot    -    lookup a slot in a radix tree
 * @root:  radix tree root
 * @index:  index key
 *
 * Lookup the slot corresponding to the position @index in the radix tree
 * @root. This is useful for update-if-exists operations.
 */
void **radix_tree_lookup_slot(struct radix_tree_root *root, unsigned long index)
{
    return __lookup_slot(root, index);
}
EXPORT_SYMBOL(radix_tree_lookup_slot);

/**
 * radix_tree_lookup    -    perform lookup operation on a radix tree
 * @root:  radix tree root
 * @index:  index key
 *
 * Lookup the item at the position @index in the radix tree @root.
 */
void *radix_tree_lookup(struct radix_tree_root *root, unsigned long index)
{
    void **slot;

    slot = __lookup_slot(root, index);
    return slot != NULL ? *slot : NULL;
}
EXPORT_SYMBOL(radix_tree_lookup);

static unsigned int
__lookup(struct radix_tree_root *root, void **results, unsigned long index,
         unsigned int max_items, unsigned long *next_index)
{
    unsigned int nr_found = 0;
    unsigned int shift, height;
    struct radix_tree_node *slot;
    unsigned long i;

    height = root->height;
    if (index > radix_tree_maxindex(height))
        if (height == 0) {
            if (root->rnode && index == 0)
                results[nr_found++] = root->rnode;
            goto out;
        }

    shift = (height-1) * RADIX_TREE_MAP_SHIFT;
    slot = root->rnode;

    for ( ; height > 1; height--) {

        for (i = (index >> shift) & RADIX_TREE_MAP_MASK ;
             i < RADIX_TREE_MAP_SIZE; i++) {
            if (slot->slots[i] != NULL)
                break;
            index &= ~((1UL << shift) - 1);
            index += 1UL << shift;
            if (index == 0)
                goto out; /* 32-bit wraparound */
        }
        if (i == RADIX_TREE_MAP_SIZE)
            goto out;

        shift -= RADIX_TREE_MAP_SHIFT;
        slot = slot->slots[i];
    }

    /* Bottom level: grab some items */
    for (i = index & RADIX_TREE_MAP_MASK; i < RADIX_TREE_MAP_SIZE; i++) {
        index++;
        if (slot->slots[i]) {
            results[nr_found++] = slot->slots[i];
            if (nr_found == max_items)
                goto out;
        }
    }
 out:
    *next_index = index;
    return nr_found;
}

/**
 * radix_tree_gang_lookup - perform multiple lookup on a radix tree
 * @root:  radix tree root
 * @results: where the results of the lookup are placed
 * @first_index: start the lookup from this key
 * @max_items: place up to this many items at *results
 *
 * Performs an index-ascending scan of the tree for present items.  Places
 * them at *@results and returns the number of items which were placed at
 * *@results.
 *
 * The implementation is naive.
 */
unsigned int
radix_tree_gang_lookup(struct radix_tree_root *root, void **results,
                       unsigned long first_index, unsigned int max_items)
{
    const unsigned long max_index = radix_tree_maxindex(root->height);
    unsigned long cur_index = first_index;
    unsigned int ret = 0;

    while (ret < max_items) {
        unsigned int nr_found;
        unsigned long next_index; /* Index of next search */

        if (cur_index > max_index)
            break;
        nr_found = __lookup(root, results + ret, cur_index,
                            max_items - ret, &next_index);
        ret += nr_found;
        if (next_index == 0)
            break;
        cur_index = next_index;
    }
    return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup);

/**
 * radix_tree_shrink    -    shrink height of a radix tree to minimal
 * @root  radix tree root
 */
static inline void radix_tree_shrink(struct radix_tree_root *root,
                                     void (*node_free)(struct radix_tree_node *))
{
    /* try to shrink tree height */
    while (root->height > 0 &&
           root->rnode->count == 1 &&
           root->rnode->slots[0]) {
        struct radix_tree_node *to_free = root->rnode;

        root->rnode = to_free->slots[0];
        root->height--;
        to_free->slots[0] = NULL;
        to_free->count = 0;
        node_free(to_free);
    }
}

/**
 * radix_tree_delete    -    delete an item from a radix tree
 * @root:  radix tree root
 * @index:  index key
 *
 * Remove the item at @index from the radix tree rooted at @root.
 *
 * Returns the address of the deleted item, or NULL if it was not present.
 */
void *radix_tree_delete(struct radix_tree_root *root, unsigned long index,
                        void(*node_free)(struct radix_tree_node *))
{
    struct radix_tree_path path[RADIX_TREE_MAX_PATH + 1], *pathp = path;
    struct radix_tree_node *slot = NULL;
    unsigned int height, shift;
    int offset;

    height = root->height;
    if (index > radix_tree_maxindex(height))
        goto out;

    slot = root->rnode;
    if (height == 0 && root->rnode) {
        root->rnode = NULL;
        goto out;
    }

    shift = (height - 1) * RADIX_TREE_MAP_SHIFT;
    pathp->node = NULL;

    do {
        if (slot == NULL)
            goto out;

        pathp++;
        offset = (index >> shift) & RADIX_TREE_MAP_MASK;
        pathp->offset = offset;
        pathp->node = slot;
        slot = slot->slots[offset];
        shift -= RADIX_TREE_MAP_SHIFT;
        height--;
    } while (height > 0);

    if (slot == NULL)
        goto out;

    /* Now free the nodes we do not need anymore */
    while (pathp->node) {
        pathp->node->slots[pathp->offset] = NULL;
        pathp->node->count--;

        if (pathp->node->count) {
            if (pathp->node == root->rnode)
                radix_tree_shrink(root, node_free);
            goto out;
        }

        /* Node with zero slots in use so free it */
        node_free(pathp->node);

        pathp--;
    }
    root->height = 0;
    root->rnode = NULL;

 out:
    return slot;
}
EXPORT_SYMBOL(radix_tree_delete);

static void
radix_tree_node_destroy(struct radix_tree_node *node, unsigned int height,
                        void (*slot_free)(void *), void (*node_free)(struct radix_tree_node *))
{
    int i;

    if (height == 0)
        return;
    for (i = 0; i < RADIX_TREE_MAP_SIZE; i++) {
        if (node->slots[i]) {
            if (height == 1) {
                slot_free(node->slots[i]);
                node->slots[i] = NULL;
                continue;
            }
            radix_tree_node_destroy(node->slots[i], height-1,
                                    slot_free, node_free);
            node_free(node->slots[i]);
            node->slots[i] = NULL;
        }
    }
}

void radix_tree_destroy(struct radix_tree_root *root,
                        void (*slot_free)(void *), void (*node_free)(struct radix_tree_node *))
{
    if (root->rnode == NULL)
        return;
    if (root->height == 0)
        slot_free(root->rnode);
    else {
        radix_tree_node_destroy(root->rnode, root->height,
                                slot_free, node_free);
        node_free(root->rnode);
        root->height = 0;
    }
    root->rnode = NULL;
    /* caller must delete root if desired */
}
EXPORT_SYMBOL(radix_tree_destroy);

static unsigned long __init __maxindex(unsigned int height)
{
    unsigned int tmp = height * RADIX_TREE_MAP_SHIFT;
    unsigned long index = (~0UL >> (RADIX_TREE_INDEX_BITS - tmp - 1)) >> 1;

    if (tmp >= RADIX_TREE_INDEX_BITS)
        index = ~0UL;
    return index;
}

void __init radix_tree_init(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(height_to_maxindex); i++)
        height_to_maxindex[i] = __maxindex(i);
}
