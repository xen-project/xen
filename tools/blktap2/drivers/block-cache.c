/* 
 * Copyright (c) 2008, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "tapdisk.h"
#include "tapdisk-utils.h"
#include "tapdisk-driver.h"
#include "tapdisk-server.h"
#include "tapdisk-interface.h"

#ifdef DEBUG
#define DBG(_f, _a...) tlog_write(TLOG_DBG, _f, ##_a)
#else
#define DBG(_f, _a...) ((void)0)
#endif

#define WARN(_f, _a...) tlog_write(TLOG_WARN, _f, ##_a)

#define RADIX_TREE_PAGE_SHIFT           12 /* 4K pages */
#define RADIX_TREE_PAGE_SIZE            (1 << RADIX_TREE_PAGE_SHIFT)

#define RADIX_TREE_NODE_SHIFT           9 /* 512B nodes */
#define RADIX_TREE_NODE_SIZE            (1 << RADIX_TREE_NODE_SHIFT)
#define RADIX_TREE_NODE_MASK            (RADIX_TREE_NODE_SIZE - 1)

#define BLOCK_CACHE_NODES_PER_PAGE      (1 << (RADIX_TREE_PAGE_SHIFT - RADIX_TREE_NODE_SHIFT))

#define BLOCK_CACHE_MAX_SIZE            (10 << 20) /* 100MB cache */
#define BLOCK_CACHE_REQUESTS            (TAPDISK_DATA_REQUESTS << 3)
#define BLOCK_CACHE_PAGE_IDLETIME       60

typedef struct radix_tree               radix_tree_t;
typedef struct radix_tree_node          radix_tree_node_t;
typedef struct radix_tree_link          radix_tree_link_t;
typedef struct radix_tree_leaf          radix_tree_leaf_t;
typedef struct radix_tree_page          radix_tree_page_t;

typedef struct block_cache              block_cache_t;
typedef struct block_cache_request      block_cache_request_t;
typedef struct block_cache_stats        block_cache_stats_t;

struct radix_tree_page {
	char                           *buf;
	size_t                          size;
	uint64_t                        sec;
	radix_tree_link_t              *owners[BLOCK_CACHE_NODES_PER_PAGE];
};

struct radix_tree_leaf {
	radix_tree_page_t              *page;
	char                           *buf;
};

struct radix_tree_link {
	uint32_t                        time;
	union {
		radix_tree_node_t      *next;
		radix_tree_leaf_t       leaf;
	} u;
};

struct radix_tree_node {
	int                             height;
	radix_tree_link_t               links[RADIX_TREE_NODE_SIZE];
};

struct radix_tree {
	int                             height;
	uint64_t                        size;
	uint32_t                        nodes;
	radix_tree_node_t              *root;

	block_cache_t                  *cache;
};

struct block_cache_request {
	int                             err;
	char                           *buf;
	uint64_t                        secs;
	td_request_t                    treq;
	block_cache_t                  *cache;
};

struct block_cache_stats {
	uint64_t                        reads;
	uint64_t                        hits;
	uint64_t                        misses;
	uint64_t                        prunes;
};

struct block_cache {
	int                             ptype;
	char                           *name;

	uint64_t                        sectors;

	block_cache_request_t           requests[BLOCK_CACHE_REQUESTS];
	block_cache_request_t          *request_free_list[BLOCK_CACHE_REQUESTS];
	int                             requests_free;

	event_id_t                      timeout_id;

	radix_tree_t                    tree;

	block_cache_stats_t             stats;
};

static inline uint64_t
radix_tree_calculate_size(int height)
{
	return (uint64_t)RADIX_TREE_NODE_SIZE <<
	  (height * RADIX_TREE_NODE_SHIFT);
}

static inline int
radix_tree_calculate_height(uint64_t sectors)
{
	int height;
	uint64_t tree_size;

	height = 1;  /* always allocate root node */
	tree_size = radix_tree_calculate_size(height);
	while (sectors > tree_size)
		tree_size = radix_tree_calculate_size(++height);

	return height;
}

static inline int
radix_tree_index(radix_tree_node_t *node, uint64_t sector)
{
	return ((sector >> (node->height * RADIX_TREE_NODE_SHIFT)) &
		RADIX_TREE_NODE_MASK);
}

static inline int
radix_tree_node_contains_leaves(radix_tree_t *tree, radix_tree_node_t *node)
{
	return (node->height == 0);
}

static inline int
radix_tree_node_is_root(radix_tree_t *tree, radix_tree_node_t *node)
{
	return (node->height == tree->height);
}

static inline uint64_t
radix_tree_size(radix_tree_t *tree)
{
	return tree->size + tree->nodes * sizeof(radix_tree_node_t);
}

static inline void
radix_tree_clear_link(radix_tree_link_t *link)
{
	if (link)
		memset(link, 0, sizeof(radix_tree_link_t));
}

static inline radix_tree_node_t *
radix_tree_allocate_node(radix_tree_t *tree, int height)
{
	radix_tree_node_t *node;

	node = calloc(1, sizeof(radix_tree_node_t));
	if (!node)
		return NULL;

	node->height = height;
	tree->nodes++;

	return node;
}

static inline radix_tree_node_t *
radix_tree_allocate_child_node(radix_tree_t *tree, radix_tree_node_t *parent)
{
	return radix_tree_allocate_node(tree, parent->height - 1);
}

void
radix_tree_free_node(radix_tree_t *tree, radix_tree_node_t *node)
{
	if (!node)
		return;

	free(node);
	tree->nodes--;
}

static inline radix_tree_page_t *
radix_tree_allocate_page(radix_tree_t *tree,
			 char *buf, uint64_t sec, size_t size)
{
	radix_tree_page_t *page;

	page = calloc(1, sizeof(radix_tree_page_t));
	if (!page)
		return NULL;

	page->buf   = buf;
	page->sec   = sec;
	page->size  = size;
	tree->size += size;

	return page;
}

static inline void
radix_tree_free_page(radix_tree_t *tree, radix_tree_page_t *page)
{
	int i;

	for (i = 0; i < page->size >> RADIX_TREE_NODE_SHIFT; i++)
		DBG("%s: ejecting sector 0x%llx\n",
		    tree->cache->name, page->sec + i);

	tree->cache->stats.prunes += (page->size >> RADIX_TREE_NODE_SHIFT);
	tree->size -= page->size;
	free(page->buf);
	free(page);
}

/*
 * remove a leaf and the shared radix_tree_page_t containing its buffer.
 * leaves are deleted, nodes are not; gc will reap the nodes later.
 */
static void
radix_tree_remove_page(radix_tree_t *tree, radix_tree_page_t *page)
{
	int i;

	if (!page)
		return;

	for (i = 0; i < BLOCK_CACHE_NODES_PER_PAGE; i++)
		radix_tree_clear_link(page->owners[i]);

	radix_tree_free_page(tree, page);
}

static void
radix_tree_insert_leaf(radix_tree_t *tree, radix_tree_link_t *link,
		       radix_tree_page_t *page, off_t off)
{
	int i;

	if (off + RADIX_TREE_NODE_SIZE > page->size)
		return;

	for (i = 0; i < BLOCK_CACHE_NODES_PER_PAGE; i++) {
		if (page->owners[i])
			continue;

		page->owners[i]   = link;
		link->u.leaf.page = page;
		link->u.leaf.buf  = page->buf + off;

		break;
	}
}

static char *
radix_tree_find_leaf(radix_tree_t *tree, uint64_t sector)
{
	int idx;
	struct timeval now;
	radix_tree_link_t *link;
	radix_tree_node_t *node;

	node = tree->root;
	gettimeofday(&now, NULL);

	do {
		idx        = radix_tree_index(node, sector);
		link       = node->links + idx;
		link->time = now.tv_sec;

		if (radix_tree_node_contains_leaves(tree, node))
			return link->u.leaf.buf;

		if (!link->u.next)
			return NULL;

		node = link->u.next;
	} while (1);
}

static char *
radix_tree_add_leaf(radix_tree_t *tree, uint64_t sector,
		    radix_tree_page_t *page, off_t off)
{
	int idx;
	struct timeval now;
	radix_tree_link_t *link;
	radix_tree_node_t *node;

	node = tree->root;
	gettimeofday(&now, NULL);

	do {
		idx        = radix_tree_index(node, sector);
		link       = node->links + idx;
		link->time = now.tv_sec;

		if (radix_tree_node_contains_leaves(tree, node)) {
			radix_tree_remove_page(tree, link->u.leaf.page);
			radix_tree_insert_leaf(tree, link, page, off);
			return link->u.leaf.buf;
		}

		if (!link->u.next) {
			link->u.next = radix_tree_allocate_child_node(tree,
								      node);
			if (!link->u.next)
				return NULL;
		}

		node = link->u.next;
	} while (1);
}

static int
radix_tree_add_leaves(radix_tree_t *tree, char *buf,
		      uint64_t sector, uint64_t sectors)
{
	int i;
	radix_tree_page_t *page;

	page = radix_tree_allocate_page(tree, buf, sector,
					sectors << RADIX_TREE_NODE_SHIFT);
	if (!page)
		return -ENOMEM;

	for (i = 0; i < sectors; i++)
		if (!radix_tree_add_leaf(tree, sector + i, 
					 page, (i << RADIX_TREE_NODE_SHIFT)))
			goto fail;

	return 0;

fail:
	page->buf = NULL;
	radix_tree_remove_page(tree, page);
	return -ENOMEM;
}

static void
radix_tree_delete_branch(radix_tree_t *tree, radix_tree_node_t *node)
{
	int i;
	radix_tree_link_t *link;

	if (!node)
		return;

	for (i = 0; i < RADIX_TREE_NODE_SIZE; i++) {
		link = node->links + i;

		if (radix_tree_node_contains_leaves(tree, node))
			radix_tree_remove_page(tree, link->u.leaf.page);
		else
			radix_tree_delete_branch(tree, link->u.next);

		radix_tree_clear_link(link);
	}

	radix_tree_free_node(tree, node);
}

static inline void
radix_tree_destroy(radix_tree_t *tree)
{
	radix_tree_delete_branch(tree, tree->root);
	tree->root = NULL;
}

/*
 * returns 1 if @node is empty after pruning, 0 otherwise
 */
static int
radix_tree_prune_branch(radix_tree_t *tree,
			radix_tree_node_t *node, uint32_t now)
{
	int i, empty;
	radix_tree_link_t *link;

	empty = 1;
	if (!node)
		return empty;

	for (i = 0; i < RADIX_TREE_NODE_SIZE; i++) {
		link = node->links + i;

		if (now - link->time < BLOCK_CACHE_PAGE_IDLETIME) {
			if (radix_tree_node_contains_leaves(tree, node)) {
				empty = 0;
				continue;
			}

			if (radix_tree_prune_branch(tree, link->u.next, now))
				radix_tree_clear_link(link);
			else
				empty = 0;

			continue;
		}

		if (radix_tree_node_contains_leaves(tree, node))
			radix_tree_remove_page(tree, link->u.leaf.page);
		else
			radix_tree_delete_branch(tree, link->u.next);

		radix_tree_clear_link(link);
	}

	if (empty && !radix_tree_node_is_root(tree, node))
		radix_tree_free_node(tree, node);

	return empty;
}

/*
 * walk tree and free any node that has been idle for too long
 */
static void
radix_tree_prune(radix_tree_t *tree)
{
	struct timeval now;

	if (!tree->root)
		return;

	DPRINTF("tree %s has %"PRIu64" bytes\n",
		tree->cache->name, tree->size);

	gettimeofday(&now, NULL);
	radix_tree_prune_branch(tree, tree->root, now.tv_sec);

	DPRINTF("tree %s now has %"PRIu64" bytes\n",
		tree->cache->name, tree->size);
}

static inline int
radix_tree_initialize(radix_tree_t *tree, uint64_t sectors)
{
	tree->height = radix_tree_calculate_height(sectors);
	tree->root   = radix_tree_allocate_node(tree, tree->height);
	if (!tree->root)
		return -ENOMEM;

	return 0;
}

static inline void
radix_tree_free(radix_tree_t *tree)
{
	radix_tree_destroy(tree);
}

static void
block_cache_prune_event(event_id_t id, char mode, void *private)
{
	radix_tree_t *tree;
	block_cache_t *cache;

	cache = (block_cache_t *)private;
	tree  = &cache->tree;

	radix_tree_prune(tree);
}

static inline block_cache_request_t *
block_cache_get_request(block_cache_t *cache)
{
	if (!cache->requests_free)
		return NULL;

	return cache->request_free_list[--cache->requests_free];
}

static inline void
block_cache_put_request(block_cache_t *cache, block_cache_request_t *breq)
{
	memset(breq, 0, sizeof(block_cache_request_t));
	cache->request_free_list[cache->requests_free++] = breq;
}

static int
block_cache_open(td_driver_t *driver, const char *name, td_flag_t flags)
{
	int i, err;
	radix_tree_t *tree;
	block_cache_t *cache;

	if (!td_flag_test(flags, TD_OPEN_RDONLY))
		return -EINVAL;

	if (driver->info.sector_size != RADIX_TREE_NODE_SIZE)
		return -EINVAL;

	cache = (block_cache_t *)driver->data;
	err   = tapdisk_namedup(&cache->name, (char *)name);
	if (err)
		return -ENOMEM;

	cache->sectors = driver->info.size;

	tree = &cache->tree;
	err  = radix_tree_initialize(tree, cache->sectors);
	if (err)
		goto fail;

	tree->cache = cache;
	cache->requests_free = BLOCK_CACHE_REQUESTS;
	for (i = 0; i < BLOCK_CACHE_REQUESTS; i++)
		cache->request_free_list[i] = cache->requests + i;

	cache->timeout_id = tapdisk_server_register_event(SCHEDULER_POLL_TIMEOUT,
							  -1, /* dummy fd */
							  BLOCK_CACHE_PAGE_IDLETIME << 1,
							  block_cache_prune_event,
							  cache);
	if (cache->timeout_id < 0)
		goto fail;

	DPRINTF("opening cache for %s, sectors: %"PRIu64", "
		"tree: %p, height: %d\n",
		cache->name, cache->sectors, tree, tree->height);

	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		DPRINTF("mlockall failed: %d\n", -errno);

	return 0;

fail:
	free(cache->name);
	radix_tree_free(&cache->tree);
	return err;
}

static int
block_cache_close(td_driver_t *driver)
{
	radix_tree_t *tree;
	block_cache_t *cache;

	cache = (block_cache_t *)driver->data;
	tree  = &cache->tree;

	DPRINTF("closing cache for %s\n", cache->name);

	tapdisk_server_unregister_event(cache->timeout_id);
	radix_tree_free(tree);
	free(cache->name);

	return 0;
}

static inline uint64_t
block_cache_hash(block_cache_t *cache, char *buf)
{
	int i, n;
	uint64_t cksm, *data;

	return 0;

	cksm = 0;
	data = (uint64_t *)buf;
	n    = RADIX_TREE_NODE_SIZE / sizeof(uint64_t);

	for (i = 0; i < n; i++)
		cksm += data[i];

	return ~cksm;
}

static void
block_cache_hit(block_cache_t *cache, td_request_t treq, char *iov[])
{
	int i;
	off_t off;

	cache->stats.hits += treq.secs;

	for (i = 0; i < treq.secs; i++) {
		DBG("%s: block cache hit: sec 0x%08llx, hash: 0x%08llx\n",
		    cache->name, treq.sec + i, block_cache_hash(cache, iov[i]));

		off = i << RADIX_TREE_NODE_SHIFT;
		memcpy(treq.buf + off, iov[i], RADIX_TREE_NODE_SIZE);
	}

	td_complete_request(treq, 0);
}

static void
block_cache_populate_cache(td_request_t clone, int err)
{
	int i;
	radix_tree_t *tree;
	block_cache_t *cache;
	block_cache_request_t *breq;

	breq        = (block_cache_request_t *)clone.cb_data;
	cache       = breq->cache;
	tree        = &cache->tree;
	breq->secs -= clone.secs;
	breq->err   = (breq->err ? breq->err : err);

	if (breq->secs)
		return;

	if (breq->err) {
		free(breq->buf);
		goto out;
	}

	for (i = 0; i < breq->treq.secs; i++) {
		off_t off = i << RADIX_TREE_NODE_SHIFT;
		DBG("%s: populating sec 0x%08llx\n",
		    cache->name, breq->treq.sec + i);
		memcpy(breq->treq.buf + off,
		       breq->buf + off, RADIX_TREE_NODE_SIZE);
	}

	if (radix_tree_add_leaves(tree, breq->buf,
				  breq->treq.sec, breq->treq.secs))
		free(breq->buf);

out:
	td_complete_request(breq->treq, breq->err);
	block_cache_put_request(cache, breq);
}

static void
block_cache_miss(block_cache_t *cache, td_request_t treq)
{
	char *buf;
	size_t size;
	td_request_t clone;
	radix_tree_t *tree;
	block_cache_request_t *breq;

	DBG("%s: block cache miss: sec 0x%08llx\n", cache->name, treq.sec);

	clone = treq;
	tree  = &cache->tree;
	size  = treq.secs << RADIX_TREE_NODE_SHIFT;

	cache->stats.misses += treq.secs;

	if (radix_tree_size(tree) + size >= BLOCK_CACHE_MAX_SIZE)
		goto out;

	breq = block_cache_get_request(cache);
	if (!breq)
		goto out;

	if (posix_memalign((void **)&buf, RADIX_TREE_NODE_SIZE, size)) {
		block_cache_put_request(cache, breq);
		goto out;
	}

	breq->treq    = treq;
	breq->secs    = treq.secs;
	breq->err     = 0;
	breq->buf     = buf;
	breq->cache   = cache;

	clone.buf     = buf;
	clone.cb      = block_cache_populate_cache;
	clone.cb_data = breq;

out:
	td_forward_request(clone);
}

static void
block_cache_queue_read(td_driver_t *driver, td_request_t treq)
{
	int i;
	radix_tree_t *tree;
	block_cache_t *cache;
	char *iov[BLOCK_CACHE_NODES_PER_PAGE];

	cache = (block_cache_t *)driver->data;
	tree  = &cache->tree;

	cache->stats.reads += treq.secs;

	if (treq.secs > BLOCK_CACHE_NODES_PER_PAGE)
		return td_forward_request(treq);

	for (i = 0; i < treq.secs; i++) {
		iov[i] = radix_tree_find_leaf(tree, treq.sec + i);
		if (!iov[i])
			return block_cache_miss(cache, treq);
	}

	return block_cache_hit(cache, treq, iov);
}

static void
block_cache_queue_write(td_driver_t *driver, td_request_t treq)
{
	td_complete_request(treq, -EPERM);
}

static int
block_cache_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	return -EINVAL;
}

static int
block_cache_validate_parent(td_driver_t *driver,
			    td_driver_t *pdriver, td_flag_t flags)
{
	block_cache_t *cache;

	if (!td_flag_test(pdriver->state, TD_DRIVER_RDONLY))
		return -EINVAL;

	cache = (block_cache_t *)driver->data;
	if (strcmp(driver->name, pdriver->name))
		return -EINVAL;

	return 0;
}

static void
block_cache_debug(td_driver_t *driver)
{
	block_cache_t *cache;
	block_cache_stats_t *stats;

	cache = (block_cache_t *)driver->data;
	stats = &cache->stats;

	WARN("BLOCK CACHE %s\n", cache->name);
	WARN("reads: %"PRIu64", hits: %"PRIu64", misses: %"PRIu64", prunes: %"PRIu64"\n",
	     stats->reads, stats->hits, stats->misses, stats->prunes);
}

struct tap_disk tapdisk_block_cache = {
	.disk_type                  = "tapdisk_block_cache",
	.flags                      = 0,
	.private_data_size          = sizeof(block_cache_t),
	.td_open                    = block_cache_open,
	.td_close                   = block_cache_close,
	.td_queue_read              = block_cache_queue_read,
	.td_queue_write             = block_cache_queue_write,
	.td_get_parent_id           = block_cache_get_parent_id,
	.td_validate_parent         = block_cache_validate_parent,
	.td_debug                   = block_cache_debug,
};
