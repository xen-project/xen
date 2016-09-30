/******************************************************************************
 * tmem.c
 *
 * Transcendent memory
 *
 * Copyright (c) 2009, Dan Magenheimer, Oracle Corp.
 */

/* TODO list: 090129 (updated 100318)
   - any better reclamation policy?
   - use different tlsf pools for each client (maybe each pool)
   - test shared access more completely (ocfs2)
   - add feedback-driven compression (not for persistent pools though!)
   - add data-structure total bytes overhead stats
 */

#ifdef __XEN__
#include <xen/tmem_xen.h> /* host-specific (eg Xen) code goes here. */
#endif

#include <public/sysctl.h>
#include <xen/tmem.h>
#include <xen/rbtree.h>
#include <xen/radix-tree.h>
#include <xen/list.h>
#include <xen/init.h>

#define TMEM_SPEC_VERSION 1

struct tmem_statistics tmem_stats = {
    .global_obj_count = ATOMIC_INIT(0),
    .global_pgp_count = ATOMIC_INIT(0),
    .global_pcd_count = ATOMIC_INIT(0),
    .global_page_count = ATOMIC_INIT(0),
    .global_rtree_node_count = ATOMIC_INIT(0),
};

/************ CORE DATA STRUCTURES ************************************/

struct tmem_object_root {
    struct xen_tmem_oid oid;
    struct rb_node rb_tree_node; /* Protected by pool->pool_rwlock. */
    unsigned long objnode_count; /* Atomicity depends on obj_spinlock. */
    long pgp_count; /* Atomicity depends on obj_spinlock. */
    struct radix_tree_root tree_root; /* Tree of pages within object. */
    struct tmem_pool *pool;
    domid_t last_client;
    spinlock_t obj_spinlock;
};

struct tmem_object_node {
    struct tmem_object_root *obj;
    struct radix_tree_node rtn;
};

struct tmem_page_descriptor {
    union {
        struct list_head global_eph_pages;
        struct list_head client_inv_pages;
    };
    union {
        struct {
            union {
                struct list_head client_eph_pages;
                struct list_head pool_pers_pages;
            };
            struct tmem_object_root *obj;
        } us;
        struct xen_tmem_oid inv_oid;  /* Used for invalid list only. */
    };
    pagesize_t size; /* 0 == PAGE_SIZE (pfp), -1 == data invalid,
                    else compressed data (cdata). */
    uint32_t index;
    bool_t eviction_attempted;  /* CHANGE TO lifetimes? (settable). */
    union {
        struct page_info *pfp;  /* Page frame pointer. */
        char *cdata; /* Compressed data. */
        struct tmem_page_content_descriptor *pcd; /* Page dedup. */
    };
    union {
        uint64_t timestamp;
        uint32_t pool_id;  /* Used for invalid list only. */
    };
};

#define PCD_TZE_MAX_SIZE (PAGE_SIZE - (PAGE_SIZE/64))

struct tmem_page_content_descriptor {
    union {
        struct page_info *pfp;  /* Page frame pointer. */
        char *cdata; /* If compression_enabled. */
    };
    pagesize_t size; /* If compression_enabled -> 0<size<PAGE_SIZE (*cdata)
                     * else if tze, 0<=size<PAGE_SIZE, rounded up to mult of 8
                     * else PAGE_SIZE -> *pfp. */
};

static int tmem_initialized = 0;

struct xmem_pool *tmem_mempool = 0;
unsigned int tmem_mempool_maxalloc = 0;

DEFINE_SPINLOCK(tmem_page_list_lock);
PAGE_LIST_HEAD(tmem_page_list);
unsigned long tmem_page_list_pages = 0;

DEFINE_RWLOCK(tmem_rwlock);
static DEFINE_SPINLOCK(eph_lists_spinlock); /* Protects global AND clients. */
static DEFINE_SPINLOCK(pers_lists_spinlock);

#define ASSERT_SPINLOCK(_l) ASSERT(spin_is_locked(_l))
#define ASSERT_WRITELOCK(_l) ASSERT(rw_is_write_locked(_l))

    atomic_t client_weight_total;

struct tmem_global tmem_global = {
    .ephemeral_page_list = LIST_HEAD_INIT(tmem_global.ephemeral_page_list),
    .client_list = LIST_HEAD_INIT(tmem_global.client_list),
    .client_weight_total = ATOMIC_INIT(0),
};

/*
 * There two types of memory allocation interfaces in tmem.
 * One is based on xmem_pool and the other is used for allocate a whole page.
 * Both of them are based on the lowlevel function __tmem_alloc_page/_thispool().
 * The call trace of alloc path is like below.
 * Persistant pool:
 *     1.tmem_malloc()
 *         > xmem_pool_alloc()
 *             > tmem_persistent_pool_page_get()
 *                 > __tmem_alloc_page_thispool()
 *     2.tmem_alloc_page()
 *         > __tmem_alloc_page_thispool()
 *
 * Ephemeral pool:
 *     1.tmem_malloc()
 *         > xmem_pool_alloc()
 *             > tmem_mempool_page_get()
 *                 > __tmem_alloc_page()
 *     2.tmem_alloc_page()
 *         > __tmem_alloc_page()
 *
 * The free path is done in the same manner.
 */
static void *tmem_malloc(size_t size, struct tmem_pool *pool)
{
    void *v = NULL;

    if ( (pool != NULL) && is_persistent(pool) ) {
        if ( pool->client->persistent_pool )
            v = xmem_pool_alloc(size, pool->client->persistent_pool);
    }
    else
    {
        ASSERT( size < tmem_mempool_maxalloc );
        ASSERT( tmem_mempool != NULL );
        v = xmem_pool_alloc(size, tmem_mempool);
    }
    if ( v == NULL )
        tmem_stats.alloc_failed++;
    return v;
}

static void tmem_free(void *p, struct tmem_pool *pool)
{
    if ( pool == NULL || !is_persistent(pool) )
    {
        ASSERT( tmem_mempool != NULL );
        xmem_pool_free(p, tmem_mempool);
    }
    else
    {
        ASSERT( pool->client->persistent_pool != NULL );
        xmem_pool_free(p, pool->client->persistent_pool);
    }
}

static struct page_info *tmem_alloc_page(struct tmem_pool *pool)
{
    struct page_info *pfp = NULL;

    if ( pool != NULL && is_persistent(pool) )
        pfp = __tmem_alloc_page_thispool(pool->client->domain);
    else
        pfp = __tmem_alloc_page();
    if ( pfp == NULL )
        tmem_stats.alloc_page_failed++;
    else
        atomic_inc_and_max(global_page_count);
    return pfp;
}

static void tmem_free_page(struct tmem_pool *pool, struct page_info *pfp)
{
    ASSERT(pfp);
    if ( pool == NULL || !is_persistent(pool) )
        __tmem_free_page(pfp);
    else
        __tmem_free_page_thispool(pfp);
    atomic_dec_and_assert(global_page_count);
}

static noinline void *tmem_mempool_page_get(unsigned long size)
{
    struct page_info *pi;

    ASSERT(size == PAGE_SIZE);
    if ( (pi = __tmem_alloc_page()) == NULL )
        return NULL;
    return page_to_virt(pi);
}

static void tmem_mempool_page_put(void *page_va)
{
    ASSERT(IS_PAGE_ALIGNED(page_va));
    __tmem_free_page(virt_to_page(page_va));
}

static int __init tmem_mempool_init(void)
{
    tmem_mempool = xmem_pool_create("tmem", tmem_mempool_page_get,
        tmem_mempool_page_put, PAGE_SIZE, 0, PAGE_SIZE);
    if ( tmem_mempool )
        tmem_mempool_maxalloc = xmem_pool_maxalloc(tmem_mempool);
    return tmem_mempool != NULL;
}

/* Persistent pools are per-domain. */
static void *tmem_persistent_pool_page_get(unsigned long size)
{
    struct page_info *pi;
    struct domain *d = current->domain;

    ASSERT(size == PAGE_SIZE);
    if ( (pi = __tmem_alloc_page_thispool(d)) == NULL )
        return NULL;
    ASSERT(IS_VALID_PAGE(pi));
    return page_to_virt(pi);
}

static void tmem_persistent_pool_page_put(void *page_va)
{
    struct page_info *pi;

    ASSERT(IS_PAGE_ALIGNED(page_va));
    pi = mfn_to_page(virt_to_mfn(page_va));
    ASSERT(IS_VALID_PAGE(pi));
    __tmem_free_page_thispool(pi);
}

/*
 * Page content descriptor manipulation routines.
 */
#define NOT_SHAREABLE ((uint16_t)-1UL)

/************ PAGE DESCRIPTOR MANIPULATION ROUTINES *******************/

/* Allocate a struct tmem_page_descriptor and associate it with an object. */
static struct tmem_page_descriptor *pgp_alloc(struct tmem_object_root *obj)
{
    struct tmem_page_descriptor *pgp;
    struct tmem_pool *pool;

    ASSERT(obj != NULL);
    ASSERT(obj->pool != NULL);
    pool = obj->pool;
    if ( (pgp = tmem_malloc(sizeof(struct tmem_page_descriptor), pool)) == NULL )
        return NULL;
    pgp->us.obj = obj;
    INIT_LIST_HEAD(&pgp->global_eph_pages);
    INIT_LIST_HEAD(&pgp->us.client_eph_pages);
    pgp->pfp = NULL;
    pgp->size = -1;
    pgp->index = -1;
    pgp->timestamp = get_cycles();
    atomic_inc_and_max(global_pgp_count);
    atomic_inc(&pool->pgp_count);
    if ( _atomic_read(pool->pgp_count) > pool->pgp_count_max )
        pool->pgp_count_max = _atomic_read(pool->pgp_count);
    return pgp;
}

static struct tmem_page_descriptor *pgp_lookup_in_obj(struct tmem_object_root *obj, uint32_t index)
{
    ASSERT(obj != NULL);
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT(obj->pool != NULL);
    return radix_tree_lookup(&obj->tree_root, index);
}

static void pgp_free_data(struct tmem_page_descriptor *pgp, struct tmem_pool *pool)
{
    pagesize_t pgp_size = pgp->size;

    if ( pgp->pfp == NULL )
        return;
    if ( pgp_size )
        tmem_free(pgp->cdata, pool);
    else
        tmem_free_page(pgp->us.obj->pool,pgp->pfp);
    if ( pool != NULL && pgp_size )
    {
        pool->client->compressed_pages--;
        pool->client->compressed_sum_size -= pgp_size;
    }
    pgp->pfp = NULL;
    pgp->size = -1;
}

static void __pgp_free(struct tmem_page_descriptor *pgp, struct tmem_pool *pool)
{
    pgp->us.obj = NULL;
    pgp->index = -1;
    tmem_free(pgp, pool);
}

static void pgp_free(struct tmem_page_descriptor *pgp)
{
    struct tmem_pool *pool = NULL;

    ASSERT(pgp->us.obj != NULL);
    ASSERT(pgp->us.obj->pool != NULL);
    ASSERT(pgp->us.obj->pool->client != NULL);

    pool = pgp->us.obj->pool;
    if ( !is_persistent(pool) )
    {
        ASSERT(list_empty(&pgp->global_eph_pages));
        ASSERT(list_empty(&pgp->us.client_eph_pages));
    }
    pgp_free_data(pgp, pool);
    atomic_dec_and_assert(global_pgp_count);
    atomic_dec(&pool->pgp_count);
    ASSERT(_atomic_read(pool->pgp_count) >= 0);
    pgp->size = -1;
    if ( is_persistent(pool) && pool->client->info.flags.u.migrating )
    {
        pgp->inv_oid = pgp->us.obj->oid;
        pgp->pool_id = pool->pool_id;
        return;
    }
    __pgp_free(pgp, pool);
}

/* Remove pgp from global/pool/client lists and free it. */
static void pgp_delist_free(struct tmem_page_descriptor *pgp)
{
    struct client *client;
    uint64_t life;

    ASSERT(pgp != NULL);
    ASSERT(pgp->us.obj != NULL);
    ASSERT(pgp->us.obj->pool != NULL);
    client = pgp->us.obj->pool->client;
    ASSERT(client != NULL);

    /* Delist pgp. */
    if ( !is_persistent(pgp->us.obj->pool) )
    {
        spin_lock(&eph_lists_spinlock);
        if ( !list_empty(&pgp->us.client_eph_pages) )
            client->eph_count--;
        ASSERT(client->eph_count >= 0);
        list_del_init(&pgp->us.client_eph_pages);
        if ( !list_empty(&pgp->global_eph_pages) )
            tmem_global.eph_count--;
        ASSERT(tmem_global.eph_count >= 0);
        list_del_init(&pgp->global_eph_pages);
        spin_unlock(&eph_lists_spinlock);
    }
    else
    {
        if ( client->info.flags.u.migrating )
        {
            spin_lock(&pers_lists_spinlock);
            list_add_tail(&pgp->client_inv_pages,
                          &client->persistent_invalidated_list);
            if ( pgp != pgp->us.obj->pool->cur_pgp )
                list_del_init(&pgp->us.pool_pers_pages);
            spin_unlock(&pers_lists_spinlock);
        }
        else
        {
            spin_lock(&pers_lists_spinlock);
            list_del_init(&pgp->us.pool_pers_pages);
            spin_unlock(&pers_lists_spinlock);
        }
    }
    life = get_cycles() - pgp->timestamp;
    pgp->us.obj->pool->sum_life_cycles += life;

    /* Free pgp. */
    pgp_free(pgp);
}

/* Called only indirectly by radix_tree_destroy. */
static void pgp_destroy(void *v)
{
    struct tmem_page_descriptor *pgp = (struct tmem_page_descriptor *)v;

    pgp->us.obj->pgp_count--;
    pgp_delist_free(pgp);
}

static int pgp_add_to_obj(struct tmem_object_root *obj, uint32_t index, struct tmem_page_descriptor *pgp)
{
    int ret;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ret = radix_tree_insert(&obj->tree_root, index, pgp);
    if ( !ret )
        obj->pgp_count++;
    return ret;
}

static struct tmem_page_descriptor *pgp_delete_from_obj(struct tmem_object_root *obj, uint32_t index)
{
    struct tmem_page_descriptor *pgp;

    ASSERT(obj != NULL);
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT(obj->pool != NULL);
    pgp = radix_tree_delete(&obj->tree_root, index);
    if ( pgp != NULL )
        obj->pgp_count--;
    ASSERT(obj->pgp_count >= 0);

    return pgp;
}

/************ RADIX TREE NODE MANIPULATION ROUTINES *******************/

/* Called only indirectly from radix_tree_insert. */
static struct radix_tree_node *rtn_alloc(void *arg)
{
    struct tmem_object_node *objnode;
    struct tmem_object_root *obj = (struct tmem_object_root *)arg;

    ASSERT(obj->pool != NULL);
    objnode = tmem_malloc(sizeof(struct tmem_object_node),obj->pool);
    if (objnode == NULL)
        return NULL;
    objnode->obj = obj;
    memset(&objnode->rtn, 0, sizeof(struct radix_tree_node));
    if (++obj->pool->objnode_count > obj->pool->objnode_count_max)
        obj->pool->objnode_count_max = obj->pool->objnode_count;
    atomic_inc_and_max(global_rtree_node_count);
    obj->objnode_count++;
    return &objnode->rtn;
}

/* Called only indirectly from radix_tree_delete/destroy. */
static void rtn_free(struct radix_tree_node *rtn, void *arg)
{
    struct tmem_pool *pool;
    struct tmem_object_node *objnode;

    ASSERT(rtn != NULL);
    objnode = container_of(rtn,struct tmem_object_node,rtn);
    ASSERT(objnode->obj != NULL);
    ASSERT_SPINLOCK(&objnode->obj->obj_spinlock);
    pool = objnode->obj->pool;
    ASSERT(pool != NULL);
    pool->objnode_count--;
    objnode->obj->objnode_count--;
    objnode->obj = NULL;
    tmem_free(objnode, pool);
    atomic_dec_and_assert(global_rtree_node_count);
}

/************ POOL OBJECT COLLECTION MANIPULATION ROUTINES *******************/

static int oid_compare(struct xen_tmem_oid *left,
                       struct xen_tmem_oid *right)
{
    if ( left->oid[2] == right->oid[2] )
    {
        if ( left->oid[1] == right->oid[1] )
        {
            if ( left->oid[0] == right->oid[0] )
                return 0;
            else if ( left->oid[0] < right->oid[0] )
                return -1;
            else
                return 1;
        }
        else if ( left->oid[1] < right->oid[1] )
            return -1;
        else
            return 1;
    }
    else if ( left->oid[2] < right->oid[2] )
        return -1;
    else
        return 1;
}

static void oid_set_invalid(struct xen_tmem_oid *oidp)
{
    oidp->oid[0] = oidp->oid[1] = oidp->oid[2] = -1UL;
}

static unsigned oid_hash(struct xen_tmem_oid *oidp)
{
    return (tmem_hash(oidp->oid[0] ^ oidp->oid[1] ^ oidp->oid[2],
                     BITS_PER_LONG) & OBJ_HASH_BUCKETS_MASK);
}

/* Searches for object==oid in pool, returns locked object if found. */
static struct tmem_object_root * obj_find(struct tmem_pool *pool,
                                          struct xen_tmem_oid *oidp)
{
    struct rb_node *node;
    struct tmem_object_root *obj;

restart_find:
    read_lock(&pool->pool_rwlock);
    node = pool->obj_rb_root[oid_hash(oidp)].rb_node;
    while ( node )
    {
        obj = container_of(node, struct tmem_object_root, rb_tree_node);
        switch ( oid_compare(&obj->oid, oidp) )
        {
            case 0: /* Equal. */
                if ( !spin_trylock(&obj->obj_spinlock) )
                {
                    read_unlock(&pool->pool_rwlock);
                    goto restart_find;
                }
                read_unlock(&pool->pool_rwlock);
                return obj;
            case -1:
                node = node->rb_left;
                break;
            case 1:
                node = node->rb_right;
        }
    }
    read_unlock(&pool->pool_rwlock);
    return NULL;
}

/* Free an object that has no more pgps in it. */
static void obj_free(struct tmem_object_root *obj)
{
    struct tmem_pool *pool;
    struct xen_tmem_oid old_oid;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT(obj != NULL);
    ASSERT(obj->pgp_count == 0);
    pool = obj->pool;
    ASSERT(pool != NULL);
    ASSERT(pool->client != NULL);
    ASSERT_WRITELOCK(&pool->pool_rwlock);
    if ( obj->tree_root.rnode != NULL ) /* May be a "stump" with no leaves. */
        radix_tree_destroy(&obj->tree_root, pgp_destroy);
    ASSERT((long)obj->objnode_count == 0);
    ASSERT(obj->tree_root.rnode == NULL);
    pool->obj_count--;
    ASSERT(pool->obj_count >= 0);
    obj->pool = NULL;
    old_oid = obj->oid;
    oid_set_invalid(&obj->oid);
    obj->last_client = TMEM_CLI_ID_NULL;
    atomic_dec_and_assert(global_obj_count);
    rb_erase(&obj->rb_tree_node, &pool->obj_rb_root[oid_hash(&old_oid)]);
    spin_unlock(&obj->obj_spinlock);
    tmem_free(obj, pool);
}

static int obj_rb_insert(struct rb_root *root, struct tmem_object_root *obj)
{
    struct rb_node **new, *parent = NULL;
    struct tmem_object_root *this;

    ASSERT(obj->pool);
    ASSERT_WRITELOCK(&obj->pool->pool_rwlock);

    new = &(root->rb_node);
    while ( *new )
    {
        this = container_of(*new, struct tmem_object_root, rb_tree_node);
        parent = *new;
        switch ( oid_compare(&this->oid, &obj->oid) )
        {
            case 0:
                return 0;
            case -1:
                new = &((*new)->rb_left);
                break;
            case 1:
                new = &((*new)->rb_right);
                break;
        }
    }
    rb_link_node(&obj->rb_tree_node, parent, new);
    rb_insert_color(&obj->rb_tree_node, root);
    return 1;
}

/*
 * Allocate, initialize, and insert an tmem_object_root
 * (should be called only if find failed).
 */
static struct tmem_object_root * obj_alloc(struct tmem_pool *pool,
                                           struct xen_tmem_oid *oidp)
{
    struct tmem_object_root *obj;

    ASSERT(pool != NULL);
    if ( (obj = tmem_malloc(sizeof(struct tmem_object_root), pool)) == NULL )
        return NULL;
    pool->obj_count++;
    if (pool->obj_count > pool->obj_count_max)
        pool->obj_count_max = pool->obj_count;
    atomic_inc_and_max(global_obj_count);
    radix_tree_init(&obj->tree_root);
    radix_tree_set_alloc_callbacks(&obj->tree_root, rtn_alloc, rtn_free, obj);
    spin_lock_init(&obj->obj_spinlock);
    obj->pool = pool;
    obj->oid = *oidp;
    obj->objnode_count = 0;
    obj->pgp_count = 0;
    obj->last_client = TMEM_CLI_ID_NULL;
    return obj;
}

/* Free an object after destroying any pgps in it. */
static void obj_destroy(struct tmem_object_root *obj)
{
    ASSERT_WRITELOCK(&obj->pool->pool_rwlock);
    radix_tree_destroy(&obj->tree_root, pgp_destroy);
    obj_free(obj);
}

/* Destroys all objs in a pool, or only if obj->last_client matches cli_id. */
static void pool_destroy_objs(struct tmem_pool *pool, domid_t cli_id)
{
    struct rb_node *node;
    struct tmem_object_root *obj;
    int i;

    write_lock(&pool->pool_rwlock);
    pool->is_dying = 1;
    for (i = 0; i < OBJ_HASH_BUCKETS; i++)
    {
        node = rb_first(&pool->obj_rb_root[i]);
        while ( node != NULL )
        {
            obj = container_of(node, struct tmem_object_root, rb_tree_node);
            spin_lock(&obj->obj_spinlock);
            node = rb_next(node);
            if ( obj->last_client == cli_id )
                obj_destroy(obj);
            else
                spin_unlock(&obj->obj_spinlock);
        }
    }
    write_unlock(&pool->pool_rwlock);
}


/************ POOL MANIPULATION ROUTINES ******************************/

static struct tmem_pool * pool_alloc(void)
{
    struct tmem_pool *pool;
    int i;

    if ( (pool = xzalloc(struct tmem_pool)) == NULL )
        return NULL;
    for (i = 0; i < OBJ_HASH_BUCKETS; i++)
        pool->obj_rb_root[i] = RB_ROOT;
    INIT_LIST_HEAD(&pool->persistent_page_list);
    rwlock_init(&pool->pool_rwlock);
    return pool;
}

static void pool_free(struct tmem_pool *pool)
{
    pool->client = NULL;
    xfree(pool);
}

/*
 * Register new_client as a user of this shared pool and return 0 on succ.
 */
static int shared_pool_join(struct tmem_pool *pool, struct client *new_client)
{
    struct share_list *sl;
    ASSERT(is_shared(pool));

    if ( (sl = tmem_malloc(sizeof(struct share_list), NULL)) == NULL )
        return -1;
    sl->client = new_client;
    list_add_tail(&sl->share_list, &pool->share_list);
    if ( new_client->cli_id != pool->client->cli_id )
        tmem_client_info("adding new %s %d to shared pool owned by %s %d\n",
                    tmem_client_str, new_client->cli_id, tmem_client_str,
                    pool->client->cli_id);
    else if ( pool->shared_count )
        tmem_client_info("inter-guest sharing of shared pool %s by client %d\n",
                         tmem_client_str, pool->client->cli_id);
    ++pool->shared_count;
    return 0;
}

/* Reassign "ownership" of the pool to another client that shares this pool. */
static void shared_pool_reassign(struct tmem_pool *pool)
{
    struct share_list *sl;
    int poolid;
    struct client *old_client = pool->client, *new_client;

    ASSERT(is_shared(pool));
    if ( list_empty(&pool->share_list) )
    {
        ASSERT(pool->shared_count == 0);
        return;
    }
    old_client->pools[pool->pool_id] = NULL;
    sl = list_entry(pool->share_list.next, struct share_list, share_list);
    /*
     * The sl->client can be old_client if there are multiple shared pools
     * within an guest.
     */
    pool->client = new_client = sl->client;
    for (poolid = 0; poolid < MAX_POOLS_PER_DOMAIN; poolid++)
        if (new_client->pools[poolid] == pool)
            break;
    ASSERT(poolid != MAX_POOLS_PER_DOMAIN);
    new_client->eph_count += _atomic_read(pool->pgp_count);
    old_client->eph_count -= _atomic_read(pool->pgp_count);
    list_splice_init(&old_client->ephemeral_page_list,
                     &new_client->ephemeral_page_list);
    tmem_client_info("reassigned shared pool from %s=%d to %s=%d pool_id=%d\n",
        tmem_cli_id_str, old_client->cli_id, tmem_cli_id_str, new_client->cli_id, poolid);
    pool->pool_id = poolid;
}

/*
 * Destroy all objects with last_client same as passed cli_id,
 * remove pool's cli_id from list of sharers of this pool.
 */
static int shared_pool_quit(struct tmem_pool *pool, domid_t cli_id)
{
    struct share_list *sl;
    int s_poolid;

    ASSERT(is_shared(pool));
    ASSERT(pool->client != NULL);

    ASSERT_WRITELOCK(&tmem_rwlock);
    pool_destroy_objs(pool, cli_id);
    list_for_each_entry(sl,&pool->share_list, share_list)
    {
        if (sl->client->cli_id != cli_id)
            continue;
        list_del(&sl->share_list);
        tmem_free(sl, pool);
        --pool->shared_count;
        if (pool->client->cli_id == cli_id)
            shared_pool_reassign(pool);
        if (pool->shared_count)
            return pool->shared_count;
        for (s_poolid = 0; s_poolid < MAX_GLOBAL_SHARED_POOLS; s_poolid++)
            if ( (tmem_global.shared_pools[s_poolid]) == pool )
            {
                tmem_global.shared_pools[s_poolid] = NULL;
                break;
            }
        return 0;
    }
    tmem_client_warn("tmem: no match unsharing pool, %s=%d\n",
        tmem_cli_id_str,pool->client->cli_id);
    return -1;
}

/* Flush all data (owned by cli_id) from a pool and, optionally, free it. */
static void pool_flush(struct tmem_pool *pool, domid_t cli_id)
{
    ASSERT(pool != NULL);
    if ( (is_shared(pool)) && (shared_pool_quit(pool,cli_id) > 0) )
    {
        tmem_client_warn("tmem: %s=%d no longer using shared pool %d owned by %s=%d\n",
           tmem_cli_id_str, cli_id, pool->pool_id, tmem_cli_id_str,pool->client->cli_id);
        return;
    }
    tmem_client_info("Destroying %s-%s tmem pool %s=%d pool_id=%d\n",
                    is_persistent(pool) ? "persistent" : "ephemeral" ,
                    is_shared(pool) ? "shared" : "private",
                    tmem_cli_id_str, pool->client->cli_id, pool->pool_id);
    if ( pool->client->info.flags.u.migrating )
    {
        tmem_client_warn("can't destroy pool while %s is live-migrating\n",
                    tmem_client_str);
        return;
    }
    pool_destroy_objs(pool, TMEM_CLI_ID_NULL);
    pool->client->pools[pool->pool_id] = NULL;
    pool_free(pool);
}

/************ CLIENT MANIPULATION OPERATIONS **************************/

static struct client *client_create(domid_t cli_id)
{
    struct client *client = xzalloc(struct client);
    int i, shift;
    char name[5];
    struct domain *d;

    tmem_client_info("tmem: initializing tmem capability for %s=%d...",
                    tmem_cli_id_str, cli_id);
    if ( client == NULL )
    {
        tmem_client_err("failed... out of memory\n");
        goto fail;
    }

    for (i = 0, shift = 12; i < 4; shift -=4, i++)
        name[i] = (((unsigned short)cli_id >> shift) & 0xf) + '0';
    name[4] = '\0';
    client->persistent_pool = xmem_pool_create(name, tmem_persistent_pool_page_get,
        tmem_persistent_pool_page_put, PAGE_SIZE, 0, PAGE_SIZE);
    if ( client->persistent_pool == NULL )
    {
        tmem_client_err("failed... can't alloc persistent pool\n");
        goto fail;
    }

    d = rcu_lock_domain_by_id(cli_id);
    if ( d == NULL ) {
        tmem_client_err("failed... can't set client\n");
        xmem_pool_destroy(client->persistent_pool);
        goto fail;
    }
    if ( !d->is_dying ) {
        d->tmem_client = client;
        client->domain = d;
    }
    rcu_unlock_domain(d);

    client->cli_id = cli_id;
    client->info.version = TMEM_SPEC_VERSION;
    client->info.maxpools = MAX_POOLS_PER_DOMAIN;
    client->info.flags.u.compress = tmem_compression_enabled();
    client->shared_auth_required = tmem_shared_auth();
    for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++)
        client->shared_auth_uuid[i][0] =
            client->shared_auth_uuid[i][1] = -1L;
    list_add_tail(&client->client_list, &tmem_global.client_list);
    INIT_LIST_HEAD(&client->ephemeral_page_list);
    INIT_LIST_HEAD(&client->persistent_invalidated_list);
    tmem_client_info("ok\n");
    return client;

 fail:
    xfree(client);
    return NULL;
}

static void client_free(struct client *client)
{
    list_del(&client->client_list);
    xmem_pool_destroy(client->persistent_pool);
    xfree(client);
}

/* Flush all data from a client and, optionally, free it. */
static void client_flush(struct client *client)
{
    int i;
    struct tmem_pool *pool;

    for  (i = 0; i < MAX_POOLS_PER_DOMAIN; i++)
    {
        if ( (pool = client->pools[i]) == NULL )
            continue;
        pool_flush(pool, client->cli_id);
        client->pools[i] = NULL;
        client->info.nr_pools--;
    }
    client_free(client);
}

static bool_t client_over_quota(struct client *client)
{
    int total = _atomic_read(tmem_global.client_weight_total);

    ASSERT(client != NULL);
    if ( (total == 0) || (client->info.weight == 0) ||
          (client->eph_count == 0) )
        return 0;
    return ( ((tmem_global.eph_count*100L) / client->eph_count ) >
             ((total*100L) / client->info.weight) );
}

/************ MEMORY REVOCATION ROUTINES *******************************/

static bool_t tmem_try_to_evict_pgp(struct tmem_page_descriptor *pgp, bool_t *hold_pool_rwlock)
{
    struct tmem_object_root *obj = pgp->us.obj;
    struct tmem_pool *pool = obj->pool;

    if ( pool->is_dying )
        return 0;
    if ( spin_trylock(&obj->obj_spinlock) )
    {
        if ( obj->pgp_count > 1 )
            return 1;
        if ( write_trylock(&pool->pool_rwlock) )
        {
            *hold_pool_rwlock = 1;
            return 1;
        }
        spin_unlock(&obj->obj_spinlock);
    }
    return 0;
}

int tmem_evict(void)
{
    struct client *client = current->domain->tmem_client;
    struct tmem_page_descriptor *pgp = NULL, *pgp_del;
    struct tmem_object_root *obj;
    struct tmem_pool *pool;
    int ret = 0;
    bool_t hold_pool_rwlock = 0;

    tmem_stats.evict_attempts++;
    spin_lock(&eph_lists_spinlock);
    if ( (client != NULL) && client_over_quota(client) &&
         !list_empty(&client->ephemeral_page_list) )
    {
        list_for_each_entry(pgp, &client->ephemeral_page_list, us.client_eph_pages)
            if ( tmem_try_to_evict_pgp(pgp, &hold_pool_rwlock) )
                goto found;
    }
    else if ( !list_empty(&tmem_global.ephemeral_page_list) )
    {
        list_for_each_entry(pgp, &tmem_global.ephemeral_page_list, global_eph_pages)
            if ( tmem_try_to_evict_pgp(pgp, &hold_pool_rwlock) )
            {
                client = pgp->us.obj->pool->client;
                goto found;
            }
    }
     /* Global_ephemeral_page_list is empty, so we bail out. */
    spin_unlock(&eph_lists_spinlock);
    goto out;

found:
    /* Delist. */
    list_del_init(&pgp->us.client_eph_pages);
    client->eph_count--;
    list_del_init(&pgp->global_eph_pages);
    tmem_global.eph_count--;
    ASSERT(tmem_global.eph_count >= 0);
    ASSERT(client->eph_count >= 0);
    spin_unlock(&eph_lists_spinlock);

    ASSERT(pgp != NULL);
    obj = pgp->us.obj;
    ASSERT(obj != NULL);
    ASSERT(obj->pool != NULL);
    pool = obj->pool;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    pgp_del = pgp_delete_from_obj(obj, pgp->index);
    ASSERT(pgp_del == pgp);

    /* pgp already delist, so call pgp_free directly. */
    pgp_free(pgp);
    if ( obj->pgp_count == 0 )
    {
        ASSERT_WRITELOCK(&pool->pool_rwlock);
        obj_free(obj);
    }
    else
        spin_unlock(&obj->obj_spinlock);
    if ( hold_pool_rwlock )
        write_unlock(&pool->pool_rwlock);
    tmem_stats.evicted_pgs++;
    ret = 1;
out:
    return ret;
}


/*
 * Under certain conditions (e.g. if each client is putting pages for exactly
 * one object), once locks are held, freeing up memory may
 * result in livelocks and very long "put" times, so we try to ensure there
 * is a minimum amount of memory (1MB) available BEFORE any data structure
 * locks are held.
 */
static inline bool_t tmem_ensure_avail_pages(void)
{
    int failed_evict = 10;
    unsigned long free_mem;

    do {
        free_mem = (tmem_page_list_pages + total_free_pages())
                        >> (20 - PAGE_SHIFT);
        if ( free_mem )
            return 1;
        if ( !tmem_evict() )
            failed_evict--;
    } while ( failed_evict > 0 );

    return 0;
}

/************ TMEM CORE OPERATIONS ************************************/

static int do_tmem_put_compress(struct tmem_page_descriptor *pgp, xen_pfn_t cmfn,
                                         tmem_cli_va_param_t clibuf)
{
    void *dst, *p;
    size_t size;
    int ret = 0;

    ASSERT(pgp != NULL);
    ASSERT(pgp->us.obj != NULL);
    ASSERT_SPINLOCK(&pgp->us.obj->obj_spinlock);
    ASSERT(pgp->us.obj->pool != NULL);
    ASSERT(pgp->us.obj->pool->client != NULL);

    if ( pgp->pfp != NULL )
        pgp_free_data(pgp, pgp->us.obj->pool);
    ret = tmem_compress_from_client(cmfn, &dst, &size, clibuf);
    if ( ret <= 0 )
        goto out;
    else if ( (size == 0) || (size >= tmem_mempool_maxalloc) ) {
        ret = 0;
        goto out;
    } else if ( (p = tmem_malloc(size,pgp->us.obj->pool)) == NULL ) {
        ret = -ENOMEM;
        goto out;
    } else {
        memcpy(p,dst,size);
        pgp->cdata = p;
    }
    pgp->size = size;
    pgp->us.obj->pool->client->compressed_pages++;
    pgp->us.obj->pool->client->compressed_sum_size += size;
    ret = 1;

out:
    return ret;
}

static int do_tmem_dup_put(struct tmem_page_descriptor *pgp, xen_pfn_t cmfn,
       tmem_cli_va_param_t clibuf)
{
    struct tmem_pool *pool;
    struct tmem_object_root *obj;
    struct client *client;
    struct tmem_page_descriptor *pgpfound = NULL;
    int ret;

    ASSERT(pgp != NULL);
    ASSERT(pgp->pfp != NULL);
    ASSERT(pgp->size != -1);
    obj = pgp->us.obj;
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT(obj != NULL);
    pool = obj->pool;
    ASSERT(pool != NULL);
    client = pool->client;
    if ( client->info.flags.u.migrating )
        goto failed_dup; /* No dups allowed when migrating. */
    /* Can we successfully manipulate pgp to change out the data? */
    if ( client->info.flags.u.compress && pgp->size != 0 )
    {
        ret = do_tmem_put_compress(pgp, cmfn, clibuf);
        if ( ret == 1 )
            goto done;
        else if ( ret == 0 )
            goto copy_uncompressed;
        else if ( ret == -ENOMEM )
            goto failed_dup;
        else if ( ret == -EFAULT )
            goto bad_copy;
    }

copy_uncompressed:
    if ( pgp->pfp )
        pgp_free_data(pgp, pool);
    if ( ( pgp->pfp = tmem_alloc_page(pool) ) == NULL )
        goto failed_dup;
    pgp->size = 0;
    ret = tmem_copy_from_client(pgp->pfp, cmfn, tmem_cli_buf_null);
    if ( ret < 0 )
        goto bad_copy;

done:
    /* Successfully replaced data, clean up and return success. */
    if ( is_shared(pool) )
        obj->last_client = client->cli_id;
    spin_unlock(&obj->obj_spinlock);
    pool->dup_puts_replaced++;
    pool->good_puts++;
    if ( is_persistent(pool) )
        client->succ_pers_puts++;
    return 1;

bad_copy:
    tmem_stats.failed_copies++;
    goto cleanup;

failed_dup:
    /*
     * Couldn't change out the data, flush the old data and return
     * -ENOSPC instead of -ENOMEM to differentiate failed _dup_ put.
     */
    ret = -ENOSPC;
cleanup:
    pgpfound = pgp_delete_from_obj(obj, pgp->index);
    ASSERT(pgpfound == pgp);
    pgp_delist_free(pgpfound);
    if ( obj->pgp_count == 0 )
    {
        write_lock(&pool->pool_rwlock);
        obj_free(obj);
        write_unlock(&pool->pool_rwlock);
    } else {
        spin_unlock(&obj->obj_spinlock);
    }
    pool->dup_puts_flushed++;
    return ret;
}

static int do_tmem_put(struct tmem_pool *pool,
                       struct xen_tmem_oid *oidp, uint32_t index,
                       xen_pfn_t cmfn, tmem_cli_va_param_t clibuf)
{
    struct tmem_object_root *obj = NULL;
    struct tmem_page_descriptor *pgp = NULL;
    struct client *client;
    int ret, newobj = 0;

    ASSERT(pool != NULL);
    client = pool->client;
    ASSERT(client != NULL);
    ret = client->info.flags.u.frozen  ? -EFROZEN : -ENOMEM;
    pool->puts++;

refind:
    /* Does page already exist (dup)?  if so, handle specially. */
    if ( (obj = obj_find(pool, oidp)) != NULL )
    {
        if ((pgp = pgp_lookup_in_obj(obj, index)) != NULL)
        {
            return do_tmem_dup_put(pgp, cmfn, clibuf);
        }
        else
        {
            /* No puts allowed into a frozen pool (except dup puts). */
            if ( client->info.flags.u.frozen )
                goto unlock_obj;
        }
    }
    else
    {
        /* No puts allowed into a frozen pool (except dup puts). */
        if ( client->info.flags.u.frozen )
            return ret;
        if ( (obj = obj_alloc(pool, oidp)) == NULL )
            return -ENOMEM;

        write_lock(&pool->pool_rwlock);
        /*
         * Parallel callers may already allocated obj and inserted to obj_rb_root
         * before us.
         */
        if ( !obj_rb_insert(&pool->obj_rb_root[oid_hash(oidp)], obj) )
        {
            tmem_free(obj, pool);
            write_unlock(&pool->pool_rwlock);
            goto refind;
        }

        spin_lock(&obj->obj_spinlock);
        newobj = 1;
        write_unlock(&pool->pool_rwlock);
    }

    /* When arrive here, we have a spinlocked obj for use. */
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    if ( (pgp = pgp_alloc(obj)) == NULL )
        goto unlock_obj;

    ret = pgp_add_to_obj(obj, index, pgp);
    if ( ret == -ENOMEM  )
        /* Warning: may result in partially built radix tree ("stump"). */
        goto free_pgp;

    pgp->index = index;
    pgp->size = 0;

    if ( client->info.flags.u.compress )
    {
        ASSERT(pgp->pfp == NULL);
        ret = do_tmem_put_compress(pgp, cmfn, clibuf);
        if ( ret == 1 )
            goto insert_page;
        if ( ret == -ENOMEM )
        {
            client->compress_nomem++;
            goto del_pgp_from_obj;
        }
        if ( ret == 0 )
        {
            client->compress_poor++;
            goto copy_uncompressed;
        }
        if ( ret == -EFAULT )
            goto bad_copy;
    }

copy_uncompressed:
    if ( ( pgp->pfp = tmem_alloc_page(pool) ) == NULL )
    {
        ret = -ENOMEM;
        goto del_pgp_from_obj;
    }
    ret = tmem_copy_from_client(pgp->pfp, cmfn, clibuf);
    if ( ret < 0 )
        goto bad_copy;

insert_page:
    if ( !is_persistent(pool) )
    {
        spin_lock(&eph_lists_spinlock);
        list_add_tail(&pgp->global_eph_pages, &tmem_global.ephemeral_page_list);
        if (++tmem_global.eph_count > tmem_stats.global_eph_count_max)
            tmem_stats.global_eph_count_max = tmem_global.eph_count;
        list_add_tail(&pgp->us.client_eph_pages,
            &client->ephemeral_page_list);
        if (++client->eph_count > client->eph_count_max)
            client->eph_count_max = client->eph_count;
        spin_unlock(&eph_lists_spinlock);
    }
    else
    { /* is_persistent. */
        spin_lock(&pers_lists_spinlock);
        list_add_tail(&pgp->us.pool_pers_pages,
            &pool->persistent_page_list);
        spin_unlock(&pers_lists_spinlock);
    }

    if ( is_shared(pool) )
        obj->last_client = client->cli_id;

    /* Free the obj spinlock. */
    spin_unlock(&obj->obj_spinlock);
    pool->good_puts++;

    if ( is_persistent(pool) )
        client->succ_pers_puts++;
    else
        tmem_stats.tot_good_eph_puts++;
    return 1;

bad_copy:
    tmem_stats.failed_copies++;

del_pgp_from_obj:
    ASSERT((obj != NULL) && (pgp != NULL) && (pgp->index != -1));
    pgp_delete_from_obj(obj, pgp->index);

free_pgp:
    pgp_free(pgp);
unlock_obj:
    if ( newobj )
    {
        write_lock(&pool->pool_rwlock);
        obj_free(obj);
        write_unlock(&pool->pool_rwlock);
    }
    else
    {
        spin_unlock(&obj->obj_spinlock);
    }
    pool->no_mem_puts++;
    return ret;
}

static int do_tmem_get(struct tmem_pool *pool,
                       struct xen_tmem_oid *oidp, uint32_t index,
                       xen_pfn_t cmfn, tmem_cli_va_param_t clibuf)
{
    struct tmem_object_root *obj;
    struct tmem_page_descriptor *pgp;
    struct client *client = pool->client;
    int rc;

    if ( !_atomic_read(pool->pgp_count) )
        return -EEMPTY;

    pool->gets++;
    obj = obj_find(pool,oidp);
    if ( obj == NULL )
        return 0;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    if (is_shared(pool) || is_persistent(pool) )
        pgp = pgp_lookup_in_obj(obj, index);
    else
        pgp = pgp_delete_from_obj(obj, index);
    if ( pgp == NULL )
    {
        spin_unlock(&obj->obj_spinlock);
        return 0;
    }
    ASSERT(pgp->size != -1);
    if ( pgp->size != 0 )
    {
        rc = tmem_decompress_to_client(cmfn, pgp->cdata, pgp->size, clibuf);
    }
    else
        rc = tmem_copy_to_client(cmfn, pgp->pfp, clibuf);
    if ( rc <= 0 )
        goto bad_copy;

    if ( !is_persistent(pool) )
    {
        if ( !is_shared(pool) )
        {
            pgp_delist_free(pgp);
            if ( obj->pgp_count == 0 )
            {
                write_lock(&pool->pool_rwlock);
                obj_free(obj);
                obj = NULL;
                write_unlock(&pool->pool_rwlock);
            }
        } else {
            spin_lock(&eph_lists_spinlock);
            list_del(&pgp->global_eph_pages);
            list_add_tail(&pgp->global_eph_pages,&tmem_global.ephemeral_page_list);
            list_del(&pgp->us.client_eph_pages);
            list_add_tail(&pgp->us.client_eph_pages,&client->ephemeral_page_list);
            spin_unlock(&eph_lists_spinlock);
            obj->last_client = current->domain->domain_id;
        }
    }
    if ( obj != NULL )
    {
        spin_unlock(&obj->obj_spinlock);
    }
    pool->found_gets++;
    if ( is_persistent(pool) )
        client->succ_pers_gets++;
    else
        client->succ_eph_gets++;
    return 1;

bad_copy:
    spin_unlock(&obj->obj_spinlock);
    tmem_stats.failed_copies++;
    return rc;
}

static int do_tmem_flush_page(struct tmem_pool *pool,
                              struct xen_tmem_oid *oidp, uint32_t index)
{
    struct tmem_object_root *obj;
    struct tmem_page_descriptor *pgp;

    pool->flushs++;
    obj = obj_find(pool,oidp);
    if ( obj == NULL )
        goto out;
    pgp = pgp_delete_from_obj(obj, index);
    if ( pgp == NULL )
    {
        spin_unlock(&obj->obj_spinlock);
        goto out;
    }
    pgp_delist_free(pgp);
    if ( obj->pgp_count == 0 )
    {
        write_lock(&pool->pool_rwlock);
        obj_free(obj);
        write_unlock(&pool->pool_rwlock);
    } else {
        spin_unlock(&obj->obj_spinlock);
    }
    pool->flushs_found++;

out:
    if ( pool->client->info.flags.u.frozen )
        return -EFROZEN;
    else
        return 1;
}

static int do_tmem_flush_object(struct tmem_pool *pool,
                                struct xen_tmem_oid *oidp)
{
    struct tmem_object_root *obj;

    pool->flush_objs++;
    obj = obj_find(pool,oidp);
    if ( obj == NULL )
        goto out;
    write_lock(&pool->pool_rwlock);
    obj_destroy(obj);
    pool->flush_objs_found++;
    write_unlock(&pool->pool_rwlock);

out:
    if ( pool->client->info.flags.u.frozen )
        return -EFROZEN;
    else
        return 1;
}

static int do_tmem_destroy_pool(uint32_t pool_id)
{
    struct client *client = current->domain->tmem_client;
    struct tmem_pool *pool;

    if ( pool_id >= MAX_POOLS_PER_DOMAIN )
        return 0;
    if ( (pool = client->pools[pool_id]) == NULL )
        return 0;
    client->pools[pool_id] = NULL;
    pool_flush(pool, client->cli_id);
    client->info.nr_pools--;
    return 1;
}

static int do_tmem_new_pool(domid_t this_cli_id,
                                     uint32_t d_poolid, uint32_t flags,
                                     uint64_t uuid_lo, uint64_t uuid_hi)
{
    struct client *client;
    domid_t cli_id;
    int persistent = flags & TMEM_POOL_PERSIST;
    int shared = flags & TMEM_POOL_SHARED;
    int pagebits = (flags >> TMEM_POOL_PAGESIZE_SHIFT)
         & TMEM_POOL_PAGESIZE_MASK;
    int specversion = (flags >> TMEM_POOL_VERSION_SHIFT)
         & TMEM_POOL_VERSION_MASK;
    struct tmem_pool *pool, *shpool;
    int i, first_unused_s_poolid;

    if ( this_cli_id == TMEM_CLI_ID_NULL )
        cli_id = current->domain->domain_id;
    else
        cli_id = this_cli_id;
    tmem_client_info("tmem: allocating %s-%s tmem pool for %s=%d...",
        persistent ? "persistent" : "ephemeral" ,
        shared ? "shared" : "private", tmem_cli_id_str, cli_id);
    if ( specversion != TMEM_SPEC_VERSION )
    {
        tmem_client_err("failed... unsupported spec version\n");
        return -EPERM;
    }
    if ( shared && persistent )
    {
        tmem_client_err("failed... unable to create a shared-persistant pool\n");
        return -EPERM;
    }
    if ( pagebits != (PAGE_SHIFT - 12) )
    {
        tmem_client_err("failed... unsupported pagesize %d\n",
                       1 << (pagebits + 12));
        return -EPERM;
    }
    if ( flags & TMEM_POOL_PRECOMPRESSED )
    {
        tmem_client_err("failed... precompression flag set but unsupported\n");
        return -EPERM;
    }
    if ( flags & TMEM_POOL_RESERVED_BITS )
    {
        tmem_client_err("failed... reserved bits must be zero\n");
        return -EPERM;
    }
    if ( this_cli_id != TMEM_CLI_ID_NULL )
    {
        if ( (client = tmem_client_from_cli_id(this_cli_id)) == NULL
             || d_poolid >= MAX_POOLS_PER_DOMAIN
             || client->pools[d_poolid] != NULL )
            return -EPERM;
    }
    else
    {
        client = current->domain->tmem_client;
        ASSERT(client != NULL);
        for ( d_poolid = 0; d_poolid < MAX_POOLS_PER_DOMAIN; d_poolid++ )
            if ( client->pools[d_poolid] == NULL )
                break;
        if ( d_poolid >= MAX_POOLS_PER_DOMAIN )
        {
            tmem_client_err("failed... no more pool slots available for this %s\n",
                   tmem_client_str);
            return -EPERM;
        }
    }

    if ( (pool = pool_alloc()) == NULL )
    {
        tmem_client_err("failed... out of memory\n");
        return -ENOMEM;
    }
    client->pools[d_poolid] = pool;
    pool->client = client;
    pool->pool_id = d_poolid;
    pool->shared = shared;
    pool->persistent = persistent;
    pool->uuid[0] = uuid_lo;
    pool->uuid[1] = uuid_hi;

    /*
     * Already created a pool when arrived here, but need some special process
     * for shared pool.
     */
    if ( shared )
    {
        if ( uuid_lo == -1L && uuid_hi == -1L )
        {
            tmem_client_info("Invalid uuid, create non shared pool instead!\n");
            pool->shared = 0;
            goto out;
        }
        if ( client->shared_auth_required && !tmem_global.shared_auth )
        {
            for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++)
                if ( (client->shared_auth_uuid[i][0] == uuid_lo) &&
                     (client->shared_auth_uuid[i][1] == uuid_hi) )
                    break;
            if ( i == MAX_GLOBAL_SHARED_POOLS )
            {
                tmem_client_info("Shared auth failed, create non shared pool instead!\n");
                pool->shared = 0;
                goto out;
            }
        }

        /*
         * Authorize okay, match a global shared pool or use the newly allocated
         * one.
         */
        first_unused_s_poolid = MAX_GLOBAL_SHARED_POOLS;
        for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++ )
        {
            if ( (shpool = tmem_global.shared_pools[i]) != NULL )
            {
                if ( shpool->uuid[0] == uuid_lo && shpool->uuid[1] == uuid_hi )
                {
                    /* Succ to match a global shared pool. */
                    tmem_client_info("(matches shared pool uuid=%"PRIx64".%"PRIx64") pool_id=%d\n",
                        uuid_hi, uuid_lo, d_poolid);
                    client->pools[d_poolid] = shpool;
                    if ( !shared_pool_join(shpool, client) )
                    {
                        pool_free(pool);
                        goto out;
                    }
                    else
                        goto fail;
                }
            }
            else
            {
                if ( first_unused_s_poolid == MAX_GLOBAL_SHARED_POOLS )
                    first_unused_s_poolid = i;
            }
        }

        /* Failed to find a global shared pool slot. */
        if ( first_unused_s_poolid == MAX_GLOBAL_SHARED_POOLS )
        {
            tmem_client_warn("tmem: failed... no global shared pool slots available\n");
            goto fail;
        }
        /* Add pool to global shared pool. */
        else
        {
            INIT_LIST_HEAD(&pool->share_list);
            pool->shared_count = 0;
            if ( shared_pool_join(pool, client) )
                goto fail;
            tmem_global.shared_pools[first_unused_s_poolid] = pool;
        }
    }

out:
    tmem_client_info("pool_id=%d\n", d_poolid);
    client->info.nr_pools++;
    return d_poolid;

fail:
    pool_free(pool);
    return -EPERM;
}

/************ TMEM CONTROL OPERATIONS ************************************/

static int tmemc_shared_pool_auth(domid_t cli_id, uint64_t uuid_lo,
                                  uint64_t uuid_hi, bool_t auth)
{
    struct client *client;
    int i, free = -1;

    if ( cli_id == TMEM_CLI_ID_NULL )
    {
        tmem_global.shared_auth = auth;
        return 1;
    }
    client = tmem_client_from_cli_id(cli_id);
    if ( client == NULL )
        return -EINVAL;

    for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++)
    {
        if ( auth == 0 )
        {
            if ( (client->shared_auth_uuid[i][0] == uuid_lo) &&
                    (client->shared_auth_uuid[i][1] == uuid_hi) )
            {
                client->shared_auth_uuid[i][0] = -1L;
                client->shared_auth_uuid[i][1] = -1L;
                return 1;
            }
        }
        else
        {
            if ( (client->shared_auth_uuid[i][0] == -1L) &&
                    (client->shared_auth_uuid[i][1] == -1L) )
            {
                free = i;
                break;
            }
	}
    }
    if ( auth == 0 )
        return 0;
    else if ( free == -1)
        return -ENOMEM;
    else
    {
        client->shared_auth_uuid[free][0] = uuid_lo;
        client->shared_auth_uuid[free][1] = uuid_hi;
        return 1;
    }
}

static int tmemc_save_subop(int cli_id, uint32_t pool_id,
                        uint32_t subop, tmem_cli_va_param_t buf, uint32_t arg)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    uint32_t p;
    struct tmem_page_descriptor *pgp, *pgp2;
    int rc = -ENOENT;

    switch(subop)
    {
    case XEN_SYSCTL_TMEM_OP_SAVE_BEGIN:
        if ( client == NULL )
            break;
        for (p = 0; p < MAX_POOLS_PER_DOMAIN; p++)
            if ( client->pools[p] != NULL )
                break;

        if ( p == MAX_POOLS_PER_DOMAIN )
            break;

        client->was_frozen = client->info.flags.u.frozen;
        client->info.flags.u.frozen = 1;
        if ( arg != 0 )
            client->info.flags.u.migrating = 1;
        rc = 0;
        break;
    case XEN_SYSCTL_TMEM_OP_RESTORE_BEGIN:
        if ( client == NULL )
            rc = client_create(cli_id) ? 0 : -ENOMEM;
        else
            rc = -EEXIST;
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_END:
        if ( client == NULL )
            break;
        client->info.flags.u.migrating = 0;
        if ( !list_empty(&client->persistent_invalidated_list) )
            list_for_each_entry_safe(pgp,pgp2,
              &client->persistent_invalidated_list, client_inv_pages)
                __pgp_free(pgp, client->pools[pgp->pool_id]);
        client->info.flags.u.frozen = client->was_frozen;
        rc = 0;
        break;
    }
    return rc;
}

static int tmemc_save_get_next_page(int cli_id, uint32_t pool_id,
                        tmem_cli_va_param_t buf, uint32_t bufsize)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    struct tmem_pool *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];
    struct tmem_page_descriptor *pgp;
    struct xen_tmem_oid *oid;
    int ret = 0;
    struct tmem_handle h;

    if ( pool == NULL || !is_persistent(pool) )
        return -1;

    if ( bufsize < PAGE_SIZE + sizeof(struct tmem_handle) )
        return -ENOMEM;

    spin_lock(&pers_lists_spinlock);
    if ( list_empty(&pool->persistent_page_list) )
    {
        ret = -1;
        goto out;
    }
    /* Note: pool->cur_pgp is the pgp last returned by get_next_page. */
    if ( pool->cur_pgp == NULL )
    {
        /* Process the first one. */
        pool->cur_pgp = pgp = list_entry((&pool->persistent_page_list)->next,
                         struct tmem_page_descriptor,us.pool_pers_pages);
    } else if ( list_is_last(&pool->cur_pgp->us.pool_pers_pages,
                             &pool->persistent_page_list) )
    {
        /* Already processed the last one in the list. */
        ret = -1;
        goto out;
    }
    pgp = list_entry((&pool->cur_pgp->us.pool_pers_pages)->next,
                         struct tmem_page_descriptor,us.pool_pers_pages);
    pool->cur_pgp = pgp;
    oid = &pgp->us.obj->oid;
    h.pool_id = pool_id;
    BUILD_BUG_ON(sizeof(h.oid) != sizeof(*oid));
    memcpy(&(h.oid), oid, sizeof(h.oid));
    h.index = pgp->index;
    if ( copy_to_guest(guest_handle_cast(buf, void), &h, 1) )
    {
        ret = -EFAULT;
        goto out;
    }
    guest_handle_add_offset(buf, sizeof(h));
    ret = do_tmem_get(pool, oid, pgp->index, 0, buf);

out:
    spin_unlock(&pers_lists_spinlock);
    return ret;
}

static int tmemc_save_get_next_inv(int cli_id, tmem_cli_va_param_t buf,
                        uint32_t bufsize)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    struct tmem_page_descriptor *pgp;
    struct tmem_handle h;
    int ret = 0;

    if ( client == NULL )
        return 0;
    if ( bufsize < sizeof(struct tmem_handle) )
        return 0;
    spin_lock(&pers_lists_spinlock);
    if ( list_empty(&client->persistent_invalidated_list) )
        goto out;
    if ( client->cur_pgp == NULL )
    {
        pgp = list_entry((&client->persistent_invalidated_list)->next,
                         struct tmem_page_descriptor,client_inv_pages);
        client->cur_pgp = pgp;
    } else if ( list_is_last(&client->cur_pgp->client_inv_pages,
                             &client->persistent_invalidated_list) )
    {
        client->cur_pgp = NULL;
        ret = 0;
        goto out;
    } else {
        pgp = list_entry((&client->cur_pgp->client_inv_pages)->next,
                         struct tmem_page_descriptor,client_inv_pages);
        client->cur_pgp = pgp;
    }
    h.pool_id = pgp->pool_id;
    BUILD_BUG_ON(sizeof(h.oid) != sizeof(pgp->inv_oid));
    memcpy(&(h.oid), &(pgp->inv_oid), sizeof(h.oid));
    h.index = pgp->index;
    ret = 1;
    if ( copy_to_guest(guest_handle_cast(buf, void), &h, 1) )
        ret = -EFAULT;
out:
    spin_unlock(&pers_lists_spinlock);
    return ret;
}

static int tmemc_restore_put_page(int cli_id, uint32_t pool_id,
                                  struct xen_tmem_oid *oidp,
                                  uint32_t index, tmem_cli_va_param_t buf,
                                  uint32_t bufsize)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    struct tmem_pool *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];

    if ( pool == NULL )
        return -1;
    if (bufsize != PAGE_SIZE) {
        tmem_client_err("tmem: %s: invalid parameter bufsize(%d) != (%ld)\n",
                __func__, bufsize, PAGE_SIZE);
        return -EINVAL;
    }
    return do_tmem_put(pool, oidp, index, 0, buf);
}

static int tmemc_restore_flush_page(int cli_id, uint32_t pool_id,
                                    struct xen_tmem_oid *oidp,
                                    uint32_t index)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    struct tmem_pool *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];

    if ( pool == NULL )
        return -1;
    return do_tmem_flush_page(pool,oidp,index);
}

int do_tmem_control(struct xen_sysctl_tmem_op *op)
{
    int ret;
    uint32_t pool_id = op->pool_id;
    uint32_t cmd = op->cmd;
    struct xen_tmem_oid *oidp = &op->oid;

    ASSERT(rw_is_write_locked(&tmem_rwlock));

    switch (cmd)
    {
    case XEN_SYSCTL_TMEM_OP_SAVE_BEGIN:
    case XEN_SYSCTL_TMEM_OP_RESTORE_BEGIN:
    case XEN_SYSCTL_TMEM_OP_SAVE_END:
        ret = tmemc_save_subop(op->cli_id, pool_id, cmd,
                               guest_handle_cast(op->u.buf, char), op->arg);
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_NEXT_PAGE:
        ret = tmemc_save_get_next_page(op->cli_id, pool_id,
                                       guest_handle_cast(op->u.buf, char), op->len);
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_NEXT_INV:
        ret = tmemc_save_get_next_inv(op->cli_id,
                                      guest_handle_cast(op->u.buf, char), op->len);
        break;
    case XEN_SYSCTL_TMEM_OP_RESTORE_PUT_PAGE:
        ret = tmemc_restore_put_page(op->cli_id, pool_id, oidp, op->arg,
                                     guest_handle_cast(op->u.buf, char), op->len);
        break;
    case XEN_SYSCTL_TMEM_OP_RESTORE_FLUSH_PAGE:
        ret = tmemc_restore_flush_page(op->cli_id, pool_id, oidp, op->arg);
        break;
    default:
        ret = -1;
    }

    return ret;
}

/************ EXPORTed FUNCTIONS **************************************/

long do_tmem_op(tmem_cli_op_t uops)
{
    struct tmem_op op;
    struct client *client = current->domain->tmem_client;
    struct tmem_pool *pool = NULL;
    struct xen_tmem_oid *oidp;
    int rc = 0;
    bool_t succ_get = 0, succ_put = 0;
    bool_t non_succ_get = 0, non_succ_put = 0;
    bool_t flush = 0, flush_obj = 0;

    if ( !tmem_initialized )
        return -ENODEV;

    if ( xsm_tmem_op(XSM_HOOK) )
        return -EPERM;

    tmem_stats.total_tmem_ops++;

    if ( client != NULL && client->domain->is_dying )
    {
        tmem_stats.errored_tmem_ops++;
        return -ENODEV;
    }

    if ( unlikely(tmem_get_tmemop_from_client(&op, uops) != 0) )
    {
        tmem_client_err("tmem: can't get tmem struct from %s\n", tmem_client_str);
        tmem_stats.errored_tmem_ops++;
        return -EFAULT;
    }

    /* Acquire write lock for all commands at first. */
    write_lock(&tmem_rwlock);

    if ( op.cmd == TMEM_CONTROL )
    {
        rc = -EOPNOTSUPP;
    }
    else if ( op.cmd == TMEM_AUTH )
    {
        rc = tmemc_shared_pool_auth(op.u.creat.arg1,op.u.creat.uuid[0],
                         op.u.creat.uuid[1],op.u.creat.flags);
    }
    else if ( op.cmd == TMEM_RESTORE_NEW )
    {
        rc = do_tmem_new_pool(op.u.creat.arg1, op.pool_id, op.u.creat.flags,
                         op.u.creat.uuid[0], op.u.creat.uuid[1]);
    }
    else {
    /*
	 * For other commands, create per-client tmem structure dynamically on
	 * first use by client.
	 */
        if ( client == NULL )
        {
            if ( (client = client_create(current->domain->domain_id)) == NULL )
            {
                tmem_client_err("tmem: can't create tmem structure for %s\n",
                               tmem_client_str);
                rc = -ENOMEM;
                goto out;
            }
        }

        if ( op.cmd == TMEM_NEW_POOL || op.cmd == TMEM_DESTROY_POOL )
        {
            if ( op.cmd == TMEM_NEW_POOL )
                rc = do_tmem_new_pool(TMEM_CLI_ID_NULL, 0, op.u.creat.flags,
                                op.u.creat.uuid[0], op.u.creat.uuid[1]);
	        else
                rc = do_tmem_destroy_pool(op.pool_id);
        }
        else
        {
            if ( ((uint32_t)op.pool_id >= MAX_POOLS_PER_DOMAIN) ||
                 ((pool = client->pools[op.pool_id]) == NULL) )
            {
                tmem_client_err("tmem: operation requested on uncreated pool\n");
                rc = -ENODEV;
                goto out;
            }
            /* Commands that only need read lock. */
            write_unlock(&tmem_rwlock);
            read_lock(&tmem_rwlock);

            oidp = &op.u.gen.oid;
            switch ( op.cmd )
            {
            case TMEM_NEW_POOL:
            case TMEM_DESTROY_POOL:
                BUG(); /* Done earlier. */
                break;
            case TMEM_PUT_PAGE:
                if (tmem_ensure_avail_pages())
                    rc = do_tmem_put(pool, oidp, op.u.gen.index, op.u.gen.cmfn,
                                tmem_cli_buf_null);
                else
                    rc = -ENOMEM;
                if (rc == 1) succ_put = 1;
                else non_succ_put = 1;
                break;
            case TMEM_GET_PAGE:
                rc = do_tmem_get(pool, oidp, op.u.gen.index, op.u.gen.cmfn,
                                tmem_cli_buf_null);
                if (rc == 1) succ_get = 1;
                else non_succ_get = 1;
                break;
            case TMEM_FLUSH_PAGE:
                flush = 1;
                rc = do_tmem_flush_page(pool, oidp, op.u.gen.index);
                break;
            case TMEM_FLUSH_OBJECT:
                rc = do_tmem_flush_object(pool, oidp);
                flush_obj = 1;
                break;
            default:
                tmem_client_warn("tmem: op %d not implemented\n", op.cmd);
                rc = -ENOSYS;
                break;
            }
            read_unlock(&tmem_rwlock);
            if ( rc < 0 )
                tmem_stats.errored_tmem_ops++;
            return rc;
        }
    }
out:
    write_unlock(&tmem_rwlock);
    if ( rc < 0 )
        tmem_stats.errored_tmem_ops++;
    return rc;
}

/* This should be called when the host is destroying a client (domain). */
void tmem_destroy(void *v)
{
    struct client *client = (struct client *)v;

    if ( client == NULL )
        return;

    if ( !client->domain->is_dying )
    {
        printk("tmem: tmem_destroy can only destroy dying client\n");
        return;
    }

    write_lock(&tmem_rwlock);

    printk("tmem: flushing tmem pools for %s=%d\n",
           tmem_cli_id_str, client->cli_id);
    client_flush(client);

    write_unlock(&tmem_rwlock);
}

#define MAX_EVICTS 10  /* Should be variable or set via XEN_SYSCTL_TMEM_OP_ ?? */
void *tmem_relinquish_pages(unsigned int order, unsigned int memflags)
{
    struct page_info *pfp;
    unsigned long evicts_per_relinq = 0;
    int max_evictions = 10;

    if (!tmem_enabled() || !tmem_freeable_pages())
        return NULL;

    tmem_stats.relinq_attempts++;
    if ( order > 0 )
    {
#ifndef NDEBUG
        printk("tmem_relinquish_page: failing order=%d\n", order);
#endif
        return NULL;
    }

    while ( (pfp = tmem_page_list_get()) == NULL )
    {
        if ( (max_evictions-- <= 0) || !tmem_evict())
            break;
        evicts_per_relinq++;
    }
    if ( evicts_per_relinq > tmem_stats.max_evicts_per_relinq )
        tmem_stats.max_evicts_per_relinq = evicts_per_relinq;
    if ( pfp != NULL )
    {
        if ( !(memflags & MEMF_tmem) )
            scrub_one_page(pfp);
        tmem_stats.relinq_pgs++;
    }

    return pfp;
}

unsigned long tmem_freeable_pages(void)
{
    if ( !tmem_enabled() )
        return 0;

    return tmem_page_list_pages + _atomic_read(freeable_page_count);
}

/* Called at hypervisor startup. */
static int __init init_tmem(void)
{
    if ( !tmem_enabled() )
        return 0;

    if ( !tmem_mempool_init() )
        return 0;

    if ( tmem_init() )
    {
        printk("tmem: initialized comp=%d\n", tmem_compression_enabled());
        tmem_initialized = 1;
    }
    else
        printk("tmem: initialization FAILED\n");

    return 0;
}
__initcall(init_tmem);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
