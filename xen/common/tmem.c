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
#include <xen/tmem_xen.h> /* host-specific (eg Xen) code goes here */
#endif

#include <xen/tmem.h>
#include <xen/rbtree.h>
#include <xen/radix-tree.h>
#include <xen/list.h>
#include <xen/init.h>

#define TMEM_SPEC_VERSION 1

/* global statistics (none need to be locked) */
static unsigned long total_tmem_ops = 0;
static unsigned long errored_tmem_ops = 0;
static unsigned long total_flush_pool = 0;
static unsigned long alloc_failed = 0, alloc_page_failed = 0;
static unsigned long evicted_pgs = 0, evict_attempts = 0;
static unsigned long relinq_pgs = 0, relinq_attempts = 0;
static unsigned long max_evicts_per_relinq = 0;
static unsigned long low_on_memory = 0;
static unsigned long deduped_puts = 0;
static unsigned long tot_good_eph_puts = 0;
static int global_obj_count_max = 0;
static int global_pgp_count_max = 0;
static int global_pcd_count_max = 0;
static int global_page_count_max = 0;
static int global_rtree_node_count_max = 0;
static long global_eph_count_max = 0;
static unsigned long failed_copies;
static unsigned long pcd_tot_tze_size = 0;
static unsigned long pcd_tot_csize = 0;

/************ CORE DATA STRUCTURES ************************************/

#define MAX_POOLS_PER_DOMAIN 16
#define MAX_GLOBAL_SHARED_POOLS  16

struct tmem_pool;
struct tmem_page_descriptor;
struct tmem_page_content_descriptor;
struct client {
    struct list_head client_list;
    struct tmem_pool *pools[MAX_POOLS_PER_DOMAIN];
    struct domain *domain;
    struct xmem_pool *persistent_pool;
    struct list_head ephemeral_page_list;
    long eph_count, eph_count_max;
    domid_t cli_id;
    uint32_t weight;
    uint32_t cap;
    bool_t compress;
    bool_t frozen;
    bool_t shared_auth_required;
    /* for save/restore/migration */
    bool_t live_migrating;
    bool_t was_frozen;
    struct list_head persistent_invalidated_list;
    struct tmem_page_descriptor *cur_pgp;
    /* statistics collection */
    unsigned long compress_poor, compress_nomem;
    unsigned long compressed_pages;
    uint64_t compressed_sum_size;
    uint64_t total_cycles;
    unsigned long succ_pers_puts, succ_eph_gets, succ_pers_gets;
    /* shared pool authentication */
    uint64_t shared_auth_uuid[MAX_GLOBAL_SHARED_POOLS][2];
};

struct share_list {
    struct list_head share_list;
    struct client *client;
};

#define POOL_PAGESHIFT (PAGE_SHIFT - 12)
#define OBJ_HASH_BUCKETS 256 /* must be power of two */
#define OBJ_HASH_BUCKETS_MASK (OBJ_HASH_BUCKETS-1)

struct tmem_pool {
    bool_t shared;
    bool_t persistent;
    bool_t is_dying;
    struct client *client;
    uint64_t uuid[2]; /* 0 for private, non-zero for shared */
    uint32_t pool_id;
    rwlock_t pool_rwlock;
    struct rb_root obj_rb_root[OBJ_HASH_BUCKETS]; /* protected by pool_rwlock */
    struct list_head share_list; /* valid if shared */
    int shared_count; /* valid if shared */
    /* for save/restore/migration */
    struct list_head persistent_page_list;
    struct tmem_page_descriptor *cur_pgp;
    /* statistics collection */
    atomic_t pgp_count;
    int pgp_count_max;
    long obj_count;  /* atomicity depends on pool_rwlock held for write */
    long obj_count_max;  
    unsigned long objnode_count, objnode_count_max;
    uint64_t sum_life_cycles;
    uint64_t sum_evicted_cycles;
    unsigned long puts, good_puts, no_mem_puts;
    unsigned long dup_puts_flushed, dup_puts_replaced;
    unsigned long gets, found_gets;
    unsigned long flushs, flushs_found;
    unsigned long flush_objs, flush_objs_found;
};

#define is_persistent(_p)  (_p->persistent)
#define is_shared(_p)      (_p->shared)

struct oid {
    uint64_t oid[3];
};

struct tmem_object_root {
    struct oid oid;
    struct rb_node rb_tree_node; /* protected by pool->pool_rwlock */
    unsigned long objnode_count; /* atomicity depends on obj_spinlock */
    long pgp_count; /* atomicity depends on obj_spinlock */
    struct radix_tree_root tree_root; /* tree of pages within object */
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
        struct oid inv_oid;  /* used for invalid list only */
    };
    pagesize_t size; /* 0 == PAGE_SIZE (pfp), -1 == data invalid,
                    else compressed data (cdata) */
    uint32_t index;
    /* must hold pcd_tree_rwlocks[firstbyte] to use pcd pointer/siblings */
    uint16_t firstbyte; /* NON_SHAREABLE->pfp  otherwise->pcd */
    bool_t eviction_attempted;  /* CHANGE TO lifetimes? (settable) */
    struct list_head pcd_siblings;
    union {
        struct page_info *pfp;  /* page frame pointer */
        char *cdata; /* compressed data */
        struct tmem_page_content_descriptor *pcd; /* page dedup */
    };
    union {
        uint64_t timestamp;
        uint32_t pool_id;  /* used for invalid list only */
    };
};

#define PCD_TZE_MAX_SIZE (PAGE_SIZE - (PAGE_SIZE/64))

struct tmem_page_content_descriptor {
    union {
        struct page_info *pfp;  /* page frame pointer */
        char *cdata; /* if compression_enabled */
        char *tze; /* if !compression_enabled, trailing zeroes eliminated */
    };
    struct list_head pgp_list;
    struct rb_node pcd_rb_tree_node;
    uint32_t pgp_ref_count;
    pagesize_t size; /* if compression_enabled -> 0<size<PAGE_SIZE (*cdata)
                     * else if tze, 0<=size<PAGE_SIZE, rounded up to mult of 8
                     * else PAGE_SIZE -> *pfp */
};
struct rb_root pcd_tree_roots[256]; /* choose based on first byte of page */
rwlock_t pcd_tree_rwlocks[256]; /* poor man's concurrency for now */

static LIST_HEAD(global_ephemeral_page_list); /* all pages in ephemeral pools */

static LIST_HEAD(global_client_list);

static struct tmem_pool *global_shared_pools[MAX_GLOBAL_SHARED_POOLS] = { 0 };
static bool_t global_shared_auth = 0;
static atomic_t client_weight_total = ATOMIC_INIT(0);
static int tmem_initialized = 0;

struct xmem_pool *tmem_mempool = 0;
unsigned int tmem_mempool_maxalloc = 0;

DEFINE_SPINLOCK(tmem_page_list_lock);
PAGE_LIST_HEAD(tmem_page_list);
unsigned long tmem_page_list_pages = 0;

DEFINE_RWLOCK(tmem_rwlock);
static DEFINE_SPINLOCK(eph_lists_spinlock); /* protects global AND clients */
static DEFINE_SPINLOCK(pers_lists_spinlock);

#define ASSERT_SPINLOCK(_l) ASSERT(spin_is_locked(_l))
#define ASSERT_WRITELOCK(_l) ASSERT(rw_is_write_locked(_l))

/* global counters (should use long_atomic_t access) */
static long global_eph_count = 0; /* atomicity depends on eph_lists_spinlock */
static atomic_t global_obj_count = ATOMIC_INIT(0);
static atomic_t global_pgp_count = ATOMIC_INIT(0);
static atomic_t global_pcd_count = ATOMIC_INIT(0);
static atomic_t global_page_count = ATOMIC_INIT(0);
static atomic_t global_rtree_node_count = ATOMIC_INIT(0);

#define atomic_inc_and_max(_c) do { \
    atomic_inc(&_c); \
    if ( _atomic_read(_c) > _c##_max ) \
        _c##_max = _atomic_read(_c); \
} while (0)

#define atomic_dec_and_assert(_c) do { \
    atomic_dec(&_c); \
    ASSERT(_atomic_read(_c) >= 0); \
} while (0)


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
        alloc_failed++;
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
        alloc_page_failed++;
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

/* persistent pools are per-domain */
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
 * Page content descriptor manipulation routines
 */
#define NOT_SHAREABLE ((uint16_t)-1UL)

static int pcd_copy_to_client(xen_pfn_t cmfn, struct tmem_page_descriptor *pgp)
{
    uint8_t firstbyte = pgp->firstbyte;
    struct tmem_page_content_descriptor *pcd;
    int ret;

    ASSERT(tmem_dedup_enabled());
    read_lock(&pcd_tree_rwlocks[firstbyte]);
    pcd = pgp->pcd;
    if ( pgp->size < PAGE_SIZE && pgp->size != 0 &&
         pcd->size < PAGE_SIZE && pcd->size != 0 )
        ret = tmem_decompress_to_client(cmfn, pcd->cdata, pcd->size,
                                       tmem_cli_buf_null);
    else if ( tmem_tze_enabled() && pcd->size < PAGE_SIZE )
        ret = tmem_copy_tze_to_client(cmfn, pcd->tze, pcd->size);
    else
        ret = tmem_copy_to_client(cmfn, pcd->pfp, tmem_cli_buf_null);
    read_unlock(&pcd_tree_rwlocks[firstbyte]);
    return ret;
}

/* ensure pgp no longer points to pcd, nor vice-versa */
/* take pcd rwlock unless have_pcd_rwlock is set, always unlock when done */
static void pcd_disassociate(struct tmem_page_descriptor *pgp, struct tmem_pool *pool, bool_t have_pcd_rwlock)
{
    struct tmem_page_content_descriptor *pcd = pgp->pcd;
    struct page_info *pfp = pgp->pcd->pfp;
    uint16_t firstbyte = pgp->firstbyte;
    char *pcd_tze = pgp->pcd->tze;
    pagesize_t pcd_size = pcd->size;
    pagesize_t pgp_size = pgp->size;
    char *pcd_cdata = pgp->pcd->cdata;
    pagesize_t pcd_csize = pgp->pcd->size;

    ASSERT(tmem_dedup_enabled());
    ASSERT(firstbyte != NOT_SHAREABLE);
    ASSERT(firstbyte < 256);

    if ( have_pcd_rwlock )
        ASSERT_WRITELOCK(&pcd_tree_rwlocks[firstbyte]);
    else
        write_lock(&pcd_tree_rwlocks[firstbyte]);
    list_del_init(&pgp->pcd_siblings);
    pgp->pcd = NULL;
    pgp->firstbyte = NOT_SHAREABLE;
    pgp->size = -1;
    if ( --pcd->pgp_ref_count )
    {
        write_unlock(&pcd_tree_rwlocks[firstbyte]);
        return;
    }

    /* no more references to this pcd, recycle it and the physical page */
    ASSERT(list_empty(&pcd->pgp_list));
    pcd->pfp = NULL;
    /* remove pcd from rbtree */
    rb_erase(&pcd->pcd_rb_tree_node,&pcd_tree_roots[firstbyte]);
    /* reinit the struct for safety for now */
    RB_CLEAR_NODE(&pcd->pcd_rb_tree_node);
    /* now free up the pcd memory */
    tmem_free(pcd, NULL);
    atomic_dec_and_assert(global_pcd_count);
    if ( pgp_size != 0 && pcd_size < PAGE_SIZE )
    {
        /* compressed data */
        tmem_free(pcd_cdata, pool);
        pcd_tot_csize -= pcd_csize;
    }
    else if ( pcd_size != PAGE_SIZE )
    {
        /* trailing zero data */
        pcd_tot_tze_size -= pcd_size;
        if ( pcd_size )
            tmem_free(pcd_tze, pool);
    } else {
        /* real physical page */
        if ( tmem_tze_enabled() )
            pcd_tot_tze_size -= PAGE_SIZE;
        if ( tmem_compression_enabled() )
            pcd_tot_csize -= PAGE_SIZE;
        tmem_free_page(pool,pfp);
    }
    write_unlock(&pcd_tree_rwlocks[firstbyte]);
}


static int pcd_associate(struct tmem_page_descriptor *pgp, char *cdata, pagesize_t csize)
{
    struct rb_node **new, *parent = NULL;
    struct rb_root *root;
    struct tmem_page_content_descriptor *pcd;
    int cmp;
    pagesize_t pfp_size = 0;
    uint8_t firstbyte = (cdata == NULL) ? tmem_get_first_byte(pgp->pfp) : *cdata;
    int ret = 0;

    if ( !tmem_dedup_enabled() )
        return 0;
    ASSERT(pgp->us.obj != NULL);
    ASSERT(pgp->us.obj->pool != NULL);
    ASSERT(!pgp->us.obj->pool->persistent);
    if ( cdata == NULL )
    {
        ASSERT(pgp->pfp != NULL);
        pfp_size = PAGE_SIZE;
        if ( tmem_tze_enabled() )
        {
            pfp_size = tmem_tze_pfp_scan(pgp->pfp);
            if ( pfp_size > PCD_TZE_MAX_SIZE )
                pfp_size = PAGE_SIZE;
        }
        ASSERT(pfp_size <= PAGE_SIZE);
        ASSERT(!(pfp_size & (sizeof(uint64_t)-1)));
    }
    write_lock(&pcd_tree_rwlocks[firstbyte]);

    /* look for page match */
    root = &pcd_tree_roots[firstbyte];
    new = &(root->rb_node);
    while ( *new )
    {
        pcd = container_of(*new, struct tmem_page_content_descriptor, pcd_rb_tree_node);
        parent = *new;
        /* compare new entry and rbtree entry, set cmp accordingly */
        if ( cdata != NULL )
        {
            if ( pcd->size < PAGE_SIZE )
                /* both new entry and rbtree entry are compressed */
                cmp = tmem_pcd_cmp(cdata,csize,pcd->cdata,pcd->size);
            else
                /* new entry is compressed, rbtree entry is not */
                cmp = -1;
        } else if ( pcd->size < PAGE_SIZE )
            /* rbtree entry is compressed, rbtree entry is not */
            cmp = 1;
        else if ( tmem_tze_enabled() ) {
            if ( pcd->size < PAGE_SIZE )
                /* both new entry and rbtree entry are trailing zero */
                cmp = tmem_tze_pfp_cmp(pgp->pfp,pfp_size,pcd->tze,pcd->size);
            else
                /* new entry is trailing zero, rbtree entry is not */
                cmp = tmem_tze_pfp_cmp(pgp->pfp,pfp_size,pcd->pfp,PAGE_SIZE);
        } else  {
            /* both new entry and rbtree entry are full physical pages */
            ASSERT(pgp->pfp != NULL);
            ASSERT(pcd->pfp != NULL);
            cmp = tmem_page_cmp(pgp->pfp,pcd->pfp);
        }

        /* walk tree or match depending on cmp */
        if ( cmp < 0 )
            new = &((*new)->rb_left);
        else if ( cmp > 0 )
            new = &((*new)->rb_right);
        else
        {
            /* match! if not compressed, free the no-longer-needed page */
            /* but if compressed, data is assumed static so don't free! */
            if ( cdata == NULL )
                tmem_free_page(pgp->us.obj->pool,pgp->pfp);
            deduped_puts++;
            goto match;
        }
    }

    /* exited while loop with no match, so alloc a pcd and put it in the tree */
    if ( (pcd = tmem_malloc(sizeof(struct tmem_page_content_descriptor), NULL)) == NULL )
    {
        ret = -ENOMEM;
        goto unlock;
    } else if ( cdata != NULL ) {
        if ( (pcd->cdata = tmem_malloc(csize,pgp->us.obj->pool)) == NULL )
        {
            tmem_free(pcd, NULL);
            ret = -ENOMEM;
            goto unlock;
        }
    }
    atomic_inc_and_max(global_pcd_count);
    RB_CLEAR_NODE(&pcd->pcd_rb_tree_node);  /* is this necessary */
    INIT_LIST_HEAD(&pcd->pgp_list);  /* is this necessary */
    pcd->pgp_ref_count = 0;
    if ( cdata != NULL )
    {
        memcpy(pcd->cdata,cdata,csize);
        pcd->size = csize;
        pcd_tot_csize += csize;
    } else if ( pfp_size == 0 ) {
        ASSERT(tmem_tze_enabled());
        pcd->size = 0;
        pcd->tze = NULL;
    } else if ( pfp_size < PAGE_SIZE &&
         ((pcd->tze = tmem_malloc(pfp_size,pgp->us.obj->pool)) != NULL) ) {
        tmem_tze_copy_from_pfp(pcd->tze,pgp->pfp,pfp_size);
        pcd->size = pfp_size;
        pcd_tot_tze_size += pfp_size;
        tmem_free_page(pgp->us.obj->pool,pgp->pfp);
    } else {
        pcd->pfp = pgp->pfp;
        pcd->size = PAGE_SIZE;
        if ( tmem_tze_enabled() )
            pcd_tot_tze_size += PAGE_SIZE;
        if ( tmem_compression_enabled() )
            pcd_tot_csize += PAGE_SIZE;
    }
    rb_link_node(&pcd->pcd_rb_tree_node, parent, new);
    rb_insert_color(&pcd->pcd_rb_tree_node, root);

match:
    pcd->pgp_ref_count++;
    list_add(&pgp->pcd_siblings,&pcd->pgp_list);
    pgp->firstbyte = firstbyte;
    pgp->eviction_attempted = 0;
    pgp->pcd = pcd;

unlock:
    write_unlock(&pcd_tree_rwlocks[firstbyte]);
    return ret;
}

/************ PAGE DESCRIPTOR MANIPULATION ROUTINES *******************/

/* allocate a struct tmem_page_descriptor and associate it with an object */
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
    if ( tmem_dedup_enabled() )
    {
        pgp->firstbyte = NOT_SHAREABLE;
        pgp->eviction_attempted = 0;
        INIT_LIST_HEAD(&pgp->pcd_siblings);
    }
    pgp->size = -1;
    pgp->index = -1;
    pgp->timestamp = get_cycles();
    atomic_inc_and_max(global_pgp_count);
    atomic_inc_and_max(pool->pgp_count);
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
    if ( tmem_dedup_enabled() && pgp->firstbyte != NOT_SHAREABLE )
        pcd_disassociate(pgp,pool,0); /* pgp->size lost */
    else if ( pgp_size )
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
    atomic_dec_and_assert(pool->pgp_count);
    pgp->size = -1;
    if ( is_persistent(pool) && pool->client->live_migrating )
    {
        pgp->inv_oid = pgp->us.obj->oid;
        pgp->pool_id = pool->pool_id;
        return;
    }
    __pgp_free(pgp, pool);
}

/* remove pgp from global/pool/client lists and free it */
static void pgp_delist_free(struct tmem_page_descriptor *pgp)
{
    struct client *client;
    uint64_t life;

    ASSERT(pgp != NULL);
    ASSERT(pgp->us.obj != NULL);
    ASSERT(pgp->us.obj->pool != NULL);
    client = pgp->us.obj->pool->client;
    ASSERT(client != NULL);

    /* Delist pgp */
    if ( !is_persistent(pgp->us.obj->pool) )
    {
        spin_lock(&eph_lists_spinlock);
        if ( !list_empty(&pgp->us.client_eph_pages) )
            client->eph_count--;
        ASSERT(client->eph_count >= 0);
        list_del_init(&pgp->us.client_eph_pages);
        if ( !list_empty(&pgp->global_eph_pages) )
            global_eph_count--;
        ASSERT(global_eph_count >= 0);
        list_del_init(&pgp->global_eph_pages);
        spin_unlock(&eph_lists_spinlock);
    }
    else
    {
        if ( client->live_migrating )
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

    /* free pgp */
    pgp_free(pgp);
}

/* called only indirectly by radix_tree_destroy */
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

/* called only indirectly from radix_tree_insert */
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

/* called only indirectly from radix_tree_delete/destroy */
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

static int oid_compare(struct oid *left, struct oid *right)
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

static void oid_set_invalid(struct oid *oidp)
{
    oidp->oid[0] = oidp->oid[1] = oidp->oid[2] = -1UL;
}

static unsigned oid_hash(struct oid *oidp)
{
    return (tmem_hash(oidp->oid[0] ^ oidp->oid[1] ^ oidp->oid[2],
                     BITS_PER_LONG) & OBJ_HASH_BUCKETS_MASK);
}

/* searches for object==oid in pool, returns locked object if found */
static struct tmem_object_root * obj_find(struct tmem_pool *pool, struct oid *oidp)
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
            case 0: /* equal */
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

/* free an object that has no more pgps in it */
static void obj_free(struct tmem_object_root *obj)
{
    struct tmem_pool *pool;
    struct oid old_oid;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT(obj != NULL);
    ASSERT(obj->pgp_count == 0);
    pool = obj->pool;
    ASSERT(pool != NULL);
    ASSERT(pool->client != NULL);
    ASSERT_WRITELOCK(&pool->pool_rwlock);
    if ( obj->tree_root.rnode != NULL ) /* may be a "stump" with no leaves */
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
 * allocate, initialize, and insert an tmem_object_root
 * (should be called only if find failed)
 */
static struct tmem_object_root * obj_alloc(struct tmem_pool *pool, struct oid *oidp)
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

/* free an object after destroying any pgps in it */
static void obj_destroy(struct tmem_object_root *obj)
{
    ASSERT_WRITELOCK(&obj->pool->pool_rwlock);
    radix_tree_destroy(&obj->tree_root, pgp_destroy);
    obj_free(obj);
}

/* destroys all objs in a pool, or only if obj->last_client matches cli_id */
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
    ++pool->shared_count;
    return 0;
}

/* reassign "ownership" of the pool to another client that shares this pool */
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
    ASSERT(sl->client != old_client);
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

/* destroy all objects with last_client same as passed cli_id,
   remove pool's cli_id from list of sharers of this pool */
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
            if ( (global_shared_pools[s_poolid]) == pool )
            {
                global_shared_pools[s_poolid] = NULL;
                break;
            }
        return 0;
    }
    tmem_client_warn("tmem: no match unsharing pool, %s=%d\n",
        tmem_cli_id_str,pool->client->cli_id);
    return -1;
}

/* flush all data (owned by cli_id) from a pool and, optionally, free it */
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
    if ( pool->client->live_migrating )
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
    client->compress = tmem_compression_enabled();
    client->shared_auth_required = tmem_shared_auth();
    for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++)
        client->shared_auth_uuid[i][0] =
            client->shared_auth_uuid[i][1] = -1L;
    list_add_tail(&client->client_list, &global_client_list);
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

/* flush all data from a client and, optionally, free it */
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
    }
    client_free(client);
}

static bool_t client_over_quota(struct client *client)
{
    int total = _atomic_read(client_weight_total);

    ASSERT(client != NULL);
    if ( (total == 0) || (client->weight == 0) || 
          (client->eph_count == 0) )
        return 0;
    return ( ((global_eph_count*100L) / client->eph_count ) >
             ((total*100L) / client->weight) );
}

/************ MEMORY REVOCATION ROUTINES *******************************/

static bool_t tmem_try_to_evict_pgp(struct tmem_page_descriptor *pgp, bool_t *hold_pool_rwlock)
{
    struct tmem_object_root *obj = pgp->us.obj;
    struct tmem_pool *pool = obj->pool;
    struct client *client = pool->client;
    uint16_t firstbyte = pgp->firstbyte;

    if ( pool->is_dying )
        return 0;
    if ( spin_trylock(&obj->obj_spinlock) )
    {
        if ( tmem_dedup_enabled() )
        {
            firstbyte = pgp->firstbyte;
            if ( firstbyte ==  NOT_SHAREABLE )
                goto obj_unlock;
            ASSERT(firstbyte < 256);
            if ( !write_trylock(&pcd_tree_rwlocks[firstbyte]) )
                goto obj_unlock;
            if ( pgp->pcd->pgp_ref_count > 1 && !pgp->eviction_attempted )
            {
                pgp->eviction_attempted++;
                list_del(&pgp->global_eph_pages);
                list_add_tail(&pgp->global_eph_pages,&global_ephemeral_page_list);
                list_del(&pgp->us.client_eph_pages);
                list_add_tail(&pgp->us.client_eph_pages,&client->ephemeral_page_list);
                goto pcd_unlock;
            }
        }
        if ( obj->pgp_count > 1 )
            return 1;
        if ( write_trylock(&pool->pool_rwlock) )
        {
            *hold_pool_rwlock = 1;
            return 1;
        }
pcd_unlock:
        if ( tmem_dedup_enabled() )
            write_unlock(&pcd_tree_rwlocks[firstbyte]);
obj_unlock:
        spin_unlock(&obj->obj_spinlock);
    }
    return 0;
}

static int tmem_evict(void)
{
    struct client *client = current->domain->tmem_client;
    struct tmem_page_descriptor *pgp = NULL, *pgp_del;
    struct tmem_object_root *obj;
    struct tmem_pool *pool;
    int ret = 0;
    bool_t hold_pool_rwlock = 0;

    evict_attempts++;
    spin_lock(&eph_lists_spinlock);
    if ( (client != NULL) && client_over_quota(client) &&
         !list_empty(&client->ephemeral_page_list) )
    {
        list_for_each_entry(pgp, &client->ephemeral_page_list, us.client_eph_pages)
            if ( tmem_try_to_evict_pgp(pgp, &hold_pool_rwlock) )
                goto found;
    }
    else if ( !list_empty(&global_ephemeral_page_list) )
    {
        list_for_each_entry(pgp, &global_ephemeral_page_list, global_eph_pages)
            if ( tmem_try_to_evict_pgp(pgp, &hold_pool_rwlock) )
            {
                client = pgp->us.obj->pool->client;
                goto found;
            }
    }
     /* global_ephemeral_page_list is empty, so we bail out. */
    spin_unlock(&eph_lists_spinlock);
    goto out;

found:
    /* Delist */
    list_del_init(&pgp->us.client_eph_pages);
    client->eph_count--;
    list_del_init(&pgp->global_eph_pages);
    global_eph_count--;
    ASSERT(global_eph_count >= 0);
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
    if ( tmem_dedup_enabled() && pgp->firstbyte != NOT_SHAREABLE )
    {
        ASSERT(pgp->pcd->pgp_ref_count == 1 || pgp->eviction_attempted);
        pcd_disassociate(pgp,pool,1);
    }

    /* pgp already delist, so call pgp_free directly */
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
    evicted_pgs++;
    ret = 1;
out:
    return ret;
}

static unsigned long tmem_flush_npages(unsigned long n)
{
    unsigned long avail_pages = 0;

    while ( (avail_pages = tmem_page_list_pages) < n )
    {
        if (  !tmem_evict() )
            break;
    }
    if ( avail_pages )
    {
        spin_lock(&tmem_page_list_lock);
        while ( !page_list_empty(&tmem_page_list) )
        {
            struct page_info *pg = page_list_remove_head(&tmem_page_list);
            scrub_one_page(pg);
            tmem_page_list_pages--;
            free_domheap_page(pg);
        }
        ASSERT(tmem_page_list_pages == 0);
        INIT_PAGE_LIST_HEAD(&tmem_page_list);
        spin_unlock(&tmem_page_list_lock);
    }
    return avail_pages;
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
    } else if ( tmem_dedup_enabled() && !is_persistent(pgp->us.obj->pool) ) {
        if ( (ret = pcd_associate(pgp,dst,size)) == -ENOMEM )
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
    if ( client->live_migrating )
        goto failed_dup; /* no dups allowed when migrating */
    /* can we successfully manipulate pgp to change out the data? */
    if ( client->compress && pgp->size != 0 )
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
    if ( tmem_dedup_enabled() && !is_persistent(pool) )
    {
        if ( pcd_associate(pgp,NULL,0) == -ENOMEM )
            goto failed_dup;
    }

done:
    /* successfully replaced data, clean up and return success */
    if ( is_shared(pool) )
        obj->last_client = client->cli_id;
    spin_unlock(&obj->obj_spinlock);
    pool->dup_puts_replaced++;
    pool->good_puts++;
    if ( is_persistent(pool) )
        client->succ_pers_puts++;
    return 1;

bad_copy:
    failed_copies++;
    goto cleanup;

failed_dup:
   /* couldn't change out the data, flush the old data and return
    * -ENOSPC instead of -ENOMEM to differentiate failed _dup_ put */
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
              struct oid *oidp, uint32_t index,
              xen_pfn_t cmfn, tmem_cli_va_param_t clibuf)
{
    struct tmem_object_root *obj = NULL;
    struct tmem_page_descriptor *pgp = NULL;
    struct client *client;
    int ret, newobj = 0;

    ASSERT(pool != NULL);
    client = pool->client;
    ASSERT(client != NULL);
    ret = client->frozen ? -EFROZEN : -ENOMEM;
    pool->puts++;

refind:
    /* does page already exist (dup)?  if so, handle specially */
    if ( (obj = obj_find(pool, oidp)) != NULL )
    {
        if ((pgp = pgp_lookup_in_obj(obj, index)) != NULL)
        {
            return do_tmem_dup_put(pgp, cmfn, clibuf);
        }
        else
        {
            /* no puts allowed into a frozen pool (except dup puts) */
            if ( client->frozen )
	        goto unlock_obj;
        }
    }
    else
    {
        /* no puts allowed into a frozen pool (except dup puts) */
        if ( client->frozen )
            return ret;
        if ( (obj = obj_alloc(pool, oidp)) == NULL )
            return -ENOMEM;

        write_lock(&pool->pool_rwlock);
        /*
	 * Parallel callers may already allocated obj and inserted to obj_rb_root
	 * before us.
	 */
        if (!obj_rb_insert(&pool->obj_rb_root[oid_hash(oidp)], obj))
        {
            tmem_free(obj, pool);
            write_unlock(&pool->pool_rwlock);
            goto refind;
        }

        spin_lock(&obj->obj_spinlock);
        newobj = 1;
        write_unlock(&pool->pool_rwlock);
    }

    /* When arrive here, we have a spinlocked obj for use */
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    if ( (pgp = pgp_alloc(obj)) == NULL )
        goto unlock_obj;

    ret = pgp_add_to_obj(obj, index, pgp);
    if ( ret == -ENOMEM  )
        /* warning, may result in partially built radix tree ("stump") */
        goto free_pgp;

    pgp->index = index;
    pgp->size = 0;

    if ( client->compress )
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

    if ( tmem_dedup_enabled() && !is_persistent(pool) )
    {
        if ( pcd_associate(pgp, NULL, 0) == -ENOMEM )
        {
            ret = -ENOMEM;
            goto del_pgp_from_obj;
        }
    }

insert_page:
    if ( !is_persistent(pool) )
    {
        spin_lock(&eph_lists_spinlock);
        list_add_tail(&pgp->global_eph_pages,
            &global_ephemeral_page_list);
        if (++global_eph_count > global_eph_count_max)
            global_eph_count_max = global_eph_count;
        list_add_tail(&pgp->us.client_eph_pages,
            &client->ephemeral_page_list);
        if (++client->eph_count > client->eph_count_max)
            client->eph_count_max = client->eph_count;
        spin_unlock(&eph_lists_spinlock);
    }
    else
    { /* is_persistent */
        spin_lock(&pers_lists_spinlock);
        list_add_tail(&pgp->us.pool_pers_pages,
            &pool->persistent_page_list);
        spin_unlock(&pers_lists_spinlock);
    }

    if ( is_shared(pool) )
        obj->last_client = client->cli_id;

    /* free the obj spinlock */
    spin_unlock(&obj->obj_spinlock);
    pool->good_puts++;

    if ( is_persistent(pool) )
        client->succ_pers_puts++;
    else
        tot_good_eph_puts++;
    return 1;

bad_copy:
    failed_copies++;

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

static int do_tmem_get(struct tmem_pool *pool, struct oid *oidp, uint32_t index,
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
    if ( tmem_dedup_enabled() && !is_persistent(pool) &&
              pgp->firstbyte != NOT_SHAREABLE )
        rc = pcd_copy_to_client(cmfn, pgp);
    else if ( pgp->size != 0 )
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
            list_add_tail(&pgp->global_eph_pages,&global_ephemeral_page_list);
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
    failed_copies++;
    return rc;
}

static int do_tmem_flush_page(struct tmem_pool *pool, struct oid *oidp, uint32_t index)
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
    if ( pool->client->frozen )
        return -EFROZEN;
    else
        return 1;
}

static int do_tmem_flush_object(struct tmem_pool *pool, struct oid *oidp)
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
    if ( pool->client->frozen )
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
        if ( client->shared_auth_required && !global_shared_auth )
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
         * one
         */
        first_unused_s_poolid = MAX_GLOBAL_SHARED_POOLS;
        for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++ )
        {
            if ( (shpool = global_shared_pools[i]) != NULL )
            {
                if ( shpool->uuid[0] == uuid_lo && shpool->uuid[1] == uuid_hi )
                {
                    /* Succ to match a global shared pool */
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

        /* Failed to find a global shard pool slot */
        if ( first_unused_s_poolid == MAX_GLOBAL_SHARED_POOLS )
        {
            tmem_client_warn("tmem: failed... no global shared pool slots available\n");
            goto fail;
        }
        /* Add pool to global shard pool */
        else
        {
            INIT_LIST_HEAD(&pool->share_list);
            pool->shared_count = 0;
            global_shared_pools[first_unused_s_poolid] = pool;
        }
    }

out:
    tmem_client_info("pool_id=%d\n", d_poolid);
    return d_poolid;

fail:
    pool_free(pool);
    return -EPERM;
}

/************ TMEM CONTROL OPERATIONS ************************************/

/* freeze/thaw all pools belonging to client cli_id (all domains if -1) */
static int tmemc_freeze_pools(domid_t cli_id, int arg)
{
    struct client *client;
    bool_t freeze = (arg == TMEMC_FREEZE) ? 1 : 0;
    bool_t destroy = (arg == TMEMC_DESTROY) ? 1 : 0;
    char *s;

    s = destroy ? "destroyed" : ( freeze ? "frozen" : "thawed" );
    if ( cli_id == TMEM_CLI_ID_NULL )
    {
        list_for_each_entry(client,&global_client_list,client_list)
            client->frozen = freeze;
        tmem_client_info("tmem: all pools %s for all %ss\n", s, tmem_client_str);
    }
    else
    {
        if ( (client = tmem_client_from_cli_id(cli_id)) == NULL)
            return -1;
        client->frozen = freeze;
        tmem_client_info("tmem: all pools %s for %s=%d\n",
                         s, tmem_cli_id_str, cli_id);
    }
    return 0;
}

static int tmemc_flush_mem(domid_t cli_id, uint32_t kb)
{
    uint32_t npages, flushed_pages, flushed_kb;

    if ( cli_id != TMEM_CLI_ID_NULL )
    {
        tmem_client_warn("tmem: %s-specific flush not supported yet, use --all\n",
           tmem_client_str);
        return -1;
    }
    /* convert kb to pages, rounding up if necessary */
    npages = (kb + ((1 << (PAGE_SHIFT-10))-1)) >> (PAGE_SHIFT-10);
    flushed_pages = tmem_flush_npages(npages);
    flushed_kb = flushed_pages << (PAGE_SHIFT-10);
    return flushed_kb;
}

/*
 * These tmemc_list* routines output lots of stats in a format that is
 *  intended to be program-parseable, not human-readable. Further, by
 *  tying each group of stats to a line format indicator (e.g. G= for
 *  global stats) and each individual stat to a two-letter specifier
 *  (e.g. Ec:nnnnn in the G= line says there are nnnnn pages in the
 *  global ephemeral pool), it should allow the stats reported to be
 *  forward and backwards compatible as tmem evolves.
 */
#define BSIZE 1024

static int tmemc_list_client(struct client *c, tmem_cli_va_param_t buf,
                             int off, uint32_t len, bool_t use_long)
{
    char info[BSIZE];
    int i, n = 0, sum = 0;
    struct tmem_pool *p;
    bool_t s;

    n = scnprintf(info,BSIZE,"C=CI:%d,ww:%d,ca:%d,co:%d,fr:%d,"
        "Tc:%"PRIu64",Ge:%ld,Pp:%ld,Gp:%ld%c",
        c->cli_id, c->weight, c->cap, c->compress, c->frozen,
        c->total_cycles, c->succ_eph_gets, c->succ_pers_puts, c->succ_pers_gets,
        use_long ? ',' : '\n');
    if (use_long)
        n += scnprintf(info+n,BSIZE-n,
             "Ec:%ld,Em:%ld,cp:%ld,cb:%"PRId64",cn:%ld,cm:%ld\n",
             c->eph_count, c->eph_count_max,
             c->compressed_pages, c->compressed_sum_size,
             c->compress_poor, c->compress_nomem);
    if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
        sum += n;
    for ( i = 0; i < MAX_POOLS_PER_DOMAIN; i++ )
    {
        if ( (p = c->pools[i]) == NULL )
            continue;
        s = is_shared(p);
        n = scnprintf(info,BSIZE,"P=CI:%d,PI:%d,"
                      "PT:%c%c,U0:%"PRIx64",U1:%"PRIx64"%c",
                      c->cli_id, p->pool_id,
                      is_persistent(p) ? 'P' : 'E', s ? 'S' : 'P',
                      (uint64_t)(s ? p->uuid[0] : 0),
                      (uint64_t)(s ? p->uuid[1] : 0LL),
                      use_long ? ',' : '\n');
        if (use_long)
            n += scnprintf(info+n,BSIZE-n,
             "Pc:%d,Pm:%d,Oc:%ld,Om:%ld,Nc:%lu,Nm:%lu,"
             "ps:%lu,pt:%lu,pd:%lu,pr:%lu,px:%lu,gs:%lu,gt:%lu,"
             "fs:%lu,ft:%lu,os:%lu,ot:%lu\n",
             _atomic_read(p->pgp_count), p->pgp_count_max,
             p->obj_count, p->obj_count_max,
             p->objnode_count, p->objnode_count_max,
             p->good_puts, p->puts,p->dup_puts_flushed, p->dup_puts_replaced,
             p->no_mem_puts, 
             p->found_gets, p->gets,
             p->flushs_found, p->flushs, p->flush_objs_found, p->flush_objs);
        if ( sum + n >= len )
            return sum;
        if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
            sum += n;
    }
    return sum;
}

static int tmemc_list_shared(tmem_cli_va_param_t buf, int off, uint32_t len,
                              bool_t use_long)
{
    char info[BSIZE];
    int i, n = 0, sum = 0;
    struct tmem_pool *p;
    struct share_list *sl;

    for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++ )
    {
        if ( (p = global_shared_pools[i]) == NULL )
            continue;
        n = scnprintf(info+n,BSIZE-n,"S=SI:%d,PT:%c%c,U0:%"PRIx64",U1:%"PRIx64,
                      i, is_persistent(p) ? 'P' : 'E',
                      is_shared(p) ? 'S' : 'P',
                      p->uuid[0], p->uuid[1]);
        list_for_each_entry(sl,&p->share_list, share_list)
            n += scnprintf(info+n,BSIZE-n,",SC:%d",sl->client->cli_id);
        n += scnprintf(info+n,BSIZE-n,"%c", use_long ? ',' : '\n');
        if (use_long)
            n += scnprintf(info+n,BSIZE-n,
             "Pc:%d,Pm:%d,Oc:%ld,Om:%ld,Nc:%lu,Nm:%lu,"
             "ps:%lu,pt:%lu,pd:%lu,pr:%lu,px:%lu,gs:%lu,gt:%lu,"
             "fs:%lu,ft:%lu,os:%lu,ot:%lu\n",
             _atomic_read(p->pgp_count), p->pgp_count_max,
             p->obj_count, p->obj_count_max,
             p->objnode_count, p->objnode_count_max,
             p->good_puts, p->puts,p->dup_puts_flushed, p->dup_puts_replaced,
             p->no_mem_puts, 
             p->found_gets, p->gets,
             p->flushs_found, p->flushs, p->flush_objs_found, p->flush_objs);
        if ( sum + n >= len )
            return sum;
        if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
            sum += n;
    }
    return sum;
}

static int tmemc_list_global_perf(tmem_cli_va_param_t buf, int off,
                                  uint32_t len, bool_t use_long)
{
    char info[BSIZE];
    int n = 0, sum = 0;

    n = scnprintf(info+n,BSIZE-n,"T=");
    n--; /* overwrite trailing comma */
    n += scnprintf(info+n,BSIZE-n,"\n");
    if ( sum + n >= len )
        return sum;
    if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
        sum += n;
    return sum;
}

static int tmemc_list_global(tmem_cli_va_param_t buf, int off, uint32_t len,
                              bool_t use_long)
{
    char info[BSIZE];
    int n = 0, sum = off;

    n += scnprintf(info,BSIZE,"G="
      "Tt:%lu,Te:%lu,Cf:%lu,Af:%lu,Pf:%lu,Ta:%lu,"
      "Lm:%lu,Et:%lu,Ea:%lu,Rt:%lu,Ra:%lu,Rx:%lu,Fp:%lu%c",
      total_tmem_ops, errored_tmem_ops, failed_copies,
      alloc_failed, alloc_page_failed, tmem_page_list_pages,
      low_on_memory, evicted_pgs,
      evict_attempts, relinq_pgs, relinq_attempts, max_evicts_per_relinq,
      total_flush_pool, use_long ? ',' : '\n');
    if (use_long)
        n += scnprintf(info+n,BSIZE-n,
          "Ec:%ld,Em:%ld,Oc:%d,Om:%d,Nc:%d,Nm:%d,Pc:%d,Pm:%d,"
          "Fc:%d,Fm:%d,Sc:%d,Sm:%d,Ep:%lu,Gd:%lu,Zt:%lu,Gz:%lu\n",
          global_eph_count, global_eph_count_max,
          _atomic_read(global_obj_count), global_obj_count_max,
          _atomic_read(global_rtree_node_count), global_rtree_node_count_max,
          _atomic_read(global_pgp_count), global_pgp_count_max,
          _atomic_read(global_page_count), global_page_count_max,
          _atomic_read(global_pcd_count), global_pcd_count_max,
         tot_good_eph_puts,deduped_puts,pcd_tot_tze_size,pcd_tot_csize);
    if ( sum + n >= len )
        return sum;
    if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
        sum += n;
    return sum;
}

static int tmemc_list(domid_t cli_id, tmem_cli_va_param_t buf, uint32_t len,
                               bool_t use_long)
{
    struct client *client;
    int off = 0;

    if ( cli_id == TMEM_CLI_ID_NULL ) {
        off = tmemc_list_global(buf,0,len,use_long);
        off += tmemc_list_shared(buf,off,len-off,use_long);
        list_for_each_entry(client,&global_client_list,client_list)
            off += tmemc_list_client(client, buf, off, len-off, use_long);
        off += tmemc_list_global_perf(buf,off,len-off,use_long);
    }
    else if ( (client = tmem_client_from_cli_id(cli_id)) == NULL)
        return -1;
    else
        off = tmemc_list_client(client, buf, 0, len, use_long);

    return 0;
}

static int __tmemc_set_var(struct client *client, uint32_t subop, uint32_t arg1)
{
    domid_t cli_id = client->cli_id;
    uint32_t old_weight;

    switch (subop)
    {
    case TMEMC_SET_WEIGHT:
        old_weight = client->weight;
        client->weight = arg1;
        tmem_client_info("tmem: weight set to %d for %s=%d\n",
                        arg1, tmem_cli_id_str, cli_id);
        atomic_sub(old_weight,&client_weight_total);
        atomic_add(client->weight,&client_weight_total);
        break;
    case TMEMC_SET_CAP:
        client->cap = arg1;
        tmem_client_info("tmem: cap set to %d for %s=%d\n",
                        arg1, tmem_cli_id_str, cli_id);
        break;
    case TMEMC_SET_COMPRESS:
        if ( tmem_dedup_enabled() )
        {
            tmem_client_warn("tmem: compression %s for all %ss, cannot be changed when tmem_dedup is enabled\n",
                            tmem_compression_enabled() ? "enabled" : "disabled",
                            tmem_client_str);
            return -1;
        }
        client->compress = arg1 ? 1 : 0;
        tmem_client_info("tmem: compression %s for %s=%d\n",
            arg1 ? "enabled" : "disabled",tmem_cli_id_str,cli_id);
        break;
    default:
        tmem_client_warn("tmem: unknown subop %d for tmemc_set_var\n", subop);
        return -1;
    }
    return 0;
}

static int tmemc_set_var(domid_t cli_id, uint32_t subop, uint32_t arg1)
{
    struct client *client;
    int ret = -1;

    if ( cli_id == TMEM_CLI_ID_NULL )
    {
        list_for_each_entry(client,&global_client_list,client_list)
        {
            ret =  __tmemc_set_var(client, subop, arg1);
            if (ret)
                break;
        }
    }
    else
    {
        client = tmem_client_from_cli_id(cli_id);
        if ( client )
            ret = __tmemc_set_var(client, subop, arg1);
    }
    return ret;
}

static int tmemc_shared_pool_auth(domid_t cli_id, uint64_t uuid_lo,
                                  uint64_t uuid_hi, bool_t auth)
{
    struct client *client;
    int i, free = -1;

    if ( cli_id == TMEM_CLI_ID_NULL )
    {
        global_shared_auth = auth;
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
                        uint32_t subop, tmem_cli_va_param_t buf, uint32_t arg1)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    struct tmem_pool *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];
    uint32_t p;
    struct tmem_page_descriptor *pgp, *pgp2;
    int rc = -1;

    switch(subop)
    {
    case TMEMC_SAVE_BEGIN:
        if ( client == NULL )
            return 0;
        for (p = 0; p < MAX_POOLS_PER_DOMAIN; p++)
            if ( client->pools[p] != NULL )
                break;
        if ( p == MAX_POOLS_PER_DOMAIN )
        {
            rc = 0;
            break;
        }
        client->was_frozen = client->frozen;
        client->frozen = 1;
        if ( arg1 != 0 )
            client->live_migrating = 1;
        rc = 1;
        break;
    case TMEMC_RESTORE_BEGIN:
        if ( client == NULL && (client = client_create(cli_id)) != NULL )
            return 1;
        break;
    case TMEMC_SAVE_GET_VERSION:
        rc = TMEM_SPEC_VERSION;
        break;
    case TMEMC_SAVE_GET_MAXPOOLS:
        rc = MAX_POOLS_PER_DOMAIN;
        break;
    case TMEMC_SAVE_GET_CLIENT_WEIGHT:
        if ( client == NULL )
            break;
        rc = client->weight == -1 ? -2 : client->weight;
        break;
    case TMEMC_SAVE_GET_CLIENT_CAP:
        if ( client == NULL )
            break;
        rc = client->cap == -1 ? -2 : client->cap;
        break;
    case TMEMC_SAVE_GET_CLIENT_FLAGS:
        if ( client == NULL )
            break;
        rc = (client->compress ? TMEM_CLIENT_COMPRESS : 0 ) |
             (client->was_frozen ? TMEM_CLIENT_FROZEN : 0 );
        break;
    case TMEMC_SAVE_GET_POOL_FLAGS:
         if ( pool == NULL )
             break;
         rc = (pool->persistent ? TMEM_POOL_PERSIST : 0) |
              (pool->shared ? TMEM_POOL_SHARED : 0) |
              (POOL_PAGESHIFT << TMEM_POOL_PAGESIZE_SHIFT) |
              (TMEM_SPEC_VERSION << TMEM_POOL_VERSION_SHIFT);
        break;
    case TMEMC_SAVE_GET_POOL_NPAGES:
         if ( pool == NULL )
             break;
        rc = _atomic_read(pool->pgp_count);
        break;
    case TMEMC_SAVE_GET_POOL_UUID:
         if ( pool == NULL )
             break;
        rc = 0;
        if ( copy_to_guest(guest_handle_cast(buf, void), pool->uuid, 2) )
            rc = -EFAULT;
        break;
    case TMEMC_SAVE_END:
        if ( client == NULL )
            break;
        client->live_migrating = 0;
        if ( !list_empty(&client->persistent_invalidated_list) )
            list_for_each_entry_safe(pgp,pgp2,
              &client->persistent_invalidated_list, client_inv_pages)
                __pgp_free(pgp, client->pools[pgp->pool_id]);
        client->frozen = client->was_frozen;
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
    struct oid oid;
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
    /* note: pool->cur_pgp is the pgp last returned by get_next_page */
    if ( pool->cur_pgp == NULL )
    {
        /* process the first one */
        pool->cur_pgp = pgp = list_entry((&pool->persistent_page_list)->next,
                         struct tmem_page_descriptor,us.pool_pers_pages);
    } else if ( list_is_last(&pool->cur_pgp->us.pool_pers_pages, 
                             &pool->persistent_page_list) )
    {
        /* already processed the last one in the list */
        ret = -1;
        goto out;
    }
    pgp = list_entry((&pool->cur_pgp->us.pool_pers_pages)->next,
                         struct tmem_page_descriptor,us.pool_pers_pages);
    pool->cur_pgp = pgp;
    oid = pgp->us.obj->oid;
    h.pool_id = pool_id;
    BUILD_BUG_ON(sizeof(h.oid) != sizeof(oid));
    memcpy(h.oid, oid.oid, sizeof(h.oid));
    h.index = pgp->index;
    if ( copy_to_guest(guest_handle_cast(buf, void), &h, 1) )
    {
        ret = -EFAULT;
        goto out;
    }
    guest_handle_add_offset(buf, sizeof(h));
    ret = do_tmem_get(pool, &oid, pgp->index, 0, buf);

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
    memcpy(h.oid, pgp->inv_oid.oid, sizeof(h.oid));
    h.index = pgp->index;
    ret = 1;
    if ( copy_to_guest(guest_handle_cast(buf, void), &h, 1) )
        ret = -EFAULT;
out:
    spin_unlock(&pers_lists_spinlock);
    return ret;
}

static int tmemc_restore_put_page(int cli_id, uint32_t pool_id, struct oid *oidp,
                      uint32_t index, tmem_cli_va_param_t buf, uint32_t bufsize)
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

static int tmemc_restore_flush_page(int cli_id, uint32_t pool_id, struct oid *oidp,
                        uint32_t index)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    struct tmem_pool *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];

    if ( pool == NULL )
        return -1;
    return do_tmem_flush_page(pool,oidp,index);
}

static int do_tmem_control(struct tmem_op *op)
{
    int ret;
    uint32_t pool_id = op->pool_id;
    uint32_t subop = op->u.ctrl.subop;
    struct oid *oidp = (struct oid *)(&op->u.ctrl.oid[0]);

    if ( xsm_tmem_control(XSM_PRIV) )
        return -EPERM;

    switch(subop)
    {
    case TMEMC_THAW:
    case TMEMC_FREEZE:
    case TMEMC_DESTROY:
        ret = tmemc_freeze_pools(op->u.ctrl.cli_id,subop);
        break;
    case TMEMC_FLUSH:
        ret = tmemc_flush_mem(op->u.ctrl.cli_id,op->u.ctrl.arg1);
        break;
    case TMEMC_LIST:
        ret = tmemc_list(op->u.ctrl.cli_id,
                         guest_handle_cast(op->u.ctrl.buf, char),
                         op->u.ctrl.arg1,op->u.ctrl.arg2);
        break;
    case TMEMC_SET_WEIGHT:
    case TMEMC_SET_CAP:
    case TMEMC_SET_COMPRESS:
        ret = tmemc_set_var(op->u.ctrl.cli_id,subop,op->u.ctrl.arg1);
        break;
    case TMEMC_QUERY_FREEABLE_MB:
        ret = tmem_freeable_pages() >> (20 - PAGE_SHIFT);
        break;
    case TMEMC_SAVE_BEGIN:
    case TMEMC_RESTORE_BEGIN:
    case TMEMC_SAVE_GET_VERSION:
    case TMEMC_SAVE_GET_MAXPOOLS:
    case TMEMC_SAVE_GET_CLIENT_WEIGHT:
    case TMEMC_SAVE_GET_CLIENT_CAP:
    case TMEMC_SAVE_GET_CLIENT_FLAGS:
    case TMEMC_SAVE_GET_POOL_FLAGS:
    case TMEMC_SAVE_GET_POOL_NPAGES:
    case TMEMC_SAVE_GET_POOL_UUID:
    case TMEMC_SAVE_END:
        ret = tmemc_save_subop(op->u.ctrl.cli_id,pool_id,subop,
                               guest_handle_cast(op->u.ctrl.buf, char),
                               op->u.ctrl.arg1);
        break;
    case TMEMC_SAVE_GET_NEXT_PAGE:
        ret = tmemc_save_get_next_page(op->u.ctrl.cli_id, pool_id,
                                       guest_handle_cast(op->u.ctrl.buf, char),
                                       op->u.ctrl.arg1);
        break;
    case TMEMC_SAVE_GET_NEXT_INV:
        ret = tmemc_save_get_next_inv(op->u.ctrl.cli_id,
                                      guest_handle_cast(op->u.ctrl.buf, char),
                                      op->u.ctrl.arg1);
        break;
    case TMEMC_RESTORE_PUT_PAGE:
        ret = tmemc_restore_put_page(op->u.ctrl.cli_id,pool_id,
                                     oidp, op->u.ctrl.arg2,
                                     guest_handle_cast(op->u.ctrl.buf, char),
                                     op->u.ctrl.arg1);
        break;
    case TMEMC_RESTORE_FLUSH_PAGE:
        ret = tmemc_restore_flush_page(op->u.ctrl.cli_id,pool_id,
                                       oidp, op->u.ctrl.arg2);
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
    struct oid *oidp;
    int rc = 0;
    bool_t succ_get = 0, succ_put = 0;
    bool_t non_succ_get = 0, non_succ_put = 0;
    bool_t flush = 0, flush_obj = 0;

    if ( !tmem_initialized )
        return -ENODEV;

    if ( xsm_tmem_op(XSM_HOOK) )
        return -EPERM;

    total_tmem_ops++;

    if ( client != NULL && client->domain->is_dying )
    {
        errored_tmem_ops++;
        return -ENODEV;
    }

    if ( unlikely(tmem_get_tmemop_from_client(&op, uops) != 0) )
    {
        tmem_client_err("tmem: can't get tmem struct from %s\n", tmem_client_str);
        errored_tmem_ops++;
        return -EFAULT;
    }

    /* Acquire wirte lock for all command at first */
    write_lock(&tmem_rwlock);

    if ( op.cmd == TMEM_CONTROL )
    {
        rc = do_tmem_control(&op);
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
            /* Commands only need read lock */
            write_unlock(&tmem_rwlock);
            read_lock(&tmem_rwlock);

            oidp = (struct oid *)&op.u.gen.oid[0];
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
                errored_tmem_ops++;
            return rc;
        }
    }
out:
    write_unlock(&tmem_rwlock);
    if ( rc < 0 )
        errored_tmem_ops++;
    return rc;
}

/* this should be called when the host is destroying a client */
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

#define MAX_EVICTS 10  /* should be variable or set via TMEMC_ ?? */
void *tmem_relinquish_pages(unsigned int order, unsigned int memflags)
{
    struct page_info *pfp;
    unsigned long evicts_per_relinq = 0;
    int max_evictions = 10;

    if (!tmem_enabled() || !tmem_freeable_pages())
        return NULL;

    relinq_attempts++;
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
    if ( evicts_per_relinq > max_evicts_per_relinq )
        max_evicts_per_relinq = evicts_per_relinq;
    if ( pfp != NULL )
    {
        if ( !(memflags & MEMF_tmem) )
            scrub_one_page(pfp);
        relinq_pgs++;
    }

    return pfp;
}

unsigned long tmem_freeable_pages(void)
{
    return tmem_page_list_pages + _atomic_read(freeable_page_count);
}

/* called at hypervisor startup */
static int __init init_tmem(void)
{
    int i;
    if ( !tmem_enabled() )
        return 0;

    if ( tmem_dedup_enabled() )
        for (i = 0; i < 256; i++ )
        {
            pcd_tree_roots[i] = RB_ROOT;
            rwlock_init(&pcd_tree_rwlocks[i]);
        }

    if ( !tmem_mempool_init() )
        return 0;

    if ( tmem_init() )
    {
        printk("tmem: initialized comp=%d dedup=%d tze=%d\n",
            tmem_compression_enabled(), tmem_dedup_enabled(), tmem_tze_enabled());
        if ( tmem_dedup_enabled()&&tmem_compression_enabled()&&tmem_tze_enabled() )
        {
            tmem_tze_disable();
            printk("tmem: tze and compression not compatible, disabling tze\n");
        }
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
