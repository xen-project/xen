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

#define EXPORT /* indicates code other modules are dependent upon */
#define FORWARD

#define TMEM_SPEC_VERSION 0

/************  INTERFACE TO TMEM HOST-DEPENDENT (tmh) CODE ************/

#define CLI_ID_NULL TMH_CLI_ID_NULL
#define cli_id_str  tmh_cli_id_str
#define client_str  tmh_client_str

/************ DEBUG and STATISTICS (+ some compression testing) *******/

#ifndef NDEBUG
#define SENTINELS
#define NOINLINE noinline
#else
#define NOINLINE
#endif

#ifdef SENTINELS
#define DECL_SENTINEL unsigned long sentinel;
#define SET_SENTINEL(_x,_y) _x->sentinel = _y##_SENTINEL
#define INVERT_SENTINEL(_x,_y) _x->sentinel = ~_y##_SENTINEL
#define ASSERT_SENTINEL(_x,_y) \
    ASSERT(_x->sentinel != ~_y##_SENTINEL);ASSERT(_x->sentinel == _y##_SENTINEL)
#ifdef __i386__
#define POOL_SENTINEL 0x87658765
#define OBJ_SENTINEL 0x12345678
#define OBJNODE_SENTINEL 0xfedcba09
#define PGD_SENTINEL  0x43214321
#else
#define POOL_SENTINEL 0x8765876587658765
#define OBJ_SENTINEL 0x1234567812345678
#define OBJNODE_SENTINEL 0xfedcba0987654321
#define PGD_SENTINEL  0x4321432143214321
#endif
#else
#define DECL_SENTINEL
#define SET_SENTINEL(_x,_y) do { } while (0)
#define ASSERT_SENTINEL(_x,_y) do { } while (0)
#define INVERT_SENTINEL(_x,_y) do { } while (0)
#endif

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

DECL_CYC_COUNTER(succ_get);
DECL_CYC_COUNTER(succ_put);
DECL_CYC_COUNTER(non_succ_get);
DECL_CYC_COUNTER(non_succ_put);
DECL_CYC_COUNTER(flush);
DECL_CYC_COUNTER(flush_obj);
#ifdef COMPARE_COPY_PAGE_SSE2
EXTERN_CYC_COUNTER(pg_copy1);
EXTERN_CYC_COUNTER(pg_copy2);
EXTERN_CYC_COUNTER(pg_copy3);
EXTERN_CYC_COUNTER(pg_copy4);
#else
EXTERN_CYC_COUNTER(pg_copy);
#endif
DECL_CYC_COUNTER(compress);
DECL_CYC_COUNTER(decompress);

/************ CORE DATA STRUCTURES ************************************/

#define MAX_POOLS_PER_DOMAIN 16
#define MAX_GLOBAL_SHARED_POOLS  16

struct tm_pool;
struct tmem_page_descriptor;
struct tmem_page_content_descriptor;
struct client {
    struct list_head client_list;
    struct tm_pool *pools[MAX_POOLS_PER_DOMAIN];
    tmh_client_t *tmh;
    struct list_head ephemeral_page_list;
    long eph_count, eph_count_max;
    cli_id_t cli_id;
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
typedef struct client client_t;

struct share_list {
    struct list_head share_list;
    client_t *client;
};
typedef struct share_list sharelist_t;

#define OBJ_HASH_BUCKETS 256 /* must be power of two */
#define OBJ_HASH_BUCKETS_MASK (OBJ_HASH_BUCKETS-1)
#define OBJ_HASH(_oid) (tmh_hash(_oid, BITS_PER_LONG) & OBJ_HASH_BUCKETS_MASK)

struct tm_pool {
    bool_t shared;
    bool_t persistent;
    bool_t is_dying;
    int pageshift; /* 0 == 2**12 */
    struct list_head pool_list; /* FIXME do we need this anymore? */
    client_t *client;
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
    DECL_SENTINEL
};
typedef struct tm_pool pool_t;

#define is_persistent(_p)  (_p->persistent)
#define is_ephemeral(_p)   (!(_p->persistent))
#define is_shared(_p)      (_p->shared)
#define is_private(_p)     (!(_p->shared))

struct tmem_object_root {
    DECL_SENTINEL
    uint64_t oid;
    struct rb_node rb_tree_node; /* protected by pool->pool_rwlock */
    unsigned long objnode_count; /* atomicity depends on obj_spinlock */
    long pgp_count; /* atomicity depends on obj_spinlock */
    struct radix_tree_root tree_root; /* tree of pages within object */
    pool_t *pool;
    cli_id_t last_client;
    spinlock_t obj_spinlock;
    bool_t no_evict; /* if globally locked, pseudo-locks against eviction */
};
typedef struct tmem_object_root obj_t;

typedef struct radix_tree_node rtn_t;
struct tmem_object_node {
    obj_t *obj;
    DECL_SENTINEL
    rtn_t rtn;
};
typedef struct tmem_object_node objnode_t;

struct tmem_page_descriptor {
    union {
        struct list_head global_eph_pages;
        struct list_head client_inv_pages;
    };
    union {
        struct list_head client_eph_pages;
        struct list_head pool_pers_pages;
    };
    union {
        obj_t *obj;
        uint64_t inv_oid;  /* used for invalid list only */
    };
    pagesize_t size; /* 0 == PAGE_SIZE (pfp), -1 == data invalid,
                    else compressed data (cdata) */
    uint32_t index;
    /* must hold pcd_tree_rwlocks[firstbyte] to use pcd pointer/siblings */
    uint16_t firstbyte; /* NON_SHAREABLE->pfp  otherwise->pcd */
    bool_t eviction_attempted;  /* CHANGE TO lifetimes? (settable) */
    struct list_head pcd_siblings;
    union {
        pfp_t *pfp;  /* page frame pointer */
        char *cdata; /* compressed data */
        struct tmem_page_content_descriptor *pcd; /* page dedup */
    };
    union {
        uint64_t timestamp;
        uint32_t pool_id;  /* used for invalid list only */
    };
    DECL_SENTINEL
};
typedef struct tmem_page_descriptor pgp_t;

#define PCD_TZE_MAX_SIZE (PAGE_SIZE - (PAGE_SIZE/64))

struct tmem_page_content_descriptor {
    union {
        pfp_t *pfp;  /* page frame pointer */
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
typedef struct tmem_page_content_descriptor pcd_t;
struct rb_root pcd_tree_roots[256]; /* choose based on first byte of page */
rwlock_t pcd_tree_rwlocks[256]; /* poor man's concurrency for now */

static LIST_HEAD(global_ephemeral_page_list); /* all pages in ephemeral pools */

static LIST_HEAD(global_client_list);
static LIST_HEAD(global_pool_list);

static pool_t *global_shared_pools[MAX_GLOBAL_SHARED_POOLS] = { 0 };
static bool_t global_shared_auth = 0;
static atomic_t client_weight_total = ATOMIC_INIT(0);
static int tmem_initialized = 0;

/************ CONCURRENCY  ***********************************************/

EXPORT DEFINE_SPINLOCK(tmem_spinlock);  /* used iff tmh_lock_all */
EXPORT DEFINE_RWLOCK(tmem_rwlock);      /* used iff !tmh_lock_all */
static DEFINE_SPINLOCK(eph_lists_spinlock); /* protects global AND clients */
static DEFINE_SPINLOCK(pers_lists_spinlock);

#define tmem_spin_lock(_l)  do {if (!tmh_lock_all) spin_lock(_l);}while(0)
#define tmem_spin_unlock(_l)  do {if (!tmh_lock_all) spin_unlock(_l);}while(0)
#define tmem_read_lock(_l)  do {if (!tmh_lock_all) read_lock(_l);}while(0)
#define tmem_read_unlock(_l)  do {if (!tmh_lock_all) read_unlock(_l);}while(0)
#define tmem_write_lock(_l)  do {if (!tmh_lock_all) write_lock(_l);}while(0)
#define tmem_write_unlock(_l)  do {if (!tmh_lock_all) write_unlock(_l);}while(0)
#define tmem_write_trylock(_l)  ((tmh_lock_all)?1:write_trylock(_l))
#define tmem_spin_trylock(_l)  (tmh_lock_all?1:spin_trylock(_l))

#define ASSERT_SPINLOCK(_l) ASSERT(tmh_lock_all || spin_is_locked(_l))
#define ASSERT_WRITELOCK(_l) ASSERT(tmh_lock_all || rw_is_write_locked(_l))

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


/************ MEMORY ALLOCATION INTERFACE *****************************/

#define tmem_malloc(_type,_pool) \
       _tmem_malloc(sizeof(_type), __alignof__(_type), _pool)

#define tmem_malloc_bytes(_size,_pool) \
       _tmem_malloc(_size, 1, _pool)

static NOINLINE void *_tmem_malloc(size_t size, size_t align, pool_t *pool)
{
    void *v;

    if ( (pool != NULL) && is_persistent(pool) )
        v = tmh_alloc_subpage_thispool(pool,size,align);
    else
        v = tmh_alloc_subpage(pool, size, align);
    if ( v == NULL )
        alloc_failed++;
    return v;
}

static NOINLINE void tmem_free(void *p, size_t size, pool_t *pool)
{
    if ( pool == NULL || !is_persistent(pool) )
        tmh_free_subpage(p,size);
    else
        tmh_free_subpage_thispool(pool,p,size);
}

static NOINLINE pfp_t *tmem_page_alloc(pool_t *pool)
{
    pfp_t *pfp = NULL;

    if ( pool != NULL && is_persistent(pool) )
        pfp = tmh_alloc_page_thispool(pool);
    else
        pfp = tmh_alloc_page(pool,0);
    if ( pfp == NULL )
        alloc_page_failed++;
    else
        atomic_inc_and_max(global_page_count);
    return pfp;
}

static NOINLINE void tmem_page_free(pool_t *pool, pfp_t *pfp)
{
    ASSERT(pfp);
    if ( pool == NULL || !is_persistent(pool) )
        tmh_free_page(pfp);
    else
        tmh_free_page_thispool(pool,pfp);
    atomic_dec_and_assert(global_page_count);
}

/************ PAGE CONTENT DESCRIPTOR MANIPULATION ROUTINES ***********/

#define NOT_SHAREABLE ((uint16_t)-1UL)

static NOINLINE int pcd_copy_to_client(tmem_cli_mfn_t cmfn, pgp_t *pgp)
{
    uint8_t firstbyte = pgp->firstbyte;
    pcd_t *pcd;
    int ret;

    ASSERT(tmh_dedup_enabled());
    tmem_read_lock(&pcd_tree_rwlocks[firstbyte]);
    pcd = pgp->pcd;
    if ( pgp->size < PAGE_SIZE && pgp->size != 0 &&
         pcd->size < PAGE_SIZE && pcd->size != 0 )
        ret = tmh_decompress_to_client(cmfn, pcd->cdata, pcd->size, NULL);
    else if ( tmh_tze_enabled() && pcd->size < PAGE_SIZE )
        ret = tmh_copy_tze_to_client(cmfn, pcd->tze, pcd->size);
    else
        ret = tmh_copy_to_client(cmfn, pcd->pfp, 0, 0, PAGE_SIZE, NULL);
    tmem_read_unlock(&pcd_tree_rwlocks[firstbyte]);
    return ret;
}

/* ensure pgp no longer points to pcd, nor vice-versa */
/* take pcd rwlock unless have_pcd_rwlock is set, always unlock when done */
static NOINLINE void pcd_disassociate(pgp_t *pgp, pool_t *pool, bool_t have_pcd_rwlock)
{
    pcd_t *pcd = pgp->pcd;
    pfp_t *pfp = pgp->pcd->pfp;
    uint16_t firstbyte = pgp->firstbyte;
    char *pcd_tze = pgp->pcd->tze;
    pagesize_t pcd_size = pcd->size;
    pagesize_t pgp_size = pgp->size;
    char *pcd_cdata = pgp->pcd->cdata;
    pagesize_t pcd_csize = pgp->pcd->size;

    ASSERT(tmh_dedup_enabled());
    ASSERT(firstbyte != NOT_SHAREABLE);
    ASSERT(firstbyte < 256);

    if ( have_pcd_rwlock )
        ASSERT_WRITELOCK(&pcd_tree_rwlocks[firstbyte]);
    else
        tmem_write_lock(&pcd_tree_rwlocks[firstbyte]);
    list_del_init(&pgp->pcd_siblings);
    pgp->pcd = NULL;
    pgp->firstbyte = NOT_SHAREABLE;
    pgp->size = -1;
    if ( --pcd->pgp_ref_count )
    {
        tmem_write_unlock(&pcd_tree_rwlocks[firstbyte]);
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
    tmem_free(pcd,sizeof(pcd_t),NULL);
    atomic_dec_and_assert(global_pcd_count);
    if ( pgp_size != 0 && pcd_size < PAGE_SIZE )
    {
        /* compressed data */
        tmem_free(pcd_cdata,pcd_csize,pool);
        pcd_tot_csize -= pcd_csize;
    }
    else if ( pcd_size != PAGE_SIZE )
    {
        /* trailing zero data */
        pcd_tot_tze_size -= pcd_size;
        if ( pcd_size )
            tmem_free(pcd_tze,pcd_size,pool);
    } else {
        /* real physical page */
        if ( tmh_tze_enabled() )
            pcd_tot_tze_size -= PAGE_SIZE;
        if ( tmh_compression_enabled() )
            pcd_tot_csize -= PAGE_SIZE;
        tmem_page_free(pool,pfp);
    }
    tmem_write_unlock(&pcd_tree_rwlocks[firstbyte]);
}


static NOINLINE int pcd_associate(pgp_t *pgp, char *cdata, pagesize_t csize)
{
    struct rb_node **new, *parent = NULL;
    struct rb_root *root;
    pcd_t *pcd;
    int cmp;
    pagesize_t pfp_size = 0;
    uint8_t firstbyte = (cdata == NULL) ? tmh_get_first_byte(pgp->pfp) : *cdata;
    int ret = 0;

    if ( !tmh_dedup_enabled() )
        return 0;
    ASSERT(pgp->obj != NULL);
    ASSERT(pgp->obj->pool != NULL);
    ASSERT(!pgp->obj->pool->persistent);
    if ( cdata == NULL )
    {
        ASSERT(pgp->pfp != NULL);
        pfp_size = PAGE_SIZE;
        if ( tmh_tze_enabled() )
        {
            pfp_size = tmh_tze_pfp_scan(pgp->pfp);
            if ( pfp_size > PCD_TZE_MAX_SIZE )
                pfp_size = PAGE_SIZE;
        }
        ASSERT(pfp_size <= PAGE_SIZE);
        ASSERT(!(pfp_size & (sizeof(uint64_t)-1)));
    }
    tmem_write_lock(&pcd_tree_rwlocks[firstbyte]);

    /* look for page match */
    root = &pcd_tree_roots[firstbyte];
    new = &(root->rb_node);
    while ( *new )
    {
        pcd = container_of(*new, pcd_t, pcd_rb_tree_node);
        parent = *new;
        /* compare new entry and rbtree entry, set cmp accordingly */
        if ( cdata != NULL )
        {
            if ( pcd->size < PAGE_SIZE )
                /* both new entry and rbtree entry are compressed */
                cmp = tmh_pcd_cmp(cdata,csize,pcd->cdata,pcd->size);
            else
                /* new entry is compressed, rbtree entry is not */
                cmp = -1;
        } else if ( pcd->size < PAGE_SIZE )
            /* rbtree entry is compressed, rbtree entry is not */
            cmp = 1;
        else if ( tmh_tze_enabled() ) {
            if ( pcd->size < PAGE_SIZE )
                /* both new entry and rbtree entry are trailing zero */
                cmp = tmh_tze_pfp_cmp(pgp->pfp,pfp_size,pcd->tze,pcd->size);
            else
                /* new entry is trailing zero, rbtree entry is not */
                cmp = tmh_tze_pfp_cmp(pgp->pfp,pfp_size,pcd->pfp,PAGE_SIZE);
        } else  {
            /* both new entry and rbtree entry are full physical pages */
            ASSERT(pgp->pfp != NULL);
            ASSERT(pcd->pfp != NULL);
            cmp = tmh_page_cmp(pgp->pfp,pcd->pfp);
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
                tmem_page_free(pgp->obj->pool,pgp->pfp);
            deduped_puts++;
            goto match;
        }
    }

    /* exited while loop with no match, so alloc a pcd and put it in the tree */
    if ( (pcd = tmem_malloc(pcd_t, NULL)) == NULL )
    {
        ret = -ENOMEM;
        goto unlock;
    } else if ( cdata != NULL ) {
        if ( (pcd->cdata = tmem_malloc_bytes(csize,pgp->obj->pool)) == NULL )
        {
            tmem_free(pcd,sizeof(pcd_t),NULL);
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
        ASSERT(tmh_tze_enabled());
        pcd->size = 0;
        pcd->tze = NULL;
    } else if ( pfp_size < PAGE_SIZE &&
         ((pcd->tze = tmem_malloc_bytes(pfp_size,pgp->obj->pool)) != NULL) ) {
        tmh_tze_copy_from_pfp(pcd->tze,pgp->pfp,pfp_size);
        pcd->size = pfp_size;
        pcd_tot_tze_size += pfp_size;
        tmem_page_free(pgp->obj->pool,pgp->pfp);
    } else {
        pcd->pfp = pgp->pfp;
        pcd->size = PAGE_SIZE;
        if ( tmh_tze_enabled() )
            pcd_tot_tze_size += PAGE_SIZE;
        if ( tmh_compression_enabled() )
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
    tmem_write_unlock(&pcd_tree_rwlocks[firstbyte]);
    return ret;
}

/************ PAGE DESCRIPTOR MANIPULATION ROUTINES *******************/

/* allocate a pgp_t and associate it with an object */
static NOINLINE pgp_t *pgp_alloc(obj_t *obj)
{
    pgp_t *pgp;
    pool_t *pool;

    ASSERT(obj != NULL);
    ASSERT(obj->pool != NULL);
    pool = obj->pool;
    if ( (pgp = tmem_malloc(pgp_t, pool)) == NULL )
        return NULL;
    pgp->obj = obj;
    INIT_LIST_HEAD(&pgp->global_eph_pages);
    INIT_LIST_HEAD(&pgp->client_eph_pages);
    pgp->pfp = NULL;
    if ( tmh_dedup_enabled() )
    {
        pgp->firstbyte = NOT_SHAREABLE;
        pgp->eviction_attempted = 0;
        INIT_LIST_HEAD(&pgp->pcd_siblings);
    }
    pgp->size = -1;
    pgp->index = -1;
    pgp->timestamp = get_cycles();
    SET_SENTINEL(pgp,PGD);
    atomic_inc_and_max(global_pgp_count);
    atomic_inc_and_max(pool->pgp_count);
    return pgp;
}

static pgp_t *pgp_lookup_in_obj(obj_t *obj, uint32_t index)
{
    ASSERT(obj != NULL);
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT_SENTINEL(obj,OBJ);
    ASSERT(obj->pool != NULL);
    ASSERT_SENTINEL(obj->pool,POOL);
    return radix_tree_lookup(&obj->tree_root, index);
}

static NOINLINE void pgp_free_data(pgp_t *pgp, pool_t *pool)
{
    pagesize_t pgp_size = pgp->size;

    if ( pgp->pfp == NULL )
        return;
    if ( tmh_dedup_enabled() && pgp->firstbyte != NOT_SHAREABLE )
        pcd_disassociate(pgp,pool,0); /* pgp->size lost */
    else if ( pgp_size )
        tmem_free(pgp->cdata,pgp_size,pool);
    else
        tmem_page_free(pgp->obj->pool,pgp->pfp);
    if ( pool != NULL && pgp_size )
    {
        pool->client->compressed_pages--;
        pool->client->compressed_sum_size -= pgp_size;
    }
    pgp->pfp = NULL;
    pgp->size = -1;
}

static NOINLINE void pgp_free(pgp_t *pgp, int from_delete)
{
    pool_t *pool = NULL;

    ASSERT_SENTINEL(pgp,PGD);
    ASSERT(pgp->obj != NULL);
    ASSERT_SENTINEL(pgp->obj,OBJ);
    ASSERT_SENTINEL(pgp->obj->pool,POOL);
    ASSERT(pgp->obj->pool->client != NULL);
    if ( from_delete )
        ASSERT(pgp_lookup_in_obj(pgp->obj,pgp->index) == NULL);
    ASSERT(pgp->obj->pool != NULL);
    pool = pgp->obj->pool;
    if ( is_ephemeral(pool) )
    {
        ASSERT(list_empty(&pgp->global_eph_pages));
        ASSERT(list_empty(&pgp->client_eph_pages));
    }
    pgp_free_data(pgp, pool);
    atomic_dec_and_assert(global_pgp_count);
    atomic_dec_and_assert(pool->pgp_count);
    pgp->size = -1;
    if ( is_persistent(pool) && pool->client->live_migrating )
    {
        pgp->inv_oid = pgp->obj->oid;
        pgp->pool_id = pool->pool_id;
        return;
    }
    INVERT_SENTINEL(pgp,PGD);
    pgp->obj = NULL;
    pgp->index = -1;
    tmem_free(pgp,sizeof(pgp_t),pool);
}

static NOINLINE void pgp_free_from_inv_list(client_t *client, pgp_t *pgp)
{
    pool_t *pool = client->pools[pgp->pool_id];

    ASSERT_SENTINEL(pool,POOL);
    ASSERT_SENTINEL(pgp,PGD);
    INVERT_SENTINEL(pgp,PGD);
    pgp->obj = NULL;
    pgp->index = -1;
    tmem_free(pgp,sizeof(pgp_t),pool);
}

/* remove the page from appropriate lists but not from parent object */
static void pgp_delist(pgp_t *pgp, bool_t no_eph_lock)
{
    client_t *client;

    ASSERT(pgp != NULL);
    ASSERT(pgp->obj != NULL);
    ASSERT(pgp->obj->pool != NULL);
    client = pgp->obj->pool->client;
    ASSERT(client != NULL);
    if ( is_ephemeral(pgp->obj->pool) )
    {
        if ( !no_eph_lock )
            tmem_spin_lock(&eph_lists_spinlock);
        if ( !list_empty(&pgp->client_eph_pages) )
            client->eph_count--;
        ASSERT(client->eph_count >= 0);
        list_del_init(&pgp->client_eph_pages);
        if ( !list_empty(&pgp->global_eph_pages) )
            global_eph_count--;
        ASSERT(global_eph_count >= 0);
        list_del_init(&pgp->global_eph_pages);
        if ( !no_eph_lock )
            tmem_spin_unlock(&eph_lists_spinlock);
    } else {
        if ( client->live_migrating )
        {
            tmem_spin_lock(&pers_lists_spinlock);
            list_add_tail(&pgp->client_inv_pages,
                          &client->persistent_invalidated_list);
            if ( pgp != pgp->obj->pool->cur_pgp )
                list_del_init(&pgp->pool_pers_pages);
            tmem_spin_unlock(&pers_lists_spinlock);
        } else {
            tmem_spin_lock(&pers_lists_spinlock);
            list_del_init(&pgp->pool_pers_pages);
            tmem_spin_unlock(&pers_lists_spinlock);
        }
    }
}

/* remove page from lists (but not from parent object) and free it */
static NOINLINE void pgp_delete(pgp_t *pgp, bool_t no_eph_lock)
{
    uint64_t life;

    ASSERT(pgp != NULL);
    ASSERT(pgp->obj != NULL);
    ASSERT(pgp->obj->pool != NULL);
    life = get_cycles() - pgp->timestamp;
    pgp->obj->pool->sum_life_cycles += life;
    pgp_delist(pgp, no_eph_lock);
    pgp_free(pgp,1);
}

/* called only indirectly by radix_tree_destroy */
static NOINLINE void pgp_destroy(void *v)
{
    pgp_t *pgp = (pgp_t *)v;

    ASSERT_SPINLOCK(&pgp->obj->obj_spinlock);
    pgp_delist(pgp,0);
    ASSERT(pgp->obj != NULL);
    pgp->obj->pgp_count--;
    ASSERT(pgp->obj->pgp_count >= 0);
    pgp_free(pgp,0);
}

FORWARD static rtn_t *rtn_alloc(void *arg);
FORWARD static void rtn_free(rtn_t *rtn);

static int pgp_add_to_obj(obj_t *obj, uint32_t index, pgp_t *pgp)
{
    int ret;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ret = radix_tree_insert(&obj->tree_root, index, pgp, rtn_alloc, obj);
    if ( !ret )
        obj->pgp_count++;
    return ret;
}

static NOINLINE pgp_t *pgp_delete_from_obj(obj_t *obj, uint32_t index)
{
    pgp_t *pgp;

    ASSERT(obj != NULL);
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT_SENTINEL(obj,OBJ);
    ASSERT(obj->pool != NULL);
    ASSERT_SENTINEL(obj->pool,POOL);
    pgp = radix_tree_delete(&obj->tree_root, index, rtn_free);
    if ( pgp != NULL )
        obj->pgp_count--;
    ASSERT(obj->pgp_count >= 0);

    return pgp;
}

/************ RADIX TREE NODE MANIPULATION ROUTINES *******************/

/* called only indirectly from radix_tree_insert */
static NOINLINE rtn_t *rtn_alloc(void *arg)
{
    objnode_t *objnode;
    obj_t *obj = (obj_t *)arg;

    ASSERT_SENTINEL(obj,OBJ);
    ASSERT(obj->pool != NULL);
    ASSERT_SENTINEL(obj->pool,POOL);
    objnode = tmem_malloc(objnode_t,obj->pool);
    if (objnode == NULL)
        return NULL;
    objnode->obj = obj;
    SET_SENTINEL(objnode,OBJNODE);
    memset(&objnode->rtn, 0, sizeof(rtn_t));
    if (++obj->pool->objnode_count > obj->pool->objnode_count_max)
        obj->pool->objnode_count_max = obj->pool->objnode_count;
    atomic_inc_and_max(global_rtree_node_count);
    obj->objnode_count++;
    return &objnode->rtn;
}

/* called only indirectly from radix_tree_delete/destroy */
static void rtn_free(rtn_t *rtn)
{
    pool_t *pool;
    objnode_t *objnode;
    int i;

    ASSERT(rtn != NULL);
    for (i = 0; i < RADIX_TREE_MAP_SIZE; i++)
        ASSERT(rtn->slots[i] == NULL);
    objnode = container_of(rtn,objnode_t,rtn);
    ASSERT_SENTINEL(objnode,OBJNODE);
    INVERT_SENTINEL(objnode,OBJNODE);
    ASSERT(objnode->obj != NULL);
    ASSERT_SPINLOCK(&objnode->obj->obj_spinlock);
    ASSERT_SENTINEL(objnode->obj,OBJ);
    pool = objnode->obj->pool;
    ASSERT(pool != NULL);
    ASSERT_SENTINEL(pool,POOL);
    pool->objnode_count--;
    objnode->obj->objnode_count--;
    objnode->obj = NULL;
    tmem_free(objnode,sizeof(objnode_t),pool);
    atomic_dec_and_assert(global_rtree_node_count);
}

/************ POOL OBJECT COLLECTION MANIPULATION ROUTINES *******************/

/* searches for object==oid in pool, returns locked object if found */
static NOINLINE obj_t * obj_find(pool_t *pool, uint64_t oid)
{
    struct rb_node *node;
    obj_t *obj;

restart_find:
    tmem_read_lock(&pool->pool_rwlock);
    node = pool->obj_rb_root[OBJ_HASH(oid)].rb_node;
    while ( node )
    {
        obj = container_of(node, obj_t, rb_tree_node);
        if ( obj->oid == oid )
        {
            if ( tmh_lock_all )
                obj->no_evict = 1;
            else
            {
                if ( !tmem_spin_trylock(&obj->obj_spinlock) )
                {
                    tmem_read_unlock(&pool->pool_rwlock);
                    goto restart_find;
                }
                tmem_read_unlock(&pool->pool_rwlock);
            }
            return obj;
        }
        else if ( oid < obj->oid )
            node = node->rb_left;
        else
            node = node->rb_right;
    }
    tmem_read_unlock(&pool->pool_rwlock);
    return NULL;
}

/* free an object that has no more pgps in it */
static NOINLINE void obj_free(obj_t *obj, int no_rebalance)
{
    pool_t *pool;
    uint64_t old_oid;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT(obj != NULL);
    ASSERT_SENTINEL(obj,OBJ);
    ASSERT(obj->pgp_count == 0);
    pool = obj->pool;
    ASSERT(pool != NULL);
    ASSERT(pool->client != NULL);
    ASSERT_WRITELOCK(&pool->pool_rwlock);
    if ( obj->tree_root.rnode != NULL ) /* may be a "stump" with no leaves */
        radix_tree_destroy(&obj->tree_root, pgp_destroy, rtn_free);
    ASSERT((long)obj->objnode_count == 0);
    ASSERT(obj->tree_root.rnode == NULL);
    pool->obj_count--;
    ASSERT(pool->obj_count >= 0);
    INVERT_SENTINEL(obj,OBJ);
    obj->pool = NULL;
    old_oid = obj->oid;
    obj->oid = -1;
    obj->last_client = CLI_ID_NULL;
    atomic_dec_and_assert(global_obj_count);
    /* use no_rebalance only if all objects are being destroyed anyway */
    if ( !no_rebalance )
        rb_erase(&obj->rb_tree_node,&pool->obj_rb_root[OBJ_HASH(old_oid)]);
    tmem_free(obj,sizeof(obj_t),pool);
}

static NOINLINE int obj_rb_insert(struct rb_root *root, obj_t *obj)
{
    struct rb_node **new, *parent = NULL;
    obj_t *this;

    new = &(root->rb_node);
    while ( *new )
    {
        this = container_of(*new, obj_t, rb_tree_node);
        parent = *new;
        if ( obj->oid < this->oid )
            new = &((*new)->rb_left);
        else if ( obj->oid > this->oid )
            new = &((*new)->rb_right);
        else
            return 0;
    }
    rb_link_node(&obj->rb_tree_node, parent, new);
    rb_insert_color(&obj->rb_tree_node, root);
    return 1;
}

/*
 * allocate, initialize, and insert an tmem_object_root
 * (should be called only if find failed)
 */
static NOINLINE obj_t * obj_new(pool_t *pool, uint64_t oid)
{
    obj_t *obj;

    ASSERT(pool != NULL);
    ASSERT_WRITELOCK(&pool->pool_rwlock);
    if ( (obj = tmem_malloc(obj_t,pool)) == NULL )
        return NULL;
    pool->obj_count++;
    if (pool->obj_count > pool->obj_count_max)
        pool->obj_count_max = pool->obj_count;
    atomic_inc_and_max(global_obj_count);
    INIT_RADIX_TREE(&obj->tree_root,0);
    spin_lock_init(&obj->obj_spinlock);
    obj->pool = pool;
    obj->oid = oid;
    obj->objnode_count = 0;
    obj->pgp_count = 0;
    obj->last_client = CLI_ID_NULL;
    SET_SENTINEL(obj,OBJ);
    tmem_spin_lock(&obj->obj_spinlock);
    obj_rb_insert(&pool->obj_rb_root[OBJ_HASH(oid)], obj);
    obj->no_evict = 1;
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    return obj;
}

/* free an object after destroying any pgps in it */
static NOINLINE void obj_destroy(obj_t *obj, int no_rebalance)
{
    ASSERT_WRITELOCK(&obj->pool->pool_rwlock);
    radix_tree_destroy(&obj->tree_root, pgp_destroy, rtn_free);
    obj_free(obj,no_rebalance);
}

/* destroys all objs in a pool, or only if obj->last_client matches cli_id */
static void pool_destroy_objs(pool_t *pool, bool_t selective, cli_id_t cli_id)
{
    struct rb_node *node;
    obj_t *obj;
    int i;

    tmem_write_lock(&pool->pool_rwlock);
    pool->is_dying = 1;
    for (i = 0; i < OBJ_HASH_BUCKETS; i++)
    {
        node = rb_first(&pool->obj_rb_root[i]);
        while ( node != NULL )
        {
            obj = container_of(node, obj_t, rb_tree_node);
            tmem_spin_lock(&obj->obj_spinlock);
            node = rb_next(node);
            ASSERT(obj->no_evict == 0);
            if ( !selective )
                /* FIXME: should be obj,1 but walking/erasing rbtree is racy */
                obj_destroy(obj,0);
            else if ( obj->last_client == cli_id )
                obj_destroy(obj,0);
            else
                tmem_spin_unlock(&obj->obj_spinlock);
        }
    }
    tmem_write_unlock(&pool->pool_rwlock);
}


/************ POOL MANIPULATION ROUTINES ******************************/

static pool_t * pool_alloc(void)
{
    pool_t *pool;
    int i;

    if ( (pool = tmh_alloc_infra(sizeof(pool_t),__alignof__(pool_t))) == NULL )
        return NULL;
    for (i = 0; i < OBJ_HASH_BUCKETS; i++)
        pool->obj_rb_root[i] = RB_ROOT;
    INIT_LIST_HEAD(&pool->pool_list);
    INIT_LIST_HEAD(&pool->persistent_page_list);
    pool->cur_pgp = NULL;
    rwlock_init(&pool->pool_rwlock);
    pool->pgp_count_max = pool->obj_count_max = 0;
    pool->objnode_count = pool->objnode_count_max = 0;
    atomic_set(&pool->pgp_count,0);
    pool->obj_count = 0; pool->shared_count = 0;
    pool->pageshift = PAGE_SHIFT - 12;
    pool->good_puts = pool->puts = pool->dup_puts_flushed = 0;
    pool->dup_puts_replaced = pool->no_mem_puts = 0;
    pool->found_gets = pool->gets = 0;
    pool->flushs_found = pool->flushs = 0;
    pool->flush_objs_found = pool->flush_objs = 0;
    pool->is_dying = 0;
    SET_SENTINEL(pool,POOL);
    return pool;
}

static NOINLINE void pool_free(pool_t *pool)
{
    ASSERT_SENTINEL(pool,POOL);
    INVERT_SENTINEL(pool,POOL);
    pool->client = NULL;
    list_del(&pool->pool_list);
    tmh_free_infra(pool);
}

/* register new_client as a user of this shared pool and return new
   total number of registered users */
static int shared_pool_join(pool_t *pool, client_t *new_client)
{
    sharelist_t *sl;

    ASSERT(is_shared(pool));
    if ( (sl = tmem_malloc(sharelist_t,NULL)) == NULL )
        return -1;
    sl->client = new_client;
    list_add_tail(&sl->share_list, &pool->share_list);
    if ( new_client->cli_id != pool->client->cli_id )
        printk("adding new %s %d to shared pool owned by %s %d\n",
            client_str, new_client->cli_id, client_str, pool->client->cli_id);
    return ++pool->shared_count;
}

/* reassign "ownership" of the pool to another client that shares this pool */
static NOINLINE void shared_pool_reassign(pool_t *pool)
{
    sharelist_t *sl;
    int poolid;
    client_t *old_client = pool->client, *new_client;

    ASSERT(is_shared(pool));
    if ( list_empty(&pool->share_list) )
    {
        ASSERT(pool->shared_count == 0);
        return;
    }
    old_client->pools[pool->pool_id] = NULL;
    sl = list_entry(pool->share_list.next, sharelist_t, share_list);
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
    printk("reassigned shared pool from %s=%d to %s=%d pool_id=%d\n",
        cli_id_str, old_client->cli_id, cli_id_str, new_client->cli_id, poolid);
    pool->pool_id = poolid;
}

/* destroy all objects with last_client same as passed cli_id,
   remove pool's cli_id from list of sharers of this pool */
static NOINLINE int shared_pool_quit(pool_t *pool, cli_id_t cli_id)
{
    sharelist_t *sl;
    int s_poolid;

    ASSERT(is_shared(pool));
    ASSERT(pool->client != NULL);
    
    ASSERT_WRITELOCK(&tmem_rwlock);
    pool_destroy_objs(pool,1,cli_id);
    list_for_each_entry(sl,&pool->share_list, share_list)
    {
        if (sl->client->cli_id != cli_id)
            continue;
        list_del(&sl->share_list);
        tmem_free(sl,sizeof(sharelist_t),pool);
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
    printk("tmem: no match unsharing pool, %s=%d\n",
        cli_id_str,pool->client->cli_id);
    return -1;
}

/* flush all data (owned by cli_id) from a pool and, optionally, free it */
static void pool_flush(pool_t *pool, cli_id_t cli_id, bool_t destroy)
{
    ASSERT(pool != NULL);
    if ( (is_shared(pool)) && (shared_pool_quit(pool,cli_id) > 0) )
    {
        printk("tmem: %s=%d no longer using shared pool %d owned by %s=%d\n",
           cli_id_str, cli_id, pool->pool_id, cli_id_str,pool->client->cli_id);
        return;
    }
    printk("%s %s-%s tmem pool ",destroy?"destroying":"flushing",
        is_persistent(pool) ? "persistent" : "ephemeral" ,
        is_shared(pool) ? "shared" : "private");
    printk("%s=%d pool_id=%d\n", cli_id_str,pool->client->cli_id,pool->pool_id);
    if ( pool->client->live_migrating )
    {
        printk("can't %s pool while %s is live-migrating\n",
               destroy?"destroy":"flush", client_str);
        return;
    }
    pool_destroy_objs(pool,0,CLI_ID_NULL);
    if ( destroy )
    {
        pool->client->pools[pool->pool_id] = NULL;
        pool_free(pool);
    }
}

/************ CLIENT MANIPULATION OPERATIONS **************************/

static client_t *client_create(cli_id_t cli_id)
{
    client_t *client = tmh_alloc_infra(sizeof(client_t),__alignof__(client_t));
    int i;

    printk("tmem: initializing tmem capability for %s=%d...",cli_id_str,cli_id);
    if ( client == NULL )
    {
        printk("failed... out of memory\n");
        goto fail;
    }
    memset(client,0,sizeof(client_t));
    if ( (client->tmh = tmh_client_init(cli_id)) == NULL )
    {
        printk("failed... can't allocate host-dependent part of client\n");
        goto fail;
    }
    if ( !tmh_set_client_from_id(client, client->tmh, cli_id) )
    {
        printk("failed... can't set client\n");
        goto fail;
    }
    client->cli_id = cli_id;
#ifdef __i386__
    client->compress = 0;
#else
    client->compress = tmh_compression_enabled();
#endif
    client->shared_auth_required = tmh_shared_auth();
    for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++)
        client->shared_auth_uuid[i][0] =
            client->shared_auth_uuid[i][1] = -1L;
    client->frozen = 0; client->live_migrating = 0;
    client->weight = 0; client->cap = 0;
    list_add_tail(&client->client_list, &global_client_list);
    INIT_LIST_HEAD(&client->ephemeral_page_list);
    INIT_LIST_HEAD(&client->persistent_invalidated_list);
    client->cur_pgp = NULL;
    client->eph_count = client->eph_count_max = 0;
    client->total_cycles = 0; client->succ_pers_puts = 0;
    client->succ_eph_gets = 0; client->succ_pers_gets = 0;
    printk("ok\n");
    return client;

 fail:
    tmh_free_infra(client);
    return NULL;
}

static void client_free(client_t *client)
{
    list_del(&client->client_list);
    tmh_client_destroy(client->tmh);
    tmh_free_infra(client);
}

/* flush all data from a client and, optionally, free it */
static void client_flush(client_t *client, bool_t destroy)
{
    int i;
    pool_t *pool;

    for  (i = 0; i < MAX_POOLS_PER_DOMAIN; i++)
    {
        if ( (pool = client->pools[i]) == NULL )
            continue;
        pool_flush(pool,client->cli_id,destroy);
        if ( destroy )
            client->pools[i] = NULL;
    }
    if ( destroy )
        client_free(client);
}

static bool_t client_over_quota(client_t *client)
{
    int total = _atomic_read(client_weight_total);

    ASSERT(client != NULL);
    if ( (total == 0) || (client->weight == 0) || 
          (client->eph_count == 0) )
        return 0;
    return ( ((global_eph_count*100L) / client->eph_count ) >
             ((total*100L) / client->weight) );
}

static void client_freeze(client_t *client, int freeze)
{
    client->frozen = freeze;
}

/************ MEMORY REVOCATION ROUTINES *******************************/

static bool_t tmem_try_to_evict_pgp(pgp_t *pgp, bool_t *hold_pool_rwlock)
{
    obj_t *obj = pgp->obj;
    pool_t *pool = obj->pool;
    client_t *client = pool->client;
    uint16_t firstbyte = pgp->firstbyte;

    if ( pool->is_dying )
        return 0;
    if ( tmh_lock_all && !obj->no_evict )
       return 1;
    if ( tmem_spin_trylock(&obj->obj_spinlock) )
    {
        if ( tmh_dedup_enabled() )
        {
            firstbyte = pgp->firstbyte;
            if ( firstbyte ==  NOT_SHAREABLE )
                goto obj_unlock;
            ASSERT(firstbyte < 256);
            if ( !tmem_write_trylock(&pcd_tree_rwlocks[firstbyte]) )
                goto obj_unlock;
            if ( pgp->pcd->pgp_ref_count > 1 && !pgp->eviction_attempted )
            {
                pgp->eviction_attempted++;
                list_del(&pgp->global_eph_pages);
                list_add_tail(&pgp->global_eph_pages,&global_ephemeral_page_list);
                list_del(&pgp->client_eph_pages);
                list_add_tail(&pgp->client_eph_pages,&client->ephemeral_page_list);
                goto pcd_unlock;
            }
        }
        if ( obj->pgp_count > 1 )
            return 1;
        if ( tmem_write_trylock(&pool->pool_rwlock) )
        {
            *hold_pool_rwlock = 1;
            return 1;
        }
pcd_unlock:
        tmem_write_unlock(&pcd_tree_rwlocks[firstbyte]);
obj_unlock:
        tmem_spin_unlock(&obj->obj_spinlock);
    }
    return 0;
}

static int tmem_evict(void)
{
    client_t *client = tmh_client_from_current();
    pgp_t *pgp = NULL, *pgp2, *pgp_del;
    obj_t *obj;
    pool_t *pool;
    int ret = 0;
    bool_t hold_pool_rwlock = 0;

    evict_attempts++;
    tmem_spin_lock(&eph_lists_spinlock);
    if ( (client != NULL) && client_over_quota(client) &&
         !list_empty(&client->ephemeral_page_list) )
    {
        list_for_each_entry_safe(pgp,pgp2,&client->ephemeral_page_list,client_eph_pages)
            if ( tmem_try_to_evict_pgp(pgp,&hold_pool_rwlock) )
                goto found;
    } else if ( list_empty(&global_ephemeral_page_list) ) {
        goto out;
    } else {
        list_for_each_entry_safe(pgp,pgp2,&global_ephemeral_page_list,global_eph_pages)
            if ( tmem_try_to_evict_pgp(pgp,&hold_pool_rwlock) )
                goto found;
    }

    ret = 0;
    goto out;

found:
    ASSERT(pgp != NULL);
    ASSERT_SENTINEL(pgp,PGD);
    obj = pgp->obj;
    ASSERT(obj != NULL);
    ASSERT(obj->no_evict == 0);
    ASSERT(obj->pool != NULL);
    ASSERT_SENTINEL(obj,OBJ);
    pool = obj->pool;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    pgp_del = pgp_delete_from_obj(obj, pgp->index);
    ASSERT(pgp_del == pgp);
    if ( tmh_dedup_enabled() && pgp->firstbyte != NOT_SHAREABLE )
    {
        ASSERT(pgp->pcd->pgp_ref_count == 1 || pgp->eviction_attempted);
        pcd_disassociate(pgp,pool,1);
    }
    pgp_delete(pgp,1);
    if ( obj->pgp_count == 0 )
    {
        ASSERT_WRITELOCK(&pool->pool_rwlock);
        obj_free(obj,0);
    }
    else
        tmem_spin_unlock(&obj->obj_spinlock);
    if ( hold_pool_rwlock )
        tmem_write_unlock(&pool->pool_rwlock);
    evicted_pgs++;
    ret = 1;

out:
    tmem_spin_unlock(&eph_lists_spinlock);
    return ret;
}

static unsigned long tmem_relinquish_npages(unsigned long n)
{
    unsigned long avail_pages = 0;

    while ( (avail_pages = tmh_avail_pages()) < n )
    {
        if (  !tmem_evict() )
            break;
    }
    if ( avail_pages )
        tmh_release_avail_pages_to_host();
    return avail_pages;
}

/* Under certain conditions (e.g. if each client is putting pages for exactly
 * one object), once locks are held, freeing up memory may
 * result in livelocks and very long "put" times, so we try to ensure there
 * is a minimum amount of memory (1MB) available BEFORE any data structure
 * locks are held */
static inline void tmem_ensure_avail_pages(void)
{
    int failed_evict = 10;

    while ( !tmh_free_mb() )
    {
        if ( tmem_evict() )
            continue;
        else if ( failed_evict-- <= 0 )
            break;
    }
}

/************ TMEM CORE OPERATIONS ************************************/

static NOINLINE int do_tmem_put_compress(pgp_t *pgp, tmem_cli_mfn_t cmfn,
                                         void *cva)
{
    void *dst, *p;
    size_t size;
    int ret = 0;
    DECL_LOCAL_CYC_COUNTER(compress);
    
    ASSERT(pgp != NULL);
    ASSERT(pgp->obj != NULL);
    ASSERT_SPINLOCK(&pgp->obj->obj_spinlock);
    ASSERT(pgp->obj->pool != NULL);
    ASSERT(pgp->obj->pool->client != NULL);
#ifdef __i386__
    return -ENOMEM;
#endif

    if ( pgp->pfp != NULL )
        pgp_free_data(pgp, pgp->obj->pool);
    START_CYC_COUNTER(compress);
    ret = tmh_compress_from_client(cmfn, &dst, &size, cva);
    if ( (ret == -EFAULT) || (ret == 0) )
        goto out;
    else if ( (size == 0) || (size >= tmem_subpage_maxsize()) ) {
        ret = 0;
        goto out;
    } else if ( tmh_dedup_enabled() && !is_persistent(pgp->obj->pool) ) {
        if ( (ret = pcd_associate(pgp,dst,size)) == -ENOMEM )
            goto out;
    } else if ( (p = tmem_malloc_bytes(size,pgp->obj->pool)) == NULL ) {
        ret = -ENOMEM;
        goto out;
    } else {
        memcpy(p,dst,size);
        pgp->cdata = p;
    }
    pgp->size = size;
    pgp->obj->pool->client->compressed_pages++;
    pgp->obj->pool->client->compressed_sum_size += size;
    ret = 1;

out:
    END_CYC_COUNTER(compress);
    return ret;
}

static NOINLINE int do_tmem_dup_put(pgp_t *pgp, tmem_cli_mfn_t cmfn,
       pagesize_t tmem_offset, pagesize_t pfn_offset, pagesize_t len, void *cva)
{
    pool_t *pool;
    obj_t *obj;
    client_t *client;
    pgp_t *pgpfound = NULL;
    int ret;

    ASSERT(pgp != NULL);
    ASSERT(pgp->pfp != NULL);
    ASSERT(pgp->size != -1);
    obj = pgp->obj;
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    ASSERT(obj != NULL);
    pool = obj->pool;
    ASSERT(pool != NULL);
    client = pool->client;
    if ( client->live_migrating )
        goto failed_dup; /* no dups allowed when migrating */
    /* can we successfully manipulate pgp to change out the data? */
    if ( len != 0 && client->compress && pgp->size != 0 )
    {
        ret = do_tmem_put_compress(pgp,cmfn,cva);
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
    if ( ( pgp->pfp = tmem_page_alloc(pool) ) == NULL )
        goto failed_dup;
    /* tmh_copy_from_client properly handles len==0 and offsets != 0 */
    ret = tmh_copy_from_client(pgp->pfp,cmfn,tmem_offset,pfn_offset,len,0);
    if ( ret == -EFAULT )
        goto bad_copy;
    if ( tmh_dedup_enabled() && !is_persistent(pool) )
    {
        if ( pcd_associate(pgp,NULL,0) == -ENOMEM )
            goto failed_dup;
    }
    pgp->size = 0;

done:
    /* successfully replaced data, clean up and return success */
    if ( is_shared(pool) )
        obj->last_client = client->cli_id;
    obj->no_evict = 0;
    tmem_spin_unlock(&obj->obj_spinlock);
    pool->dup_puts_replaced++;
    pool->good_puts++;
    if ( is_persistent(pool) )
        client->succ_pers_puts++;
    return 1;

bad_copy:
    /* this should only happen if the client passed a bad mfn */
    failed_copies++;
ASSERT(0);
    return -EFAULT;

failed_dup:
   /* couldn't change out the data, flush the old data and return
    * -ENOSPC instead of -ENOMEM to differentiate failed _dup_ put */
    pgpfound = pgp_delete_from_obj(obj, pgp->index);
    ASSERT(pgpfound == pgp);
    pgp_delete(pgpfound,0);
    if ( obj->pgp_count == 0 )
    {
        tmem_write_lock(&pool->pool_rwlock);
        obj_free(obj,0);
        tmem_write_unlock(&pool->pool_rwlock);
    } else {
        obj->no_evict = 0;
        tmem_spin_unlock(&obj->obj_spinlock);
    }
    pool->dup_puts_flushed++;
    return -ENOSPC;
}


static NOINLINE int do_tmem_put(pool_t *pool,
              uint64_t oid, uint32_t index,
              tmem_cli_mfn_t cmfn, pagesize_t tmem_offset,
              pagesize_t pfn_offset, pagesize_t len, void *cva)
{
    obj_t *obj = NULL, *objfound = NULL, *objnew = NULL;
    pgp_t *pgp = NULL, *pgpdel = NULL;
    client_t *client = pool->client;
    int ret = client->frozen ? -EFROZEN : -ENOMEM;

    ASSERT(pool != NULL);
    pool->puts++;
    /* does page already exist (dup)?  if so, handle specially */
    if ( (obj = objfound = obj_find(pool,oid)) != NULL )
    {
        ASSERT_SPINLOCK(&objfound->obj_spinlock);
        if ((pgp = pgp_lookup_in_obj(objfound, index)) != NULL)
            return do_tmem_dup_put(pgp,cmfn,tmem_offset,pfn_offset,len,cva);
    }

    /* no puts allowed into a frozen pool (except dup puts) */
    if ( client->frozen )
        goto free;

    if ( (objfound == NULL) )
    {
        tmem_write_lock(&pool->pool_rwlock);
        if ( (obj = objnew = obj_new(pool,oid)) == NULL )
        {
            tmem_write_unlock(&pool->pool_rwlock);
            return -ENOMEM;
        }
        ASSERT_SPINLOCK(&objnew->obj_spinlock);
        tmem_write_unlock(&pool->pool_rwlock);
    }

    ASSERT((obj != NULL)&&((objnew==obj)||(objfound==obj))&&(objnew!=objfound));
    ASSERT_SPINLOCK(&obj->obj_spinlock);
    if ( (pgp = pgp_alloc(obj)) == NULL )
        goto free;

    ret = pgp_add_to_obj(obj, index, pgp);
    if ( ret == -ENOMEM  )
        /* warning, may result in partially built radix tree ("stump") */
        goto free;
    ASSERT(ret != -EEXIST);
    pgp->index = index;

    if ( len != 0 && client->compress )
    {
        ASSERT(pgp->pfp == NULL);
        ret = do_tmem_put_compress(pgp,cmfn,cva);
        if ( ret == 1 )
            goto insert_page;
        if ( ret == -ENOMEM )
        {
            client->compress_nomem++;
            goto delete_and_free;
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
    if ( ( pgp->pfp = tmem_page_alloc(pool) ) == NULL )
    {
        ret = -ENOMEM;
        goto delete_and_free;
    }
    /* tmh_copy_from_client properly handles len==0 (TMEM_NEW_PAGE) */
    ret = tmh_copy_from_client(pgp->pfp,cmfn,tmem_offset,pfn_offset,len,cva);
    if ( ret == -EFAULT )
        goto bad_copy;
    if ( tmh_dedup_enabled() && !is_persistent(pool) )
    {
        if ( pcd_associate(pgp,NULL,0) == -ENOMEM )
            goto delete_and_free;
    }
    pgp->size = 0;

insert_page:
    if ( is_ephemeral(pool) )
    {
        tmem_spin_lock(&eph_lists_spinlock);
        list_add_tail(&pgp->global_eph_pages,
            &global_ephemeral_page_list);
        if (++global_eph_count > global_eph_count_max)
            global_eph_count_max = global_eph_count;
        list_add_tail(&pgp->client_eph_pages,
            &client->ephemeral_page_list);
        if (++client->eph_count > client->eph_count_max)
            client->eph_count_max = client->eph_count;
        tmem_spin_unlock(&eph_lists_spinlock);
    } else { /* is_persistent */
        tmem_spin_lock(&pers_lists_spinlock);
        list_add_tail(&pgp->pool_pers_pages,
            &pool->persistent_page_list);
        tmem_spin_unlock(&pers_lists_spinlock);
    }
    ASSERT( ((objnew==obj)||(objfound==obj)) && (objnew!=objfound));
    if ( is_shared(pool) )
        obj->last_client = client->cli_id;
    obj->no_evict = 0;
    tmem_spin_unlock(&obj->obj_spinlock);
    pool->good_puts++;
    if ( is_persistent(pool) )
        client->succ_pers_puts++;
    else
        tot_good_eph_puts++;
    return 1;

delete_and_free:
    ASSERT((obj != NULL) && (pgp != NULL) && (pgp->index != -1));
    pgpdel = pgp_delete_from_obj(obj, pgp->index);
    ASSERT(pgp == pgpdel);

free:
    if ( pgp )
        pgp_delete(pgp,0);
    if ( objfound )
    {
        objfound->no_evict = 0;
        tmem_spin_unlock(&objfound->obj_spinlock);
    }
    if ( objnew )
    {
        tmem_write_lock(&pool->pool_rwlock);
        obj_free(objnew,0);
        tmem_write_unlock(&pool->pool_rwlock);
    }
    pool->no_mem_puts++;
    return ret;

bad_copy:
    /* this should only happen if the client passed a bad mfn */
    failed_copies++;
ASSERT(0);
    goto free;
}

static NOINLINE int do_tmem_get(pool_t *pool, uint64_t oid, uint32_t index,
              tmem_cli_mfn_t cmfn, pagesize_t tmem_offset,
              pagesize_t pfn_offset, pagesize_t len, void *cva)
{
    obj_t *obj;
    pgp_t *pgp;
    client_t *client = pool->client;
    DECL_LOCAL_CYC_COUNTER(decompress);

    if ( !_atomic_read(pool->pgp_count) )
        return -EEMPTY;

    pool->gets++;
    obj = obj_find(pool,oid);
    if ( obj == NULL )
        return 0;

    ASSERT_SPINLOCK(&obj->obj_spinlock);
    if (is_shared(pool) || is_persistent(pool) )
        pgp = pgp_lookup_in_obj(obj, index);
    else
        pgp = pgp_delete_from_obj(obj, index);
    if ( pgp == NULL )
    {
        obj->no_evict = 0;
        tmem_spin_unlock(&obj->obj_spinlock);
        return 0;
    }
    ASSERT(pgp->size != -1);
    if ( tmh_dedup_enabled() && !is_persistent(pool) &&
              pgp->firstbyte != NOT_SHAREABLE )
    {
        if ( pcd_copy_to_client(cmfn, pgp) == -EFAULT )
            goto bad_copy;
    } else if ( pgp->size != 0 ) {
        START_CYC_COUNTER(decompress);
        if ( tmh_decompress_to_client(cmfn, pgp->cdata,
                                      pgp->size, cva) == -EFAULT )
            goto bad_copy;
        END_CYC_COUNTER(decompress);
    } else if ( tmh_copy_to_client(cmfn, pgp->pfp, tmem_offset,
                                 pfn_offset, len, cva) == -EFAULT)
        goto bad_copy;
    if ( is_ephemeral(pool) )
    {
        if ( is_private(pool) )
        {
            pgp_delete(pgp,0);
            if ( obj->pgp_count == 0 )
            {
                tmem_write_lock(&pool->pool_rwlock);
                obj_free(obj,0);
                obj = NULL;
                tmem_write_unlock(&pool->pool_rwlock);
            }
        } else {
            tmem_spin_lock(&eph_lists_spinlock);
            list_del(&pgp->global_eph_pages);
            list_add_tail(&pgp->global_eph_pages,&global_ephemeral_page_list);
            list_del(&pgp->client_eph_pages);
            list_add_tail(&pgp->client_eph_pages,&client->ephemeral_page_list);
            tmem_spin_unlock(&eph_lists_spinlock);
            ASSERT(obj != NULL);
            obj->last_client = tmh_get_cli_id_from_current();
        }
    }
    if ( obj != NULL )
    {
        obj->no_evict = 0;
        tmem_spin_unlock(&obj->obj_spinlock);
    }
    pool->found_gets++;
    if ( is_ephemeral(pool) )
        client->succ_eph_gets++;
    else
        client->succ_pers_gets++;
    return 1;

bad_copy:
    /* this should only happen if the client passed a bad mfn */
    failed_copies++;
ASSERT(0);
    return -EFAULT;

}

static NOINLINE int do_tmem_flush_page(pool_t *pool, uint64_t oid, uint32_t index)
{
    obj_t *obj;
    pgp_t *pgp;

    pool->flushs++;
    obj = obj_find(pool,oid);
    if ( obj == NULL )
        goto out;
    pgp = pgp_delete_from_obj(obj, index);
    if ( pgp == NULL )
    {
        obj->no_evict = 0;
        tmem_spin_unlock(&obj->obj_spinlock);
        goto out;
    }
    pgp_delete(pgp,0);
    if ( obj->pgp_count == 0 )
    {
        tmem_write_lock(&pool->pool_rwlock);
        obj_free(obj,0);
        tmem_write_unlock(&pool->pool_rwlock);
    } else {
        obj->no_evict = 0;
        tmem_spin_unlock(&obj->obj_spinlock);
    }
    pool->flushs_found++;

out:
    if ( pool->client->frozen )
        return -EFROZEN;
    else
        return 1;
}

static NOINLINE int do_tmem_flush_object(pool_t *pool, uint64_t oid)
{
    obj_t *obj;

    pool->flush_objs++;
    obj = obj_find(pool,oid);
    if ( obj == NULL )
        goto out;
    tmem_write_lock(&pool->pool_rwlock);
    obj_destroy(obj,0);
    pool->flush_objs_found++;
    tmem_write_unlock(&pool->pool_rwlock);

out:
    if ( pool->client->frozen )
        return -EFROZEN;
    else
        return 1;
}

static NOINLINE int do_tmem_destroy_pool(uint32_t pool_id)
{
    client_t *client = tmh_client_from_current();
    pool_t *pool;

    if ( client->pools == NULL )
        return 0;
    if ( (pool = client->pools[pool_id]) == NULL )
        return 0;
    client->pools[pool_id] = NULL;
    pool_flush(pool,client->cli_id,1);
    return 1;
}

static NOINLINE int do_tmem_new_pool(cli_id_t this_cli_id,
                                     uint32_t d_poolid, uint32_t flags,
                                     uint64_t uuid_lo, uint64_t uuid_hi)
{
    client_t *client;
    cli_id_t cli_id;
    int persistent = flags & TMEM_POOL_PERSIST;
    int shared = flags & TMEM_POOL_SHARED;
    int pagebits = (flags >> TMEM_POOL_PAGESIZE_SHIFT)
         & TMEM_POOL_PAGESIZE_MASK;
    int specversion = (flags >> TMEM_POOL_VERSION_SHIFT)
         & TMEM_POOL_VERSION_MASK;
    pool_t *pool, *shpool;
    int s_poolid, first_unused_s_poolid;
    int i;

    if ( this_cli_id == CLI_ID_NULL )
        cli_id = tmh_get_cli_id_from_current();
    else
        cli_id = this_cli_id;
    printk("tmem: allocating %s-%s tmem pool for %s=%d...",
        persistent ? "persistent" : "ephemeral" ,
        shared ? "shared" : "private", cli_id_str, cli_id);
    if ( specversion != TMEM_SPEC_VERSION )
    {
        printk("failed... unsupported spec version\n");
        return -EPERM;
    }
    if ( pagebits != (PAGE_SHIFT - 12) )
    {
        printk("failed... unsupported pagesize %d\n",1<<(pagebits+12));
        return -EPERM;
    }
    if ( (pool = pool_alloc()) == NULL )
    {
        printk("failed... out of memory\n");
        return -ENOMEM;
    }
    if ( this_cli_id != CLI_ID_NULL )
    {
        if ( (client = tmh_client_from_cli_id(this_cli_id)) == NULL
             || d_poolid >= MAX_POOLS_PER_DOMAIN
             || client->pools[d_poolid] != NULL )
            goto fail;
    }
    else
    {
        client = tmh_client_from_current();
        ASSERT(client != NULL);
        for ( d_poolid = 0; d_poolid < MAX_POOLS_PER_DOMAIN; d_poolid++ )
            if ( client->pools[d_poolid] == NULL )
                break;
        if ( d_poolid >= MAX_POOLS_PER_DOMAIN )
        {
            printk("failed... no more pool slots available for this %s\n",
                   client_str);
            goto fail;
        }
    }
    if ( shared )
    {
        if ( uuid_lo == -1L && uuid_hi == -1L )
            shared = 0;
        if ( client->shared_auth_required && !global_shared_auth )
        {
            for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++)
                if ( (client->shared_auth_uuid[i][0] == uuid_lo) &&
                     (client->shared_auth_uuid[i][1] == uuid_hi) )
                    break;
            if ( i == MAX_GLOBAL_SHARED_POOLS )
                shared = 0;
        }
    }
    pool->shared = shared;
    pool->client = client;
    if ( shared )
    {
        first_unused_s_poolid = MAX_GLOBAL_SHARED_POOLS;
        for ( s_poolid = 0; s_poolid < MAX_GLOBAL_SHARED_POOLS; s_poolid++ )
        {
            if ( (shpool = global_shared_pools[s_poolid]) != NULL )
            {
                if ( shpool->uuid[0] == uuid_lo && shpool->uuid[1] == uuid_hi )
                {
                    printk("(matches shared pool uuid=%"PRIx64".%"PRIx64") ",
                        uuid_hi, uuid_lo);
                    printk("pool_id=%d\n",d_poolid);
                    client->pools[d_poolid] = global_shared_pools[s_poolid];
                    shared_pool_join(global_shared_pools[s_poolid], client);
                    pool_free(pool);
                    return d_poolid;
                }
            }
            else if ( first_unused_s_poolid == MAX_GLOBAL_SHARED_POOLS )
                first_unused_s_poolid = s_poolid;
        }
        if ( first_unused_s_poolid == MAX_GLOBAL_SHARED_POOLS )
        {
            printk("tmem: failed... no global shared pool slots available\n");
            goto fail;
        }
        else
        {
            INIT_LIST_HEAD(&pool->share_list);
            pool->shared_count = 0;
            global_shared_pools[first_unused_s_poolid] = pool;
            (void)shared_pool_join(pool,client);
        }
    }
    client->pools[d_poolid] = pool;
    list_add_tail(&pool->pool_list, &global_pool_list);
    pool->pool_id = d_poolid;
    pool->persistent = persistent;
    pool->uuid[0] = uuid_lo; pool->uuid[1] = uuid_hi;
    printk("pool_id=%d\n",d_poolid);
    return d_poolid;

fail:
    pool_free(pool);
    return -EPERM;
}

/************ TMEM CONTROL OPERATIONS ************************************/

/* freeze/thaw all pools belonging to client cli_id (all domains if -1) */
static int tmemc_freeze_pools(cli_id_t cli_id, int arg)
{
    client_t *client;
    bool_t freeze = (arg == TMEMC_FREEZE) ? 1 : 0;
    bool_t destroy = (arg == TMEMC_DESTROY) ? 1 : 0;
    char *s;

    s = destroy ? "destroyed" : ( freeze ? "frozen" : "thawed" );
    if ( cli_id == CLI_ID_NULL )
    {
        list_for_each_entry(client,&global_client_list,client_list)
            client_freeze(client,freeze);
        printk("tmem: all pools %s for all %ss\n",s,client_str);
    }
    else
    {
        if ( (client = tmh_client_from_cli_id(cli_id)) == NULL)
            return -1;
        client_freeze(client,freeze);
        printk("tmem: all pools %s for %s=%d\n",s,cli_id_str,cli_id);
    }
    return 0;
}

static int tmemc_flush_mem(cli_id_t cli_id, uint32_t kb)
{
    uint32_t npages, flushed_pages, flushed_kb;

    if ( cli_id != CLI_ID_NULL )
    {
        printk("tmem: %s-specific flush not supported yet, use --all\n",
           client_str);
        return -1;
    }
    /* convert kb to pages, rounding up if necessary */
    npages = (kb + ((1 << (PAGE_SHIFT-10))-1)) >> (PAGE_SHIFT-10);
    flushed_pages = tmem_relinquish_npages(npages);
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

static int tmemc_list_client(client_t *c, tmem_cli_va_t buf, int off, 
                             uint32_t len, bool_t use_long)
{
    char info[BSIZE];
    int i, n = 0, sum = 0;
    pool_t *p;
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
    tmh_copy_to_client_buf_offset(buf,off+sum,info,n+1);
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
        tmh_copy_to_client_buf_offset(buf,off+sum,info,n+1);
        sum += n;
    }
    return sum;
}

static int tmemc_list_shared(tmem_cli_va_t buf, int off, uint32_t len,
                              bool_t use_long)
{
    char info[BSIZE];
    int i, n = 0, sum = 0;
    pool_t *p;
    sharelist_t *sl;

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
        tmh_copy_to_client_buf_offset(buf,off+sum,info,n+1);
        sum += n;
    }
    return sum;
}

#ifdef TMEM_PERF
static int tmemc_list_global_perf(tmem_cli_va_t buf, int off, uint32_t len,
                              bool_t use_long)
{
    char info[BSIZE];
    int n = 0, sum = 0;

    n = scnprintf(info+n,BSIZE-n,"T=");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,succ_get,"G");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,succ_put,"P");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,non_succ_get,"g");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,non_succ_put,"p");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,flush,"F");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,flush_obj,"O");
#ifdef COMPARE_COPY_PAGE_SSE2
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,pg_copy1,"1");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,pg_copy2,"2");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,pg_copy3,"3");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,pg_copy4,"4");
#else
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,pg_copy,"C");
#endif
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,compress,"c");
    n += SCNPRINTF_CYC_COUNTER(info+n,BSIZE-n,decompress,"d");
    n--; /* overwrite trailing comma */
    n += scnprintf(info+n,BSIZE-n,"\n");
    if ( sum + n >= len )
        return sum;
    tmh_copy_to_client_buf_offset(buf,off+sum,info,n+1);
    sum += n;
    return sum;
}
#else
#define tmemc_list_global_perf(_buf,_off,_len,_use) (0)
#endif

static int tmemc_list_global(tmem_cli_va_t buf, int off, uint32_t len,
                              bool_t use_long)
{
    char info[BSIZE];
    int n = 0, sum = off;

    n += scnprintf(info,BSIZE,"G="
      "Tt:%lu,Te:%lu,Cf:%lu,Af:%lu,Pf:%lu,Ta:%lu,"
      "Lm:%lu,Et:%lu,Ea:%lu,Rt:%lu,Ra:%lu,Rx:%lu,Fp:%lu%c",
      total_tmem_ops, errored_tmem_ops, failed_copies,
      alloc_failed, alloc_page_failed, tmh_avail_pages(),
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
    tmh_copy_to_client_buf_offset(buf,off+sum,info,n+1);
    sum += n;
    return sum;
}

static int tmemc_list(cli_id_t cli_id, tmem_cli_va_t buf, uint32_t len,
                               bool_t use_long)
{
    client_t *client;
    int off = 0;

    if ( cli_id == CLI_ID_NULL ) {
        off = tmemc_list_global(buf,0,len,use_long);
        off += tmemc_list_shared(buf,off,len-off,use_long);
        list_for_each_entry(client,&global_client_list,client_list)
            off += tmemc_list_client(client, buf, off, len-off, use_long);
        off += tmemc_list_global_perf(buf,off,len-off,use_long);
    }
    else if ( (client = tmh_client_from_cli_id(cli_id)) == NULL)
        return -1;
    else
        off = tmemc_list_client(client, buf, 0, len, use_long);

    return 0;
}

static int tmemc_set_var_one(client_t *client, uint32_t subop, uint32_t arg1)
{
    cli_id_t cli_id = client->cli_id;
    uint32_t old_weight;

    switch (subop)
    {
    case TMEMC_SET_WEIGHT:
        old_weight = client->weight;
        client->weight = arg1;
        printk("tmem: weight set to %d for %s=%d\n",arg1,cli_id_str,cli_id);
        atomic_sub(old_weight,&client_weight_total);
        atomic_add(client->weight,&client_weight_total);
        break;
    case TMEMC_SET_CAP:
        client->cap = arg1;
        printk("tmem: cap set to %d for %s=%d\n",arg1,cli_id_str,cli_id);
        break;
    case TMEMC_SET_COMPRESS:
#ifdef __i386__
        return -1;
#endif
        if ( tmh_dedup_enabled() )
        {
            printk("tmem: compression %s for all %ss, cannot be changed "
                   "when tmem_dedup is enabled\n",
            tmh_compression_enabled() ? "enabled" : "disabled",client_str);
            return -1;
        }
        client->compress = arg1 ? 1 : 0;
        printk("tmem: compression %s for %s=%d\n",
            arg1 ? "enabled" : "disabled",cli_id_str,cli_id);
        break;
    default:
        printk("tmem: unknown subop %d for tmemc_set_var\n",subop);
        return -1;
    }
    return 0;
}

static int tmemc_set_var(cli_id_t cli_id, uint32_t subop, uint32_t arg1)
{
    client_t *client;

    if ( cli_id == CLI_ID_NULL )
        list_for_each_entry(client,&global_client_list,client_list)
            tmemc_set_var_one(client, subop, arg1);
    else if ( (client = tmh_client_from_cli_id(cli_id)) == NULL)
        return -1;
    else
        tmemc_set_var_one(client, subop, arg1);
    return 0;
}

static NOINLINE int tmemc_shared_pool_auth(cli_id_t cli_id, uint64_t uuid_lo,
                                  uint64_t uuid_hi, bool_t auth)
{
    client_t *client;
    int i, free = -1;

    if ( cli_id == CLI_ID_NULL )
    {
        global_shared_auth = auth;
        return 1;
    }
    client = tmh_client_from_cli_id(cli_id);
    if ( client == NULL )
        return -EINVAL;
    for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++)
    {
        if ( (client->shared_auth_uuid[i][0] == uuid_lo) &&
             (client->shared_auth_uuid[i][1] == uuid_hi) )
        {
            if ( auth == 0 )
                client->shared_auth_uuid[i][0] =
                    client->shared_auth_uuid[i][1] = -1L;
            return 1;
        }
        if ( (auth == 1) && (client->shared_auth_uuid[i][0] == -1L) &&
                 (client->shared_auth_uuid[i][1] == -1L) && (free == -1) )
            free = i;
    }
    if ( auth == 0 )
        return 0;
    if ( auth == 1 && free == -1 )
        return -ENOMEM;
    client->shared_auth_uuid[free][0] = uuid_lo;
    client->shared_auth_uuid[free][1] = uuid_hi;
    return 1;
}

static NOINLINE int tmemc_save_subop(int cli_id, uint32_t pool_id,
                        uint32_t subop, tmem_cli_va_t buf, uint32_t arg1)
{
    client_t *client = tmh_client_from_cli_id(cli_id);
    pool_t *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];
    uint32_t p;
    uint64_t *uuid;
    pgp_t *pgp, *pgp2;
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
        rc = client->weight == -1 ? -2 : client->weight;
        break;
    case TMEMC_SAVE_GET_CLIENT_CAP:
        rc = client->cap == -1 ? -2 : client->cap;
        break;
    case TMEMC_SAVE_GET_CLIENT_FLAGS:
        rc = (client->compress ? TMEM_CLIENT_COMPRESS : 0 ) |
             (client->was_frozen ? TMEM_CLIENT_FROZEN : 0 );
        break;
    case TMEMC_SAVE_GET_POOL_FLAGS:
         if ( pool == NULL )
             break;
         rc = (pool->persistent ? TMEM_POOL_PERSIST : 0) |
              (pool->shared ? TMEM_POOL_SHARED : 0) |
              (pool->pageshift << TMEM_POOL_PAGESIZE_SHIFT);
        break;
    case TMEMC_SAVE_GET_POOL_NPAGES:
         if ( pool == NULL )
             break;
        rc = _atomic_read(pool->pgp_count);
        break;
    case TMEMC_SAVE_GET_POOL_UUID:
         if ( pool == NULL )
             break;
        uuid = (uint64_t *)buf.p;
        *uuid++ = pool->uuid[0];
        *uuid = pool->uuid[1];
        rc = 0;
    case TMEMC_SAVE_END:
        client->live_migrating = 0;
        if ( !list_empty(&client->persistent_invalidated_list) )
            list_for_each_entry_safe(pgp,pgp2,
              &client->persistent_invalidated_list, client_inv_pages)
                pgp_free_from_inv_list(client,pgp);
        client->frozen = client->was_frozen;
        rc = 0;
    }
    return rc;
}

static NOINLINE int tmemc_save_get_next_page(int cli_id, int pool_id,
                        tmem_cli_va_t buf, uint32_t bufsize)
{
    client_t *client = tmh_client_from_cli_id(cli_id);
    pool_t *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];
    pgp_t *pgp;
    int ret = 0;
    struct tmem_handle *h;
    unsigned int pagesize = 1 << (pool->pageshift+12);

    if ( pool == NULL || is_ephemeral(pool) )
        return -1;
    if ( bufsize < pagesize + sizeof(struct tmem_handle) )
        return -ENOMEM;

    tmem_spin_lock(&pers_lists_spinlock);
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
                         pgp_t,pool_pers_pages);
    } else if ( list_is_last(&pool->cur_pgp->pool_pers_pages, 
                             &pool->persistent_page_list) )
    {
        /* already processed the last one in the list */
        ret = -1;
        goto out;
    }
    pgp = list_entry((&pool->cur_pgp->pool_pers_pages)->next,
                         pgp_t,pool_pers_pages);
    pool->cur_pgp = pgp;
    h = (struct tmem_handle *)buf.p;
    h->oid = pgp->obj->oid;
    h->index = pgp->index;
    buf.p = (void *)(h+1);
    ret = do_tmem_get(pool, h->oid, h->index,0,0,0,pagesize,buf.p);

out:
    tmem_spin_unlock(&pers_lists_spinlock);
    return ret;
}

static NOINLINE int tmemc_save_get_next_inv(int cli_id, tmem_cli_va_t buf,
                        uint32_t bufsize)
{
    client_t *client = tmh_client_from_cli_id(cli_id);
    pgp_t *pgp;
    struct tmem_handle *h;
    int ret = 0;

    if ( client == NULL )
        return 0;
    if ( bufsize < sizeof(struct tmem_handle) )
        return 0;
    tmem_spin_lock(&pers_lists_spinlock);
    if ( list_empty(&client->persistent_invalidated_list) )
        goto out;
    if ( client->cur_pgp == NULL )
    {
        pgp = list_entry((&client->persistent_invalidated_list)->next,
                         pgp_t,client_inv_pages);
        client->cur_pgp = pgp;
    } else if ( list_is_last(&client->cur_pgp->client_inv_pages, 
                             &client->persistent_invalidated_list) )
    {
        client->cur_pgp = NULL;
        ret = 0;
        goto out;
    } else {
        pgp = list_entry((&client->cur_pgp->client_inv_pages)->next,
                         pgp_t,client_inv_pages);
        client->cur_pgp = pgp;
    }
    h = (struct tmem_handle *)buf.p;
    h->pool_id = pgp->pool_id;
    h->oid = pgp->inv_oid;
    h->index = pgp->index;
    ret = 1;
out:
    tmem_spin_unlock(&pers_lists_spinlock);
    return ret;
}

static int tmemc_restore_put_page(int cli_id, int pool_id, uint64_t oid,
                      uint32_t index, tmem_cli_va_t buf, uint32_t bufsize)
{
    client_t *client = tmh_client_from_cli_id(cli_id);
    pool_t *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];

    if ( pool == NULL )
        return -1;
    return do_tmem_put(pool,oid,index,0,0,0,bufsize,buf.p);
}

static int tmemc_restore_flush_page(int cli_id, int pool_id, uint64_t oid,
                        uint32_t index)
{
    client_t *client = tmh_client_from_cli_id(cli_id);
    pool_t *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];

    if ( pool == NULL )
        return -1;
    return do_tmem_flush_page(pool,oid,index);
}

static NOINLINE int do_tmem_control(struct tmem_op *op)
{
    int ret;
    uint32_t pool_id = op->pool_id;
    uint32_t subop = op->u.ctrl.subop;

    if (!tmh_current_is_privileged())
    {
        /* don't fail... mystery: sometimes dom0 fails here */
        /* return -EPERM; */
    }
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
        ret = tmemc_list(op->u.ctrl.cli_id,op->u.ctrl.buf,
                         op->u.ctrl.arg1,op->u.ctrl.arg2);
        break;
    case TMEMC_SET_WEIGHT:
    case TMEMC_SET_CAP:
    case TMEMC_SET_COMPRESS:
        ret = tmemc_set_var(op->u.ctrl.cli_id,subop,op->u.ctrl.arg1);
        break;
    case TMEMC_QUERY_FREEABLE_MB:
        ret = tmh_freeable_pages() >> (20 - PAGE_SHIFT);
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
                        op->u.ctrl.buf,op->u.ctrl.arg1);
        break;
    case TMEMC_SAVE_GET_NEXT_PAGE:
        ret = tmemc_save_get_next_page(op->u.ctrl.cli_id, pool_id,
                                       op->u.ctrl.buf, op->u.ctrl.arg1);
        break;
    case TMEMC_SAVE_GET_NEXT_INV:
        ret = tmemc_save_get_next_inv(op->u.ctrl.cli_id, op->u.ctrl.buf,
                                      op->u.ctrl.arg1);
        break;
    case TMEMC_RESTORE_PUT_PAGE:
        ret = tmemc_restore_put_page(op->u.ctrl.cli_id,pool_id,
                                     op->u.ctrl.arg3, op->u.ctrl.arg2,
                                     op->u.ctrl.buf, op->u.ctrl.arg1);
        break;
    case TMEMC_RESTORE_FLUSH_PAGE:
        ret = tmemc_restore_flush_page(op->u.ctrl.cli_id,pool_id,
                                       op->u.ctrl.arg3, op->u.ctrl.arg2);
        break;
    default:
        ret = -1;
    }
    return ret;
}

/************ EXPORTed FUNCTIONS **************************************/

EXPORT long do_tmem_op(tmem_cli_op_t uops)
{
    struct tmem_op op;
    client_t *client = tmh_client_from_current();
    pool_t *pool = NULL;
    int rc = 0;
    bool_t succ_get = 0, succ_put = 0;
    bool_t non_succ_get = 0, non_succ_put = 0;
    bool_t flush = 0, flush_obj = 0;
    bool_t tmem_write_lock_set = 0, tmem_read_lock_set = 0;
    DECL_LOCAL_CYC_COUNTER(succ_get);
    DECL_LOCAL_CYC_COUNTER(succ_put);
    DECL_LOCAL_CYC_COUNTER(non_succ_get);
    DECL_LOCAL_CYC_COUNTER(non_succ_put);
    DECL_LOCAL_CYC_COUNTER(flush);
    DECL_LOCAL_CYC_COUNTER(flush_obj);

    if ( !tmem_initialized )
        return -ENODEV;

    total_tmem_ops++;

    if ( tmh_lock_all )
    {
        if ( tmh_lock_all > 1 )
            spin_lock_irq(&tmem_spinlock);
        else
            spin_lock(&tmem_spinlock);
    }

    START_CYC_COUNTER(succ_get);
    DUP_START_CYC_COUNTER(succ_put,succ_get);
    DUP_START_CYC_COUNTER(non_succ_get,succ_get);
    DUP_START_CYC_COUNTER(non_succ_put,succ_get);
    DUP_START_CYC_COUNTER(flush,succ_get);
    DUP_START_CYC_COUNTER(flush_obj,succ_get);

    if ( client != NULL && tmh_client_is_dying(client) )
    {
        rc = -ENODEV;
        goto out;
    }

    if ( unlikely(tmh_get_tmemop_from_client(&op, uops) != 0) )
    {
        printk("tmem: can't get tmem struct from %s\n",client_str);
        rc = -EFAULT;
        goto out;
    }

    if ( op.cmd == TMEM_CONTROL )
    {
        tmem_write_lock(&tmem_rwlock);
        tmem_write_lock_set = 1;
        rc = do_tmem_control(&op);
        goto out;
    } else if ( op.cmd == TMEM_AUTH ) {
        tmem_write_lock(&tmem_rwlock);
        tmem_write_lock_set = 1;
        rc = tmemc_shared_pool_auth(op.u.new.arg1,op.u.new.uuid[0],
                         op.u.new.uuid[1],op.u.new.flags);
        goto out;
    } else if ( op.cmd == TMEM_RESTORE_NEW ) {
        tmem_write_lock(&tmem_rwlock);
        tmem_write_lock_set = 1;
        rc = do_tmem_new_pool(op.u.new.arg1, op.pool_id, op.u.new.flags,
                         op.u.new.uuid[0], op.u.new.uuid[1]);
        goto out;
    }

    /* create per-client tmem structure dynamically on first use by client */
    if ( client == NULL )
    {
        tmem_write_lock(&tmem_rwlock);
        tmem_write_lock_set = 1;
        if ( (client = client_create(tmh_get_cli_id_from_current())) == NULL )
        {
            printk("tmem: can't create tmem structure for %s\n",client_str);
            rc = -ENOMEM;
            goto out;
        }
    }

    if ( op.cmd == TMEM_NEW_POOL || op.cmd == TMEM_DESTROY_POOL )
    {
        if ( !tmem_write_lock_set )
        {
            tmem_write_lock(&tmem_rwlock);
            tmem_write_lock_set = 1;
        }
    }
    else
    {
        if ( !tmem_write_lock_set )
        {
            tmem_read_lock(&tmem_rwlock);
            tmem_read_lock_set = 1;
        }
        if ( ((uint32_t)op.pool_id >= MAX_POOLS_PER_DOMAIN) ||
             ((pool = client->pools[op.pool_id]) == NULL) )
        {
            rc = -ENODEV;
            printk("tmem: operation requested on uncreated pool\n");
            goto out;
        }
        ASSERT_SENTINEL(pool,POOL);
    }

    switch ( op.cmd )
    {
    case TMEM_NEW_POOL:
        rc = do_tmem_new_pool(CLI_ID_NULL, 0, op.u.new.flags,
                              op.u.new.uuid[0], op.u.new.uuid[1]);
        break;
    case TMEM_NEW_PAGE:
        tmem_ensure_avail_pages();
        rc = do_tmem_put(pool, op.u.gen.object,
                         op.u.gen.index, op.u.gen.cmfn, 0, 0, 0, NULL);
        break;
    case TMEM_PUT_PAGE:
        tmem_ensure_avail_pages();
        rc = do_tmem_put(pool, op.u.gen.object,
                    op.u.gen.index, op.u.gen.cmfn, 0, 0, PAGE_SIZE, NULL);
        if (rc == 1) succ_put = 1;
        else non_succ_put = 1;
        break;
    case TMEM_GET_PAGE:
        rc = do_tmem_get(pool, op.u.gen.object, op.u.gen.index, op.u.gen.cmfn,
                         0, 0, PAGE_SIZE, 0);
        if (rc == 1) succ_get = 1;
        else non_succ_get = 1;
        break;
    case TMEM_FLUSH_PAGE:
        flush = 1;
        rc = do_tmem_flush_page(pool, op.u.gen.object, op.u.gen.index);
        break;
    case TMEM_FLUSH_OBJECT:
        rc = do_tmem_flush_object(pool, op.u.gen.object);
        flush_obj = 1;
        break;
    case TMEM_DESTROY_POOL:
        flush = 1;
        rc = do_tmem_destroy_pool(op.pool_id);
        break;
    case TMEM_READ:
        rc = do_tmem_get(pool, op.u.gen.object, op.u.gen.index, op.u.gen.cmfn,
                         op.u.gen.tmem_offset, op.u.gen.pfn_offset,
                         op.u.gen.len,0);
        break;
    case TMEM_WRITE:
        rc = do_tmem_put(pool, op.u.gen.object,
                         op.u.gen.index, op.u.gen.cmfn,
                         op.u.gen.tmem_offset, op.u.gen.pfn_offset,
                         op.u.gen.len, NULL);
        break;
    case TMEM_XCHG:
        /* need to hold global lock to ensure xchg is atomic */
        printk("tmem_xchg op not implemented yet\n");
        rc = 0;
        break;
    default:
        printk("tmem: op %d not implemented\n", op.cmd);
        rc = 0;
        break;
    }

out:
    if ( rc < 0 )
        errored_tmem_ops++;
    if ( succ_get )
        END_CYC_COUNTER_CLI(succ_get,client);
    else if ( succ_put )
        END_CYC_COUNTER_CLI(succ_put,client);
    else if ( non_succ_get )
        END_CYC_COUNTER_CLI(non_succ_get,client);
    else if ( non_succ_put )
        END_CYC_COUNTER_CLI(non_succ_put,client);
    else if ( flush )
        END_CYC_COUNTER_CLI(flush,client);
    else if ( flush_obj )
        END_CYC_COUNTER_CLI(flush_obj,client);

    if ( tmh_lock_all )
    {
        if ( tmh_lock_all > 1 )
            spin_unlock_irq(&tmem_spinlock);
        else
            spin_unlock(&tmem_spinlock);
    } else {
        if ( tmem_write_lock_set )
            write_unlock(&tmem_rwlock);
        else if ( tmem_read_lock_set )
            read_unlock(&tmem_rwlock);
        else 
            ASSERT(0);
    }

    return rc;
}

/* this should be called when the host is destroying a client */
EXPORT void tmem_destroy(void *v)
{
    client_t *client = (client_t *)v;

    if ( client == NULL )
        return;

    if ( !tmh_client_is_dying(client) )
    {
        printk("tmem: tmem_destroy can only destroy dying client\n");
        return;
    }

    if ( tmh_lock_all )
        spin_lock(&tmem_spinlock);
    else
        write_lock(&tmem_rwlock);

    printk("tmem: flushing tmem pools for %s=%d\n",
           cli_id_str, client->cli_id);
    client_flush(client, 1);

    if ( tmh_lock_all )
        spin_unlock(&tmem_spinlock);
    else
        write_unlock(&tmem_rwlock);
}

/* freezing all pools guarantees that no additional memory will be consumed */
EXPORT void tmem_freeze_all(unsigned char key)
{
    static int freeze = 0;
 
    if ( tmh_lock_all )
        spin_lock(&tmem_spinlock);
    else
        write_lock(&tmem_rwlock);

    freeze = !freeze;
    tmemc_freeze_pools(CLI_ID_NULL,freeze);

    if ( tmh_lock_all )
        spin_unlock(&tmem_spinlock);
    else
        write_unlock(&tmem_rwlock);
}

#define MAX_EVICTS 10  /* should be variable or set via TMEMC_ ?? */

EXPORT void *tmem_relinquish_pages(unsigned int order, unsigned int memflags)
{
    pfp_t *pfp;
    unsigned long evicts_per_relinq = 0;
    int max_evictions = 10;

    if (!tmh_enabled() || !tmh_freeable_pages())
        return NULL;
#ifdef __i386__
    return NULL;
#endif

    relinq_attempts++;
    if ( order > 0 )
    {
#ifndef NDEBUG
        printk("tmem_relinquish_page: failing order=%d\n", order);
#endif
        return NULL;
    }

    if ( tmh_called_from_tmem(memflags) )
    {
        if ( tmh_lock_all )
            spin_lock(&tmem_spinlock);
        else
            read_lock(&tmem_rwlock);
    }

    while ( (pfp = tmh_alloc_page(NULL,1)) == NULL )
    {
        if ( (max_evictions-- <= 0) || !tmem_evict())
            break;
        evicts_per_relinq++;
    }
    if ( evicts_per_relinq > max_evicts_per_relinq )
        max_evicts_per_relinq = evicts_per_relinq;
    tmh_scrub_page(pfp, memflags);
    if ( pfp != NULL )
        relinq_pgs++;

    if ( tmh_called_from_tmem(memflags) )
    {
        if ( tmh_lock_all )
            spin_unlock(&tmem_spinlock);
        else
            read_unlock(&tmem_rwlock);
    }

    return pfp;
}

/* called at hypervisor startup */
static int __init init_tmem(void)
{
    int i;
    if ( !tmh_enabled() )
        return 0;

    radix_tree_init();
    if ( tmh_dedup_enabled() )
        for (i = 0; i < 256; i++ )
        {
            pcd_tree_roots[i] = RB_ROOT;
            rwlock_init(&pcd_tree_rwlocks[i]);
        }

    if ( tmh_init() )
    {
        printk("tmem: initialized comp=%d dedup=%d tze=%d global-lock=%d\n",
            tmh_compression_enabled(), tmh_dedup_enabled(), tmh_tze_enabled(),
            tmh_lock_all);
        if ( tmh_dedup_enabled()&&tmh_compression_enabled()&&tmh_tze_enabled() )
        {
            tmh_tze_disable();
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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
