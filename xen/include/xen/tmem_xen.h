/******************************************************************************
 * tmem_xen.h
 *
 * Xen-specific Transcendent memory
 *
 * Copyright (c) 2009, Dan Magenheimer, Oracle Corp.
 */

#ifndef __XEN_TMEM_XEN_H__
#define __XEN_TMEM_XEN_H__

#include <xen/mm.h> /* heap alloc/free */
#include <xen/pfn.h>
#include <xen/xmalloc.h> /* xmalloc/xfree */
#include <xen/sched.h>  /* struct domain */
#include <xen/guest_access.h> /* copy_from_guest */
#include <xen/hash.h> /* hash_long */
#include <xen/domain_page.h> /* __map_domain_page */
#include <xen/rbtree.h> /* struct rb_root */
#include <xsm/xsm.h> /* xsm_tmem_control */
#include <public/tmem.h>
#ifdef CONFIG_COMPAT
#include <compat/tmem.h>
#endif
typedef uint32_t pagesize_t;  /* like size_t, must handle largest PAGE_SIZE */

#define IS_PAGE_ALIGNED(addr) IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
#define IS_VALID_PAGE(_pi)  ( mfn_valid(page_to_mfn(_pi)) )

extern struct page_list_head tmem_page_list;
extern spinlock_t tmem_page_list_lock;
extern unsigned long tmem_page_list_pages;
extern atomic_t freeable_page_count;

extern int tmem_init(void);
#define tmem_hash hash_long

extern bool_t opt_tmem_compress;
static inline bool_t tmem_compression_enabled(void)
{
    return opt_tmem_compress;
}

extern bool_t opt_tmem_shared_auth;
static inline bool_t tmem_shared_auth(void)
{
    return opt_tmem_shared_auth;
}

#ifdef CONFIG_TMEM
extern bool_t opt_tmem;
static inline bool_t tmem_enabled(void)
{
    return opt_tmem;
}

static inline void tmem_disable(void)
{
    opt_tmem = 0;
}
#else
static inline bool_t tmem_enabled(void)
{
    return 0;
}

static inline void tmem_disable(void)
{
}
#endif /* CONFIG_TMEM */

/*
 * Memory free page list management
 */

static inline struct page_info *tmem_page_list_get(void)
{
    struct page_info *pi;

    spin_lock(&tmem_page_list_lock);
    if ( (pi = page_list_remove_head(&tmem_page_list)) != NULL )
        tmem_page_list_pages--;
    spin_unlock(&tmem_page_list_lock);
    ASSERT((pi == NULL) || IS_VALID_PAGE(pi));
    return pi;
}

static inline void tmem_page_list_put(struct page_info *pi)
{
    ASSERT(IS_VALID_PAGE(pi));
    spin_lock(&tmem_page_list_lock);
    page_list_add(pi, &tmem_page_list);
    tmem_page_list_pages++;
    spin_unlock(&tmem_page_list_lock);
}

/*
 * Memory allocation for persistent data 
 */
static inline struct page_info *__tmem_alloc_page_thispool(struct domain *d)
{
    struct page_info *pi;

    /* note that this tot_pages check is not protected by d->page_alloc_lock,
     * so may race and periodically fail in donate_page or alloc_domheap_pages
     * That's OK... neither is a problem, though chatty if log_lvl is set */ 
    if ( d->tot_pages >= d->max_pages )
        return NULL;

    if ( tmem_page_list_pages )
    {
        if ( (pi = tmem_page_list_get()) != NULL )
        {
            if ( donate_page(d,pi,0) == 0 )
                goto out;
            else
                tmem_page_list_put(pi);
        }
    }

    pi = alloc_domheap_pages(d,0,MEMF_tmem);

out:
    ASSERT((pi == NULL) || IS_VALID_PAGE(pi));
    return pi;
}

static inline void __tmem_free_page_thispool(struct page_info *pi)
{
    struct domain *d = page_get_owner(pi);

    ASSERT(IS_VALID_PAGE(pi));
    if ( (d == NULL) || steal_page(d,pi,0) == 0 )
        tmem_page_list_put(pi);
    else
    {
        scrub_one_page(pi);
        ASSERT((pi->count_info & ~(PGC_allocated | 1)) == 0);
        free_domheap_pages(pi,0);
    }
}

/*
 * Memory allocation for ephemeral (non-persistent) data
 */
static inline struct page_info *__tmem_alloc_page(void)
{
    struct page_info *pi = tmem_page_list_get();

    if ( pi == NULL)
        pi = alloc_domheap_pages(0,0,MEMF_tmem);

    if ( pi )
        atomic_inc(&freeable_page_count);
    ASSERT((pi == NULL) || IS_VALID_PAGE(pi));
    return pi;
}

static inline void __tmem_free_page(struct page_info *pi)
{
    ASSERT(IS_VALID_PAGE(pi));
    tmem_page_list_put(pi);
    atomic_dec(&freeable_page_count);
}

/*  "Client" (==domain) abstraction */
static inline struct client *tmem_client_from_cli_id(domid_t cli_id)
{
    struct client *c;
    struct domain *d = rcu_lock_domain_by_id(cli_id);
    if (d == NULL)
        return NULL;
    c = d->tmem_client;
    rcu_unlock_domain(d);
    return c;
}

/* these typedefs are in the public/tmem.h interface
typedef XEN_GUEST_HANDLE(void) cli_mfn_t;
typedef XEN_GUEST_HANDLE(char) cli_va_t;
*/
typedef XEN_GUEST_HANDLE_PARAM(tmem_op_t) tmem_cli_op_t;
typedef XEN_GUEST_HANDLE_PARAM(char) tmem_cli_va_param_t;

static inline int tmem_get_tmemop_from_client(tmem_op_t *op, tmem_cli_op_t uops)
{
#ifdef CONFIG_COMPAT
    if ( has_hvm_container_vcpu(current) ?
         hvm_guest_x86_mode(current) != 8 :
         is_pv_32bit_vcpu(current) )
    {
        int rc;
        enum XLAT_tmem_op_u u;
        tmem_op_compat_t cop;

        rc = copy_from_guest(&cop, guest_handle_cast(uops, void), 1);
        if ( rc )
            return rc;
        switch ( cop.cmd )
        {
        case TMEM_NEW_POOL:   u = XLAT_tmem_op_u_creat; break;
        case TMEM_AUTH:       u = XLAT_tmem_op_u_creat; break;
        case TMEM_RESTORE_NEW:u = XLAT_tmem_op_u_creat; break;
        default:              u = XLAT_tmem_op_u_gen ;  break;
        }
        XLAT_tmem_op(op, &cop);
        return 0;
    }
#endif
    return copy_from_guest(op, uops, 1);
}

#define tmem_cli_buf_null guest_handle_from_ptr(NULL, char)
#define TMEM_CLI_ID_NULL ((domid_t)((domid_t)-1L))
#define tmem_cli_id_str "domid"
#define tmem_client_str "domain"

int tmem_decompress_to_client(xen_pfn_t, void *, size_t,
			     tmem_cli_va_param_t);
int tmem_compress_from_client(xen_pfn_t, void **, size_t *,
			     tmem_cli_va_param_t);

int tmem_copy_from_client(struct page_info *, xen_pfn_t, tmem_cli_va_param_t);
int tmem_copy_to_client(xen_pfn_t, struct page_info *, tmem_cli_va_param_t);

#define tmem_client_err(fmt, args...)  printk(XENLOG_G_ERR fmt, ##args)
#define tmem_client_warn(fmt, args...) printk(XENLOG_G_WARNING fmt, ##args)
#define tmem_client_info(fmt, args...) printk(XENLOG_G_INFO fmt, ##args)

/* Global statistics (none need to be locked). */
struct tmem_statistics {
    unsigned long total_tmem_ops;
    unsigned long errored_tmem_ops;
    unsigned long total_flush_pool;
    unsigned long alloc_failed;
    unsigned long alloc_page_failed;
    unsigned long evicted_pgs;
    unsigned long evict_attempts;
    unsigned long relinq_pgs;
    unsigned long relinq_attempts;
    unsigned long max_evicts_per_relinq;
    unsigned long low_on_memory;
    unsigned long deduped_puts;
    unsigned long tot_good_eph_puts;
    int global_obj_count_max;
    int global_pgp_count_max;
    int global_pcd_count_max;
    int global_page_count_max;
    int global_rtree_node_count_max;
    long global_eph_count_max;
    unsigned long failed_copies;
    unsigned long pcd_tot_tze_size;
    unsigned long pcd_tot_csize;
    /* Global counters (should use long_atomic_t access). */
    atomic_t global_obj_count;
    atomic_t global_pgp_count;
    atomic_t global_pcd_count;
    atomic_t global_page_count;
    atomic_t global_rtree_node_count;
};

#define atomic_inc_and_max(_c) do { \
    atomic_inc(&tmem_stats._c); \
    if ( _atomic_read(tmem_stats._c) > tmem_stats._c##_max ) \
        tmem_stats._c##_max = _atomic_read(tmem_stats._c); \
} while (0)

#define atomic_dec_and_assert(_c) do { \
    atomic_dec(&tmem_stats._c); \
    ASSERT(_atomic_read(tmem_stats._c) >= 0); \
} while (0)

#define MAX_GLOBAL_SHARED_POOLS  16
struct tmem_global {
    struct list_head ephemeral_page_list;  /* All pages in ephemeral pools. */
    struct list_head client_list;
    struct tmem_pool *shared_pools[MAX_GLOBAL_SHARED_POOLS];
    bool_t shared_auth;
    long eph_count;  /* Atomicity depends on eph_lists_spinlock. */
    atomic_t client_weight_total;
};

#define MAX_POOLS_PER_DOMAIN 16

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
    xen_tmem_client_t info;
    bool_t shared_auth_required;
    /* For save/restore/migration. */
    bool_t was_frozen;
    struct list_head persistent_invalidated_list;
    struct tmem_page_descriptor *cur_pgp;
    /* Statistics collection. */
    unsigned long compress_poor, compress_nomem;
    unsigned long compressed_pages;
    uint64_t compressed_sum_size;
    uint64_t total_cycles;
    unsigned long succ_pers_puts, succ_eph_gets, succ_pers_gets;
    /* Shared pool authentication. */
    uint64_t shared_auth_uuid[MAX_GLOBAL_SHARED_POOLS][2];
};

#define POOL_PAGESHIFT (PAGE_SHIFT - 12)
#define OBJ_HASH_BUCKETS 256 /* Must be power of two. */
#define OBJ_HASH_BUCKETS_MASK (OBJ_HASH_BUCKETS-1)

#define is_persistent(_p)  (_p->persistent)
#define is_shared(_p)      (_p->shared)

struct tmem_pool {
    bool_t shared;
    bool_t persistent;
    bool_t is_dying;
    struct client *client;
    uint64_t uuid[2]; /* 0 for private, non-zero for shared. */
    uint32_t pool_id;
    rwlock_t pool_rwlock;
    struct rb_root obj_rb_root[OBJ_HASH_BUCKETS]; /* Protected by pool_rwlock. */
    struct list_head share_list; /* Valid if shared. */
    int shared_count; /* Valid if shared. */
    /* For save/restore/migration. */
    struct list_head persistent_page_list;
    struct tmem_page_descriptor *cur_pgp;
    /* Statistics collection. */
    atomic_t pgp_count;
    int pgp_count_max;
    long obj_count;  /* Atomicity depends on pool_rwlock held for write. */
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

struct share_list {
    struct list_head share_list;
    struct client *client;
};

#endif /* __XEN_TMEM_XEN_H__ */
