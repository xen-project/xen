/******************************************************************************
 * tmem_xen.h
 *
 * Xen-specific Transcendent memory
 *
 * Copyright (c) 2009, Dan Magenheimer, Oracle Corp.
 */

#ifndef __XEN_TMEM_XEN_H__
#define __XEN_TMEM_XEN_H__

#include <xen/config.h>
#include <xen/mm.h> /* heap alloc/free */
#include <xen/xmalloc.h> /* xmalloc/xfree */
#include <xen/sched.h>  /* struct domain */
#include <xen/guest_access.h> /* copy_from_guest */
#include <xen/hash.h> /* hash_long */
#include <public/tmem.h>
#ifdef CONFIG_COMPAT
#include <compat/tmem.h>
#endif

struct tmem_host_dependent_client {
    struct domain *domain;
    struct xmem_pool *persistent_pool;
};
typedef struct tmem_host_dependent_client tmh_client_t;

typedef uint32_t pagesize_t;  /* like size_t, must handle largest PAGE_SIZE */

#define IS_PAGE_ALIGNED(addr) \
  ((void *)((((unsigned long)addr + (PAGE_SIZE - 1)) & PAGE_MASK)) == addr)
#define IS_VALID_PAGE(_pi)  ( mfn_valid(page_to_mfn(_pi)) )

extern struct xmem_pool *tmh_mempool;
extern unsigned int tmh_mempool_maxalloc;
extern struct page_list_head tmh_page_list;
extern spinlock_t tmh_page_list_lock;
extern unsigned long tmh_page_list_pages;
extern atomic_t freeable_page_count;

extern spinlock_t tmem_lock;
extern spinlock_t tmem_spinlock;
extern rwlock_t tmem_rwlock;

extern void tmh_copy_page(char *to, char*from);
extern int tmh_init(void);
#define tmh_hash hash_long

extern void tmh_release_avail_pages_to_host(void);
extern void tmh_scrub_page(struct page_info *pi, unsigned int memflags);

extern int opt_tmem_compress;
static inline int tmh_compression_enabled(void)
{
    return opt_tmem_compress;
}

extern int opt_tmem_dedup;
static inline int tmh_dedup_enabled(void)
{
    return opt_tmem_dedup;
}

extern int opt_tmem_tze;
static inline int tmh_tze_enabled(void)
{
    return opt_tmem_tze;
}

static inline void tmh_tze_disable(void)
{
    opt_tmem_tze = 0;
}

extern int opt_tmem_shared_auth;
static inline int tmh_shared_auth(void)
{
    return opt_tmem_shared_auth;
}

extern int opt_tmem;
static inline int tmh_enabled(void)
{
    return opt_tmem;
}

extern int opt_tmem_lock;

extern int opt_tmem_flush_dups;

/*
 * Memory free page list management
 */

static inline struct page_info *tmh_page_list_get(void)
{
    struct page_info *pi;

    spin_lock(&tmh_page_list_lock);
    if ( (pi = page_list_remove_head(&tmh_page_list)) != NULL )
        tmh_page_list_pages--;
    spin_unlock(&tmh_page_list_lock);
    ASSERT((pi == NULL) || IS_VALID_PAGE(pi));
    return pi;
}

static inline void tmh_page_list_put(struct page_info *pi)
{
    ASSERT(IS_VALID_PAGE(pi));
    spin_lock(&tmh_page_list_lock);
    page_list_add(pi, &tmh_page_list);
    tmh_page_list_pages++;
    spin_unlock(&tmh_page_list_lock);
}

static inline unsigned long tmh_avail_pages(void)
{
    return tmh_page_list_pages;
}

/*
 * Memory allocation for persistent data 
 */

static inline bool_t domain_fully_allocated(struct domain *d)
{
    return ( d->tot_pages >= d->max_pages );
}
#define tmh_client_memory_fully_allocated(_pool) \
 domain_fully_allocated(_pool->client->tmh->domain)

static inline void *_tmh_alloc_subpage_thispool(struct xmem_pool *cmem_mempool,
                                                 size_t size, size_t align)
{
#if 0
    if ( d->tot_pages >= d->max_pages )
        return NULL;
#endif
#ifdef __i386__
    return _xmalloc(size,align);
#else
    ASSERT( size < tmh_mempool_maxalloc );
    if ( cmem_mempool == NULL )
        return NULL;
    return xmem_pool_alloc(size, cmem_mempool);
#endif
}
#define tmh_alloc_subpage_thispool(_pool, _s, _a) \
            _tmh_alloc_subpage_thispool(pool->client->tmh->persistent_pool, \
                                         _s, _a)

static inline void _tmh_free_subpage_thispool(struct xmem_pool *cmem_mempool,
                                               void *ptr, size_t size)
{
#ifdef __i386__
    xfree(ptr);
#else
    ASSERT( size < tmh_mempool_maxalloc );
    ASSERT( cmem_mempool != NULL );
    xmem_pool_free(ptr,cmem_mempool);
#endif
}
#define tmh_free_subpage_thispool(_pool, _p, _s) \
 _tmh_free_subpage_thispool(_pool->client->tmh->persistent_pool, _p, _s)

static inline struct page_info *_tmh_alloc_page_thispool(struct domain *d)
{
    struct page_info *pi;

    /* note that this tot_pages check is not protected by d->page_alloc_lock,
     * so may race and periodically fail in donate_page or alloc_domheap_pages
     * That's OK... neither is a problem, though chatty if log_lvl is set */ 
    if ( d->tot_pages >= d->max_pages )
        return NULL;

    if ( tmh_page_list_pages )
    {
        if ( (pi = tmh_page_list_get()) != NULL )
        {
            if ( donate_page(d,pi,0) == 0 )
                goto out;
            else
                tmh_page_list_put(pi);
        }
    }

    pi = alloc_domheap_pages(d,0,MEMF_tmem);

out:
    ASSERT((pi == NULL) || IS_VALID_PAGE(pi));
    return pi;
}
#define tmh_alloc_page_thispool(_pool) \
    _tmh_alloc_page_thispool(_pool->client->tmh->domain)

static inline void _tmh_free_page_thispool(struct page_info *pi)
{
    struct domain *d = page_get_owner(pi);

    ASSERT(IS_VALID_PAGE(pi));
    if ( (d == NULL) || steal_page(d,pi,0) == 0 )
        tmh_page_list_put(pi);
    else
    {
        scrub_one_page(pi);
        ASSERT((pi->count_info & ~(PGC_allocated | 1)) == 0);
        free_domheap_pages(pi,0);
    }
}
#define tmh_free_page_thispool(_pool,_pg) \
    _tmh_free_page_thispool(_pg)

/*
 * Memory allocation for ephemeral (non-persistent) data
 */

static inline void *tmh_alloc_subpage(void *pool, size_t size,
                                                 size_t align)
{
#ifdef __i386__
    ASSERT( size < PAGE_SIZE );
    return _xmalloc(size, align);
#else
    ASSERT( size < tmh_mempool_maxalloc );
    ASSERT( tmh_mempool != NULL );
    return xmem_pool_alloc(size, tmh_mempool);
#endif
}

static inline void tmh_free_subpage(void *ptr, size_t size)
{
#ifdef __i386__
    ASSERT( size < PAGE_SIZE );
    xfree(ptr);
#else
    ASSERT( size < tmh_mempool_maxalloc );
    xmem_pool_free(ptr,tmh_mempool);
#endif
}

static inline struct page_info *tmh_alloc_page(void *pool, int no_heap)
{
    struct page_info *pi = tmh_page_list_get();

    if ( pi == NULL && !no_heap )
        pi = alloc_domheap_pages(0,0,MEMF_tmem);
    ASSERT((pi == NULL) || IS_VALID_PAGE(pi));
    if ( pi != NULL && !no_heap )
        atomic_inc(&freeable_page_count);
    return pi;
}

static inline void tmh_free_page(struct page_info *pi)
{
    ASSERT(IS_VALID_PAGE(pi));
    tmh_page_list_put(pi);
    atomic_dec(&freeable_page_count);
}

static inline unsigned int tmem_subpage_maxsize(void)
{
    return tmh_mempool_maxalloc;
}

static inline unsigned long tmh_freeable_pages(void)
{
    return tmh_avail_pages() + _atomic_read(freeable_page_count);
}

static inline unsigned long tmh_free_mb(void)
{
    return (tmh_avail_pages() + total_free_pages()) >> (20 - PAGE_SHIFT);
}

/*
 * Memory allocation for "infrastructure" data
 */

static inline void *tmh_alloc_infra(size_t size, size_t align)
{
    return _xmalloc(size,align);
}

static inline void tmh_free_infra(void *p)
{
    return xfree(p);
}

#define tmh_lock_all  opt_tmem_lock
#define tmh_flush_dups  opt_tmem_flush_dups
#define tmh_called_from_tmem(_memflags) (_memflags & MEMF_tmem)

/*  "Client" (==domain) abstraction */

struct client;
typedef domid_t cli_id_t;
typedef struct domain tmh_cli_ptr_t;
typedef struct page_info pfp_t;

extern tmh_client_t *tmh_client_init(cli_id_t);
extern void tmh_client_destroy(tmh_client_t *);

/* this appears to be unreliable when a domain is being shut down */
static inline struct client *tmh_client_from_cli_id(cli_id_t cli_id)
{
    struct domain *d = get_domain_by_id(cli_id); /* incs d->refcnt! */
    if (d == NULL)
        return NULL;
    return (struct client *)(d->tmem);
}

static inline void tmh_client_put(tmh_client_t *tmh)
{
    put_domain(tmh->domain);
}

static inline struct client *tmh_client_from_current(void)
{
    return (struct client *)(current->domain->tmem);
}

#define tmh_client_is_dying(_client) (!!_client->tmh->domain->is_dying)

static inline cli_id_t tmh_get_cli_id_from_current(void)
{
    return current->domain->domain_id;
}

static inline tmh_cli_ptr_t *tmh_get_cli_ptr_from_current(void)
{
    return current->domain;
}

static inline void tmh_set_client_from_id(struct client *client,
                                          tmh_client_t *tmh, cli_id_t cli_id)
{
    struct domain *d = get_domain_by_id(cli_id);
    d->tmem = client;
    tmh->domain = d;
}

static inline bool_t tmh_current_is_privileged(void)
{
    return IS_PRIV(current->domain);
}

static inline uint8_t tmh_get_first_byte(pfp_t *pfp)
{
    void *p = __map_domain_page(pfp);

    return (uint8_t)(*(char *)p);
}

static inline int tmh_page_cmp(pfp_t *pfp1, pfp_t *pfp2)
{
    const uint64_t *p1 = (uint64_t *)__map_domain_page(pfp1);
    const uint64_t *p2 = (uint64_t *)__map_domain_page(pfp2);
    int i;

    // FIXME: code in assembly?
ASSERT(p1 != NULL);
ASSERT(p2 != NULL);
    for ( i = PAGE_SIZE/sizeof(uint64_t); i && *p1 == *p2; i--, *p1++, *p2++ );
    if ( !i )
        return 0;
    if ( *p1 < *p2 )
        return -1;
    return 1;
}

static inline int tmh_pcd_cmp(void *va1, pagesize_t len1, void *va2, pagesize_t len2)
{
    const char *p1 = (char *)va1;
    const char *p2 = (char *)va2;
    pagesize_t i;

    ASSERT(len1 <= PAGE_SIZE);
    ASSERT(len2 <= PAGE_SIZE);
    if ( len1 < len2 )
        return -1;
    if ( len1 > len2 )
        return 1;
    ASSERT(len1 == len2);
    for ( i = len2; i && *p1 == *p2; i--, *p1++, *p2++ );
    if ( !i )
        return 0;
    if ( *p1 < *p2 )
        return -1;
    return 1;
}

static inline int tmh_tze_pfp_cmp(pfp_t *pfp1, pagesize_t pfp_len, void *tva, pagesize_t tze_len)
{
    const uint64_t *p1 = (uint64_t *)__map_domain_page(pfp1);
    const uint64_t *p2;
    pagesize_t i;

    if ( tze_len == PAGE_SIZE )
       p2 = (uint64_t *)__map_domain_page((pfp_t *)tva);
    else
       p2 = (uint64_t *)tva;
    ASSERT(pfp_len <= PAGE_SIZE);
    ASSERT(!(pfp_len & (sizeof(uint64_t)-1)));
    ASSERT(tze_len <= PAGE_SIZE);
    ASSERT(!(tze_len & (sizeof(uint64_t)-1)));
    if ( pfp_len < tze_len )
        return -1;
    if ( pfp_len > tze_len )
        return 1;
    ASSERT(pfp_len == tze_len);
    for ( i = tze_len/sizeof(uint64_t); i && *p1 == *p2; i--, *p1++, *p2++ );
    if ( !i )
        return 0;
    if ( *p1 < *p2 )
        return -1;
    return 1;
}

/* return the size of the data in the pfp, ignoring trailing zeroes and
 * rounded up to the nearest multiple of 8 */
static inline pagesize_t tmh_tze_pfp_scan(pfp_t *pfp)
{
    const uint64_t *p = (uint64_t *)__map_domain_page(pfp);
    pagesize_t bytecount = PAGE_SIZE;
    pagesize_t len = PAGE_SIZE/sizeof(uint64_t);
    p += len;
    while ( len-- && !*--p )
        bytecount -= sizeof(uint64_t);
    return bytecount;
}

static inline void tmh_tze_copy_from_pfp(void *tva, pfp_t *pfp, pagesize_t len)
{
    uint64_t *p1 = (uint64_t *)tva;
    const uint64_t *p2 = (uint64_t *)__map_domain_page(pfp);

    pagesize_t i;
    ASSERT(!(len & (sizeof(uint64_t)-1)));
    for ( i = len/sizeof(uint64_t); i--; *p1++ = *p2++);
}

/* these typedefs are in the public/tmem.h interface
typedef XEN_GUEST_HANDLE(void) cli_mfn_t;
typedef XEN_GUEST_HANDLE(char) cli_va_t;
*/
typedef XEN_GUEST_HANDLE(tmem_op_t) tmem_cli_op_t;

static inline int tmh_get_tmemop_from_client(tmem_op_t *op, tmem_cli_op_t uops)
{
#ifdef CONFIG_COMPAT
    if ( is_pv_32on64_vcpu(current) )
    {
        int rc;
        enum XLAT_tmem_op_u u;
        tmem_op_compat_t cop;

        rc = copy_from_guest(&cop, guest_handle_cast(uops, void), 1);
        if ( rc )
            return rc;
        switch ( cop.cmd )
        {
        case TMEM_NEW_POOL:   u = XLAT_tmem_op_u_new;   break;
        case TMEM_CONTROL:    u = XLAT_tmem_op_u_ctrl;  break;
        case TMEM_AUTH:       u = XLAT_tmem_op_u_new;   break;
        case TMEM_RESTORE_NEW:u = XLAT_tmem_op_u_new;   break;
        default:              u = XLAT_tmem_op_u_gen ;  break;
        }
#define XLAT_tmem_op_HNDL_u_ctrl_buf(_d_, _s_) \
        guest_from_compat_handle((_d_)->u.ctrl.buf, (_s_)->u.ctrl.buf)
        XLAT_tmem_op(op, &cop);
#undef XLAT_tmem_op_HNDL_u_ctrl_buf
        return 0;
    }
#endif
    return copy_from_guest(op, uops, 1);
}

static inline void tmh_copy_to_client_buf_offset(tmem_cli_va_t clibuf, int off,
                                           char *tmembuf, int len)
{
    copy_to_guest_offset(clibuf,off,tmembuf,len);
}

#define TMH_CLI_ID_NULL ((cli_id_t)((domid_t)-1L))

#define tmh_cli_id_str "domid"
#define tmh_client_str "domain"

extern int tmh_decompress_to_client(tmem_cli_mfn_t,void*,size_t,void*);

extern int tmh_compress_from_client(tmem_cli_mfn_t,void**,size_t *,void*);

extern int tmh_copy_from_client(pfp_t *pfp,
    tmem_cli_mfn_t cmfn, pagesize_t tmem_offset,
    pagesize_t pfn_offset, pagesize_t len, void *cva);

extern int tmh_copy_to_client(tmem_cli_mfn_t cmfn, pfp_t *pfp,
    pagesize_t tmem_offset, pagesize_t pfn_offset, pagesize_t len, void *cva);

extern int tmh_copy_tze_to_client(tmem_cli_mfn_t cmfn, void *tmem_va, pagesize_t len);


#define TMEM_PERF
#ifdef TMEM_PERF
#define DECL_CYC_COUNTER(x) \
    uint64_t x##_sum_cycles = 0, x##_count = 0; \
    uint32_t x##_min_cycles = 0x7fffffff, x##_max_cycles = 0;
#define EXTERN_CYC_COUNTER(x) \
    extern uint64_t x##_sum_cycles, x##_count; \
    extern uint32_t x##_min_cycles, x##_max_cycles;
#define DECL_LOCAL_CYC_COUNTER(x) \
    int64_t x##_start = 0
#define START_CYC_COUNTER(x) x##_start = get_cycles()
#define DUP_START_CYC_COUNTER(x,y) x##_start = y##_start
/* following might race, but since its advisory only, don't care */
#define END_CYC_COUNTER(x) \
    do { \
      x##_start = get_cycles() - x##_start; \
      if (x##_start > 0 && x##_start < 1000000000) { \
       x##_sum_cycles += x##_start; x##_count++; \
       if ((uint32_t)x##_start < x##_min_cycles) x##_min_cycles = x##_start; \
       if ((uint32_t)x##_start > x##_max_cycles) x##_max_cycles = x##_start; \
      } \
    } while (0)
#define END_CYC_COUNTER_CLI(x,y) \
    do { \
      x##_start = get_cycles() - x##_start; \
      if (x##_start > 0 && x##_start < 1000000000) { \
       x##_sum_cycles += x##_start; x##_count++; \
       if ((uint32_t)x##_start < x##_min_cycles) x##_min_cycles = x##_start; \
       if ((uint32_t)x##_start > x##_max_cycles) x##_max_cycles = x##_start; \
       y->total_cycles += x##_start; \
      } \
    } while (0)
#define RESET_CYC_COUNTER(x) { x##_sum_cycles = 0, x##_count = 0; \
  x##_min_cycles = 0x7fffffff, x##_max_cycles = 0; }
#define SCNPRINTF_CYC_COUNTER(buf,size,x,tag) \
  scnprintf(buf,size, \
  tag"n:%"PRIu64","tag"t:%"PRIu64","tag"x:%"PRId32","tag"m:%"PRId32",", \
  x##_count,x##_sum_cycles,x##_max_cycles,x##_min_cycles)
#else
#define DECL_CYC_COUNTER(x)
#define EXTERN_CYC_COUNTER(x) \
    extern uint64_t x##_sum_cycles, x##_count; \
    extern uint32_t x##_min_cycles, x##_max_cycles;
#define DECL_LOCAL_CYC_COUNTER(x) do { } while (0)
#define START_CYC_COUNTER(x) do { } while (0)
#define DUP_START_CYC_COUNTER(x) do { } while (0)
#define END_CYC_COUNTER(x) do { } while (0)
#define SCNPRINTF_CYC_COUNTER(buf,size,x,tag) (0)
#define RESET_CYC_COUNTER(x) do { } while (0)
#endif

#endif /* __XEN_TMEM_XEN_H__ */
