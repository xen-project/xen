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
#include <xsm/xsm.h> /* xsm_tmem_control */
#include <public/tmem.h>
#ifdef CONFIG_COMPAT
#include <compat/tmem.h>
#endif

struct tmem_host_dependent_client {
    struct domain *domain;
    struct xmem_pool *persistent_pool;
};
typedef struct tmem_host_dependent_client tmem_client_t;

typedef uint32_t pagesize_t;  /* like size_t, must handle largest PAGE_SIZE */

#define IS_PAGE_ALIGNED(addr) \
  ((void *)((((unsigned long)addr + (PAGE_SIZE - 1)) & PAGE_MASK)) == addr)
#define IS_VALID_PAGE(_pi)  ( mfn_valid(page_to_mfn(_pi)) )

extern struct xmem_pool *tmem_mempool;
extern unsigned int tmem_mempool_maxalloc;
extern struct page_list_head tmem_page_list;
extern spinlock_t tmem_page_list_lock;
extern unsigned long tmem_page_list_pages;
extern atomic_t freeable_page_count;

extern spinlock_t tmem_lock;
extern spinlock_t tmem_spinlock;
extern rwlock_t tmem_rwlock;

extern void tmem_copy_page(char *to, char*from);
extern int tmem_init(void);
#define tmem_hash hash_long

extern void tmem_release_avail_pages_to_host(void);
extern void tmem_scrub_page(struct page_info *pi, unsigned int memflags);

extern bool_t opt_tmem_compress;
static inline bool_t tmem_compression_enabled(void)
{
    return opt_tmem_compress;
}

extern bool_t opt_tmem_dedup;
static inline bool_t tmem_dedup_enabled(void)
{
    return opt_tmem_dedup;
}

extern bool_t opt_tmem_tze;
static inline bool_t tmem_tze_enabled(void)
{
    return opt_tmem_tze;
}

static inline void tmem_tze_disable(void)
{
    opt_tmem_tze = 0;
}

extern bool_t opt_tmem_shared_auth;
static inline bool_t tmem_shared_auth(void)
{
    return opt_tmem_shared_auth;
}

extern bool_t opt_tmem;
static inline bool_t tmem_enabled(void)
{
    return opt_tmem;
}

extern int opt_tmem_lock;

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

static inline bool_t domain_fully_allocated(struct domain *d)
{
    return ( d->tot_pages >= d->max_pages );
}
#define tmem_client_memory_fully_allocated(_pool) \
 domain_fully_allocated(_pool->client->tmem->domain)

static inline void *_tmem_alloc_subpage_thispool(struct xmem_pool *cmem_mempool,
                                                 size_t size, size_t align)
{
#if 0
    if ( d->tot_pages >= d->max_pages )
        return NULL;
#endif
    ASSERT( size < tmem_mempool_maxalloc );
    if ( cmem_mempool == NULL )
        return NULL;
    return xmem_pool_alloc(size, cmem_mempool);
}
#define tmem_alloc_subpage_thispool(_pool, _s, _a) \
            _tmem_alloc_subpage_thispool(pool->client->tmem->persistent_pool, \
                                         _s, _a)

static inline void _tmem_free_subpage_thispool(struct xmem_pool *cmem_mempool,
                                               void *ptr, size_t size)
{
    ASSERT( size < tmem_mempool_maxalloc );
    ASSERT( cmem_mempool != NULL );
    xmem_pool_free(ptr,cmem_mempool);
}
#define tmem_free_subpage_thispool(_pool, _p, _s) \
 _tmem_free_subpage_thispool(_pool->client->tmem->persistent_pool, _p, _s)

static inline struct page_info *_tmem_alloc_page_thispool(struct domain *d)
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
#define tmem_alloc_page_thispool(_pool) \
    _tmem_alloc_page_thispool(_pool->client->tmem->domain)

static inline void _tmem_free_page_thispool(struct page_info *pi)
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
#define tmem_free_page_thispool(_pool,_pg) \
    _tmem_free_page_thispool(_pg)

/*
 * Memory allocation for ephemeral (non-persistent) data
 */

static inline void *tmem_alloc_subpage(void *pool, size_t size,
                                                 size_t align)
{
    ASSERT( size < tmem_mempool_maxalloc );
    ASSERT( tmem_mempool != NULL );
    return xmem_pool_alloc(size, tmem_mempool);
}

static inline void tmem_free_subpage(void *ptr, size_t size)
{
    ASSERT( size < tmem_mempool_maxalloc );
    xmem_pool_free(ptr,tmem_mempool);
}

static inline struct page_info *tmem_alloc_page(void *pool, int no_heap)
{
    struct page_info *pi = tmem_page_list_get();

    if ( pi == NULL && !no_heap )
        pi = alloc_domheap_pages(0,0,MEMF_tmem);
    ASSERT((pi == NULL) || IS_VALID_PAGE(pi));
    if ( pi != NULL && !no_heap )
        atomic_inc(&freeable_page_count);
    return pi;
}

static inline void tmem_free_page(struct page_info *pi)
{
    ASSERT(IS_VALID_PAGE(pi));
    tmem_page_list_put(pi);
    atomic_dec(&freeable_page_count);
}

static inline unsigned int tmem_subpage_maxsize(void)
{
    return tmem_mempool_maxalloc;
}

static inline unsigned long tmem_free_mb(void)
{
    return (tmem_page_list_pages + total_free_pages()) >> (20 - PAGE_SHIFT);
}

#define tmem_lock_all  opt_tmem_lock
#define tmem_called_from_tmem(_memflags) (_memflags & MEMF_tmem)

/*  "Client" (==domain) abstraction */

struct client;

extern tmem_client_t *tmem_client_init(domid_t);
extern void tmem_client_destroy(tmem_client_t *);

static inline struct client *tmem_client_from_cli_id(domid_t cli_id)
{
    struct client *c;
    struct domain *d = rcu_lock_domain_by_id(cli_id);
    if (d == NULL)
        return NULL;
    c = (struct client *)(d->tmem);
    rcu_unlock_domain(d);
    return c;
}

static inline struct client *tmem_client_from_current(void)
{
    return (struct client *)(current->domain->tmem);
}

#define tmem_client_is_dying(_client) (!!_client->tmem->domain->is_dying)

static inline domid_t tmem_get_cli_id_from_current(void)
{
    return current->domain->domain_id;
}

static inline struct domain *tmem_get_cli_ptr_from_current(void)
{
    return current->domain;
}

static inline bool_t tmem_set_client_from_id(
    struct client *client, tmem_client_t *tmem, domid_t cli_id)
{
    struct domain *d = rcu_lock_domain_by_id(cli_id);
    bool_t rc = 0;
    if ( d == NULL )
        return 0;
    if ( !d->is_dying )
    {
        d->tmem = client;
        tmem->domain = d;
        rc = 1;
    }
    rcu_unlock_domain(d);
    return rc;
}

static inline bool_t tmem_current_permitted(void)
{
    return !xsm_tmem_op(XSM_HOOK);
}

static inline bool_t tmem_current_is_privileged(void)
{
    return !xsm_tmem_control(XSM_PRIV);
}

static inline uint8_t tmem_get_first_byte(struct page_info *pfp)
{
    void *p = __map_domain_page(pfp);

    return (uint8_t)(*(char *)p);
}

static inline int tmem_page_cmp(struct page_info *pfp1, struct page_info *pfp2)
{
    const uint64_t *p1 = (uint64_t *)__map_domain_page(pfp1);
    const uint64_t *p2 = (uint64_t *)__map_domain_page(pfp2);
    int i;

    // FIXME: code in assembly?
ASSERT(p1 != NULL);
ASSERT(p2 != NULL);
    for ( i = PAGE_SIZE/sizeof(uint64_t); i && *p1 == *p2; i--, p1++, p2++ );
    if ( !i )
        return 0;
    if ( *p1 < *p2 )
        return -1;
    return 1;
}

static inline int tmem_pcd_cmp(void *va1, pagesize_t len1, void *va2, pagesize_t len2)
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
    for ( i = len2; i && *p1 == *p2; i--, p1++, p2++ );
    if ( !i )
        return 0;
    if ( *p1 < *p2 )
        return -1;
    return 1;
}

static inline int tmem_tze_pfp_cmp(struct page_info *pfp1, pagesize_t pfp_len, void *tva, pagesize_t tze_len)
{
    const uint64_t *p1 = (uint64_t *)__map_domain_page(pfp1);
    const uint64_t *p2;
    pagesize_t i;

    if ( tze_len == PAGE_SIZE )
       p2 = (uint64_t *)__map_domain_page((struct page_info *)tva);
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
    for ( i = tze_len/sizeof(uint64_t); i && *p1 == *p2; i--, p1++, p2++ );
    if ( !i )
        return 0;
    if ( *p1 < *p2 )
        return -1;
    return 1;
}

/* return the size of the data in the pfp, ignoring trailing zeroes and
 * rounded up to the nearest multiple of 8 */
static inline pagesize_t tmem_tze_pfp_scan(struct page_info *pfp)
{
    const uint64_t *p = (uint64_t *)__map_domain_page(pfp);
    pagesize_t bytecount = PAGE_SIZE;
    pagesize_t len = PAGE_SIZE/sizeof(uint64_t);
    p += len;
    while ( len-- && !*--p )
        bytecount -= sizeof(uint64_t);
    return bytecount;
}

static inline void tmem_tze_copy_from_pfp(void *tva, struct page_info *pfp, pagesize_t len)
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
typedef XEN_GUEST_HANDLE_PARAM(tmem_op_t) tmem_cli_op_t;
typedef XEN_GUEST_HANDLE_PARAM(char) tmem_cli_va_param_t;

static inline int tmem_get_tmemop_from_client(tmem_op_t *op, tmem_cli_op_t uops)
{
#ifdef CONFIG_COMPAT
    if ( is_hvm_vcpu(current) ?
         hvm_guest_x86_mode(current) != 8 :
         is_pv_32on64_vcpu(current) )
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
        case TMEM_CONTROL:    u = XLAT_tmem_op_u_ctrl;  break;
        case TMEM_AUTH:       u = XLAT_tmem_op_u_creat; break;
        case TMEM_RESTORE_NEW:u = XLAT_tmem_op_u_creat; break;
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

#define tmem_cli_buf_null guest_handle_from_ptr(NULL, char)

static inline void tmem_copy_to_client_buf_offset(tmem_cli_va_param_t clibuf,
						 int off,
						 char *tmembuf, int len)
{
    copy_to_guest_offset(clibuf,off,tmembuf,len);
}

#define tmem_copy_to_client_buf(clibuf, tmembuf, cnt) \
    copy_to_guest(guest_handle_cast(clibuf, void), tmembuf, cnt)

#define tmem_client_buf_add guest_handle_add_offset

#define TMEM_CLI_ID_NULL ((domid_t)((domid_t)-1L))

#define tmem_cli_id_str "domid"
#define tmem_client_str "domain"

int tmem_decompress_to_client(xen_pfn_t, void *, size_t,
			     tmem_cli_va_param_t);

int tmem_compress_from_client(xen_pfn_t, void **, size_t *,
			     tmem_cli_va_param_t);

int tmem_copy_from_client(struct page_info *, xen_pfn_t, pagesize_t tmem_offset,
    pagesize_t pfn_offset, pagesize_t len, tmem_cli_va_param_t);

int tmem_copy_to_client(xen_pfn_t, struct page_info *, pagesize_t tmem_offset,
    pagesize_t pfn_offset, pagesize_t len, tmem_cli_va_param_t);

extern int tmem_copy_tze_to_client(xen_pfn_t cmfn, void *tmem_va, pagesize_t len);

#define tmem_client_err(fmt, args...)  printk(XENLOG_G_ERR fmt, ##args)
#define tmem_client_warn(fmt, args...) printk(XENLOG_G_WARNING fmt, ##args)
#define tmem_client_info(fmt, args...) printk(XENLOG_G_INFO fmt, ##args)

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
