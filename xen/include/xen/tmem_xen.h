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
typedef uint32_t pagesize_t;  /* like size_t, must handle largest PAGE_SIZE */

#define IS_PAGE_ALIGNED(addr) \
  ((void *)((((unsigned long)addr + (PAGE_SIZE - 1)) & PAGE_MASK)) == addr)
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

static inline uint8_t tmem_get_first_byte(struct page_info *pfp)
{
    const uint8_t *p = __map_domain_page(pfp);
    uint8_t byte = p[0];

    unmap_domain_page(p);

    return byte;
}

static inline int tmem_page_cmp(struct page_info *pfp1, struct page_info *pfp2)
{
    const uint64_t *p1 = __map_domain_page(pfp1);
    const uint64_t *p2 = __map_domain_page(pfp2);
    int rc = memcmp(p1, p2, PAGE_SIZE);

    unmap_domain_page(p2);
    unmap_domain_page(p1);

    return rc;
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

static inline int tmem_tze_pfp_cmp(struct page_info *pfp1, pagesize_t pfp_len,
                                   void *tva, const pagesize_t tze_len)
{
    const uint64_t *p1 = __map_domain_page(pfp1);
    const uint64_t *p2 = tze_len == PAGE_SIZE ?
        __map_domain_page((struct page_info *)tva) : tva;
    int rc;

    ASSERT(pfp_len <= PAGE_SIZE);
    ASSERT(!(pfp_len & (sizeof(uint64_t)-1)));
    ASSERT(tze_len <= PAGE_SIZE);
    ASSERT(!(tze_len & (sizeof(uint64_t)-1)));
    if ( pfp_len < tze_len )
        rc = -1;
    else if ( pfp_len > tze_len )
        rc = 1;
    else
        rc = memcmp(p1, p2, tze_len);

    if ( tze_len == PAGE_SIZE )
        unmap_domain_page(p2);
    unmap_domain_page(p1);

    return rc;
}

/* return the size of the data in the pfp, ignoring trailing zeroes and
 * rounded up to the nearest multiple of 8 */
static inline pagesize_t tmem_tze_pfp_scan(struct page_info *pfp)
{
    const uint64_t *const page = __map_domain_page(pfp);
    const uint64_t *p = page;
    pagesize_t bytecount = PAGE_SIZE;
    pagesize_t len = PAGE_SIZE/sizeof(uint64_t);

    p += len;
    while ( len-- && !*--p )
        bytecount -= sizeof(uint64_t);

    unmap_domain_page(page);

    return bytecount;
}

static inline void tmem_tze_copy_from_pfp(void *tva, struct page_info *pfp, pagesize_t len)
{
    const uint64_t *p = __map_domain_page(pfp);

    ASSERT(!(len & (sizeof(uint64_t)-1)));
    memcpy(tva, p, len);

    unmap_domain_page(p);
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
#define TMEM_CLI_ID_NULL ((domid_t)((domid_t)-1L))
#define tmem_cli_id_str "domid"
#define tmem_client_str "domain"

int tmem_decompress_to_client(xen_pfn_t, void *, size_t,
			     tmem_cli_va_param_t);
int tmem_compress_from_client(xen_pfn_t, void **, size_t *,
			     tmem_cli_va_param_t);

int tmem_copy_from_client(struct page_info *, xen_pfn_t, tmem_cli_va_param_t);
int tmem_copy_to_client(xen_pfn_t, struct page_info *, tmem_cli_va_param_t);
extern int tmem_copy_tze_to_client(xen_pfn_t cmfn, void *tmem_va, pagesize_t len);

#define tmem_client_err(fmt, args...)  printk(XENLOG_G_ERR fmt, ##args)
#define tmem_client_warn(fmt, args...) printk(XENLOG_G_WARNING fmt, ##args)
#define tmem_client_info(fmt, args...) printk(XENLOG_G_INFO fmt, ##args)

#endif /* __XEN_TMEM_XEN_H__ */
