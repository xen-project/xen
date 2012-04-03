/******************************************************************************
 * tmem-xen.c
 *
 * Xen-specific Transcendent memory
 *
 * Copyright (c) 2009, Dan Magenheimer, Oracle Corp.
 */

#include <xen/tmem.h>
#include <xen/tmem_xen.h>
#include <xen/lzo.h> /* compression code */
#include <xen/paging.h>
#include <xen/domain_page.h>
#include <xen/cpu.h>
#include <xen/init.h>

#define EXPORT /* indicates code other modules are dependent upon */

EXPORT bool_t __read_mostly opt_tmem = 0;
boolean_param("tmem", opt_tmem);

EXPORT bool_t __read_mostly opt_tmem_compress = 0;
boolean_param("tmem_compress", opt_tmem_compress);

EXPORT bool_t __read_mostly opt_tmem_dedup = 0;
boolean_param("tmem_dedup", opt_tmem_dedup);

EXPORT bool_t __read_mostly opt_tmem_tze = 0;
boolean_param("tmem_tze", opt_tmem_tze);

EXPORT bool_t __read_mostly opt_tmem_shared_auth = 0;
boolean_param("tmem_shared_auth", opt_tmem_shared_auth);

EXPORT int __read_mostly opt_tmem_lock = 0;
integer_param("tmem_lock", opt_tmem_lock);

EXPORT atomic_t freeable_page_count = ATOMIC_INIT(0);

#ifdef COMPARE_COPY_PAGE_SSE2
DECL_CYC_COUNTER(pg_copy1);
DECL_CYC_COUNTER(pg_copy2);
DECL_CYC_COUNTER(pg_copy3);
DECL_CYC_COUNTER(pg_copy4);
#else
DECL_CYC_COUNTER(pg_copy);
#endif

/* these are a concurrency bottleneck, could be percpu and dynamically
 * allocated iff opt_tmem_compress */
#define LZO_WORKMEM_BYTES LZO1X_1_MEM_COMPRESS
#define LZO_DSTMEM_PAGES 2
static DEFINE_PER_CPU_READ_MOSTLY(unsigned char *, workmem);
static DEFINE_PER_CPU_READ_MOSTLY(unsigned char *, dstmem);

#ifdef COMPARE_COPY_PAGE_SSE2
#include <asm/flushtlb.h>  /* REMOVE ME AFTER TEST */
#include <asm/page.h>  /* REMOVE ME AFTER TEST */
#endif
void tmh_copy_page(char *to, char*from)
{
#ifdef COMPARE_COPY_PAGE_SSE2
    DECL_LOCAL_CYC_COUNTER(pg_copy1);
    DECL_LOCAL_CYC_COUNTER(pg_copy2);
    DECL_LOCAL_CYC_COUNTER(pg_copy3);
    DECL_LOCAL_CYC_COUNTER(pg_copy4);
    *to = *from;  /* don't measure TLB misses */
    flush_area_local(to,FLUSH_CACHE|FLUSH_ORDER(0));
    flush_area_local(from,FLUSH_CACHE|FLUSH_ORDER(0));
    START_CYC_COUNTER(pg_copy1);
    copy_page_sse2(to, from);  /* cold cache */
    END_CYC_COUNTER(pg_copy1);
    START_CYC_COUNTER(pg_copy2);
    copy_page_sse2(to, from);  /* hot cache */
    END_CYC_COUNTER(pg_copy2);
    flush_area_local(to,FLUSH_CACHE|FLUSH_ORDER(0));
    flush_area_local(from,FLUSH_CACHE|FLUSH_ORDER(0));
    START_CYC_COUNTER(pg_copy3);
    memcpy(to, from, PAGE_SIZE);  /* cold cache */
    END_CYC_COUNTER(pg_copy3);
    START_CYC_COUNTER(pg_copy4);
    memcpy(to, from, PAGE_SIZE); /* hot cache */
    END_CYC_COUNTER(pg_copy4);
#else
    DECL_LOCAL_CYC_COUNTER(pg_copy);
    START_CYC_COUNTER(pg_copy);
    memcpy(to, from, PAGE_SIZE);
    END_CYC_COUNTER(pg_copy);
#endif
}

#if defined(CONFIG_ARM)
static inline void *cli_get_page(tmem_cli_mfn_t cmfn, unsigned long *pcli_mfn,
                                 pfp_t **pcli_pfp, bool_t cli_write)
{
    ASSERT(0);
    return NULL;
}

static inline void cli_put_page(tmem_cli_mfn_t cmfn, void *cli_va, pfp_t *cli_pfp,
                                unsigned long cli_mfn, bool_t mark_dirty)
{
    ASSERT(0);
}
#else
#include <asm/p2m.h>

static inline void *cli_get_page(tmem_cli_mfn_t cmfn, unsigned long *pcli_mfn,
                                 pfp_t **pcli_pfp, bool_t cli_write)
{
    unsigned long cli_mfn;
    p2m_type_t t;
    struct page_info *page;
    int ret;

    cli_mfn = mfn_x(get_gfn(current->domain, cmfn, &t));
    if ( t != p2m_ram_rw || !mfn_valid(cli_mfn) )
    {
            put_gfn(current->domain, (unsigned long) cmfn);
            return NULL;
    }
    page = mfn_to_page(cli_mfn);
    if ( cli_write )
        ret = get_page_and_type(page, current->domain, PGT_writable_page);
    else
        ret = get_page(page, current->domain);
    if ( !ret )
    {
        put_gfn(current->domain, (unsigned long) cmfn);
        return NULL;
    }
    *pcli_mfn = cli_mfn;
    *pcli_pfp = (pfp_t *)page;
    return map_domain_page(cli_mfn);
}

static inline void cli_put_page(tmem_cli_mfn_t cmfn, void *cli_va, pfp_t *cli_pfp,
                                unsigned long cli_mfn, bool_t mark_dirty)
{
    if ( mark_dirty )
    {
        put_page_and_type((struct page_info *)cli_pfp);
        paging_mark_dirty(current->domain,cli_mfn);
    }
    else
        put_page((struct page_info *)cli_pfp);
    unmap_domain_page(cli_va);
    put_gfn(current->domain, (unsigned long) cmfn);
}
#endif

EXPORT int tmh_copy_from_client(pfp_t *pfp,
    tmem_cli_mfn_t cmfn, pagesize_t tmem_offset,
    pagesize_t pfn_offset, pagesize_t len, void *cli_va)
{
    unsigned long tmem_mfn, cli_mfn = 0;
    void *tmem_va;
    pfp_t *cli_pfp = NULL;
    bool_t tmemc = cli_va != NULL; /* if true, cli_va is control-op buffer */

    ASSERT(pfp != NULL);
    tmem_mfn = page_to_mfn(pfp);
    tmem_va = map_domain_page(tmem_mfn);
    if ( tmem_offset == 0 && pfn_offset == 0 && len == 0 )
    {
        memset(tmem_va, 0, PAGE_SIZE);
        unmap_domain_page(tmem_va);
        return 1;
    }
    if ( !tmemc )
    {
        cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 0);
        if ( cli_va == NULL )
            return -EFAULT;
    }
    mb();
    if (len == PAGE_SIZE && !tmem_offset && !pfn_offset)
        tmh_copy_page(tmem_va, cli_va);
    else if ( (tmem_offset+len <= PAGE_SIZE) &&
              (pfn_offset+len <= PAGE_SIZE) )
        memcpy((char *)tmem_va+tmem_offset,(char *)cli_va+pfn_offset,len);
    if ( !tmemc )
        cli_put_page(cmfn, cli_va, cli_pfp, cli_mfn, 0);
    unmap_domain_page(tmem_va);
    return 1;
}

EXPORT int tmh_compress_from_client(tmem_cli_mfn_t cmfn,
    void **out_va, size_t *out_len, void *cli_va)
{
    int ret = 0;
    unsigned char *dmem = this_cpu(dstmem);
    unsigned char *wmem = this_cpu(workmem);
    pfp_t *cli_pfp = NULL;
    unsigned long cli_mfn = 0;
    bool_t tmemc = cli_va != NULL; /* if true, cli_va is control-op buffer */

    if ( dmem == NULL || wmem == NULL )
        return 0;  /* no buffer, so can't compress */
    if ( !tmemc )
    {
        cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 0);
        if ( cli_va == NULL )
            return -EFAULT;
    }
    mb();
    ret = lzo1x_1_compress(cli_va, PAGE_SIZE, dmem, out_len, wmem);
    ASSERT(ret == LZO_E_OK);
    *out_va = dmem;
    if ( !tmemc )
        cli_put_page(cmfn, cli_va, cli_pfp, cli_mfn, 0);
    unmap_domain_page(cli_va);
    return 1;
}

EXPORT int tmh_copy_to_client(tmem_cli_mfn_t cmfn, pfp_t *pfp,
    pagesize_t tmem_offset, pagesize_t pfn_offset, pagesize_t len, void *cli_va)
{
    unsigned long tmem_mfn, cli_mfn = 0;
    void *tmem_va;
    pfp_t *cli_pfp = NULL;
    bool_t tmemc = cli_va != NULL; /* if true, cli_va is control-op buffer */

    ASSERT(pfp != NULL);
    if ( !tmemc )
    {
        cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 1);
        if ( cli_va == NULL )
            return -EFAULT;
    }
    tmem_mfn = page_to_mfn(pfp);
    tmem_va = map_domain_page(tmem_mfn);
    if (len == PAGE_SIZE && !tmem_offset && !pfn_offset)
        tmh_copy_page(cli_va, tmem_va);
    else if ( (tmem_offset+len <= PAGE_SIZE) && (pfn_offset+len <= PAGE_SIZE) )
        memcpy((char *)cli_va+pfn_offset,(char *)tmem_va+tmem_offset,len);
    unmap_domain_page(tmem_va);
    if ( !tmemc )
        cli_put_page(cmfn, cli_va, cli_pfp, cli_mfn, 1);
    mb();
    return 1;
}

EXPORT int tmh_decompress_to_client(tmem_cli_mfn_t cmfn, void *tmem_va,
                                    size_t size, void *cli_va)
{
    unsigned long cli_mfn = 0;
    pfp_t *cli_pfp = NULL;
    size_t out_len = PAGE_SIZE;
    bool_t tmemc = cli_va != NULL; /* if true, cli_va is control-op buffer */
    int ret;

    if ( !tmemc )
    {
        cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 1);
        if ( cli_va == NULL )
            return -EFAULT;
    }
    ret = lzo1x_decompress_safe(tmem_va, size, cli_va, &out_len);
    ASSERT(ret == LZO_E_OK);
    ASSERT(out_len == PAGE_SIZE);
    if ( !tmemc )
        cli_put_page(cmfn, cli_va, cli_pfp, cli_mfn, 1);
    mb();
    return 1;
}

EXPORT int tmh_copy_tze_to_client(tmem_cli_mfn_t cmfn, void *tmem_va,
                                    pagesize_t len)
{
    void *cli_va;
    unsigned long cli_mfn;
    pfp_t *cli_pfp = NULL;

    ASSERT(!(len & (sizeof(uint64_t)-1)));
    ASSERT(len <= PAGE_SIZE);
    ASSERT(len > 0 || tmem_va == NULL);
    cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 1);
    if ( cli_va == NULL )
        return -EFAULT;
    if ( len > 0 )
        memcpy((char *)cli_va,(char *)tmem_va,len);
    if ( len < PAGE_SIZE )
        memset((char *)cli_va+len,0,PAGE_SIZE-len);
    cli_put_page(cmfn, cli_va, cli_pfp, cli_mfn, 1);
    mb();
    return 1;
}

/******************  XEN-SPECIFIC MEMORY ALLOCATION ********************/

EXPORT struct xmem_pool *tmh_mempool = 0;
EXPORT unsigned int tmh_mempool_maxalloc = 0;

EXPORT DEFINE_SPINLOCK(tmh_page_list_lock);
EXPORT PAGE_LIST_HEAD(tmh_page_list);
EXPORT unsigned long tmh_page_list_pages = 0;

/* free anything on tmh_page_list to Xen's scrub list */
EXPORT void tmh_release_avail_pages_to_host(void)
{
    spin_lock(&tmh_page_list_lock);
    while ( !page_list_empty(&tmh_page_list) )
    {
        struct page_info *pg = page_list_remove_head(&tmh_page_list);
        scrub_one_page(pg);
        tmh_page_list_pages--;
        free_domheap_page(pg);
    }
    ASSERT(tmh_page_list_pages == 0);
    INIT_PAGE_LIST_HEAD(&tmh_page_list);
    spin_unlock(&tmh_page_list_lock);
}

EXPORT void tmh_scrub_page(struct page_info *pi, unsigned int memflags)
{
    if ( pi == NULL )
        return;
    if ( !(memflags & MEMF_tmem) )
        scrub_one_page(pi);
}

#ifndef __i386__
static noinline void *tmh_mempool_page_get(unsigned long size)
{
    struct page_info *pi;

    ASSERT(size == PAGE_SIZE);
    if ( (pi = tmh_alloc_page(NULL,0)) == NULL )
        return NULL;
    ASSERT(IS_VALID_PAGE(pi));
    return page_to_virt(pi);
}

static void tmh_mempool_page_put(void *page_va)
{
    ASSERT(IS_PAGE_ALIGNED(page_va));
    tmh_free_page(virt_to_page(page_va));
}

static int __init tmh_mempool_init(void)
{
    tmh_mempool = xmem_pool_create("tmem", tmh_mempool_page_get,
        tmh_mempool_page_put, PAGE_SIZE, 0, PAGE_SIZE);
    if ( tmh_mempool )
        tmh_mempool_maxalloc = xmem_pool_maxalloc(tmh_mempool);
    return tmh_mempool != NULL;
}

/* persistent pools are per-domain */

static void *tmh_persistent_pool_page_get(unsigned long size)
{
    struct page_info *pi;
    struct domain *d = current->domain;

    ASSERT(size == PAGE_SIZE);
    if ( (pi = _tmh_alloc_page_thispool(d)) == NULL )
        return NULL;
    ASSERT(IS_VALID_PAGE(pi));
    return __map_domain_page(pi);
}

static void tmh_persistent_pool_page_put(void *page_va)
{
    struct page_info *pi;

    ASSERT(IS_PAGE_ALIGNED(page_va));
    pi = virt_to_page(page_va);
    ASSERT(IS_VALID_PAGE(pi));
    _tmh_free_page_thispool(pi);
}
#endif

/******************  XEN-SPECIFIC CLIENT HANDLING ********************/

EXPORT tmh_client_t *tmh_client_init(cli_id_t cli_id)
{
    tmh_client_t *tmh;
    char name[5];
    int i, shift;

    if ( (tmh = xmalloc(tmh_client_t)) == NULL )
        return NULL;
    for (i = 0, shift = 12; i < 4; shift -=4, i++)
        name[i] = (((unsigned short)cli_id >> shift) & 0xf) + '0';
    name[4] = '\0';
#ifndef __i386__
    tmh->persistent_pool = xmem_pool_create(name, tmh_persistent_pool_page_get,
        tmh_persistent_pool_page_put, PAGE_SIZE, 0, PAGE_SIZE);
    if ( tmh->persistent_pool == NULL )
    {
        xfree(tmh);
        return NULL;
    }
#endif
    return tmh;
}

EXPORT void tmh_client_destroy(tmh_client_t *tmh)
{
    ASSERT(tmh->domain->is_dying);
#ifndef __i386__
    xmem_pool_destroy(tmh->persistent_pool);
#endif
    tmh->domain = NULL;
}

/******************  XEN-SPECIFIC HOST INITIALIZATION ********************/

#ifndef __i386__

static int dstmem_order, workmem_order;

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE: {
        if ( per_cpu(dstmem, cpu) == NULL )
        {
            struct page_info *p = alloc_domheap_pages(0, dstmem_order, 0);
            per_cpu(dstmem, cpu) = p ? page_to_virt(p) : NULL;
        }
        if ( per_cpu(workmem, cpu) == NULL )
        {
            struct page_info *p = alloc_domheap_pages(0, workmem_order, 0);
            per_cpu(workmem, cpu) = p ? page_to_virt(p) : NULL;
        }
        break;
    }
    case CPU_DEAD:
    case CPU_UP_CANCELED: {
        if ( per_cpu(dstmem, cpu) != NULL )
        {
            struct page_info *p = virt_to_page(per_cpu(dstmem, cpu));
            free_domheap_pages(p, dstmem_order);
            per_cpu(dstmem, cpu) = NULL;
        }
        if ( per_cpu(workmem, cpu) != NULL )
        {
            struct page_info *p = virt_to_page(per_cpu(workmem, cpu));
            free_domheap_pages(p, workmem_order);
            per_cpu(workmem, cpu) = NULL;
        }
        break;
    }
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

EXPORT int __init tmh_init(void)
{
    unsigned int cpu;

    if ( !tmh_mempool_init() )
        return 0;

    dstmem_order = get_order_from_pages(LZO_DSTMEM_PAGES);
    workmem_order = get_order_from_bytes(LZO1X_1_MEM_COMPRESS);

    for_each_online_cpu ( cpu )
    {
        void *hcpu = (void *)(long)cpu;
        cpu_callback(&cpu_nfb, CPU_UP_PREPARE, hcpu);
    }

    register_cpu_notifier(&cpu_nfb);

    return 1;
}

#else

EXPORT int __init tmh_init(void)
{
    return 1;
}

#endif
