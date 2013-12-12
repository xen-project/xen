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

bool_t __read_mostly opt_tmem = 0;
boolean_param("tmem", opt_tmem);

bool_t __read_mostly opt_tmem_compress = 0;
boolean_param("tmem_compress", opt_tmem_compress);

bool_t __read_mostly opt_tmem_dedup = 0;
boolean_param("tmem_dedup", opt_tmem_dedup);

bool_t __read_mostly opt_tmem_tze = 0;
boolean_param("tmem_tze", opt_tmem_tze);

bool_t __read_mostly opt_tmem_shared_auth = 0;
boolean_param("tmem_shared_auth", opt_tmem_shared_auth);

atomic_t freeable_page_count = ATOMIC_INIT(0);

/* these are a concurrency bottleneck, could be percpu and dynamically
 * allocated iff opt_tmem_compress */
#define LZO_WORKMEM_BYTES LZO1X_1_MEM_COMPRESS
#define LZO_DSTMEM_PAGES 2
static DEFINE_PER_CPU_READ_MOSTLY(unsigned char *, workmem);
static DEFINE_PER_CPU_READ_MOSTLY(unsigned char *, dstmem);
static DEFINE_PER_CPU_READ_MOSTLY(void *, scratch_page);

#if defined(CONFIG_ARM)
static inline void *cli_get_page(xen_pfn_t cmfn, unsigned long *pcli_mfn,
                                 struct page_info **pcli_pfp, bool_t cli_write)
{
    ASSERT(0);
    return NULL;
}

static inline void cli_put_page(void *cli_va, struct page_info *cli_pfp,
                                unsigned long cli_mfn, bool_t mark_dirty)
{
    ASSERT(0);
}
#else
#include <asm/p2m.h>

static inline void *cli_get_page(xen_pfn_t cmfn, unsigned long *pcli_mfn,
                                 struct page_info **pcli_pfp, bool_t cli_write)
{
    p2m_type_t t;
    struct page_info *page;

    page = get_page_from_gfn(current->domain, cmfn, &t, P2M_ALLOC);
    if ( !page || t != p2m_ram_rw )
    {
        if ( page )
            put_page(page);
        return NULL;
    }

    if ( cli_write && !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        return NULL;
    }

    *pcli_mfn = page_to_mfn(page);
    *pcli_pfp = page;
    return map_domain_page(*pcli_mfn);
}

static inline void cli_put_page(void *cli_va, struct page_info *cli_pfp,
                                unsigned long cli_mfn, bool_t mark_dirty)
{
    if ( mark_dirty )
    {
        put_page_and_type(cli_pfp);
        paging_mark_dirty(current->domain,cli_mfn);
    }
    else
        put_page(cli_pfp);
    unmap_domain_page(cli_va);
}
#endif

int tmem_copy_from_client(struct page_info *pfp,
    xen_pfn_t cmfn, tmem_cli_va_param_t clibuf)
{
    unsigned long tmem_mfn, cli_mfn = 0;
    char *tmem_va, *cli_va = NULL;
    struct page_info *cli_pfp = NULL;
    int rc = 1;

    ASSERT(pfp != NULL);
    tmem_mfn = page_to_mfn(pfp);
    tmem_va = map_domain_page(tmem_mfn);
    if ( guest_handle_is_null(clibuf) )
    {
        cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 0);
        if ( cli_va == NULL )
        {
            unmap_domain_page(tmem_va);
            return -EFAULT;
        }
    }
    smp_mb();
    if ( cli_va )
    {
        memcpy(tmem_va, cli_va, PAGE_SIZE);
        cli_put_page(cli_va, cli_pfp, cli_mfn, 0);
    }
    else
        rc = -EINVAL;
    unmap_domain_page(tmem_va);
    return rc;
}

int tmem_compress_from_client(xen_pfn_t cmfn,
    void **out_va, size_t *out_len, tmem_cli_va_param_t clibuf)
{
    int ret = 0;
    unsigned char *dmem = this_cpu(dstmem);
    unsigned char *wmem = this_cpu(workmem);
    char *scratch = this_cpu(scratch_page);
    struct page_info *cli_pfp = NULL;
    unsigned long cli_mfn = 0;
    void *cli_va = NULL;

    if ( dmem == NULL || wmem == NULL )
        return 0;  /* no buffer, so can't compress */
    if ( guest_handle_is_null(clibuf) )
    {
        cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 0);
        if ( cli_va == NULL )
            return -EFAULT;
    }
    else if ( !scratch )
        return 0;
    else if ( copy_from_guest(scratch, clibuf, PAGE_SIZE) )
        return -EFAULT;
    smp_mb();
    ret = lzo1x_1_compress(cli_va ?: scratch, PAGE_SIZE, dmem, out_len, wmem);
    ASSERT(ret == LZO_E_OK);
    *out_va = dmem;
    if ( cli_va )
        cli_put_page(cli_va, cli_pfp, cli_mfn, 0);
    return 1;
}

int tmem_copy_to_client(xen_pfn_t cmfn, struct page_info *pfp,
    tmem_cli_va_param_t clibuf)
{
    unsigned long tmem_mfn, cli_mfn = 0;
    char *tmem_va, *cli_va = NULL;
    struct page_info *cli_pfp = NULL;
    int rc = 1;

    ASSERT(pfp != NULL);
    if ( guest_handle_is_null(clibuf) )
    {
        cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 1);
        if ( cli_va == NULL )
            return -EFAULT;
    }
    tmem_mfn = page_to_mfn(pfp);
    tmem_va = map_domain_page(tmem_mfn);
    if ( cli_va )
    {
        memcpy(cli_va, tmem_va, PAGE_SIZE);
        cli_put_page(cli_va, cli_pfp, cli_mfn, 1);
    }
    else
        rc = -EINVAL;
    unmap_domain_page(tmem_va);
    smp_mb();
    return rc;
}

int tmem_decompress_to_client(xen_pfn_t cmfn, void *tmem_va,
                                    size_t size, tmem_cli_va_param_t clibuf)
{
    unsigned long cli_mfn = 0;
    struct page_info *cli_pfp = NULL;
    void *cli_va = NULL;
    char *scratch = this_cpu(scratch_page);
    size_t out_len = PAGE_SIZE;
    int ret;

    if ( guest_handle_is_null(clibuf) )
    {
        cli_va = cli_get_page(cmfn, &cli_mfn, &cli_pfp, 1);
        if ( cli_va == NULL )
            return -EFAULT;
    }
    else if ( !scratch )
        return 0;
    ret = lzo1x_decompress_safe(tmem_va, size, cli_va ?: scratch, &out_len);
    ASSERT(ret == LZO_E_OK);
    ASSERT(out_len == PAGE_SIZE);
    if ( cli_va )
        cli_put_page(cli_va, cli_pfp, cli_mfn, 1);
    else if ( copy_to_guest(clibuf, scratch, PAGE_SIZE) )
        return -EFAULT;
    smp_mb();
    return 1;
}

int tmem_copy_tze_to_client(xen_pfn_t cmfn, void *tmem_va,
                                    pagesize_t len)
{
    void *cli_va;
    unsigned long cli_mfn;
    struct page_info *cli_pfp = NULL;

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
    cli_put_page(cli_va, cli_pfp, cli_mfn, 1);
    smp_mb();
    return 1;
}

/******************  XEN-SPECIFIC HOST INITIALIZATION ********************/
static int dstmem_order, workmem_order;

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE: {
        if ( per_cpu(dstmem, cpu) == NULL )
            per_cpu(dstmem, cpu) = alloc_xenheap_pages(dstmem_order, 0);
        if ( per_cpu(workmem, cpu) == NULL )
            per_cpu(workmem, cpu) = alloc_xenheap_pages(workmem_order, 0);
        if ( per_cpu(scratch_page, cpu) == NULL )
            per_cpu(scratch_page, cpu) = alloc_xenheap_page();
        break;
    }
    case CPU_DEAD:
    case CPU_UP_CANCELED: {
        if ( per_cpu(dstmem, cpu) != NULL )
        {
            free_xenheap_pages(per_cpu(dstmem, cpu), dstmem_order);
            per_cpu(dstmem, cpu) = NULL;
        }
        if ( per_cpu(workmem, cpu) != NULL )
        {
            free_xenheap_pages(per_cpu(workmem, cpu), workmem_order);
            per_cpu(workmem, cpu) = NULL;
        }
        if ( per_cpu(scratch_page, cpu) != NULL )
        {
            free_xenheap_page(per_cpu(scratch_page, cpu));
            per_cpu(scratch_page, cpu) = NULL;
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

int __init tmem_init(void)
{
    unsigned int cpu;

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
