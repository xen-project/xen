#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <xendevicemodel.h>
#include <xenforeignmemory.h>
#include <xengnttab.h>
#include <xen-tools/common-macros.h>

static unsigned int nr_failures;
#define fail(fmt, ...)                          \
({                                              \
    nr_failures++;                              \
    (void)printf(fmt, ##__VA_ARGS__);           \
    -1;                                         \
})

static xc_interface *xch;
static xendevicemodel_handle *dh;
static xenforeignmemory_handle *fh;
static uint32_t domid = DOMID_ANY;

static struct xen_domctl_createdomain create = {
    .flags = (XEN_DOMCTL_CDF_hvm |
              XEN_DOMCTL_CDF_hap |
              XEN_DOMCTL_CDF_iommu |
              0),
    .max_vcpus = 1,
    .max_grant_frames = 1,
    .grant_opts = XEN_DOMCTL_GRANT_version(1),

    .arch = {
#if defined(__x86_64__) || defined(__i386__)
        .emulation_flags = XEN_X86_EMU_LAPIC,
#endif
    },
};

static uint64_t default_mempool_size_bytes =
#if defined(__x86_64__) || defined(__i386__)
    256 << 12; /* Only x86 HAP for now.  x86 Shadow needs more work. */
#elif defined (__arm__) || defined(__aarch64__)
    16 << 12;
#endif

static int test_paging_mempool_size(void)
{
    xen_pfn_t physmap[] = { 0 };
    uint64_t size_bytes, old_size_bytes;
    int rc;

    printf("Test default mempool size\n");

    rc = xc_get_paging_mempool_size(xch, domid, &size_bytes);
    if ( rc )
        return fail("  Fail: get mempool size: %d - %s\n",
                    errno, strerror(errno));

    printf("mempool size %"PRIu64" bytes (%"PRIu64"kB, %"PRIu64"MB)\n",
           size_bytes, size_bytes >> 10, size_bytes >> 20);


    /*
     * Check that the domain has the expected default allocation size.  This
     * will fail if the logic in Xen is altered without an equivalent
     * adjustment here.
     */
    if ( size_bytes != default_mempool_size_bytes )
        return fail("  Fail: size %"PRIu64" != expected size %"PRIu64"\n",
                    size_bytes, default_mempool_size_bytes);


    printf("Test that allocate doesn't alter pool size\n");

    /*
     * Populate the domain with some RAM.  This will cause more of the mempool
     * to be used.
     */
    old_size_bytes = size_bytes;

    rc = xc_domain_setmaxmem(xch, domid, -1);
    if ( rc )
        return fail("  Fail: setmaxmem: : %d - %s\n",
                    errno, strerror(errno));

    rc = xc_domain_populate_physmap_exact(
        xch, domid, ARRAY_SIZE(physmap),
        0 /* order 4k */, 0 /* flags */, physmap);
    if ( rc )
        return fail("  Fail: populate physmap: %d - %s\n",
                    errno, strerror(errno));

    /*
     * Re-get the p2m size.  Should not have changed as a consequence of
     * populate physmap.
     */
    rc = xc_get_paging_mempool_size(xch, domid, &size_bytes);
    if ( rc )
        return fail("  Fail: get mempool size: %d - %s\n",
                    errno, strerror(errno));

    if ( old_size_bytes != size_bytes )
        return fail("  Fail: mempool size changed %"PRIu64" => %"PRIu64"\n",
                    old_size_bytes, size_bytes);

    /* We added one 4k page.  Check we can remove it. */
    rc = xc_domain_remove_from_physmap(xch, domid, physmap[0]);
    if ( rc )
        return fail("  Fail: remove from physmap: %d - %s\n",
                    errno, strerror(errno));


    printf("Test bad set size\n");

    /*
     * Check that setting a non-page size results in failure.
     */
    rc = xc_set_paging_mempool_size(xch, domid, size_bytes + 1);
    if ( rc != -1 || errno != EINVAL )
        return fail("  Fail: Bad set size: expected -1/EINVAL, got %d/%d - %s\n",
                    rc, errno, strerror(errno));


    printf("Test set continuation\n");

    /*
     * Check that setting a large P2M size succeeds.  This is expecting to
     * trigger continuations.
     */
    rc = xc_set_paging_mempool_size(xch, domid, 64 << 20);
    if ( rc )
        return fail("  Fail: Set size 64MB: %d - %s\n",
                    errno, strerror(errno));


    /*
     * Check that the reported size matches what set consumed.
     */
    rc = xc_get_paging_mempool_size(xch, domid, &size_bytes);
    if ( rc )
        return fail("  Fail: get p2m mempool size: %d - %s\n",
                    errno, strerror(errno));

    if ( size_bytes != 64 << 20 )
        return fail("  Fail: expected mempool size %u, got %"PRIu64"\n",
                    64 << 20, size_bytes);

    return 0;
}

static int mark_guest_mem(xen_pfn_t gfn, size_t count)
{
    xen_pfn_t gfns[count];
    uint32_t *mem;
    size_t i;
    int rc;

    for ( i = 0; i < count; ++i )
        gfns[i] = gfn + i;

    mem = xenforeignmemory_map(fh, domid, PROT_READ | PROT_WRITE,
                               count, gfns, NULL);
    if ( !mem )
        return fail("  Fail: mark mem foreign map: %d - %s\n",
                    errno, strerror(errno));

    for ( i = 0; i < count; ++i )
    {
        uint32_t *mark = &mem[i << 10];

        *mark = ~i;
    }

    rc = xenforeignmemory_unmap(fh, mem, count);
    if ( rc )
        return fail("  Fail: mark mem foreign unmap: %d - %s\n",
                    errno, strerror(errno));

    return 0;
}

static int check_guest_marks(xen_pfn_t gfn, uint32_t mark_start, size_t count)
{
    xen_pfn_t gfns[count];
    int errs[count];
    uint32_t *mem;
    size_t i;
    int rc = 0;

    for ( i = 0; i < count; ++i )
        gfns[i] = gfn + i;

    mem = xenforeignmemory_map(fh, domid, PROT_READ,
                               count, gfns, errs);
    if ( !mem )
        return fail("    Fail: check mark foreign map: %d - %s\n",
                    errno, strerror(errno));

    for ( i = 0; i < count; ++i )
    {
        uint32_t *mark = &mem[i << 10];
        uint32_t exp = ~(mark_start + i);

        if ( errs[i] )
        {
            rc = -1;
            fail("    Fail: check mark unable to map gfn %05lx: %d\n",
                 gfns[i], errs[i]);
            continue;
        }

        if ( *mark == exp )
            continue;

        fail("    Fail: check mark: gfn %05lx expecting %08x (%u), got %08x (%u)\n",
               gfns[i], exp, ~exp, *mark, ~*mark);
        rc = -1;
    }

    if ( xenforeignmemory_unmap(fh, mem, count) )
        return fail("    Fail: check marks foreign unmap: %d - %s\n",
                    errno, strerror(errno));

    return rc;
}

static int test_p2m_relocate_memory(void)
{
#define GFN_2M ((2UL << 20) >> 12)
#define GFN_4M ((4UL << 20) >> 12)

    xen_pfn_t physmap[] = { GFN_2M };
    int rc;

    /*
     * Inherited state of the domain:
     * - Unlimited allocation
     * - XEN_DOMCTL_CDF_iommu, which causes xendevicemodel_relocate_memory()
     *   to undergo continuations every 16 pages
     *
     * Construction of the test:
     * - Populate 2M at 2M, mark the pages.
     */
    printf("Test p2m memory relocation\n");

    rc = xc_domain_populate_physmap_exact(
        xch, domid, ARRAY_SIZE(physmap),
        9 /* order 2M */, 0 /* flags */, physmap);
    if ( rc )
        return fail("  Fail: populate physmap: %d - %s\n",
                    errno, strerror(errno));

    rc = mark_guest_mem(GFN_2M, 1 << 9 /* order 2M */);
    if ( rc )
        return rc;

    /* Sanity check the start and end markers. */
    if ( (rc = check_guest_marks(GFN_2M,     0,       8)) ||
         (rc = check_guest_marks(GFN_4M - 8, 512 - 8, 8)) )
        return rc;


#define GFN_PAIR(g, c) (g), ((g) + (c) - 1)

    /*
     * Move the final 32 pages below 4M forward by 32 pages.  All destination
     * GFNs free, and no overlap.
     */
    printf("  Test forward, no overlap:    GFNs [%lx...%lx] -> [%lx...%lx]\n",
           GFN_PAIR(GFN_4M - 32, 32), GFN_PAIR(GFN_4M, 32));

    rc = xendevicemodel_relocate_memory(dh, domid, 32, GFN_4M - 32, GFN_4M);
    if ( rc )
        return fail("  Fail: relocate memory: %d - %s\n",
                    errno, strerror(errno));

    rc = check_guest_marks(GFN_4M, 512 - 32, 32);
    if ( rc )
        return rc;

    /*
     * Move the next 32 pages below 4M forward by 1 page.  The region is
     * almost completely overlapping.
     */
    printf("  Test forward, overlapping:   GFNs [%lx...%lx] -> [%lx...%lx]\n",
           GFN_PAIR(GFN_4M - 64, 32), GFN_PAIR(GFN_4M - 63, 32));

    rc = xendevicemodel_relocate_memory(dh, domid, 32, GFN_4M - 64, GFN_4M - 63);
    if ( rc )
        return fail("  Fail: relocate memory: %d - %s\n",
                    errno, strerror(errno));

    rc = check_guest_marks(GFN_4M - 63, 512 - 64, 32);
    if ( rc )
        return rc;

    /*
     * Move the first 32 pages above 2M backwards by 32 pages.  All
     * destination GFNs free, and no overlap.
     */
    printf("  Test backwards, no overlap:  GFNs [%lx...%lx] -> [%lx...%lx]\n",
           GFN_PAIR(GFN_2M, 32), GFN_PAIR(GFN_2M - 32, 32));

    rc = xendevicemodel_relocate_memory(dh, domid, 32, GFN_2M, GFN_2M - 32);
    if ( rc )
        return fail("  Fail: relocate memory: %d - %s\n",
                    errno, strerror(errno));

    rc = check_guest_marks(GFN_2M - 32, 0, 32);
    if ( rc )
        return rc;

    /*
     * Move the next 32 pages above 2M backwards by 1 page.  The region is
     * almost completely overlapping.
     */
    printf("  Test backwards, overlapping: GFNs [%lx...%lx] -> [%lx...%lx]\n",
           GFN_PAIR(GFN_2M + 32, 32), GFN_PAIR(GFN_2M + 31, 32));

    rc = xendevicemodel_relocate_memory(dh, domid, 32, GFN_2M + 32, GFN_2M + 31);
    if ( rc )
        return fail("  Fail: relocate memory: %d - %s\n",
                    errno, strerror(errno));

    rc = check_guest_marks(GFN_2M + 31, 32, 32);
    if ( rc )
        return rc;

    return 0;

#undef GFN_PAIR
#undef GFN_4M
#undef GFN_2M
}

static int run_tests(void)
{
    int rc;

    rc = test_paging_mempool_size();
    if ( rc )
        return rc;

    rc = test_p2m_relocate_memory();
    if ( rc )
        return rc;

    return 0;
}

int main(int argc, char **argv)
{
    int rc;

    printf("Paging mempool tests\n");

    xch = xc_interface_open(NULL, NULL, 0);
    if ( !xch )
        err(1, "xc_interface_open");

    dh = xendevicemodel_open(NULL, 0);
    if ( !dh )
        err(1, "xendevicemodel_open");

    fh = xenforeignmemory_open(NULL, 0);
    if ( !fh )
        err(1, "xenforeignmemory_open");

    rc = xc_domain_create(xch, &domid, &create);
    if ( rc )
    {
        if ( errno == EINVAL || errno == EOPNOTSUPP )
            printf("  Skip: %d - %s\n", errno, strerror(errno));
        else
            fail("  Domain create failure: %d - %s\n",
                 errno, strerror(errno));
        goto out;
    }

    printf("  Created d%u\n", domid);

    run_tests();

    rc = xc_domain_destroy(xch, domid);
    if ( rc )
        fail("  Failed to destroy domain: %d - %s\n",
             errno, strerror(errno));
 out:
    return !!nr_failures;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
