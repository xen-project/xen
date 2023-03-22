#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <xenforeignmemory.h>
#include <xengnttab.h>
#include <xen-tools/common-macros.h>

static unsigned int nr_failures;
#define fail(fmt, ...)                          \
({                                              \
    nr_failures++;                              \
    (void)printf(fmt, ##__VA_ARGS__);           \
})

static xc_interface *xch;
static uint32_t domid;

static struct xen_domctl_createdomain create = {
    .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
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

static void run_tests(void)
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

    rc = xc_domain_populate_physmap_exact(xch, domid, 1, 0, 0, physmap);
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
}

int main(int argc, char **argv)
{
    int rc;

    printf("Paging mempool tests\n");

    xch = xc_interface_open(NULL, NULL, 0);

    if ( !xch )
        err(1, "xc_interface_open");

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
