#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <xenforeignmemory.h>
#include <xen-tools/libs.h>

static unsigned int nr_failures;
#define fail(fmt, ...)                          \
({                                              \
    nr_failures++;                              \
    (void)printf(fmt, ##__VA_ARGS__);           \
})

static xc_interface *xch;
static xenforeignmemory_handle *fh;

static void test_gnttab(uint32_t domid, unsigned int nr_frames)
{
    xenforeignmemory_resource_handle *res;
    void *addr = NULL;
    size_t size;
    int rc;

    printf("  Test grant table\n");

    /* Obtain the grant table resource size. */
    rc = xenforeignmemory_resource_size(
        fh, domid, XENMEM_resource_grant_table,
        XENMEM_resource_grant_table_id_shared, &size);

    /*
     * A failure of this call indicates missing kernel support for size
     * ioctl(), or missing Xen acquire_resource support.
     */
    if ( rc )
        return fail("    Fail: Get size: %d - %s\n", errno, strerror(errno));

    /*
     * Getting 32 frames back instead of nr_frames indicates Xen is missing
     * the bugfix to make size requests actually return real data.
     */
    if ( (size >> XC_PAGE_SHIFT) != nr_frames )
        return fail("    Fail: Get size: expected %u frames, got %zu\n",
                    nr_frames, size >> XC_PAGE_SHIFT);

    /* Map the entire grant table. */
    res = xenforeignmemory_map_resource(
        fh, domid, XENMEM_resource_grant_table,
        XENMEM_resource_grant_table_id_shared, 0, size >> XC_PAGE_SHIFT,
        &addr, PROT_READ | PROT_WRITE, 0);

    /*
     * Failure here with E2BIG indicates Xen is missing the bugfix to map
     * resources larger than 32 frames.
     */
    if ( !res )
        return fail("    Fail: Map %d - %s\n", errno, strerror(errno));

    rc = xenforeignmemory_unmap_resource(fh, res);
    if ( rc )
        return fail("    Fail: Unmap %d - %s\n", errno, strerror(errno));

    /*
     * Verify that an attempt to map the status frames fails, as the domain is
     * in gnttab v1 mode.
     */
    res = xenforeignmemory_map_resource(
        fh, domid, XENMEM_resource_grant_table,
        XENMEM_resource_grant_table_id_status, 0, 1,
        (void **)&gnttab, PROT_READ | PROT_WRITE, 0);

    if ( res )
    {
        fail("    Fail: Managed to map gnttab v2 status frames in v1 mode\n");
        xenforeignmemory_unmap_resource(fh, res);
    }
}

static void test_domain_configurations(void)
{
    static struct test {
        const char *name;
        struct xen_domctl_createdomain create;
    } tests[] = {
#if defined(__x86_64__) || defined(__i386__)
        {
            .name = "x86 PV",
            .create = {
                .max_vcpus = 2,
                .max_grant_frames = 40,
            },
        },
        {
            .name = "x86 PVH",
            .create = {
                .flags = XEN_DOMCTL_CDF_hvm,
                .max_vcpus = 2,
                .max_grant_frames = 40,
                .arch = {
                    .emulation_flags = XEN_X86_EMU_LAPIC,
                },
            },
        },
#elif defined(__aarch64__) || defined(__arm__)
        {
            .name = "ARM",
            .create = {
                .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
                .max_vcpus = 2,
                .max_grant_frames = 40,
            },
        },
#endif
    };

    for ( unsigned int i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        struct test *t = &tests[i];
        uint32_t domid = 0;
        int rc;

        printf("Test %s\n", t->name);

        rc = xc_domain_create(xch, &domid, &t->create);
        if ( rc )
        {
            if ( errno == EINVAL || errno == EOPNOTSUPP )
                printf("  Skip: %d - %s\n", errno, strerror(errno));
            else
                fail("  Domain create failure: %d - %s\n",
                     errno, strerror(errno));
            continue;
        }

        printf("  Created d%u\n", domid);

        test_gnttab(domid, t->create.max_grant_frames);

        rc = xc_domain_destroy(xch, domid);
        if ( rc )
            fail("  Failed to destroy domain: %d - %s\n",
                 errno, strerror(errno));
    }
}

int main(int argc, char **argv)
{
    printf("XENMEM_acquire_resource tests\n");

    xch = xc_interface_open(NULL, NULL, 0);
    fh = xenforeignmemory_open(NULL, 0);

    if ( !xch )
        err(1, "xc_interface_open");
    if ( !fh )
        err(1, "xenforeignmemory_open");

    test_domain_configurations();

    return !!nr_failures;
}
