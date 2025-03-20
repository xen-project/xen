#include <err.h>
#include <errno.h>
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
static xenforeignmemory_handle *fh;
static xengnttab_handle *gh;

static xc_physinfo_t physinfo;

static void test_gnttab(uint32_t domid, unsigned int nr_frames,
                        unsigned long gfn)
{
    xenforeignmemory_resource_handle *res;
    grant_entry_v1_t *gnttab = NULL;
    size_t size;
    int rc;
    uint32_t refs[nr_frames], domids[nr_frames];
    void *grants;

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
        (void **)&gnttab, PROT_READ | PROT_WRITE, 0);

    /*
     * Failure here with E2BIG indicates Xen is missing the bugfix to map
     * resources larger than 32 frames.
     */
    if ( !res )
        return fail("    Fail: Map grant table %d - %s\n",
                    errno, strerror(errno));

    /* Put each gref at a unique offset in its frame. */
    for ( unsigned int i = 0; i < nr_frames; i++ )
    {
        unsigned int gref = i * (XC_PAGE_SIZE / sizeof(*gnttab)) + i;

        refs[i] = gref;
        domids[i] = domid;

        gnttab[gref].domid = 0;
        gnttab[gref].frame = gfn;
        gnttab[gref].flags = GTF_permit_access;
    }

    /* Map grants. */
    grants = xengnttab_map_grant_refs(gh, nr_frames, domids, refs,
                                      PROT_READ | PROT_WRITE);

    /*
     * Failure here indicates either that the frames were not mapped
     * in the correct order or xenforeignmemory_map_resource() didn't
     * give us the frames we asked for to begin with.
     */
    if ( grants == NULL )
    {
        fail("    Fail: Map grants %d - %s\n", errno, strerror(errno));
        goto out;
    }

    /* Unmap grants. */
    rc = xengnttab_unmap(gh, grants, nr_frames);

    if ( rc )
        fail("    Fail: Unmap grants %d - %s\n", errno, strerror(errno));

    /* Unmap grant table. */
 out:
    rc = xenforeignmemory_unmap_resource(fh, res);
    if ( rc )
        return fail("    Fail: Unmap grant table %d - %s\n",
                    errno, strerror(errno));

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

    /*
     * If this check starts failing, you've found the right place to test your
     * addition to the Acquire Resource infrastructure.
     */
    rc = xenforeignmemory_resource_size(fh, domid, 3, 0, &size);

    /* Check that Xen rejected the resource type. */
    if ( !rc )
        fail("    Fail: Expected error on an invalid resource type, got success\n");
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
                .grant_opts = XEN_DOMCTL_GRANT_version(1),
            },
        },
        {
            .name = "x86 PVH",
            .create = {
                .flags = XEN_DOMCTL_CDF_hvm,
                .max_vcpus = 2,
                .max_grant_frames = 40,
                .grant_opts = XEN_DOMCTL_GRANT_version(1),
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
                .grant_opts = XEN_DOMCTL_GRANT_version(1),
            },
        },
#endif
    };

    for ( unsigned int i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        struct test *t = &tests[i];
        uint32_t domid = 0;
        int rc;
        xen_pfn_t ram[1] = { 0 };

        printf("Test %s\n", t->name);

#if defined(__x86_64__) || defined(__i386__)
        if ( t->create.flags & XEN_DOMCTL_CDF_hvm )
        {
            if ( !(physinfo.capabilities & XEN_SYSCTL_PHYSCAP_hvm) )
            {
                printf("  Skip: HVM not available\n");
                continue;
            }

            /*
             * On x86, use HAP guests if possible, but skip if neither HAP nor
             * SHADOW is available.
             */
            if ( physinfo.capabilities & XEN_SYSCTL_PHYSCAP_hap )
                t->create.flags |= XEN_DOMCTL_CDF_hap;
            else if ( !(physinfo.capabilities & XEN_SYSCTL_PHYSCAP_shadow) )
            {
                printf("  Skip: Neither HAP or SHADOW available\n");
                continue;
            }
        }
        else
        {
            if ( !(physinfo.capabilities & XEN_SYSCTL_PHYSCAP_pv) )
            {
                printf("  Skip: PV not available\n");
                continue;
            }
        }
#endif

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

        rc = xc_domain_setmaxmem(xch, domid, -1);
        if ( rc )
        {
            fail("  Failed to set max memory for domain: %d - %s\n",
                 errno, strerror(errno));
            goto test_done;
        }

        rc = xc_domain_populate_physmap_exact(
            xch, domid, ARRAY_SIZE(ram), 0, 0, ram);
        if ( rc )
        {
            fail("  Failed to populate physmap domain: %d - %s\n",
                 errno, strerror(errno));
            goto test_done;
        }

        test_gnttab(domid, t->create.max_grant_frames, ram[0]);

    test_done:
        rc = xc_domain_destroy(xch, domid);
        if ( rc )
            fail("  Failed to destroy domain: %d - %s\n",
                 errno, strerror(errno));
    }
}

int main(int argc, char **argv)
{
    int rc;

    printf("XENMEM_acquire_resource tests\n");

    xch = xc_interface_open(NULL, NULL, 0);
    fh = xenforeignmemory_open(NULL, 0);
    gh = xengnttab_open(NULL, 0);

    if ( !xch )
        err(1, "xc_interface_open");
    if ( !fh )
        err(1, "xenforeignmemory_open");
    if ( !gh )
        err(1, "xengnttab_open");

    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        err(1, "Failed to obtain physinfo");

    test_domain_configurations();

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
