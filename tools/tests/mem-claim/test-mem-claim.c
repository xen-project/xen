/* SPDX-License-Identifier: GPL-2.0-only */
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

#define MB_PAGES(x) (MB(x) / XC_PAGE_SIZE)

static xc_interface *xch;
static uint32_t domid = DOMID_INVALID;

static xc_physinfo_t physinfo;

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

static void run_tests(void)
{
    int rc;

    /*
     * Check that the system is quiescent.  Outstanding claims is a global
     * field.
     */
    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    printf("Free pages: %"PRIu64", Oustanding claims: %"PRIu64"\n",
           physinfo.free_pages, physinfo.outstanding_pages);

    if ( physinfo.outstanding_pages )
        return fail("  Test needs running on a quiescent system\n");

    /*
     * We want any arbitrary domain.  Start with HVM/HAP, falling back to
     * HVM/Shadow and then to PV.  The dom0 running this test case is one of
     * these modes.
     */
#if defined(__x86_64__) || defined(__i386__)
    if ( !(physinfo.capabilities & XEN_SYSCTL_PHYSCAP_hap) )
        create.flags &= ~XEN_DOMCTL_CDF_hap;

    if ( !(physinfo.capabilities & (XEN_SYSCTL_PHYSCAP_hap|XEN_SYSCTL_PHYSCAP_shadow)) ||
         !(physinfo.capabilities & XEN_SYSCTL_PHYSCAP_hvm) )
    {
        create.flags &= ~XEN_DOMCTL_CDF_hvm;
        create.arch.emulation_flags = 0;
    }
#endif

    rc = xc_domain_create(xch, &domid, &create);
    if ( rc )
        return fail("  Domain create failure: %d - %s\n",
                    errno, strerror(errno));

    rc = xc_domain_setmaxmem(xch, domid, -1);
    if ( rc )
        return fail("  Failed to set maxmem: %d - %s\n",
                    errno, strerror(errno));

    printf("  Created d%u\n", domid);

    /*
     * Creating a domain shouldn't change the claim.  Check it's still 0.
     */
    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("  Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    if ( physinfo.outstanding_pages )
        return fail("  Unexpected outstanding claim of %"PRIu64" pages\n",
                    physinfo.outstanding_pages);

    /*
     * Set a claim for 4M.  This should be the only claim in the system, and
     * show up globally.
     */
    rc = xc_domain_claim_pages(xch, domid, MB_PAGES(4));
    if ( rc )
        return fail("  Failed to claim 4M of RAM: %d - %s\n",
                    errno, strerror(errno));

    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("  Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    if ( physinfo.outstanding_pages != MB_PAGES(4) )
        return fail("  Expected claim to be 4M, got %"PRIu64" pages\n",
                    physinfo.outstanding_pages);

    /*
     * Allocate 2M of RAM to the domain.  This should be deducted from global
     * claim.
     */
    xen_pfn_t ram[] = { 0 };
    rc = xc_domain_populate_physmap_exact(
        xch, domid, ARRAY_SIZE(ram), 9 /* Order 2M */, 0, ram);
    if ( rc )
        return fail("  Failed to populate physmap domain: %d - %s\n",
                    errno, strerror(errno));

    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("  Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    if ( physinfo.outstanding_pages != MB_PAGES(2) )
        return fail("  Expected claim to be 2M, got %"PRIu64" pages\n",
                    physinfo.outstanding_pages);

    /*
     * Destroying the domain should release the outstanding 2M claim.
     */
    rc = xc_domain_destroy(xch, domid);

    /* Cancel the cleanup path, even in the case of an error. */
    domid = DOMID_INVALID;

    if ( rc )
        return fail("  Failed to destroy domain: %d - %s\n",
                    errno, strerror(errno));

    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("  Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    if ( physinfo.outstanding_pages )
        return fail("  Expected no outstanding claim, got %"PRIu64" pages\n",
                    physinfo.outstanding_pages);
}

int main(int argc, char **argv)
{
    int rc;

    printf("Memory claims tests\n");

    xch = xc_interface_open(NULL, NULL, 0);

    if ( !xch )
        err(1, "xc_interface_open");

    run_tests();

    if ( domid != DOMID_INVALID )
    {
        rc = xc_domain_destroy(xch, domid);
        if ( rc )
            fail("  Failed to destroy domain: %d - %s\n",
                 errno, strerror(errno));
    }

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
