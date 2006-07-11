/******************************************************************************
 * xc_ia64_linux_save.c
 *
 * Save the state of a running Linux session.
 *
 * Copyright (c) 2003, K A Fraser.
 *  Rewritten for ia64 by Tristan Gingold <tristan.gingold@bull.net>
 */

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "xg_private.h"

/* total number of pages used by the current guest */
static unsigned long max_pfn;

static inline ssize_t
write_exact(int fd, void *buf, size_t count)
{
    if (write(fd, buf, count) != count)
        return 0;
    return 1;
}

static int
suspend_and_state(int (*suspend)(int), int xc_handle, int io_fd,
                  int dom, xc_dominfo_t *info)
{
    int i = 0;

    if (!(*suspend)(dom)) {
        ERR("Suspend request failed");
        return -1;
    }

retry:

    if (xc_domain_getinfo(xc_handle, dom, 1, info) != 1) {
        ERR("Could not get domain info");
        return -1;
    }

    if (info->shutdown && info->shutdown_reason == SHUTDOWN_suspend)
        return 0; // success

    if (info->paused) {
        // try unpausing domain, wait, and retest
        xc_domain_unpause(xc_handle, dom);

        ERR("Domain was paused. Wait and re-test.");
        usleep(10000);  // 10ms

        goto retry;
    }


    if(++i < 100) {
        ERR("Retry suspend domain.");
        usleep(10000);  // 10ms
        goto retry;
    }

    ERR("Unable to suspend domain.");

    return -1;
}

int
xc_linux_save(int xc_handle, int io_fd, uint32_t dom, uint32_t max_iters,
              uint32_t max_factor, uint32_t flags, int (*suspend)(int))
{
    DECLARE_DOM0_OP;
    xc_dominfo_t info;

    int rc = 1;
    unsigned long N;

    //int live  = (flags & XCFLAGS_LIVE);
    int debug = (flags & XCFLAGS_DEBUG);

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    unsigned long *page_array = NULL;

    /* Live mapping of shared info structure */
    shared_info_t *live_shinfo = NULL;

    char *mem;

    if (debug)
        fprintf (stderr, "xc_linux_save (ia64): started dom=%d\n", dom);

    if (xc_domain_getinfo(xc_handle, dom, 1, &info) != 1) {
        ERR("Could not get domain info");
        return 1;
    }

    shared_info_frame = info.shared_info_frame;

#if 0
    /* cheesy sanity check */
    if ((info.max_memkb >> (PAGE_SHIFT - 10)) > max_mfn) {
        ERR("Invalid state record -- pfn count out of range: %lu",
            (info.max_memkb >> (PAGE_SHIFT - 10)));
        goto out;
     }
#endif

    /* Map the shared info frame */
    live_shinfo = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                       PROT_READ, shared_info_frame);
    if (!live_shinfo) {
        ERR("Couldn't map live_shinfo");
        goto out;
    }

    max_pfn = info.max_memkb >> (PAGE_SHIFT - 10);


    /* This is a non-live suspend. Issue the call back to get the
       domain suspended */

    if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info)) {
        ERR("Domain appears not to have suspended");
        goto out;
    }

    page_array = malloc(max_pfn * sizeof(unsigned long));
    if (page_array == NULL) {
        ERR("Could not allocate memory");
        goto out;
    }

    if (xc_ia64_get_pfn_list(xc_handle, dom, page_array,
                             0, max_pfn) != max_pfn) {
        ERR("Could not get the page frame list");
        goto out;
    }

    /* This is expected by xm restore.  */
    if (!write_exact(io_fd, &max_pfn, sizeof(unsigned long))) {
        ERR("write: max_pfn");
        goto out;
    }

    /* xc_linux_restore starts to read here.  */
    /* Write a version number.  This can avoid searching for a stupid bug
       if the format change.
       The version is hard-coded, don't forget to change the restore code
       too!  */
    N = 1;
    if (!write_exact(io_fd, &N, sizeof(unsigned long))) {
        ERR("write: version");
        goto out;
    }

    op.cmd = DOM0_DOMAIN_SETUP;
    op.u.domain_setup.domain = (domid_t)dom;
    op.u.domain_setup.flags = XEN_DOMAINSETUP_query;
    if (xc_dom0_op(xc_handle, &op) < 0) {
        ERR("Could not get domain setup");
        goto out;
    }
    op.u.domain_setup.domain = 0;
    if (!write_exact(io_fd, &op.u.domain_setup, sizeof(op.u.domain_setup))) {
        ERR("write: domain setup");
        goto out;
    }

    /* Start writing out the saved-domain record. */
    for (N = 0; N < max_pfn; N++) {
        if (page_array[N] == INVALID_MFN)
            continue;
        if (debug)
            fprintf (stderr, "xc_linux_save: page %lx (%lu/%lu)\n",
                     page_array[N], N, max_pfn);

        if (!write_exact(io_fd, &N, sizeof(N))) {
            ERR("write: max_pfn");
            goto out;
        }

        mem = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                   PROT_READ|PROT_WRITE, page_array[N]);
        if (mem == NULL) {
            ERR("cannot map page");
            goto out;
        }
        if (write(io_fd, mem, PAGE_SIZE) != PAGE_SIZE) {
            ERR("Error when writing to state file (5)");
            goto out;
        }
        munmap(mem, PAGE_SIZE);
    }

    fprintf (stderr, "All memory is saved\n");

    /* terminate */
    N = INVALID_MFN;
    if (!write_exact(io_fd, &N, sizeof(N))) {
        ERR("Error when writing to state file (6)");
        goto out;
    }

    /* Send through a list of all the PFNs that were not in map at the close */
    {
        unsigned int i,j;
        unsigned long pfntab[1024];

        for (i = 0, j = 0; i < max_pfn; i++) {
            if (page_array[i] == INVALID_MFN)
                j++;
        }

        if (!write_exact(io_fd, &j, sizeof(unsigned int))) {
            ERR("Error when writing to state file (6a)");
            goto out;
        }

        for (i = 0, j = 0; i < max_pfn; ) {

            if (page_array[i] == INVALID_MFN)
                pfntab[j++] = i;

            i++;
            if (j == 1024 || i == max_pfn) {
                if (!write_exact(io_fd, &pfntab, sizeof(unsigned long)*j)) {
                    ERR("Error when writing to state file (6b)");
                    goto out;
                }
                j = 0;
            }
        }

    }

    if (xc_vcpu_getcontext(xc_handle, dom, 0, &ctxt)) {
        ERR("Could not get vcpu context");
        goto out;
    }

    if (!write_exact(io_fd, &ctxt, sizeof(ctxt))) {
        ERR("Error when writing to state file (1)");
        goto out;
    }

    mem = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                               PROT_READ|PROT_WRITE, ctxt.privregs_pfn);
    if (mem == NULL) {
        ERR("cannot map privreg page");
        goto out;
    }
    if (write(io_fd, mem, PAGE_SIZE) != PAGE_SIZE) {
        ERR("Error when writing privreg to state file (5)");
        goto out;
    }
    munmap(mem, PAGE_SIZE);    

    if (!write_exact(io_fd, live_shinfo, PAGE_SIZE)) {
        ERR("Error when writing to state file (1)");
        goto out;
    }

    /* Success! */
    rc = 0;

 out:

    free (page_array);

    if (live_shinfo)
        munmap(live_shinfo, PAGE_SIZE);

    fprintf(stderr,"Save exit rc=%d\n",rc);

    return !!rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
