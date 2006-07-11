/******************************************************************************
 * xc_ia64_linux_restore.c
 *
 * Restore the state of a Linux session.
 *
 * Copyright (c) 2003, K A Fraser.
 *  Rewritten for ia64 by Tristan Gingold <tristan.gingold@bull.net>
 */

#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"

#define PFN_TO_KB(_pfn) ((_pfn) << (PAGE_SHIFT - 10))

/* total number of pages used by the current guest */
static unsigned long max_pfn;

static ssize_t
read_exact(int fd, void *buf, size_t count)
{
    int r = 0, s;
    unsigned char *b = buf;

    while (r < count) {
        s = read(fd, &b[r], count - r);
        if ((s == -1) && (errno == EINTR))
            continue;
        if (s <= 0) {
            break;
        }
        r += s;
    }

    return (r == count) ? 1 : 0;
}

static int
read_page(int xc_handle, int io_fd, uint32_t dom, unsigned long pfn)
{
    void *mem;

    mem = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                               PROT_READ|PROT_WRITE, pfn);
    if (mem == NULL) {
            ERR("cannot map page");
	    return -1;
    }
    if (!read_exact(io_fd, mem, PAGE_SIZE)) {
            ERR("Error when reading from state file (5)");
            return -1;
    }
    munmap(mem, PAGE_SIZE);
    return 0;
}

int
xc_linux_restore(int xc_handle, int io_fd, uint32_t dom,
                 unsigned long nr_pfns, unsigned int store_evtchn,
                 unsigned long *store_mfn, unsigned int console_evtchn,
                 unsigned long *console_mfn)
{
    DECLARE_DOM0_OP;
    int rc = 1, i;
    unsigned long mfn, pfn;
    unsigned long ver;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    unsigned char shared_info_page[PAGE_SIZE]; /* saved contents from file */
    shared_info_t *shared_info = (shared_info_t *)shared_info_page;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    unsigned long *page_array = NULL;

    /* A temporary mapping of the guest's start_info page. */
    start_info_t *start_info;

    max_pfn = nr_pfns;

    DPRINTF("xc_linux_restore start: max_pfn = %ld\n", max_pfn);


    if (!read_exact(io_fd, &ver, sizeof(unsigned long))) {
	ERR("Error when reading version");
	goto out;
    }
    if (ver != 1) {
	ERR("version of save doesn't match");
	goto out;
    }

    if (mlock(&ctxt, sizeof(ctxt))) {
        /* needed for build dom0 op, but might as well do early */
        ERR("Unable to mlock ctxt");
        return 1;
    }

    /* Get the domain's shared-info frame. */
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)dom;
    if (xc_dom0_op(xc_handle, &op) < 0) {
        ERR("Could not get information on new domain");
        goto out;
    }
    shared_info_frame = op.u.getdomaininfo.shared_info_frame;

    if (xc_domain_setmaxmem(xc_handle, dom, PFN_TO_KB(max_pfn)) != 0) {
        errno = ENOMEM;
        goto out;
    }

    if (xc_domain_memory_increase_reservation(xc_handle, dom, max_pfn,
                                              0, 0, NULL) != 0) {
        ERR("Failed to increase reservation by %ld KB", PFN_TO_KB(max_pfn));
        errno = ENOMEM;
        goto out;
    }

    DPRINTF("Increased domain reservation by %ld KB\n", PFN_TO_KB(max_pfn));

    if (!read_exact(io_fd, &op.u.domain_setup, sizeof(op.u.domain_setup))) {
        ERR("read: domain setup");
        goto out;
    }

    /* Build firmware (will be overwritten).  */
    op.u.domain_setup.domain = (domid_t)dom;
    op.u.domain_setup.flags &= ~XEN_DOMAINSETUP_query;
    op.u.domain_setup.bp = ((nr_pfns - 3) << PAGE_SHIFT)
                           + sizeof (start_info_t);
    op.u.domain_setup.maxmem = (nr_pfns - 3) << PAGE_SHIFT;
    
    op.cmd = DOM0_DOMAIN_SETUP;
    if (xc_dom0_op(xc_handle, &op))
        goto out;

    /* Get pages.  */
    page_array = malloc(max_pfn * sizeof(unsigned long));
    if (page_array == NULL ) {
        ERR("Could not allocate memory");
        goto out;
    }

    if (xc_ia64_get_pfn_list(xc_handle, dom, page_array,
                             0, max_pfn) != max_pfn) {
        ERR("Could not get the page frame list");
        goto out;
    }

    DPRINTF("Reloading memory pages:   0%%\n");

    while (1) {
        if (!read_exact(io_fd, &mfn, sizeof(unsigned long))) {
            ERR("Error when reading batch size");
            goto out;
        }
	if (mfn == INVALID_MFN)
		break;

	pfn = page_array[mfn];

        DPRINTF ("xc_linux_restore: page %lu/%lu at %lx\n", mfn, max_pfn, pfn);

	if (read_page(xc_handle, io_fd, dom, page_array[mfn]) < 0)
		goto out;
    }

    DPRINTF("Received all pages\n");

    /* Get the list of PFNs that are not in the psuedo-phys map */
    {
        unsigned int count;
        unsigned long *pfntab;
        int rc;

        if (!read_exact(io_fd, &count, sizeof(count))) {
            ERR("Error when reading pfn count");
            goto out;
        }

        pfntab = malloc(sizeof(unsigned long) * count);
        if (!pfntab) {
            ERR("Out of memory");
            goto out;
        }

        if (!read_exact(io_fd, pfntab, sizeof(unsigned long)*count)) {
            ERR("Error when reading pfntab");
            goto out;
        }

	DPRINTF ("Try to free %u pages\n", count);

        for (i = 0; i < count; i++) {

	    volatile unsigned long pfn;

            struct xen_memory_reservation reservation = {
                .nr_extents   = 1,
                .extent_order = 0,
                .domid        = dom
            };
            set_xen_guest_handle(reservation.extent_start,
				 (unsigned long *)&pfn);

	    pfn = pfntab[i];
            rc = xc_memory_op(xc_handle, XENMEM_decrease_reservation,
                              &reservation);
            if (rc != 1) {
                ERR("Could not decrease reservation : %d", rc);
                goto out;
            }
        }

	DPRINTF("Decreased reservation by %d pages\n", count);
    }


    if (!read_exact(io_fd, &ctxt, sizeof(ctxt))) {
        ERR("Error when reading ctxt");
        goto out;
    }

    /* First to initialize.  */
    op.cmd = DOM0_SETVCPUCONTEXT;
    op.u.setvcpucontext.domain = (domid_t)dom;
    op.u.setvcpucontext.vcpu   = 0;
    set_xen_guest_handle(op.u.setvcpucontext.ctxt, &ctxt);
    if (xc_dom0_op(xc_handle, &op) != 0) {
	    ERR("Couldn't set vcpu context");
	    goto out;
    }

    /* Second to set registers...  */
    ctxt.flags = VGCF_EXTRA_REGS;
    op.cmd = DOM0_SETVCPUCONTEXT;
    op.u.setvcpucontext.domain = (domid_t)dom;
    op.u.setvcpucontext.vcpu   = 0;
    set_xen_guest_handle(op.u.setvcpucontext.ctxt, &ctxt);
    if (xc_dom0_op(xc_handle, &op) != 0) {
	    ERR("Couldn't set vcpu context");
	    goto out;
    }

    /* Just a check.  */
    if (xc_vcpu_getcontext(xc_handle, dom, 0 /* XXX */, &ctxt)) {
        ERR("Could not get vcpu context");
	goto out;
    }

    /* Then get privreg page.  */
    if (read_page(xc_handle, io_fd, dom, ctxt.privregs_pfn) < 0) {
	    ERR("Could not read vcpu privregs");
	    goto out;
    }

    /* Read shared info.  */
    shared_info = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                       PROT_READ|PROT_WRITE, shared_info_frame);
    if (shared_info == NULL) {
            ERR("cannot map page");
	    goto out;
    }
    if (!read_exact(io_fd, shared_info, PAGE_SIZE)) {
            ERR("Error when reading shared_info page");
	    goto out;
    }

    /* clear any pending events and the selector */
    memset(&(shared_info->evtchn_pending[0]), 0,
           sizeof (shared_info->evtchn_pending));
    for (i = 0; i < MAX_VIRT_CPUS; i++)
        shared_info->vcpu_info[i].evtchn_pending_sel = 0;

    mfn = page_array[shared_info->arch.start_info_pfn];

    munmap (shared_info, PAGE_SIZE);

    /* Uncanonicalise the suspend-record frame number and poke resume rec. */
    start_info = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                      PROT_READ | PROT_WRITE, mfn);
    start_info->nr_pages = max_pfn;
    start_info->shared_info = shared_info_frame << PAGE_SHIFT;
    start_info->flags = 0;
    *store_mfn = page_array[start_info->store_mfn];
    start_info->store_evtchn = store_evtchn;
    *console_mfn = page_array[start_info->console_mfn];
    start_info->console_evtchn = console_evtchn;
    munmap(start_info, PAGE_SIZE);

    /*
     * Safety checking of saved context:
     *  1. user_regs is fine, as Xen checks that on context switch.
     *  2. fpu_ctxt is fine, as it can't hurt Xen.
     *  3. trap_ctxt needs the code selectors checked.
     *  4. ldt base must be page-aligned, no more than 8192 ents, ...
     *  5. gdt already done, and further checking is done by Xen.
     *  6. check that kernel_ss is safe.
     *  7. pt_base is already done.
     *  8. debugregs are checked by Xen.
     *  9. callback code selectors need checking.
     */
    DPRINTF("Domain ready to be built.\n");

    rc = 0;

 out:
    if ((rc != 0) && (dom != 0))
        xc_domain_destroy(xc_handle, dom);

    free (page_array);

    DPRINTF("Restore exit with rc=%d\n", rc);

    return rc;
}
