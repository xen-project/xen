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

/* number of pfns this guest has (i.e. number of entries in the P2M) */
static unsigned long p2m_size;

/* number of 'in use' pfns in the guest (i.e. #P2M entries with a valid mfn) */
static unsigned long nr_pfns;

/* largest possible value of nr_pfns (i.e. domain's maximum memory size) */
static unsigned long max_nr_pfns;

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
            ERROR("cannot map page");
	    return -1;
    }
    if (!read_exact(io_fd, mem, PAGE_SIZE)) {
            ERROR("Error when reading from state file (5)");
            return -1;
    }
    munmap(mem, PAGE_SIZE);
    return 0;
}

int
xc_linux_restore(int xc_handle, int io_fd, uint32_t dom,
                 unsigned long p2msize, unsigned long maxnrpfns,
                 unsigned int store_evtchn, unsigned long *store_mfn,
                 unsigned int console_evtchn, unsigned long *console_mfn)
{
    DECLARE_DOMCTL;
    int rc = 1, i;
    unsigned long gmfn;
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

    p2m_size = p2msize;
    max_nr_pfns = maxnrpfns;

    /* For info only */
    nr_pfns = 0;

    DPRINTF("xc_linux_restore start: p2m_size = %lx\n", p2m_size);

    if (!read_exact(io_fd, &ver, sizeof(unsigned long))) {
	ERROR("Error when reading version");
	goto out;
    }
    if (ver != 1) {
	ERROR("version of save doesn't match");
	goto out;
    }

    if (mlock(&ctxt, sizeof(ctxt))) {
        /* needed for build domctl, but might as well do early */
        ERROR("Unable to mlock ctxt");
        return 1;
    }

    if (xc_domain_setmaxmem(xc_handle, dom, PFN_TO_KB(max_nr_pfns)) != 0) {
        errno = ENOMEM;
        goto out;
    }

    /* Get pages.  */
    page_array = malloc(p2m_size * sizeof(unsigned long));
    if (page_array == NULL) {
        ERROR("Could not allocate memory");
        goto out;
    }

    for ( i = 0; i < p2m_size; i++ )
        page_array[i] = i;

    if ( xc_domain_memory_populate_physmap(xc_handle, dom, p2m_size,
                                           0, 0, page_array) )
    {
        ERROR("Failed to allocate memory for %ld KB to dom %d.\n",
              PFN_TO_KB(p2m_size), dom);
        goto out;
    }
    DPRINTF("Allocated memory by %ld KB\n", PFN_TO_KB(p2m_size));

    if (!read_exact(io_fd, &domctl.u.arch_setup, sizeof(domctl.u.arch_setup))) {
        ERROR("read: domain setup");
        goto out;
    }

    /* Build firmware (will be overwritten).  */
    domctl.domain = (domid_t)dom;
    domctl.u.arch_setup.flags &= ~XEN_DOMAINSETUP_query;
    domctl.u.arch_setup.bp = ((p2m_size - 3) << PAGE_SHIFT)
                           + sizeof (start_info_t);
    domctl.u.arch_setup.maxmem = (p2m_size - 3) << PAGE_SHIFT;
    
    domctl.cmd = XEN_DOMCTL_arch_setup;
    if (xc_domctl(xc_handle, &domctl))
        goto out;

    /* Get the domain's shared-info frame. */
    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)dom;
    if (xc_domctl(xc_handle, &domctl) < 0) {
        ERROR("Could not get information on new domain");
        goto out;
    }
    shared_info_frame = domctl.u.getdomaininfo.shared_info_frame;

    DPRINTF("Reloading memory pages:   0%%\n");

    while (1) {
        if (!read_exact(io_fd, &gmfn, sizeof(unsigned long))) {
            ERROR("Error when reading batch size");
            goto out;
        }
	if (gmfn == INVALID_MFN)
		break;

	if (read_page(xc_handle, io_fd, dom, gmfn) < 0)
		goto out;
    }

    DPRINTF("Received all pages\n");

    /* Get the list of PFNs that are not in the psuedo-phys map */
    {
        unsigned int count;
        unsigned long *pfntab;
        int rc;

        if (!read_exact(io_fd, &count, sizeof(count))) {
            ERROR("Error when reading pfn count");
            goto out;
        }

        pfntab = malloc(sizeof(unsigned long) * count);
        if (!pfntab) {
            ERROR("Out of memory");
            goto out;
        }

        if (!read_exact(io_fd, pfntab, sizeof(unsigned long)*count)) {
            ERROR("Error when reading pfntab");
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
                ERROR("Could not decrease reservation : %d", rc);
                goto out;
            }
        }

	DPRINTF("Decreased reservation by %d pages\n", count);
    }


    if (!read_exact(io_fd, &ctxt, sizeof(ctxt))) {
        ERROR("Error when reading ctxt");
        goto out;
    }

    fprintf(stderr, "ip=%016lx, b0=%016lx\n", ctxt.user_regs.cr_iip,
            ctxt.user_regs.b0);

    /* First to initialize.  */
    domctl.cmd = XEN_DOMCTL_setvcpucontext;
    domctl.domain = (domid_t)dom;
    domctl.u.vcpucontext.vcpu   = 0;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, &ctxt);
    if (xc_domctl(xc_handle, &domctl) != 0) {
	    ERROR("Couldn't set vcpu context");
	    goto out;
    }

    /* Second to set registers...  */
    ctxt.flags = VGCF_EXTRA_REGS;
    domctl.cmd = XEN_DOMCTL_setvcpucontext;
    domctl.domain = (domid_t)dom;
    domctl.u.vcpucontext.vcpu   = 0;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, &ctxt);
    if (xc_domctl(xc_handle, &domctl) != 0) {
	    ERROR("Couldn't set vcpu context");
	    goto out;
    }

    /* Just a check.  */
    if (xc_vcpu_getcontext(xc_handle, dom, 0 /* XXX */, &ctxt)) {
        ERROR("Could not get vcpu context");
	goto out;
    }

    /* Then get privreg page.  */
    if (read_page(xc_handle, io_fd, dom, ctxt.privregs_pfn) < 0) {
	    ERROR("Could not read vcpu privregs");
	    goto out;
    }

    /* Read shared info.  */
    shared_info = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                       PROT_READ|PROT_WRITE, shared_info_frame);
    if (shared_info == NULL) {
            ERROR("cannot map page");
	    goto out;
    }
    if (!read_exact(io_fd, shared_info, PAGE_SIZE)) {
            ERROR("Error when reading shared_info page");
	    goto out;
    }

    /* clear any pending events and the selector */
    memset(&(shared_info->evtchn_pending[0]), 0,
           sizeof (shared_info->evtchn_pending));
    for (i = 0; i < MAX_VIRT_CPUS; i++)
        shared_info->vcpu_info[i].evtchn_pending_sel = 0;

    gmfn = shared_info->arch.start_info_pfn;

    munmap (shared_info, PAGE_SIZE);

    /* Uncanonicalise the suspend-record frame number and poke resume rec. */
    start_info = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                      PROT_READ | PROT_WRITE, gmfn);
    start_info->nr_pages = p2m_size;
    start_info->shared_info = shared_info_frame << PAGE_SHIFT;
    start_info->flags = 0;
    *store_mfn = start_info->store_mfn;
    start_info->store_evtchn = store_evtchn;
    *console_mfn = start_info->console.domU.mfn;
    start_info->console.domU.evtchn = console_evtchn;
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

    if (page_array != NULL)
	    free(page_array);

    DPRINTF("Restore exit with rc=%d\n", rc);

    return rc;
}
