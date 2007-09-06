/******************************************************************************
 * xc_ia64_linux_restore.c
 *
 * Restore the state of a Linux session.
 *
 * Copyright (c) 2003, K A Fraser.
 *  Rewritten for ia64 by Tristan Gingold <tristan.gingold@bull.net>
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata@valinux.co.jp>
 *   Use foreign p2m exposure.
 */

#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"
#include "xc_ia64_save_restore.h"
#include "xc_ia64.h"
#include "xc_efi.h"

#define PFN_TO_KB(_pfn) ((_pfn) << (PAGE_SHIFT - 10))

/* number of pfns this guest has (i.e. number of entries in the P2M) */
static unsigned long p2m_size;

/* number of 'in use' pfns in the guest (i.e. #P2M entries with a valid mfn) */
static unsigned long nr_pfns;

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
populate_page_if_necessary(int xc_handle, uint32_t dom, unsigned long gmfn,
                           struct xen_ia64_p2m_table *p2m_table)
{
    if (xc_ia64_p2m_present(p2m_table, gmfn))
        return 0;

    return xc_domain_memory_populate_physmap(xc_handle, dom, 1, 0, 0, &gmfn);
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
        munmap(mem, PAGE_SIZE);
        return -1;
    }
    munmap(mem, PAGE_SIZE);
    return 0;
}

int
xc_domain_restore(int xc_handle, int io_fd, uint32_t dom,
                 unsigned int store_evtchn, unsigned long *store_mfn,
                 unsigned int console_evtchn, unsigned long *console_mfn,
                 unsigned int hvm, unsigned int pae)
{
    DECLARE_DOMCTL;
    int rc = 1;
    unsigned int i;
    unsigned long gmfn;
    unsigned long ver;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    unsigned char shared_info_page[PAGE_SIZE]; /* saved contents from file */
    shared_info_t *shared_info = (shared_info_t *)shared_info_page;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    /* A temporary mapping of the guest's start_info page. */
    start_info_t *start_info;

    struct xen_ia64_p2m_table p2m_table;
    xc_ia64_p2m_init(&p2m_table);

    if (hvm) {
        ERROR("HVM Restore is unsupported");
        goto out;
    }

    /* For info only */
    nr_pfns = 0;

    if ( !read_exact(io_fd, &p2m_size, sizeof(unsigned long)) )
    {
        ERROR("read: p2m_size");
        goto out;
    }
    DPRINTF("xc_linux_restore start: p2m_size = %lx\n", p2m_size);

    if (!read_exact(io_fd, &ver, sizeof(unsigned long))) {
        ERROR("Error when reading version");
        goto out;
    }
    if (ver != XC_IA64_SR_FORMAT_VER_ONE && ver != XC_IA64_SR_FORMAT_VER_TWO) {
        ERROR("version of save doesn't match");
        goto out;
    }

    if (lock_pages(&ctxt, sizeof(ctxt))) {
        /* needed for build domctl, but might as well do early */
        ERROR("Unable to lock_pages ctxt");
        return 1;
    }

    if (!read_exact(io_fd, &domctl.u.arch_setup, sizeof(domctl.u.arch_setup))) {
        ERROR("read: domain setup");
        goto out;
    }

    /* Build firmware (will be overwritten).  */
    domctl.domain = (domid_t)dom;
    domctl.u.arch_setup.flags &= ~XEN_DOMAINSETUP_query;
    domctl.u.arch_setup.bp = 0; /* indicate domain restore */
    
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

    if (ver == XC_IA64_SR_FORMAT_VER_TWO) {
        unsigned int memmap_info_num_pages;
        unsigned long memmap_size;
        xen_ia64_memmap_info_t *memmap_info;

        if (!read_exact(io_fd, &memmap_info_num_pages,
                        sizeof(memmap_info_num_pages))) {
            ERROR("read: memmap_info_num_pages");
            goto out;
        }
        memmap_size = memmap_info_num_pages * PAGE_SIZE;
        memmap_info = malloc(memmap_size);
        if (memmap_info == NULL) {
            ERROR("Could not allocate memory for memmap_info");
            goto out;
        }
        if (!read_exact(io_fd, memmap_info, memmap_size)) {
            ERROR("read: memmap_info");
            goto out;
        }
        if (xc_ia64_p2m_map(&p2m_table, xc_handle,
                            dom, memmap_info, IA64_DOM0VP_EFP_ALLOC_PTE)) {
            ERROR("p2m mapping");
            goto out;
        }
        free(memmap_info);
    } else if (ver == XC_IA64_SR_FORMAT_VER_ONE) {
        xen_ia64_memmap_info_t *memmap_info;
        efi_memory_desc_t *memdesc;
        uint64_t buffer[(sizeof(*memmap_info) + sizeof(*memdesc) +
                         sizeof(uint64_t) - 1) / sizeof(uint64_t)];

        memset(buffer, 0, sizeof(buffer));
        memmap_info = (xen_ia64_memmap_info_t *)buffer;
        memdesc = (efi_memory_desc_t*)&memmap_info->memdesc[0];
        memmap_info->efi_memmap_size = sizeof(*memmap_info) + sizeof(*memdesc);
        memmap_info->efi_memdesc_size = sizeof(*memdesc);
        memmap_info->efi_memdesc_version = EFI_MEMORY_DESCRIPTOR_VERSION;

        memdesc->type = EFI_MEMORY_DESCRIPTOR_VERSION;
        memdesc->phys_addr = 0;
        memdesc->virt_addr = 0;
        memdesc->num_pages = nr_pfns << (PAGE_SHIFT - EFI_PAGE_SHIFT);
        memdesc->attribute = EFI_MEMORY_WB;

        if (xc_ia64_p2m_map(&p2m_table, xc_handle,
                            dom, memmap_info, IA64_DOM0VP_EFP_ALLOC_PTE)) {
            ERROR("p2m mapping");
            goto out;
        }
    } else {
        ERROR("unknown version");
        goto out;
    }

    DPRINTF("Reloading memory pages:   0%%\n");

    while (1) {
        if (!read_exact(io_fd, &gmfn, sizeof(unsigned long))) {
            ERROR("Error when reading batch size");
            goto out;
        }
        if (gmfn == INVALID_MFN)
            break;

        if (populate_page_if_necessary(xc_handle, dom, gmfn, &p2m_table) < 0) {
            ERROR("can not populate page 0x%lx", gmfn);
            goto out;
        }
        if (read_page(xc_handle, io_fd, dom, gmfn) < 0)
            goto out;
    }

    DPRINTF("Received all pages\n");

    /*
     * Get the list of PFNs that are not in the psuedo-phys map.
     * Although we allocate pages on demand, balloon driver may 
     * decreased simaltenously. So we have to free the freed
     * pages here.
     */
    {
        unsigned int count;
        unsigned long *pfntab;
        unsigned int nr_frees;

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
            free(pfntab);
            goto out;
        }

        nr_frees = 0;
        for (i = 0; i < count; i++) {
            if (xc_ia64_p2m_allocated(&p2m_table, pfntab[i])) {
                pfntab[nr_frees] = pfntab[i];
                nr_frees++;
            }
        }
        if (nr_frees > 0) {
            if (xc_domain_memory_decrease_reservation(xc_handle, dom, nr_frees,
                                                      0, pfntab) < 0) {
                ERROR("Could not decrease reservation : %d", rc);
                free(pfntab);
                goto out;
            }
            else
                DPRINTF("Decreased reservation by %d / %d pages\n",
                        nr_frees, count);
        }
        free(pfntab);
    }

    if (!read_exact(io_fd, &ctxt, sizeof(ctxt))) {
        ERROR("Error when reading ctxt");
        goto out;
    }

    fprintf(stderr, "ip=%016lx, b0=%016lx\n", ctxt.regs.ip, ctxt.regs.b[0]);

    /* Initialize and set registers.  */
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
            munmap(shared_info, PAGE_SIZE);
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
    if (populate_page_if_necessary(xc_handle, dom, gmfn, &p2m_table)) {
        ERROR("cannot populate page 0x%lx", gmfn);
        goto out;
    }
    start_info = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                      PROT_READ | PROT_WRITE, gmfn);
    if (start_info == NULL) {
        ERROR("cannot map start_info page");
        goto out;
    }
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

    xc_ia64_p2m_unmap(&p2m_table);

    unlock_pages(&ctxt, sizeof(ctxt));

    DPRINTF("Restore exit with rc=%d\n", rc);

    return rc;
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
