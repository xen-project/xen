/*
 * This supports booting another PV kernel from Mini-OS
 *
 * The idea is to setup it using libxc, answer to day0 memory allocation
 * requests, and using a trampoline boot page to switch to the new page table.
 *
 * The procedure of the boot page is:
 * - map itself at the target position (that may overwrite some C stuff, but we
 *   do not care any more)
 * - jump there
 * - switch to the target page table
 * - unpin the old page table
 * - jump to the new kernel
 *
 * Samuel Thibault <Samuel.Thibault@eu.citrix.com>, May 2008
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <xc_dom.h>

#include <kernel.h>
#include <console.h>
#include <os.h>
#include <blkfront.h>
#include <netfront.h>
#include <fbfront.h>
#include <tpmfront.h>
#include <shared.h>
#include <byteswap.h>

#include "mini-os.h"

#if 0
#define DEBUG(fmt, ...) printk(fmt, ## __VA_ARGS__)
#else
#define DEBUG(fmt, ...) (void)0
#endif

/* Assembly boot page from boot.S */
extern void _boot_page;
extern pgentry_t _boot_page_entry;
extern unsigned long _boot_pdmfn;
extern unsigned long _boot_stack, _boot_target, _boot_start_info, _boot_start;
extern xen_pfn_t _boot_oldpdmfn;
extern void _boot(void);

static unsigned long *pages;
static unsigned long *pages_mfns;
static xen_pfn_t *pages_moved2pfns;
static unsigned long allocated;

int pin_table(xc_interface *xc_handle, unsigned int type, unsigned long mfn,
              domid_t dom);

#define TPM_TAG_RQU_COMMAND 0xC1
#define TPM_ORD_Extend 20

struct pcr_extend_cmd {
	uint16_t tag;
	uint32_t size;
	uint32_t ord;

	uint32_t pcr;
	unsigned char hash[20];
} __attribute__((packed));

struct pcr_extend_rsp {
	uint16_t tag;
	uint32_t size;
	uint32_t status;

	unsigned char hash[20];
} __attribute__((packed));

/* Not imported from polarssl's header since the prototype unhelpfully defines
 * the input as unsigned char, which causes pointer type mismatches */
void sha1(const void *input, size_t ilen, unsigned char output[20]);

/* We need mfn to appear as target_pfn, so exchange with the MFN there */
static void do_exchange(struct xc_dom_image *dom, xen_pfn_t target_pfn, xen_pfn_t source_mfn)
{
    xen_pfn_t source_pfn;
    xen_pfn_t target_mfn;

    for (source_pfn = 0; source_pfn < start_info.nr_pages; source_pfn++)
        if (dom->p2m_host[source_pfn] == source_mfn)
            break;
    ASSERT(source_pfn < start_info.nr_pages);

    target_mfn = dom->p2m_host[target_pfn];

    /* Put target MFN at source PFN */
    dom->p2m_host[source_pfn] = target_mfn;

    /* Put source MFN at target PFN */
    dom->p2m_host[target_pfn] = source_mfn;
}

int kexec_allocate(struct xc_dom_image *dom)
{
    unsigned long new_allocated = dom->pfn_alloc_end - dom->rambase_pfn;
    unsigned long i;

    pages = realloc(pages, new_allocated * sizeof(*pages));
    pages_mfns = realloc(pages_mfns, new_allocated * sizeof(*pages_mfns));
    pages_moved2pfns = realloc(pages_moved2pfns, new_allocated * sizeof(*pages_moved2pfns));
    for (i = allocated; i < new_allocated; i++) {
        /* Exchange old page of PFN i with a newly allocated page.  */
        xen_pfn_t old_mfn = dom->p2m_host[i];
        xen_pfn_t new_pfn;
        xen_pfn_t new_mfn;

        pages[i] = alloc_page();
        memset((void*) pages[i], 0, PAGE_SIZE);
        new_pfn = PHYS_PFN(to_phys(pages[i]));
        pages_mfns[i] = new_mfn = pfn_to_mfn(new_pfn);

	/*
	 * If PFN of newly allocated page (new_pfn) is less then currently
	 * requested PFN (i) then look for relevant PFN/MFN pair. In this
	 * situation dom->p2m_host[new_pfn] no longer contains proper MFN
	 * because original page with new_pfn was moved earlier
	 * to different location.
	 */
	for (; new_pfn < i; new_pfn = pages_moved2pfns[new_pfn]);

	/* Store destination PFN of currently requested page. */
	pages_moved2pfns[i] = new_pfn;

        /* Put old page at new PFN */
        dom->p2m_host[new_pfn] = old_mfn;

        /* Put new page at PFN i */
        dom->p2m_host[i] = new_mfn;
    }

    allocated = new_allocated;

    return 0;
}

/* Filled from mini-os command line or left as NULL */
char *vtpm_label;

static void tpm_hash2pcr(struct xc_dom_image *dom, char *cmdline)
{
	struct tpmfront_dev* tpm = init_tpmfront(NULL);
	struct pcr_extend_rsp *resp;
	size_t resplen = 0;
	struct pcr_extend_cmd cmd;
	int rv;

	/*
	 * If vtpm_label was specified on the command line, require a vTPM to be
	 * attached and for the domain providing the vTPM to have the given
	 * label.
	 */
	if (vtpm_label) {
		char ctx[128];
		if (!tpm) {
			printf("No TPM found and vtpm_label specified, aborting!\n");
			do_exit();
		}
		rv = evtchn_get_peercontext(tpm->evtchn, ctx, sizeof(ctx) - 1);
		if (rv < 0) {
			printf("Could not verify vtpm_label: %d\n", rv);
			do_exit();
		}
		ctx[127] = 0;
		rv = strcmp(ctx, vtpm_label);
		if (rv && vtpm_label[0] == '*') {
			int match_len = strlen(vtpm_label) - 1;
			int offset = strlen(ctx) - match_len;
			if (offset > 0)
				rv = strcmp(ctx + offset, vtpm_label + 1);
		}

		if (rv) {
			printf("Mismatched vtpm_label: '%s' != '%s'\n", ctx, vtpm_label);
			do_exit();
		}
	} else if (!tpm) {
		return;
	}

	cmd.tag = bswap_16(TPM_TAG_RQU_COMMAND);
	cmd.size = bswap_32(sizeof(cmd));
	cmd.ord = bswap_32(TPM_ORD_Extend);
	cmd.pcr = bswap_32(4); // PCR #4 for kernel
	sha1(dom->kernel_blob, dom->kernel_size, cmd.hash);

	rv = tpmfront_cmd(tpm, (void*)&cmd, sizeof(cmd), (void*)&resp, &resplen);
	ASSERT(rv == 0 && resp->status == 0);

	cmd.pcr = bswap_32(5); // PCR #5 for cmdline
	sha1(cmdline, strlen(cmdline), cmd.hash);
	rv = tpmfront_cmd(tpm, (void*)&cmd, sizeof(cmd), (void*)&resp, &resplen);
	ASSERT(rv == 0 && resp->status == 0);

	cmd.pcr = bswap_32(5); // PCR #5 for initrd
	sha1(dom->modules[0].blob, dom->modules[0].size, cmd.hash);
	rv = tpmfront_cmd(tpm, (void*)&cmd, sizeof(cmd), (void*)&resp, &resplen);
	ASSERT(rv == 0 && resp->status == 0);

	shutdown_tpmfront(tpm);
}

void kexec(void *kernel, long kernel_size, void *module, long module_size, char *cmdline, unsigned long flags)
{
    struct xc_dom_image *dom;
    int rc;
    domid_t domid = DOMID_SELF;
    xen_pfn_t pfn;
    xc_interface *xc_handle;
    unsigned long i;
    void *seg;
    xen_pfn_t boot_page_mfn = virt_to_mfn(&_boot_page);
    char features[] = "";
    struct mmu_update *m2p_updates;
    unsigned long nr_m2p_updates;

    DEBUG("booting with cmdline %s\n", cmdline);
    xc_handle = xc_interface_open(0,0,0);

    dom = xc_dom_allocate(xc_handle, cmdline, features);
    dom->allocate = kexec_allocate;

    /* We are using guest owned memory, therefore no limits. */
    xc_dom_kernel_max_size(dom, 0);
    xc_dom_module_max_size(dom, 0);

    dom->kernel_blob = kernel;
    dom->kernel_size = kernel_size;

    xc_dom_module_mem(dom, module, module_size, NULL);

    dom->flags = flags;
    dom->console_evtchn = start_info.console.domU.evtchn;
    dom->xenstore_evtchn = start_info.store_evtchn;

    tpm_hash2pcr(dom, cmdline);

    if ( (rc = xc_dom_boot_xen_init(dom, xc_handle, domid)) != 0 ) {
        printk("xc_dom_boot_xen_init returned %d\n", rc);
        errnum = ERR_BOOT_FAILURE;
        goto out;
    }
    if ( (rc = xc_dom_parse_image(dom)) != 0 ) {
        printk("xc_dom_parse_image returned %d\n", rc);
        errnum = ERR_BOOT_FAILURE;
        goto out;
    }

#ifdef __i386__
    if (strcmp(dom->guest_type, "xen-3.0-x86_32p")) {
        printk("can only boot x86 32 PAE kernels, not %s\n", dom->guest_type);
        errnum = ERR_EXEC_FORMAT;
        goto out;
    }
#endif
#ifdef __x86_64__
    if (strcmp(dom->guest_type, "xen-3.0-x86_64")) {
        printk("can only boot x86 64 kernels, not %s\n", dom->guest_type);
        errnum = ERR_EXEC_FORMAT;
        goto out;
    }
#endif

    /* equivalent of xc_dom_mem_init */
    if (xc_dom_set_arch_hooks(dom)) {
        printk("xc_dom_set_arch_hooks failed\n");
        errnum = ERR_EXEC_FORMAT;
        goto out;
    }
    dom->total_pages = start_info.nr_pages;

    /* equivalent of arch_setup_meminit */
    dom->p2m_size = dom->total_pages;

    /* setup initial p2m */
    dom->p2m_host = malloc(sizeof(*dom->p2m_host) * dom->p2m_size);

    /* Start with our current P2M */
    for (i = 0; i < dom->p2m_size; i++)
        dom->p2m_host[i] = pfn_to_mfn(i);

    if ( (rc = xc_dom_build_image(dom)) != 0 ) {
        printk("xc_dom_build_image returned %d\n", rc);
        errnum = ERR_BOOT_FAILURE;
        goto out;
    }

    /* copy hypercall page */
    /* TODO: domctl instead, but requires privileges */
    if (dom->parms.virt_hypercall != -1) {
        pfn = PHYS_PFN(dom->parms.virt_hypercall - dom->parms.virt_base);
        memcpy((void *) pages[pfn], hypercall_page, PAGE_SIZE);
    }

    /* Equivalent of xc_dom_boot_image */
    dom->shared_info_mfn = PHYS_PFN(start_info.shared_info);

    if (!xc_dom_compat_check(dom)) {
        printk("xc_dom_compat_check failed\n");
        errnum = ERR_EXEC_FORMAT;
        goto out;
    }

    /* Move current console, xenstore and boot MFNs to the allocated place */
    do_exchange(dom, dom->console_pfn, start_info.console.domU.mfn);
    do_exchange(dom, dom->xenstore_pfn, start_info.store_mfn);
    DEBUG("virt base at %llx\n", dom->parms.virt_base);
    DEBUG("bootstack_pfn %lx\n", dom->bootstack_pfn);
    _boot_target = dom->parms.virt_base + PFN_PHYS(dom->bootstack_pfn);
    DEBUG("_boot_target %lx\n", _boot_target);
    do_exchange(dom, PHYS_PFN(_boot_target - dom->parms.virt_base),
            virt_to_mfn(&_boot_page));

    if ( dom->arch_hooks->setup_pgtables )
        if ( (rc = dom->arch_hooks->setup_pgtables(dom))) {
            printk("setup_pgtables returned %d\n", rc);
            errnum = ERR_BOOT_FAILURE;
            goto out;
        }

    /* start info page */
#undef start_info
    if ( dom->arch_hooks->start_info )
        dom->arch_hooks->start_info(dom);
#define start_info (start_info_union.start_info)

    xc_dom_log_memory_footprint(dom);

    /* Unmap libxc's projection of the boot page table */
    seg = xc_dom_seg_to_ptr(dom, &dom->pgtables_seg);
    munmap(seg, dom->pgtables_seg.vend - dom->pgtables_seg.vstart);
    seg = xc_dom_seg_to_ptr(dom, &dom->p2m_seg);
    munmap(seg, dom->p2m_seg.vend - dom->p2m_seg.vstart);

    /* Unmap day0 pages to avoid having a r/w mapping of the future page table */
    for (pfn = 0; pfn < allocated; pfn++)
        munmap((void*) pages[pfn], PAGE_SIZE);

    /* Pin the boot page table base */
    if ( (rc = pin_table(dom->xch,
#ifdef __i386__
                MMUEXT_PIN_L3_TABLE,
#endif
#ifdef __x86_64__
                MMUEXT_PIN_L4_TABLE,
#endif
                xc_dom_p2m(dom, dom->pgtables_seg.pfn),
                dom->guest_domid)) != 0 ) {
        printk("pin_table(%lx) returned %d\n", xc_dom_p2m(dom,
               dom->pgtables_seg.pfn), rc);
        errnum = ERR_BOOT_FAILURE;
        goto out_remap;
    }

    /* We populate the Mini-OS page table here so that boot.S can just call
     * update_va_mapping to project itself there.  */
    need_pgt(_boot_target);
    DEBUG("day0 pages %lx\n", allocated);
    DEBUG("boot target page %lx\n", _boot_target);
    DEBUG("boot page %p\n", &_boot_page);
    DEBUG("boot page mfn %lx\n", boot_page_mfn);
    _boot_page_entry = PFN_PHYS(boot_page_mfn) | L1_PROT;
    DEBUG("boot page entry %llx\n", _boot_page_entry);
    _boot_oldpdmfn = virt_to_mfn(start_info.pt_base);
    DEBUG("boot old pd mfn %lx\n", _boot_oldpdmfn);
    DEBUG("boot pd virt %lx\n", dom->pgtables_seg.vstart);
    _boot_pdmfn = dom->p2m_host[PHYS_PFN(dom->pgtables_seg.vstart - dom->parms.virt_base)];
    DEBUG("boot pd mfn %lx\n", _boot_pdmfn);
    _boot_stack = _boot_target + PAGE_SIZE;
    DEBUG("boot stack %lx\n", _boot_stack);
    _boot_start_info = dom->parms.virt_base + PFN_PHYS(dom->start_info_pfn);
    DEBUG("boot start info %lx\n", _boot_start_info);
    _boot_start = dom->parms.virt_entry;
    DEBUG("boot start %lx\n", _boot_start);

    /* Keep only useful entries */
    for (nr_m2p_updates = pfn = 0; pfn < start_info.nr_pages; pfn++)
        if (dom->p2m_host[pfn] != pfn_to_mfn(pfn))
            nr_m2p_updates++;

    m2p_updates = malloc(sizeof(*m2p_updates) * nr_m2p_updates);
    for (i = pfn = 0; pfn < start_info.nr_pages; pfn++)
        if (dom->p2m_host[pfn] != pfn_to_mfn(pfn)) {
            m2p_updates[i].ptr = PFN_PHYS(dom->p2m_host[pfn]) | MMU_MACHPHYS_UPDATE;
            m2p_updates[i].val = pfn;
            i++;
        }

    for (i = 0; i < blk_nb; i++)
        shutdown_blkfront(blk_dev[i]);
    if (net_dev)
        shutdown_netfront(net_dev);
    if (kbd_dev)
        shutdown_kbdfront(kbd_dev);
    stop_kernel();

    /* Update M2P */
    if ((rc = HYPERVISOR_mmu_update(m2p_updates, nr_m2p_updates, NULL, DOMID_SELF)) < 0) {
        xprintk("Could not update M2P\n");
        ASSERT(0);
    }

    xprintk("go!\n");

    /* Jump to trampoline boot page */
    _boot();

    ASSERT(0);

out_remap:
    for (pfn = 0; pfn < allocated; pfn++)
        do_map_frames(pages[pfn], &pages_mfns[pfn], 1, 0, 0, DOMID_SELF, 0, L1_PROT);
out:
    xc_dom_release(dom);
    for (pfn = 0; pfn < allocated; pfn++)
        free_page((void*)pages[pfn]);
    free(pages);
    free(pages_mfns);
    pages = NULL;
    pages_mfns = NULL;
    allocated = 0;
    xc_interface_close(xc_handle );
}
