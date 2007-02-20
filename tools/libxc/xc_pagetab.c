/******************************************************************************
 * xc_pagetab.c
 *
 * Function to translate virtual to physical addresses.
 */
#include "xc_private.h"

#if defined(__i386__)

#define L1_PAGETABLE_SHIFT_PAE	12
#define L2_PAGETABLE_SHIFT_PAE	21
#define L3_PAGETABLE_SHIFT_PAE	30

#define L1_PAGETABLE_SHIFT		12
#define L2_PAGETABLE_SHIFT		22

#define L0_PAGETABLE_MASK_PAE	0x00000ffffffff000ULL
#define L1_PAGETABLE_MASK_PAE	0x1ffULL
#define L2_PAGETABLE_MASK_PAE	0x1ffULL
#define L3_PAGETABLE_MASK_PAE	0x3ULL

#define L0_PAGETABLE_MASK		0xfffff000ULL
#define L1_PAGETABLE_MASK		0x3ffULL
#define L2_PAGETABLE_MASK		0x3ffULL

#elif defined(__x86_64__)

#define L1_PAGETABLE_SHIFT_PAE	12
#define L2_PAGETABLE_SHIFT_PAE	21
#define L3_PAGETABLE_SHIFT_PAE	30
#define L4_PAGETABLE_SHIFT_PAE	39

#define L1_PAGETABLE_SHIFT		L1_PAGETABLE_SHIFT_PAE
#define L2_PAGETABLE_SHIFT		L2_PAGETABLE_SHIFT_PAE

#define L0_PAGETABLE_MASK_PAE	0x000ffffffffff000ULL
#define L1_PAGETABLE_MASK_PAE	0x1ffULL
#define L2_PAGETABLE_MASK_PAE	0x1ffULL
#define L3_PAGETABLE_MASK_PAE	0x1ffULL
#define L4_PAGETABLE_MASK_PAE	0x1ffULL

#define L0_PAGETABLE_MASK		L0_PAGETABLE_MASK_PAE
#define L1_PAGETABLE_MASK		L1_PAGETABLE_MASK_PAE
#define L2_PAGETABLE_MASK		L2_PAGETABLE_MASK_PAE

#endif

unsigned long xc_translate_foreign_address(int xc_handle, uint32_t dom,
                                           int vcpu, unsigned long long virt )
{
    vcpu_guest_context_t ctx;
    unsigned long long cr3;
    void *pd, *pt, *pdppage = NULL, *pdp, *pml = NULL;
    unsigned long long pde, pte, pdpe, pmle;
    unsigned long mfn = 0;
#if defined (__i386__)
    static int pt_levels = 0;

    if (pt_levels == 0) {
        xen_capabilities_info_t xen_caps = "";

        if (xc_version(xc_handle, XENVER_capabilities, &xen_caps) != 0)
            goto out;
        if (strstr(xen_caps, "xen-3.0-x86_64"))
            pt_levels = 4;
        else if (strstr(xen_caps, "xen-3.0-x86_32p"))
            pt_levels = 3;
        else if (strstr(xen_caps, "xen-3.0-x86_32"))
            pt_levels = 2;
        else
            goto out;
    }
#elif defined (__x86_64__)
#define pt_levels 4
#endif

    if (xc_vcpu_getcontext(xc_handle, dom, vcpu, &ctx) != 0) {
        DPRINTF("failed to retreive vcpu context\n");
        goto out;
    }
    cr3 = ((unsigned long long)xen_cr3_to_pfn(ctx.ctrlreg[3])) << PAGE_SHIFT;

    /* Page Map Level 4 */

#if defined(__i386__)
    pmle = cr3;
#elif defined(__x86_64__)
    pml = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, PROT_READ, cr3 >> PAGE_SHIFT);
    if (pml == NULL) {
        DPRINTF("failed to map PML4\n");
        goto out;
    }
    pmle = *(unsigned long long *)(pml + 8 * ((virt >> L4_PAGETABLE_SHIFT_PAE) & L4_PAGETABLE_MASK_PAE));
    if((pmle & 1) == 0) {
        DPRINTF("page entry not present in PML4\n");
        goto out_unmap_pml;
    }
#endif

    /* Page Directory Pointer Table */

    if (pt_levels >= 3) {
        pdppage = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, PROT_READ, pmle >> PAGE_SHIFT);
        if (pdppage == NULL) {
            DPRINTF("failed to map PDP\n");
            goto out_unmap_pml;
        }
        if (pt_levels >= 4)
            pdp = pdppage;
        else
            /* PDP is only 32 bit aligned with 3 level pts */
            pdp = pdppage + (pmle & ~(XC_PAGE_MASK | 0x1f));

        pdpe = *(unsigned long long *)(pdp + 8 * ((virt >> L3_PAGETABLE_SHIFT_PAE) & L3_PAGETABLE_MASK_PAE));

        if((pdpe & 1) == 0) {
            DPRINTF("page entry not present in PDP\n");
            goto out_unmap_pdp;
        }
    } else {
        pdpe = pmle;
    }

    /* Page Directory */

    pd = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, PROT_READ, pdpe >> PAGE_SHIFT);
    if (pd == NULL) {
        DPRINTF("failed to map PD\n");
        goto out_unmap_pdp;
    }

    if (pt_levels >= 3)
        pde = *(unsigned long long *)(pd + 8 * ((virt >> L2_PAGETABLE_SHIFT_PAE) & L2_PAGETABLE_MASK_PAE));
    else
        pde = *(unsigned long long *)(pd + 4 * ((virt >> L2_PAGETABLE_SHIFT) & L2_PAGETABLE_MASK));

    if ((pde & 1) == 0) {
        DPRINTF("page entry not present in PD\n");
        goto out_unmap_pd;
    }

    /* Page Table */

    if (pde & 0x00000008) { /* 4M page (or 2M in PAE mode) */
        DPRINTF("Cannot currently cope with 2/4M pages\n");
        exit(-1);
    } else { /* 4k page */
        pt = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, PROT_READ,
                                  pde >> PAGE_SHIFT);

        if (pt == NULL) {
            DPRINTF("failed to map PT\n");
            goto out_unmap_pd;
        }

        if (pt_levels >= 3)
            pte = *(unsigned long long *)(pt + 8 * ((virt >> L1_PAGETABLE_SHIFT_PAE) & L1_PAGETABLE_MASK_PAE));
        else
            pte = *(unsigned long long *)(pt + 4 * ((virt >> L1_PAGETABLE_SHIFT) & L1_PAGETABLE_MASK));

        if ((pte & 0x00000001) == 0) {
            DPRINTF("page entry not present in PT\n");
            goto out_unmap_pt;
        }

        if (pt_levels >= 3)
            mfn = (pte & L0_PAGETABLE_MASK_PAE) >> PAGE_SHIFT;
        else
            mfn = (pte & L0_PAGETABLE_MASK) >> PAGE_SHIFT;
    }

 out_unmap_pt:
    munmap(pt, PAGE_SIZE);
 out_unmap_pd:
    munmap(pd, PAGE_SIZE);
 out_unmap_pdp:
    munmap(pdppage, PAGE_SIZE);
 out_unmap_pml:
    munmap(pml, PAGE_SIZE);
 out:
    return mfn;
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
