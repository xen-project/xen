/******************************************************************************
 * xc_hvm_restore.c
 *
 * Restore the state of a HVM guest.
 *
 * Copyright (c) 2003, K A Fraser.
 * Copyright (c) 2006 Intel Corperation
 * rewriten for hvm guest by Zhai Edwin <edwin.zhai@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"
#include "xg_save_restore.h"

#include <xen/hvm/ioreq.h>
#include <xen/hvm/params.h>
#include <xen/hvm/e820.h>

/* max mfn of the whole machine */
static unsigned long max_mfn;

/* virtual starting address of the hypervisor */
static unsigned long hvirt_start;

/* #levels of page tables used by the currrent guest */
static unsigned int pt_levels;

/* A list of PFNs that exist, used when allocating memory to the guest */
static xen_pfn_t *pfns = NULL;

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

int xc_hvm_restore(int xc_handle, int io_fd,
                     uint32_t dom, unsigned long max_pfn,
                     unsigned int store_evtchn, unsigned long *store_mfn,
                     unsigned int pae, unsigned int apic)
{
    DECLARE_DOMCTL;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    char *region_base;

    unsigned long buf[PAGE_SIZE/sizeof(unsigned long)];

    xc_dominfo_t info;
    unsigned int rc = 1, n, i;
    uint32_t rec_len, nr_vcpus;
    uint8_t *hvm_buf = NULL;
    unsigned long long v_end, memsize;
    unsigned long shared_page_nr;

    unsigned long pfn;
    unsigned int prev_pc, this_pc;
    int verify = 0;

    /* Types of the pfns in the current region */
    unsigned long region_pfn_type[MAX_BATCH_SIZE];

    struct xen_add_to_physmap xatp;

    /* Number of pages of memory the guest has.  *Not* the same as max_pfn. */
    unsigned long nr_pages;

    /* hvm guest mem size (Mb) */
    memsize = (unsigned long long)*store_mfn;
    v_end = memsize << 20;
    nr_pages = (unsigned long) memsize << (20 - PAGE_SHIFT);

    DPRINTF("xc_hvm_restore:dom=%d, nr_pages=0x%lx, store_evtchn=%d, *store_mfn=%ld, pae=%u, apic=%u.\n", 
            dom, nr_pages, store_evtchn, *store_mfn, pae, apic);

    
    if(!get_platform_info(xc_handle, dom,
                          &max_mfn, &hvirt_start, &pt_levels)) {
        ERROR("Unable to get platform info.");
        return 1;
    }

    DPRINTF("xc_hvm_restore start: nr_pages = %lx, max_pfn = %lx, max_mfn = %lx, hvirt_start=%lx, pt_levels=%d\n",
            nr_pages,
            max_pfn,
            max_mfn,
            hvirt_start,
            pt_levels);

    if (mlock(&ctxt, sizeof(ctxt))) {
        /* needed for build dom0 op, but might as well do early */
        ERROR("Unable to mlock ctxt");
        return 1;
    }


    pfns = malloc(max_pfn * sizeof(xen_pfn_t));
    if (pfns == NULL) {
        ERROR("memory alloc failed");
        errno = ENOMEM;
        goto out;
    }

    if(xc_domain_setmaxmem(xc_handle, dom, PFN_TO_KB(nr_pages)) != 0) {
        errno = ENOMEM;
        goto out;
    }

    for ( i = 0; i < max_pfn; i++ )
        pfns[i] = i;
    for ( i = HVM_BELOW_4G_RAM_END >> PAGE_SHIFT; i < max_pfn; i++ )
        pfns[i] += HVM_BELOW_4G_MMIO_LENGTH >> PAGE_SHIFT;

    /* Allocate memory for HVM guest, skipping VGA hole 0xA0000-0xC0000. */
    rc = xc_domain_memory_populate_physmap(
        xc_handle, dom, (nr_pages > 0xa0) ? 0xa0 : nr_pages,
        0, 0, &pfns[0x00]);
    if ( (rc == 0) && (nr_pages > 0xc0) )
        rc = xc_domain_memory_populate_physmap(
            xc_handle, dom, nr_pages - 0xc0, 0, 0, &pfns[0xc0]);
    if ( rc != 0 )
    {
        PERROR("Could not allocate memory for HVM guest.\n");
        goto out;
    }


    /**********XXXXXXXXXXXXXXXX******************/
    if (xc_domain_getinfo(xc_handle, dom, 1, &info) != 1) {
        ERROR("Could not get domain info");
        return 1;
    }

    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)dom;
    if (xc_domctl(xc_handle, &domctl) < 0) {
        ERROR("Could not get information on new domain");
        goto out;
    }

    prev_pc = 0;

    n = 0;
    while (1) {

        int j;

        this_pc = (n * 100) / nr_pages;
        if ( (this_pc - prev_pc) >= 5 )
        {
            PPRINTF("\b\b\b\b%3d%%", this_pc);
            prev_pc = this_pc;
        }

        if (!read_exact(io_fd, &j, sizeof(int))) {
            ERROR("HVM restore Error when reading batch size");
            goto out;
        }

        PPRINTF("batch %d\n",j);

        if (j == -1) {
            verify = 1;
            DPRINTF("Entering page verify mode\n");
            continue;
        }

        if (j == 0)
            break;  /* our work here is done */

        if (j > MAX_BATCH_SIZE) {
            ERROR("Max batch size exceeded. Giving up.");
            goto out;
        }

        if (!read_exact(io_fd, region_pfn_type, j*sizeof(unsigned long))) {
            ERROR("Error when reading region pfn types");
            goto out;
        }

        region_base = xc_map_foreign_batch(
            xc_handle, dom, PROT_WRITE, region_pfn_type, j);

        for ( i = 0; i < j; i++ )
        {
            void *page;

            pfn = region_pfn_type[i];
            if ( pfn > max_pfn )
            {
                ERROR("pfn out of range");
                goto out;
            }

            if ( pfn >= 0xa0 && pfn < 0xc0) {
                ERROR("hvm restore:pfn in vga hole");
                goto out;
            }


            /* In verify mode, we use a copy; otherwise we work in place */
            page = verify ? (void *)buf : (region_base + i*PAGE_SIZE);

            if (!read_exact(io_fd, page, PAGE_SIZE)) {
                ERROR("Error when reading page (%x)", i);
                goto out;
            }

            if (verify) {

                int res = memcmp(buf, (region_base + i*PAGE_SIZE), PAGE_SIZE);

                if (res) {

                    int v;

                    DPRINTF("************** pfn=%lx gotcs=%08lx "
                            "actualcs=%08lx\n", pfn, 
                            csum_page(region_base + i*PAGE_SIZE),
                            csum_page(buf));

                    for (v = 0; v < 4; v++) {

                        unsigned long *p = (unsigned long *)
                            (region_base + i*PAGE_SIZE);
                        if (buf[v] != p[v])
                            DPRINTF("    %d: %08lx %08lx\n", v, buf[v], p[v]);
                    }
                }
            }

        } /* end of 'batch' for loop */
        munmap(region_base, j*PAGE_SIZE);
        n+= j; /* crude stats */

    }/*while 1*/
    
/*    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_APIC_ENABLED, apic);*/
    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_PAE_ENABLED, pae);
    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_STORE_EVTCHN, store_evtchn);

    if ( v_end > HVM_BELOW_4G_RAM_END )
        shared_page_nr = (HVM_BELOW_4G_RAM_END >> PAGE_SHIFT) - 1;
    else
        shared_page_nr = (v_end >> PAGE_SHIFT) - 1;

    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_STORE_PFN, shared_page_nr-1);
    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_BUFIOREQ_PFN, shared_page_nr-2);
    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_IOREQ_PFN, shared_page_nr);

    /* caculate the store_mfn , wrong val cause hang when introduceDomain */
    *store_mfn = (v_end >> PAGE_SHIFT) - 2;
    DPRINTF("hvm restore:calculate new store_mfn=0x%lx,v_end=0x%llx..\n", *store_mfn, v_end);

    /* restore hvm context including pic/pit/shpage */
    if (!read_exact(io_fd, &rec_len, sizeof(uint32_t))) {
        ERROR("error read hvm context size!\n");
        goto out;
    }

    hvm_buf = malloc(rec_len);
    if (hvm_buf == NULL) {
        ERROR("memory alloc for hvm context buffer failed");
        errno = ENOMEM;
        goto out;
    }

    if (!read_exact(io_fd, hvm_buf, rec_len)) {
        ERROR("error read hvm buffer!\n");
        goto out;
    }

    if (( rc = xc_domain_hvm_setcontext(xc_handle, dom, hvm_buf, rec_len))) {
        ERROR("error set hvm buffer!\n");
        goto out;
    }

    if (!read_exact(io_fd, &nr_vcpus, sizeof(uint32_t))) {
        ERROR("error read nr vcpu !\n");
        goto out;
    }
    DPRINTF("hvm restore:get nr_vcpus=%d.\n", nr_vcpus);

    for (i =0; i < nr_vcpus; i++) {
        if (!read_exact(io_fd, &rec_len, sizeof(uint32_t))) {
            ERROR("error read vcpu context size!\n");
            goto out;
        }
        if (rec_len != sizeof(ctxt)) {
            ERROR("vcpu context size dismatch!\n");
            goto out;
        }

        if (!read_exact(io_fd, &(ctxt), sizeof(ctxt))) {
            ERROR("error read vcpu context.\n");
            goto out;
        }

        if ( (rc = xc_vcpu_setcontext(xc_handle, dom, i, &ctxt)) ) {
            ERROR("Could not set vcpu context, rc=%d", rc);
            goto out;
        }
    }

    /* Shared-info pfn */
    if (!read_exact(io_fd, &(shared_info_frame), sizeof(uint32_t)) ) {
        ERROR("reading the shared-info pfn failed!\n");
        goto out;
    }
    /* Map the shared-info frame where it was before */
    xatp.domid = dom;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.idx   = 0;
    xatp.gpfn  = shared_info_frame;
    if ( (rc = xc_memory_op(xc_handle, XENMEM_add_to_physmap, &xatp)) != 0 ) {
        ERROR("setting the shared-info pfn failed!\n");
        goto out;
    }

    rc = 0;
    goto out;

 out:
    if ( (rc != 0) && (dom != 0) )
        xc_domain_destroy(xc_handle, dom);
    free(pfns);
    free(hvm_buf);

    DPRINTF("Restore exit with rc=%d\n", rc);

    return rc;
}
