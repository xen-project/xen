/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright IBM Corporation 2006, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Ryan Harper <ryanh@us.ibm.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <inttypes.h>

#include <xen/xen.h>
#include <xen/memory.h>
#include <xc_private.h>
#include <xg_private.h>
#include <xenctrl.h>

#include "flatdevtree_env.h"
#include "flatdevtree.h"
#include "utils.h"
#include "mk_flatdevtree.h"

#define INITRD_ADDR (24UL << 20)
#define DEVTREE_ADDR (16UL << 20)

static int init_boot_vcpu(
    int xc_handle,
    int domid,
    struct domain_setup_info *dsi,
    unsigned long devtree_addr,
    unsigned long kern_addr)
{
    vcpu_guest_context_t ctxt;
    int rc;

    memset(&ctxt.user_regs, 0x55, sizeof(ctxt.user_regs));
    ctxt.user_regs.pc = dsi->v_kernentry;
    ctxt.user_regs.msr = 0;
    ctxt.user_regs.gprs[1] = 0; /* Linux uses its own stack */
    ctxt.user_regs.gprs[3] = devtree_addr;
    ctxt.user_regs.gprs[4] = kern_addr;
    ctxt.user_regs.gprs[5] = 0;
    /* There is a buggy kernel that does not zero the "local_paca", so
     * we must make sure this register is 0 */
    ctxt.user_regs.gprs[13] = 0;

    DPRINTF("xc_vcpu_setvcpucontext:\n"
                 "  pc 0x%016"PRIx64", msr 0x%016"PRIx64"\n"
                 "  r1-5 %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64
                 " %016"PRIx64"\n",
                 ctxt.user_regs.pc, ctxt.user_regs.msr,
                 ctxt.user_regs.gprs[1],
                 ctxt.user_regs.gprs[2],
                 ctxt.user_regs.gprs[3],
                 ctxt.user_regs.gprs[4],
                 ctxt.user_regs.gprs[5]);
    rc = xc_vcpu_setcontext(xc_handle, domid, 0, &ctxt);
    if (rc < 0)
        perror("setdomaininfo");

    return rc;
}

static int load_initrd(
    int xc_handle,
    int domid,
    xen_pfn_t *page_array,
    const char *initrd_path,
    unsigned long *base,
    unsigned long *len)
{
    uint8_t *initrd_img;
    int rc = -1;

    /* load the initrd file */
    initrd_img = load_file(initrd_path, len);
    if (initrd_img == NULL)
        return -1;

    DPRINTF("copying initrd to 0x%lx[0x%lx]\n", INITRD_ADDR, *len);
    if (install_image(xc_handle, domid, page_array, initrd_img, INITRD_ADDR,
                *len))
        goto out;

    *base = INITRD_ADDR;
    rc = 0;

out:
    free(initrd_img);
    return rc;
}

static void free_page_array(xen_pfn_t *page_array)
{
    free(page_array);
}

static int check_memory_config(int rma_log, unsigned int mem_mb)
{
    u64 mem_kb = (mem_mb << 10);
    u64 rma_kb = (1 << rma_log) >> 10;

    switch(rma_log)
    {
        case 26:
        case 27:
        case 28:
        case 30:
        case 34:
        case 38:
            if (mem_kb < rma_kb) {
                DPRINTF("Domain memory must be at least %dMB\n", 
                        (1 << rma_log)>>20);
                break;
            }

            if (mem_kb % (16 << 10)) {
                DPRINTF("Domain memory %dMB must be a multiple of 16MB\n",
                        mem_mb);
                       
                break;
            }

            /* rma_log and mem_mb OK */
            return 0;

        default:
            DPRINTF("Invalid rma_log (%d)\n", rma_log);
    }

    return 1;
}

int xc_linux_build(int xc_handle,
                   uint32_t domid,
                   unsigned int mem_mb,
                   const char *image_name,
                   const char *initrd_name,
                   const char *cmdline,
                   const char *features,
                   unsigned long flags,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn,
                   unsigned int console_evtchn,
                   unsigned long *console_mfn)
{
    struct domain_setup_info dsi;
    xen_pfn_t *page_array = NULL;
    unsigned long nr_pages;
    unsigned long devtree_addr = 0;
    unsigned long kern_addr;
    unsigned long initrd_base = 0;
    unsigned long initrd_len = 0;
    unsigned long rma_pages;
    unsigned long shadow_mb;
    u64 shared_info_paddr;
    u64 store_paddr;
    u64 console_paddr;
    u32 remaining_kb;
    u32 extent_order;
    u64 nr_extents;
    int rma_log = 26;  /* 64MB RMA */
    int rc = 0;
    int op;
    struct ft_cxt devtree;

    DPRINTF("%s\n", __func__);

    nr_pages = mem_mb << (20 - PAGE_SHIFT);
    DPRINTF("nr_pages 0x%lx\n", nr_pages);

    rma_pages = (1 << rma_log) >> PAGE_SHIFT;
    if (rma_pages == 0) {
        rc = -1;
        goto out;
    }

    /* validate rma_log and domain memory config */
    if (check_memory_config(rma_log, mem_mb)) {
        rc = -1;
        goto out;
    }
    
    /* alloc RMA */
    if (xc_alloc_real_mode_area(xc_handle, domid, rma_log)) {
        rc = -1;
        goto out;
    }

    /* subtract already allocated RMA to determine remaining KB to alloc */
    remaining_kb = (nr_pages - rma_pages) * (PAGE_SIZE / 1024);
    DPRINTF("totalmem - RMA = %dKB\n", remaining_kb);

    /* to allocate in 16MB chunks, we need to determine the order of 
     * the number of PAGE_SIZE pages contained in 16MB. */
    extent_order = 24 - 12; /* extent_order = log2((1 << 24) - (1 << 12)) */
    nr_extents = (remaining_kb / (PAGE_SIZE/1024)) >> extent_order;
    DPRINTF("allocating memory in %llu chunks of %luMB\n", nr_extents,
            (((1 << extent_order) >> 10) * PAGE_SIZE) >> 10);

    /* now allocate the remaining memory as large-order allocations */
    DPRINTF("increase_reservation(%u, %llu, %u)\n", domid, nr_extents, extent_order);
    if (xc_domain_memory_increase_reservation(xc_handle, domid, nr_extents, 
                                              extent_order, 0, NULL)) {
        rc = -1;
        goto out;
    }

    if (get_rma_page_array(xc_handle, domid, &page_array, rma_pages)) {
        rc = -1;
        goto out;
    }

    DPRINTF("loading image '%s'\n", image_name);
    if (load_elf_kernel(xc_handle, domid, image_name, &dsi, page_array)) {
        rc = -1;
        goto out;
    }
    kern_addr = 0;

    if (initrd_name && initrd_name[0] != '\0') {
        DPRINTF("loading initrd '%s'\n", initrd_name);
        if (load_initrd(xc_handle, domid, page_array, initrd_name,
                &initrd_base, &initrd_len)) {
            rc = -1;
            goto out;
        }
    }

    /* fetch the current shadow_memory value for this domain */
    op = XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION;
    if (xc_shadow_control(xc_handle, domid, op, NULL, 0, 
                          &shadow_mb, 0, NULL) < 0 ) {
        rc = -1;
        goto out;
    }

    /* determine shared_info, console, and store paddr */
    shared_info_paddr = (rma_pages << PAGE_SHIFT) - PAGE_SIZE;
    console_paddr = shared_info_paddr - PAGE_SIZE;
    store_paddr = console_paddr - PAGE_SIZE;

    /* map paddrs to mfns */
    *store_mfn = page_array[(xen_pfn_t)(store_paddr >> PAGE_SHIFT)];
    *console_mfn = page_array[(xen_pfn_t)(console_paddr >> PAGE_SHIFT)];
    DPRINTF("console_mfn->%08lx store_mfn->%08lx\n", *console_mfn,
            *store_mfn);

    /* build the devtree here */
    DPRINTF("constructing devtree\n");
    if (make_devtree(&devtree, domid, mem_mb, (rma_pages << PAGE_SHIFT),
                     shadow_mb, initrd_base, initrd_len, cmdline, 
                     shared_info_paddr, console_evtchn, console_paddr,
                     store_evtchn, store_paddr) < 0) {
        DPRINTF("failed to create flattened device tree\n");
        rc = -1;
        goto out;
    }

    devtree_addr = DEVTREE_ADDR;
    DPRINTF("loading flattened device tree to 0x%lx[0x%x]\n",
            devtree_addr, devtree.bph->totalsize);

    if (install_image(xc_handle, domid, page_array, (void *)devtree.bph,
                      devtree_addr, devtree.bph->totalsize)) {
        DPRINTF("couldn't load flattened device tree.\n");
        rc = -1;
        goto out;
    }

    if (init_boot_vcpu(xc_handle, domid, &dsi, devtree_addr, kern_addr)) {
        rc = -1;
        goto out;
    }

out:
    free_devtree(&devtree);
    free_page_array(page_array);
    return rc;
}
