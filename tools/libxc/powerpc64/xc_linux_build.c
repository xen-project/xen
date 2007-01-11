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
 * Copyright (C) IBM Corporation 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
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

static int load_devtree(
    int xc_handle,
    int domid,
    xen_pfn_t *page_array,
    void *devtree,
    unsigned long devtree_addr,
    uint64_t initrd_base,
    unsigned long initrd_len,
    start_info_t *start_info __attribute__((unused)),
    unsigned long start_info_addr)
{
    uint32_t si[4] = {0, start_info_addr, 0, 0x1000};
    struct boot_param_header *header;
    void *chosen;
    void *xen;
    uint64_t initrd_end = initrd_base + initrd_len;
    unsigned int devtree_size;
    int rc = 0;

    DPRINTF("adding initrd props\n");

    chosen = ft_find_node(devtree, "/chosen");
    if (chosen == NULL) {
        DPRINTF("couldn't find /chosen\n");
        return -1;
    }

    xen = ft_find_node(devtree, "/xen");
    if (xen == NULL) {
        DPRINTF("couldn't find /xen\n");
        return -1;
    }

    /* initrd-start */
    rc = ft_set_prop(&devtree, chosen, "linux,initrd-start",
            &initrd_base, sizeof(initrd_base));
    if (rc < 0) {
        DPRINTF("couldn't set /chosen/linux,initrd-start\n");
        return rc;
    }

    /* initrd-end */
    rc = ft_set_prop(&devtree, chosen, "linux,initrd-end",
            &initrd_end, sizeof(initrd_end));
    if (rc < 0) {
        DPRINTF("couldn't set /chosen/linux,initrd-end\n");
        return rc;
    }

    rc = ft_set_rsvmap(devtree, 1, initrd_base, initrd_len);
    if (rc < 0) {
        DPRINTF("couldn't set initrd reservation\n");
        return ~0UL;
    }

    /* start-info (XXX being removed soon) */
    rc = ft_set_prop(&devtree, xen, "start-info", si, sizeof(si));
    if (rc < 0) {
        DPRINTF("couldn't set /xen/start-info\n");
        return rc;
    }

    header = devtree;
    devtree_size = header->totalsize;
    {
        static const char dtb[] = "/tmp/xc_domU.dtb";
        int dfd = creat(dtb, 0666);
        if (dfd != -1) {
            write(dfd, devtree, devtree_size);
            close(dfd);
        } else
            DPRINTF("could not open(\"%s\")\n", dtb);
    }

    DPRINTF("copying device tree to 0x%lx[0x%x]\n", DEVTREE_ADDR, devtree_size);
    return install_image(xc_handle, domid, page_array, devtree, DEVTREE_ADDR,
                       devtree_size);
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

static unsigned long create_start_info(
    void *devtree, start_info_t *start_info,
        unsigned int console_evtchn, unsigned int store_evtchn,
    unsigned long nr_pages, unsigned long rma_pages)
{
    unsigned long start_info_addr;
    uint64_t rma_top;
    int rc;

    memset(start_info, 0, sizeof(*start_info));
    snprintf(start_info->magic, sizeof(start_info->magic),
             "xen-%d.%d-powerpc64HV", 3, 0);

    rma_top = rma_pages << PAGE_SHIFT;
    DPRINTF("RMA top = 0x%"PRIX64"\n", rma_top);

    start_info->nr_pages = nr_pages;
    start_info->shared_info = rma_top - PAGE_SIZE;
    start_info->store_mfn = (rma_top >> PAGE_SHIFT) - 2;
    start_info->store_evtchn = store_evtchn;
    start_info->console.domU.mfn = (rma_top >> PAGE_SHIFT) - 3;
    start_info->console.domU.evtchn = console_evtchn;
    start_info_addr = rma_top - 4*PAGE_SIZE;

    rc = ft_set_rsvmap(devtree, 0, start_info_addr, 4*PAGE_SIZE);
    if (rc < 0) {
        DPRINTF("couldn't set start_info reservation\n");
        return ~0UL;
    }


    return start_info_addr;
}

static void free_page_array(xen_pfn_t *page_array)
{
    free(page_array);
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
                   unsigned long *console_mfn,
                   void *devtree)
{
    start_info_t start_info;
    struct domain_setup_info dsi;
    xen_pfn_t *page_array = NULL;
    unsigned long nr_pages;
    unsigned long devtree_addr = 0;
    unsigned long kern_addr;
    unsigned long initrd_base = 0;
    unsigned long initrd_len = 0;
    unsigned long start_info_addr;
    unsigned long rma_pages;
    int rc = 0;

    DPRINTF("%s\n", __func__);

    nr_pages = mem_mb << (20 - PAGE_SHIFT);
    DPRINTF("nr_pages 0x%lx\n", nr_pages);

    rma_pages = get_rma_pages(devtree);
    if (rma_pages == 0) {
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

    /* start_info stuff: about to be removed  */
    start_info_addr = create_start_info(devtree, &start_info, console_evtchn,
                                        store_evtchn, nr_pages, rma_pages);
    *console_mfn = page_array[start_info.console.domU.mfn];
    *store_mfn = page_array[start_info.store_mfn];
    if (install_image(xc_handle, domid, page_array, &start_info,
                      start_info_addr, sizeof(start_info_t))) {
        rc = -1;
        goto out;
    }

    if (devtree) {
        DPRINTF("loading flattened device tree\n");
        devtree_addr = DEVTREE_ADDR;
        if (load_devtree(xc_handle, domid, page_array, devtree, devtree_addr,
                         initrd_base, initrd_len, &start_info,
                         start_info_addr)) {
            DPRINTF("couldn't load flattened device tree.\n");
            rc = -1;
            goto out;
        }
    }

    if (init_boot_vcpu(xc_handle, domid, &dsi, devtree_addr, kern_addr)) {
        rc = -1;
        goto out;
    }

out:
    free_page_array(page_array);
    return rc;
}
