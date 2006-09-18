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

#include "ft_build.h"

#define INITRD_ADDR (24UL << 20)
#define DEVTREE_ADDR (16UL << 20)

#define ALIGN_UP(addr,size) (((addr)+((size)-1))&(~((size)-1)))

#define max(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x > _y ? _x : _y; })

static void *load_file(const char *path, unsigned long *filesize)
{
    void *img;
    ssize_t size;
    int fd;

    DPRINTF("load_file(%s)\n", path);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        return NULL;
    }

    size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        perror(path);
        close(fd);
        return NULL;
    }
    lseek(fd, 0, SEEK_SET);

    img = malloc(size);
    if (img == NULL) {
        perror(path);
        close(fd);
        return NULL;
    }

    size = read(fd, img, size);
    if (size <= 0) {
        perror(path);
        close(fd);
        free(img);
        return NULL;
    }

    if (filesize)
        *filesize = size;
    close(fd);
    return img;
}

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

static int install_image(
        int xc_handle,
        int domid,
        xen_pfn_t *page_array,
        void *image,
        unsigned long paddr,
        unsigned long size)
{
    uint8_t *img = image;
    int i;
    int rc = 0;

    if (paddr & ~PAGE_MASK) {
        printf("*** unaligned address\n");
        return -1;
    }

    for (i = 0; i < size; i += PAGE_SIZE) {
        void *page = img + i;
        xen_pfn_t pfn = (paddr + i) >> PAGE_SHIFT;
        xen_pfn_t mfn = page_array[pfn];

        rc = xc_copy_to_domain_page(xc_handle, domid, mfn, page);
        if (rc < 0) {
            perror("xc_copy_to_domain_page");
            break;
        }
    }
    return rc;
}

static int load_devtree(
    int xc_handle,
    int domid,
    xen_pfn_t *page_array,
    void *devtree,
    unsigned long devtree_addr,
    unsigned long initrd_base,
    unsigned long initrd_len,
    start_info_t *si,
    unsigned long si_addr)
{
    uint32_t start_info[4] = {0, si_addr, 0, 0x1000};
    struct boot_param_header *header;
    uint64_t *prop;
    unsigned int devtree_size;
    unsigned int proplen;
    int rc = 0;

    header = devtree;
    devtree_size = header->totalsize;

    DPRINTF("adding initrd props\n");

	/* initrd-start */
    prop = ft_get_prop(devtree, "/chosen/linux,initrd-start", &proplen);
    if (prop == NULL) {
        DPRINTF("couldn't find linux,initrd-start\n");
        return -1;
    }
    if (proplen != sizeof(*prop)) {
        DPRINTF("couldn't set linux,initrd-start (size %d)\n", proplen);
        return -1;
    }
    *prop = initrd_base;

	/* initrd-end */
    prop = ft_get_prop(devtree, "/chosen/linux,initrd-end", &proplen);
    if (prop == NULL) {
        DPRINTF("couldn't find linux,initrd-end\n");
        return -1;
    }
    if (proplen != sizeof(*prop)) {
        DPRINTF("couldn't set linux,initrd-end (size %d)\n", proplen);
        return -1;
    }
    *prop = initrd_base + initrd_len;

	/* start-info (XXX being removed soon) */
    prop = ft_get_prop(devtree, "/xen/start-info", &proplen);
    if (prop == NULL) {
        DPRINTF("couldn't find /xen/start-info\n");
        return -1;
    }
    if (proplen != sizeof(start_info)) {
        DPRINTF("couldn't set /xen/start-info (size %d)\n", proplen);
        return -1;
    }
    memcpy(prop, start_info, proplen);

    DPRINTF("copying device tree to 0x%lx[0x%x]\n", DEVTREE_ADDR, devtree_size);
    rc = install_image(xc_handle, domid, page_array, devtree, DEVTREE_ADDR,
                       devtree_size);

    return rc;
}

unsigned long spin_list[] = {
#if 0
    0x100,
    0x200,
    0x300,
    0x380,
    0x400,
    0x480,
    0x500,
    0x700,
    0x900,
    0xc00,
#endif
    0
};

/* XXX yes, this is a hack */
static void hack_kernel_img(char *img)
{
    const off_t file_offset = 0x10000;
    unsigned long *addr = spin_list;

    while (*addr) {
        uint32_t *instruction = (uint32_t *)(img + *addr + file_offset);
        printf("installing spin loop at %lx (%x)\n", *addr, *instruction);
        *instruction = 0x48000000;
        addr++;
    }
}

static int load_kernel(
    int xc_handle,
    int domid,
    const char *kernel_path,
    struct domain_setup_info *dsi,
    xen_pfn_t *page_array)
{
    struct load_funcs load_funcs;
    char *kernel_img;
    unsigned long kernel_size;
    int rc;

    /* load the kernel ELF file */
    kernel_img = load_file(kernel_path, &kernel_size);
    if (kernel_img == NULL) {
        rc = -1;
        goto out;
    }

    hack_kernel_img(kernel_img);

    DPRINTF("probe_elf\n");
    rc = probe_elf(kernel_img, kernel_size, &load_funcs);
    if (rc < 0) {
        rc = -1;
        printf("%s is not an ELF file\n", kernel_path);
        goto out;
    }

    DPRINTF("parseimage\n");
    rc = (load_funcs.parseimage)(kernel_img, kernel_size, dsi);
    if (rc < 0) {
        rc = -1;
        goto out;
    }

    DPRINTF("loadimage\n");
    (load_funcs.loadimage)(kernel_img, kernel_size, xc_handle, domid,
            page_array, dsi);

    DPRINTF("  v_start     %016"PRIx64"\n", dsi->v_start);
    DPRINTF("  v_end       %016"PRIx64"\n", dsi->v_end);
    DPRINTF("  v_kernstart %016"PRIx64"\n", dsi->v_kernstart);
    DPRINTF("  v_kernend   %016"PRIx64"\n", dsi->v_kernend);
    DPRINTF("  v_kernentry %016"PRIx64"\n", dsi->v_kernentry);

out:
    free(kernel_img);
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

static unsigned long create_start_info(start_info_t *si,
        unsigned int console_evtchn, unsigned int store_evtchn,
        unsigned long nr_pages)
{
    unsigned long si_addr;

    memset(si, 0, sizeof(*si));
    snprintf(si->magic, sizeof(si->magic), "xen-%d.%d-powerpc64HV", 3, 0);

    si->nr_pages = nr_pages;
    si->shared_info = (nr_pages - 1) << PAGE_SHIFT;
    si->store_mfn = si->nr_pages - 2;
    si->store_evtchn = store_evtchn;
    si->console.domU.mfn = si->nr_pages - 3;
    si->console.domU.evtchn = console_evtchn;
    si_addr = (si->nr_pages - 4) << PAGE_SHIFT;

    return si_addr;
}

static int get_page_array(int xc_handle, int domid, xen_pfn_t **page_array,
                          unsigned long *nr_pages)
{
    int rc;

    DPRINTF("xc_get_tot_pages\n");
    *nr_pages = xc_get_tot_pages(xc_handle, domid);
    DPRINTF("  0x%lx\n", *nr_pages);

    *page_array = malloc(*nr_pages * sizeof(xen_pfn_t));
    if (*page_array == NULL) {
        perror("malloc");
        return -1;
    }

    DPRINTF("xc_get_pfn_list\n");
    rc = xc_get_pfn_list(xc_handle, domid, *page_array, *nr_pages);
    if (rc != *nr_pages) {
        perror("Could not get the page frame list");
        return -1;
    }

    return 0;
}

static void free_page_array(xen_pfn_t *page_array)
{
    free(page_array);
}



int xc_linux_build(int xc_handle,
                   uint32_t domid,
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
    start_info_t si;
    struct domain_setup_info dsi;
    xen_pfn_t *page_array = NULL;
    unsigned long nr_pages;
    unsigned long devtree_addr = 0;
    unsigned long kern_addr;
    unsigned long initrd_base = 0;
    unsigned long initrd_len = 0;
    unsigned long si_addr;
    int rc = 0;

    DPRINTF("%s\n", __func__);

    if (get_page_array(xc_handle, domid, &page_array, &nr_pages)) {
        rc = -1;
        goto out;
    }

    DPRINTF("loading image '%s'\n", image_name);
    if (load_kernel(xc_handle, domid, image_name, &dsi, page_array)) {
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
    si_addr = create_start_info(&si, console_evtchn, store_evtchn, nr_pages);
    *console_mfn = page_array[si.console.domU.mfn];
    *store_mfn = page_array[si.store_mfn];
    if (install_image(xc_handle, domid, page_array, &si, si_addr,
                sizeof(start_info_t))) {
        rc = -1;
        goto out;
    }

    if (devtree) {
        DPRINTF("loading flattened device tree\n");
        devtree_addr = DEVTREE_ADDR;
        if (load_devtree(xc_handle, domid, page_array, devtree, devtree_addr,
                     initrd_base, initrd_len, &si, si_addr)) {
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
