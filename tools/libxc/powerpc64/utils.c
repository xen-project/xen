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
 *          Jimi Xenidis <jimix@watson.ibm.com>
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

int get_rma_page_array(int xc_handle, int domid, xen_pfn_t **page_array,
		       unsigned long nr_pages)
{
    int rc;
    int i;
    xen_pfn_t *p;

    *page_array = malloc(nr_pages * sizeof(xen_pfn_t));
    if (*page_array == NULL) {
        perror("malloc");
        return -1;
    }

    DPRINTF("xc_get_pfn_list\n");
    /* We know that the RMA is machine contiguous so lets just get the
     * first MFN and fill the rest in ourselves */
    rc = xc_get_pfn_list(xc_handle, domid, *page_array, 1);
    if (rc == -1) {
        perror("Could not get the page frame list");
        return -1;
    }
    p = *page_array;
    for (i = 1; i < nr_pages; i++)
        p[i] = p[i - 1] + 1;
    return 0;
}

int install_image(
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

void *load_file(const char *path, unsigned long *filesize)
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

int load_elf_kernel(
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
