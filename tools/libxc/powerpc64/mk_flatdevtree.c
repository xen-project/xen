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
 * Copyright IBM Corporation 2007
 *
 * Authors: Ryan Harper <ryanh@us.ibm.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <libgen.h>    
#include <inttypes.h>
#include <math.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <xc_private.h> /* for PERROR() */
#include <xc_dom.h>

#include "mk_flatdevtree.h"

static uint32_t current_phandle = 0;

static uint32_t get_phandle(void)
{
   return current_phandle++;
}

static int readfile(const char *fullpath, void *data, int len)
{
    struct stat st;
    int saved_errno;
    int rc = -1;
    int fd;
   
    if ((fd = open(fullpath, O_RDONLY)) == -1) {
        PERROR("%s: failed to open file %s", __func__, fullpath);
        return -1;
    }

    if ((rc = fstat(fd, &st)) == -1) {
        PERROR("%s: failed to stat fd %d", __func__, fd);
        goto error;
    }

    if (S_ISREG(st.st_mode))
        rc = read(fd, data, len); 

    close(fd);
    return rc;

error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

/* 
 * @property - string to check against the filter list
 * @filter   - NULL terminated list of strings 
 *
 * compare @property string to each string in @filter
 *
 * return 1 if @property matches any filter, otherwise 0
 *
 */
static int match(const char *property, const char **filter)
{
    int i;
    
    for (i=0; filter[i] != NULL; i++) {
        /* compare the filter to property */
        if (strncmp(property, filter[i], strlen(filter[i])) == 0)
            return 1;
    }

    return 0;
}

/*
 * copy the node at @dirpath filtering out any properties that match in @propfilter
 */
static int copynode(struct ft_cxt *cxt, const char *dirpath, const char **propfilter)
{   
    struct dirent *tree;
    struct stat st;
    DIR *dir;
    char fullpath[MAX_PATH];
    char *bname = NULL;
    char *basec = NULL;
    int saved_errno;

    if ((dir = opendir(dirpath)) == NULL) {
        PERROR("%s: failed to open dir %s", __func__, dirpath);
        return -1;
    }

    while (1) {
        if ((tree = readdir(dir)) == NULL)
            break;  /* reached end of directory entries */

        /* ignore . and .. */
        if (strcmp(tree->d_name,"." ) == 0 || strcmp(tree->d_name,"..") == 0)
            continue;

        /* build full path name of the file, for stat() */
        if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath,
                     tree->d_name) >= sizeof(fullpath)) {
            PERROR("%s: failed to build full path", __func__);
            goto error;
        }

        /* stat the entry */
        if (stat(fullpath, &st) < 0) {
            PERROR("%s: failed to stat file %s", __func__, fullpath);
            goto error;
        }

        if (S_ISDIR(st.st_mode)) {
            /* start a new node for a dir */
            ft_begin_node(cxt, tree->d_name);

            /* copy everything in this dir */
            if (copynode(cxt, fullpath, propfilter) < 0) {
                PERROR("%s: failed to copy node @ %s", __func__, fullpath);
                goto error;
            }

            /* end the node */
            ft_end_node(cxt);
        }
        /* add files in dir as properties */
        else if (S_ISREG(st.st_mode)) {

            if ((basec = strdup(fullpath)) == NULL) {
                PERROR("%s: failed to dupe string", __func__);
                goto error;
            }

            if ((bname = basename(basec)) == NULL) {
                PERROR("%s: basename() failed", __func__);
                goto error;
            }

            /* only add files that don't match the property filter string */
            if (!match(bname, propfilter)) {
                char data[BUFSIZE];
                int len;

                /* snarf the data and push into the property */
                if ((len = readfile(fullpath, data, sizeof(data))) < 0) {
                    PERROR("%s: failed to read data from file %s", __func__,
                                                                   fullpath);
                    goto error;
                }
                ft_prop(cxt, tree->d_name, data, len);

            }

            /* strdup mallocs memory */
            if (basec != NULL ) {
                free(basec);
                basec = NULL;
            }

        }
    }

    closedir(dir);
    return 0;

error:
    saved_errno = errno;

    /* strdup mallocs memory */
    if (basec != NULL ) {
        free(basec);
        basec = NULL;
    }

    closedir(dir);

    errno = saved_errno;
    return -1;
}

static int find_cpu0(char *cpupath, int len)
{   
    const char path[] = "/proc/device-tree/cpus";
    const char device[] = "device_type";
    const char dev_cpu[] = "cpu";
    const char reg[] = "reg";
    char data[sizeof(dev_cpu)];
    char prop[MAX_PATH];
    char node[MAX_PATH];
    struct dirent *tree;
    struct stat st;
    DIR* dir;
    int saved_errno;
    int found = 0;

    if ((dir = opendir(path)) == NULL) {
        PERROR("%s: failed to open directory %s", __func__, path);
        return -1;
    }    

    while (!found) {

        if ((tree = readdir(dir)) == NULL)
            break;  /* reached end of directory entries */

        /* ignore ., .. */
        if (strcmp(tree->d_name,"." ) == 0 || strcmp(tree->d_name,"..") == 0)
            continue;

        /* build full path name of the file, for stat() */
        if (snprintf(node, sizeof(node), "%s/%s", path,
                     tree->d_name) >= sizeof(node)) {
            PERROR("%s: failed to concat strings", __func__);
            goto error;
        }

        /* stat the entry */
        if (stat(node, &st) < 0) {
            PERROR("%s: failed to stat file %s", __func__, node);
            /* something funny happen in /proc/device-tree, but march onward */
            continue;
        }

        /* for each dir, check the device_type property until we find 'cpu'*/
        if (S_ISDIR(st.st_mode)) {

            /* construct path to device_type */
            if (snprintf(prop, sizeof(prop), "%s/%s", node,
                         device) >= sizeof(prop)) {
                PERROR("%s: failed to concat strings", __func__);
                goto error;
            }

            /* read device_type into buffer */
            if ((readfile(prop, data, sizeof(data))) < 0) {
                PERROR("%s: failed to read data from file %s", __func__, prop);
                goto error;
            }

            /* if the device_type is 'cpu',  and reg is 0 
             * return the path where we found it */
            if (strcmp(data, "cpu") == 0) {

                /* construct path to reg */
                if (snprintf(prop, sizeof(prop), "%s/%s", node,
                             reg) >= sizeof(prop)) {
                    PERROR("%s: failed to concat strings", __func__);
                    goto error;
                }

                /* using data buffer since reg and device_type values have same size */
                if ((readfile(prop, data, sizeof(data))) < 0) {
                    PERROR("%s: failed to read data from file %s", __func__, prop);
                    goto error;
                }

                /* now check property "reg" for value 0 */
                if ((u32)*data == 0) {
                    if (snprintf(cpupath, len, "%s", node) >= len) {
                        PERROR("%s: failed to copy cpupath", __func__);
                        goto error;
                    }
                    found = 1;
                }
            }
        }
    }

    closedir(dir);
    return found;

error:
    saved_errno = errno;
    closedir(dir);
    errno = saved_errno;
    return -1;
}

void free_devtree(struct ft_cxt *root)
{
    if ((root != NULL) && root->bph != NULL) {
        free(root->bph);
        root->bph = NULL;
    }
}

int make_devtree(struct ft_cxt *root,
                 struct xc_dom_image *dom,
                 unsigned long shadow_mb)
{
    struct boot_param_header *bph = NULL;
    uint64_t val[2];
    uint32_t val32[2];
    uint64_t shared_info_paddr = dom->shared_info_pfn << PAGE_SHIFT;
    uint64_t xenstore_paddr = dom->xenstore_pfn << PAGE_SHIFT;
    uint64_t console_paddr = dom->console_pfn << PAGE_SHIFT;
    long remaining;
    unsigned long ramdisk_start;
    unsigned long ramdisk_size;
    unsigned long rma_bytes = 1 << dom->realmodearea_log;
    int64_t shadow_mb_log;
    uint64_t pft_size;
    char cpupath[MAX_PATH];
    const char *propfilter[] = { "ibm", "linux,", NULL };
    char *cpupath_copy = NULL;
    char *cpuname = NULL;
    int saved_errno;
    int dtb_fd = -1;
    uint32_t cpu0_phandle = get_phandle();
    uint32_t xen_phandle = get_phandle();
    uint32_t rma_phandle = get_phandle();

    /* initialize bph to prevent double free on error path */
    root->bph = NULL;

    /* carve out space for bph */
    if ((bph = (struct boot_param_header *)malloc(BPH_SIZE)) == NULL) {
        PERROR("%s: Failed to malloc bph buffer size", __func__);
        goto error;
    }

    /* NB: struct ft_cxt root defined at top of file */
    /* root = Tree() */
    ft_begin(root, bph, BPH_SIZE);

    /* you MUST set reservations BEFORE _starting_the_tree_ */

    /* reserve shared_info_t page */
    if (shared_info_paddr) {
        val[0] = cpu_to_be64((u64) shared_info_paddr);
        val[1] = cpu_to_be64((u64) PAGE_SIZE);
        ft_add_rsvmap(root, val[0], val[1]);
    }

    /* reserve console page for domU */
    if (console_paddr) {
        val[0] = cpu_to_be64((u64) console_paddr);
        val[1] = cpu_to_be64((u64) PAGE_SIZE);
        ft_add_rsvmap(root, val[0], val[1]);
    }

    /* reserve xen store page for domU */
    if (xenstore_paddr) {
        val[0] = cpu_to_be64((u64) xenstore_paddr);
        val[1] = cpu_to_be64((u64) PAGE_SIZE);
        ft_add_rsvmap(root, val[0], val[1]);
    }

    /* reserve space for initrd if needed */
    ramdisk_start = dom->ramdisk_seg.pfn << PAGE_SHIFT;
    ramdisk_size = dom->ramdisk_seg.vend - dom->ramdisk_seg.vstart;
    if (ramdisk_size > 0) {
        val[0] = cpu_to_be64((u64) ramdisk_start);
        val[1] = cpu_to_be64((u64) ramdisk_size);
        ft_add_rsvmap(root, val[0], val[1]);
    }

    /* NB: ft_add_rsvmap() already terminates with a NULL reservation for us */

    /* done with reservations, _starting_the_tree_ */
    ft_begin_tree(root);

    /* make root node */
    ft_begin_node(root, "");

    /* root.addprop('device_type', 'chrp-but-not-really\0') */
    ft_prop_str(root, "device_type", "chrp-but-not-really");

    /* root.addprop('#size-cells', 2) */
    ft_prop_int(root, "#size-cells", 2);

    /* root.addprop('#address-cells', 2) */
    ft_prop_int(root, "#address-cells", 2);

    /* root.addprop('model', 'Momentum,Maple-D\0') */
    ft_prop_str(root, "model", "Momentum,Maple-D");

    /* root.addprop('compatible', 'Momentum,Maple\0') */
    ft_prop_str(root, "compatible", "Momentum,Maple");

    /* start chosen node */
    ft_begin_node(root, "chosen");

    /* chosen.addprop('cpu', cpu0.get_phandle()) */
    ft_prop_int(root, "cpu", cpu0_phandle);

    /* chosen.addprop('rma', rma.get_phandle()) */
    ft_prop_int(root, "memory", rma_phandle);

    /* chosen.addprop('linux,stdout-path', '/xen/console\0') */
    ft_prop_str(root, "linux,stdout-path", "/xen/console");

    /* chosen.addprop('interrupt-controller, xen.get_phandle()) */
    ft_prop_int(root, "interrupt-controller", xen_phandle);

    /* chosen.addprop('bootargs', imghandler.cmdline + '\0') */
    if (dom->cmdline != NULL)
        ft_prop_str(root, "bootargs", dom->cmdline);

    /* mark where the initrd is, if present */
    if (ramdisk_size > 0) {
        val[0] = cpu_to_be64((u64) ramdisk_start);
        val[1] = cpu_to_be64((u64) ramdisk_start + ramdisk_size);
        ft_prop(root, "linux,initrd-start", &(val[0]), sizeof(val[0]));
        ft_prop(root, "linux,initrd-end", &(val[1]), sizeof(val[1]));
    }

    /* end chosen node */
    ft_end_node(root);

    /* xen = root.addnode('xen') */
    ft_begin_node(root, "xen");

    /*  xen.addprop('version', 'Xen-3.0-unstable\0') */
    ft_prop_str(root, "compatible", "Xen-3.0-unstable");

    /* xen.addprop('reg', long(imghandler.vm.domid), long(0)) */
    val[0] = cpu_to_be64((u64) dom->guest_domid);
    val[1] = cpu_to_be64((u64) 0);
    ft_prop(root, "reg", val, sizeof(val));

    /* point to shared_info_t page base addr */
    val[0] = cpu_to_be64((u64) shared_info_paddr);
    val[1] = cpu_to_be64((u64) PAGE_SIZE);
    ft_prop(root, "shared-info", val, sizeof(val));

    /* xen.addprop('domain-name', imghandler.vm.getName() + '\0') */
    /* libxc doesn't know the domain name, that is purely a xend thing */
    /* ft_prop_str(root, "domain-name", domain_name); */

    /* add xen/linux,phandle for chosen/interrupt-controller */
    ft_prop_int(root, "linux,phandle", xen_phandle);

    if (console_paddr != 0) {
        /* xencons = xen.addnode('console') */
        ft_begin_node(root, "console");

        /* console_paddr */
        val[0] = cpu_to_be64((u64) console_paddr);
        val[1] = cpu_to_be64((u64) PAGE_SIZE);
        ft_prop(root, "reg", val, sizeof(val));

        /* xencons.addprop('interrupts', console_evtchn, 0) */
        val32[0] = cpu_to_be32((u32) dom->console_evtchn);
        val32[1] = cpu_to_be32((u32) 0);
        ft_prop(root, "interrupts", val32, sizeof(val32));

        /* end of console */
        ft_end_node(root);
    }

    if (xenstore_paddr != 0) {
        /* start store node */
        ft_begin_node(root, "store");

        /* store paddr */
        val[0] = cpu_to_be64((u64) xenstore_paddr);
        val[1] = cpu_to_be64((u64) PAGE_SIZE);
        ft_prop(root, "reg", val, sizeof(val));

        /* store event channel */
        val32[0] = cpu_to_be32((u32) dom->xenstore_evtchn);
        val32[1] = cpu_to_be32((u32) 0);
        ft_prop(root, "interrupts", val32, sizeof(val32));

        /* end of store */
        ft_end_node(root);
    }

    /* end of xen node */
    ft_end_node(root);

    /* rma = root.addnode('memory@0') */
    ft_begin_node(root, "memory@0");

    /* rma.addprop('reg', long(0), long(rma_bytes)) */
    val[0] = cpu_to_be64((u64) 0);
    val[1] = cpu_to_be64((u64) rma_bytes);
    ft_prop(root, "reg", val, sizeof(val));

    /* rma.addprop('device_type', 'memory\0') */
    ft_prop_str(root, "device_type", "memory");

    /* add linux,phandle for chosen/rma node */
    ft_prop_int(root, "linux,phandle", rma_phandle);

    /* end of memory@0 */
    ft_end_node(root);

    /* calculate remaining bytes from total - rma size */
    remaining = (dom->total_pages << PAGE_SHIFT) - rma_bytes;

    /* memory@<rma_bytes> is all remaining memory after RMA */
    if (remaining > 0)
    {
        char mem[MAX_PATH];
        
        if (snprintf(mem, sizeof(mem), "memory@%lx",
                     rma_bytes) >= sizeof(mem)) {
            PERROR("%s: failed to build memory string", __func__);
            goto error;
        }

        /* memory@<rma_bytes> is all remaining memory after RMA */
        ft_begin_node(root, mem);

        /* mem.addprop('reg', long(rma_bytes), long(remaining)) */
        val[0] = cpu_to_be64((u64) rma_bytes);
        val[1] = cpu_to_be64((u64) remaining);
        ft_prop(root, "reg", val, sizeof(val));

        /* mem.addprop('device_type', 'memory\0') */
        ft_prop_str(root, "device_type", "memory");

        /* end memory@<rma_bytes> node */
        ft_end_node(root);
    }

    /* add CPU nodes */
    /* cpus = root.addnode('cpus') */
    ft_begin_node(root, "cpus");

    /* cpus.addprop('smp-enabled') */
    ft_prop(root, "smp-enabled", NULL, 0);

    /* cpus.addprop('#size-cells', 0) */
    ft_prop_int(root, "#size-cells", 0);

    /* cpus.addprop('#address-cells', 1) */
    ft_prop_int(root, "#address-cells", 1);

    /*
     * Copy all properties the system firmware gave us from a 
     * CPU node in the device tree.
     */
    if (find_cpu0(cpupath, sizeof(cpupath)) <= 0) {
        PERROR("%s: failed find cpu0 node in host devtree", __func__);
        goto error;
    }

    /* get the basename from path to cpu device */
    if ((cpupath_copy = strdup(cpupath)) == NULL) {
        PERROR("%s: failed to dupe string", __func__);
        goto error;
    }
    if ((cpuname = basename(cpupath_copy)) == NULL) {
        PERROR("%s: basename() failed", __func__);
        goto error;
    }
     
    /* start node for the cpu */
    ft_begin_node(root, cpuname);

    /* strdup() mallocs memory */
    if ( cpupath_copy != NULL ) {
        free(cpupath_copy);
        cpupath_copy = NULL;
    }

    /* copy over most properties from host tree for cpu */
    if (copynode(root, cpupath, propfilter) < 0) {
        PERROR("%s: failed to copy node", __func__);
            goto error;
    }

    /* calculate the pft-size */
    shadow_mb_log = (int)log2((double)shadow_mb);
    pft_size = shadow_mb_log + 20;

    val32[0] = cpu_to_be32((u32) 0);
    val32[1] = cpu_to_be32((u32) pft_size);
    ft_prop(root, "ibm,pft-size", val32, sizeof(val32));

    /* make phandle for cpu0 */
    ft_prop_int(root, "linux,phandle", cpu0_phandle);

    /* end <cpuname> node */
    ft_end_node(root);

    /* end cpus node */
    ft_end_node(root);

    /* end root node */
    ft_end_node(root);

    /* end of the tree */
    if (ft_end_tree(root) != 0) {
        PERROR("%s: failed to end tree", __func__);
        goto error;
    }

    /* write a copy of the tree to a file */
    if ((dtb_fd = creat(DTB_FILE, S_IRUSR | S_IWUSR)) == -1) {
        PERROR("%s: failed to open file %s", __func__, DTB_FILE);
        goto error;
    }

    if (write(dtb_fd, (const void *)bph, bph->totalsize) != bph->totalsize) {
        PERROR("%s: failed to write blob to file", __func__);
        goto error; 
    }

    return 0;
 
error:
    saved_errno = errno;

    /* strdup() mallocs memory */
    if ( cpupath_copy != NULL ) {
        free(cpupath_copy);
        cpupath_copy = NULL;
    }

    /* free bph buffer */
    free_devtree(root);

    if (dtb_fd)
        close(dtb_fd);

    errno = saved_errno;
    return -1;
}
