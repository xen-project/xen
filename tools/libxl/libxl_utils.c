/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <xs.h>
#include <xenctrl.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libxl_utils.h"
#include "libxl_internal.h"


unsigned long libxl_get_required_shadow_memory(unsigned long maxmem_kb, unsigned int smp_cpus)
{
    /* 256 pages (1MB) per vcpu,
       plus 1 page per MiB of RAM for the P2M map,
       plus 1 page per MiB of RAM to shadow the resident processes.
       This is higher than the minimum that Xen would allocate if no value
       were given (but the Xen minimum is for safety, not performance).
     */
    return 4 * (256 * smp_cpus + 2 * (maxmem_kb / 1024));
}

char *libxl_domid_to_name(struct libxl_ctx *ctx, uint32_t domid)
{
    unsigned int len;
    char path[strlen("/local/domain") + 12];
    char *s;

    snprintf(path, sizeof(path), "/local/domain/%d/name", domid);
    s = xs_read(ctx->xsh, XBT_NULL, path, &len);
    libxl_ptr_add(ctx, s);
    return s;
}

int libxl_name_to_domid(struct libxl_ctx *ctx, char *name, uint32_t *domid)
{
    unsigned int num, len;
    char path[strlen("/local/domain") + 12];
    int i, j, nb_domains;
    char *domname, **l;
    struct libxl_dominfo *dominfo;

    dominfo = libxl_domain_list(ctx, &nb_domains);

    l = xs_directory(ctx->xsh, XBT_NULL, "/local/domain", &num);
    for (i = 0; i < num; i++) {
        snprintf(path, sizeof(path), "/local/domain/%s/name", l[i]);
        domname = xs_read(ctx->xsh, XBT_NULL, path, &len);
        if (domname != NULL && len == strlen(name) && !strncmp(domname, name, len)) {
            int domid_i = atoi(l[i]);
            for (j = 0; j < nb_domains; j++) {
                if (dominfo[j].domid == domid_i) {
                    *domid = domid_i;
                    free(dominfo);
                    free(l);
                    free(domname);
                    return 0;
                }
            }
        }
        free(domname);
    }
    free(dominfo);
    free(l);
    return -1;
}

int libxl_get_stubdom_id(struct libxl_ctx *ctx, int guest_domid)
{
    char * stubdom_id_s = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/image/device-model-domid", libxl_xs_get_dompath(ctx, guest_domid)));
    if (stubdom_id_s)
        return atoi(stubdom_id_s);
    else
        return 0;
}

int libxl_is_stubdom(struct libxl_ctx *ctx, int domid)
{
    char *target = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/target", libxl_xs_get_dompath(ctx, domid)));
    if (target)
        return atoi(target);
    else
        return 0;
}

int libxl_create_logfile(struct libxl_ctx *ctx, char *name, char **full_name)
{
    struct stat stat_buf;
    char *logfile, *logfile_new;
    int i;

    logfile = libxl_sprintf(ctx, "/var/log/xen/%s.log", name);
    if (stat(logfile, &stat_buf) == 0) {
        /* file exists, rotate */
        logfile = libxl_sprintf(ctx, "/var/log/xen/%s.log.10", name);
        unlink(logfile);
        for (i = 9; i > 0; i--) {
            logfile = libxl_sprintf(ctx, "/var/log/xen/%s.log.%d", name, i);
            logfile_new = libxl_sprintf(ctx, "/var/log/xen/%s.log.%d", name, i + 1);
            rename(logfile, logfile_new);
        }
        logfile = libxl_sprintf(ctx, "/var/log/xen/%s.log", name);
        logfile_new = libxl_sprintf(ctx, "/var/log/xen/%s.log.1", name);
        rename(logfile, logfile_new);
    }
    *full_name = strdup(logfile);
    return 0;
}

int libxl_string_to_phystype(struct libxl_ctx *ctx, char *s, libxl_disk_phystype *phystype)
{
    char *p;
    int rc = 0;

    if (!strcmp(s, "phy")) {
        *phystype = PHYSTYPE_PHY;
    } else if (!strcmp(s, "file")) {
        *phystype = PHYSTYPE_FILE;
    } else if (!strcmp(s, "tap")) {
        p = strchr(s, ':');
        if (!p) {
            rc = -1;
            goto out;
        }
        p++;
        if (!strcmp(p, "aio")) {
            *phystype = PHYSTYPE_AIO;
        } else if (!strcmp(p, "vhd")) {
            *phystype = PHYSTYPE_VHD;
        } else if (!strcmp(p, "qcow")) {
            *phystype = PHYSTYPE_QCOW;
        } else if (!strcmp(p, "qcow2")) {
            *phystype = PHYSTYPE_QCOW2;
        }
    }
out:
    return rc;
}

