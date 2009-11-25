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
        if (domname != NULL && !strncmp(domname, name, len)) {
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

int libxl_uuid_to_domid(struct libxl_ctx *ctx, xen_uuid_t *uuid, uint32_t *domid)
{
    int nb_domain, i;
    struct libxl_dominfo *info = libxl_domain_list(ctx, &nb_domain);
    for (i = 0; i < nb_domain; i++) {
        if (!memcmp(info[i].uuid, uuid, 16)) {
            *domid = info[i].domid;
            free(info);
            return 0;
        }
    }
    free(info);
    return -1;
}

int libxl_domid_to_uuid(struct libxl_ctx *ctx, xen_uuid_t **uuid, uint32_t domid)
{
    int nb_domain, i;
    struct libxl_dominfo *info = libxl_domain_list(ctx, &nb_domain);
    for (i = 0; i < nb_domain; i++) {
        if (domid == info[i].domid) {
            *uuid = libxl_zalloc(ctx, 16);
            memcpy(*uuid, info[i].uuid, 16);
            free(info);
            return 0;
        }
    }
    free(info);
    return -1;
}

int libxl_is_uuid(char *s)
{
    int i;
    if (!s || strlen(s) != 36)
        return 0;
    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-')
                return 0;
        } else {
            if (!isxdigit((uint8_t)s[i]))
                return 0;
        }
    }
    return 1;
}

xen_uuid_t *libxl_string_to_uuid(struct libxl_ctx *ctx, char *s)
{
    xen_uuid_t *uuid;
    if (!s || !ctx)
        return NULL;
    uuid = libxl_zalloc(ctx, sizeof(*uuid));
    xen_uuid_from_string(uuid, s);
    return uuid;
}

char *libxl_uuid_to_string(struct libxl_ctx *ctx, xen_uuid_t *uuid)
{
    char uuid_str[39];
    if (!uuid)
        return NULL;
    xen_uuid_to_string(uuid, uuid_str, sizeof(uuid_str));
    return libxl_sprintf(ctx, "%s", uuid_str);
}

int libxl_param_to_domid(struct libxl_ctx *ctx, char *p, uint32_t *domid)
{
    xen_uuid_t *uuid;
    uint32_t d;

    if (libxl_is_uuid(p)) {
        uuid = libxl_string_to_uuid(ctx, p);
        return libxl_uuid_to_domid(ctx, uuid, domid);
    }
    errno = 0;
    d = strtoul(p, (char **) NULL, 10);
    if (!errno && d != 0 && d != ULONG_MAX && d != LONG_MIN) {
        *domid = d;
        return 0;
    }
    return libxl_name_to_domid(ctx, p, domid);
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
        return 1;
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

