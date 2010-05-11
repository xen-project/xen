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
#include <assert.h>

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

int libxl_name_to_domid(struct libxl_ctx *ctx, const char *name,
                        uint32_t *domid)
{
    int i, nb_domains;
    char *domname;
    struct libxl_dominfo *dominfo;

    dominfo = libxl_list_domain(ctx, &nb_domains);
    if (!dominfo)
        return ERROR_NOMEM;

    for (i = 0; i < nb_domains; i++) {
        domname = libxl_domid_to_name(ctx, dominfo[i].domid);
        if (!domname)
            continue;
        if (strcmp(domname, name) == 0) {
            *domid = dominfo[i].domid;
            return 0;
        }
    }
    return -1;
}

char *libxl_poolid_to_name(struct libxl_ctx *ctx, uint32_t poolid)
{
    unsigned int len;
    char path[strlen("/local/pool") + 12];
    char *s;

    if (poolid == 0)
        return "Pool-0";
    snprintf(path, sizeof(path), "/local/pool/%d/name", poolid);
    s = xs_read(ctx->xsh, XBT_NULL, path, &len);
    libxl_ptr_add(ctx, s);
    return s;
}

int libxl_name_to_poolid(struct libxl_ctx *ctx, const char *name,
                        uint32_t *poolid)
{
    int i, nb_pools;
    char *poolname;
    struct libxl_poolinfo *poolinfo;

    poolinfo = libxl_list_pool(ctx, &nb_pools);
    if (!poolinfo)
        return ERROR_NOMEM;

    for (i = 0; i < nb_pools; i++) {
        poolname = libxl_poolid_to_name(ctx, poolinfo[i].poolid);
        if (!poolname)
            continue;
        if (strcmp(poolname, name) == 0) {
            *poolid = poolinfo[i].poolid;
            return 0;
        }
    }
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

int libxl_is_stubdom(struct libxl_ctx *ctx, uint32_t domid, uint32_t *target_domid)
{
    char *target, *endptr;
    uint32_t value;

    target = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/target", libxl_xs_get_dompath(ctx, domid)));
    if (!target)
        return 0;
    value = strtol(target, &endptr, 10);
    if (*endptr != '\0')
        return 0;
    if (target_domid)
        *target_domid = value;
    return 1;
}

static int logrename(struct libxl_ctx *ctx, const char *old, const char *new) {
    int r;

    r = rename(old, new);
    if (r) {
        if (errno == ENOENT) return 0; /* ok */

        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to rotate logfile - could not"
                     " rename %s to %s", old, new);
        return ERROR_FAIL;
    }
    return 0;
}

int libxl_create_logfile(struct libxl_ctx *ctx, char *name, char **full_name)
{
    struct stat stat_buf;
    char *logfile, *logfile_new;
    int i, rc;

    logfile = libxl_sprintf(ctx, "/var/log/xen/%s.log", name);
    if (stat(logfile, &stat_buf) == 0) {
        /* file exists, rotate */
        logfile = libxl_sprintf(ctx, "/var/log/xen/%s.log.10", name);
        unlink(logfile);
        for (i = 9; i > 0; i--) {
            logfile = libxl_sprintf(ctx, "/var/log/xen/%s.log.%d", name, i);
            logfile_new = libxl_sprintf(ctx, "/var/log/xen/%s.log.%d", name, i + 1);
            rc = logrename(ctx, logfile, logfile_new);
            if (rc) return rc;
        }
        logfile = libxl_sprintf(ctx, "/var/log/xen/%s.log", name);
        logfile_new = libxl_sprintf(ctx, "/var/log/xen/%s.log.1", name);

        rc = logrename(ctx, logfile, logfile_new);
        if (rc) return rc;
    } else {
        if (errno != ENOENT)
            XL_LOG_ERRNO(ctx, XL_LOG_WARNING, "problem checking existence of"
                         " logfile %s, which might have needed to be rotated",
                         name);
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

int libxl_read_file_contents(struct libxl_ctx *ctx, const char *filename,
                             void **data_r, int *datalen_r) {
    FILE *f = 0;
    uint8_t *data = 0;
    int datalen = 0;
    int e;
    struct stat stab;
    ssize_t rs;
    
    f = fopen(filename, "r");
    if (!f) {
        if (errno == ENOENT) return ENOENT;
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to open %s", filename);
        goto xe;
    }

    if (fstat(fileno(f), &stab)) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to fstat %s", filename);
        goto xe;
    }

    if (!S_ISREG(stab.st_mode)) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "%s is not a plain file", filename);
        errno = ENOTTY;
        goto xe;
    }

    if (stab.st_size > INT_MAX) {
        XL_LOG(ctx, XL_LOG_ERROR, "file %s is far too large", filename);
        errno = EFBIG;
        goto xe;
    }

    datalen = stab.st_size;

    if (stab.st_size && data_r) {
        data = malloc(datalen);
        if (!data) goto xe;

        rs = fread(data, 1, datalen, f);
        if (rs != datalen) {
            if (ferror(f))
                XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to read %s", filename);
            else if (feof(f))
                XL_LOG(ctx, XL_LOG_ERROR, "%s changed size while we"
                       " were reading it", filename);
            else
                abort();
            goto xe;
        }
    }

    if (fclose(f)) {
        f = 0;
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to close %s", filename);
        goto xe;
    }

    if (data_r) *data_r = data;
    if (datalen_r) *datalen_r = datalen;

    return 0;

 xe:
    e = errno;
    assert(e != ENOENT);
    if (f) fclose(f);
    if (data) free(data);
    return e;
}

#define READ_WRITE_EXACTLY(rw, zero_is_eof, constdata)                    \
                                                                          \
  int libxl_##rw##_exactly(struct libxl_ctx *ctx, int fd,                 \
                           constdata void *data, ssize_t sz,              \
                           const char *filename, const char *what) {      \
      ssize_t got;                                                        \
                                                                          \
      while (sz > 0) {                                                    \
          got = rw(fd, data, sz);                                         \
          if (got == -1) {                                                \
              if (errno == EINTR) continue;                               \
              XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to " #rw " %s%s%s", \
                           what?what:"", what?" from ":"", filename);     \
              return errno;                                               \
          }                                                               \
          if (got == 0) {                                                 \
              XL_LOG(ctx, XL_LOG_ERROR,                                   \
                     zero_is_eof                                          \
                     ? "file/stream truncated reading %s%s%s"             \
                     : "file/stream write returned 0! writing %s%s%s",    \
                     what?what:"", what?" from ":"", filename);           \
              return EPROTO;                                              \
          }                                                               \
          sz -= got;                                                      \
          data = (char*)data + got;                                       \
      }                                                                   \
      return 0;                                                           \
  }

READ_WRITE_EXACTLY(read, 1, /* */)
READ_WRITE_EXACTLY(write, 0, const)


int libxl_ctx_postfork(struct libxl_ctx *ctx) {
    if (ctx->xsh) xs_daemon_destroy_postfork(ctx->xsh);
    ctx->xsh = xs_daemon_open();
    if (!ctx->xsh) return ERROR_FAIL;
    return 0;
}

pid_t libxl_fork(struct libxl_ctx *ctx)
{
    pid_t pid;

    pid = fork();
    if (pid == -1) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "fork failed");
        return -1;
    }

    if (!pid) {
        if (ctx->xsh) xs_daemon_destroy_postfork(ctx->xsh);
        ctx->xsh = 0;
        /* This ensures that anyone who forks but doesn't exec,
         * and doesn't reinitialise the libxl_ctx, is OK.
         * It also means they can safely call libxl_ctx_free. */
    }

    return pid;
}

int libxl_pipe(struct libxl_ctx *ctx, int pipes[2])
{
    if (pipe(pipes) < 0) {
        XL_LOG(ctx, XL_LOG_ERROR, "Failed to create a pipe");
        return -1;
    }
    return 0;
}
