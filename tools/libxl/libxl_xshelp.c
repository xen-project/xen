/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>

#include "libxl.h"
#include "libxl_internal.h"

int xs_writev(struct xs_handle *xsh, xs_transaction_t t, char *dir, char *kvs[])
{
    char *path;
    int i;

    if (!kvs)
        return 0;

    for (i = 0; kvs[i] != NULL; i += 2) {
        if (asprintf(&path, "%s/%s", dir, kvs[i]) < 0)
            return -1;
        if (path && kvs[i + 1]) {
            int length = strlen(kvs[i + 1]);
            xs_write(xsh, t, path, kvs[i + 1], length);
        }
        free(path);
    }
    return 0;
}

char **libxl_xs_kvs_of_flexarray(struct libxl_ctx *ctx, flexarray_t *array, int length)
{
    char **kvs;
    int i;

    kvs = libxl_calloc(ctx, length + 2, sizeof(char *));
    if (kvs) {
        for (i = 0; i < length; i += 2) {
            void *ptr;

            flexarray_get(array, i, &ptr);
            kvs[i] = (char *) ptr;
            flexarray_get(array, i + 1, &ptr);
            kvs[i + 1] = (char *) ptr;
        }
        kvs[i] = NULL;
        kvs[i + 1] = NULL;
    }
    return kvs;
}

int libxl_xs_writev(struct libxl_ctx *ctx, xs_transaction_t t,
                    char *dir, char *kvs[])
{
    char *path;
    int i;

    if (!kvs)
        return 0;

    for (i = 0; kvs[i] != NULL; i += 2) {
        path = libxl_sprintf(ctx, "%s/%s", dir, kvs[i]);
        if (path && kvs[i + 1]) {
            int length = strlen(kvs[i + 1]);
            xs_write(ctx->xsh, t, path, kvs[i + 1], length);
        }
        libxl_free(ctx, path);
    }
    return 0;
}

int libxl_xs_write(struct libxl_ctx *ctx, xs_transaction_t t,
                   char *path, char *fmt, ...)
{
    char *s;
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vasprintf(&s, fmt, ap);
    va_end(ap);

    if (ret == -1) {
        return -1;
    }
    xs_write(ctx->xsh, t, path, s, ret);
    free(s);
    return 0;
}

char * libxl_xs_read(struct libxl_ctx *ctx, xs_transaction_t t, char *path)
{
    unsigned int len;
    char *ptr;

    ptr = xs_read(ctx->xsh, t, path, &len);
    if (ptr != NULL) {
        libxl_ptr_add(ctx, ptr);
        return ptr;
    }
    return 0;
}

char *libxl_xs_get_dompath(struct libxl_ctx *ctx, uint32_t domid)
{
    char *s = xs_get_domain_path(ctx->xsh, domid);
    if (!s) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to get dompath for %" PRIu32,
                     domid);
        return NULL;
    }
    libxl_ptr_add(ctx, s);
    return s;
}

char **libxl_xs_directory(struct libxl_ctx *ctx, xs_transaction_t t, char *path, unsigned int *nb)
{
    char **ret = NULL;
    ret = xs_directory(ctx->xsh, XBT_NULL, path, nb);
    libxl_ptr_add(ctx, ret);
    return ret;
}
