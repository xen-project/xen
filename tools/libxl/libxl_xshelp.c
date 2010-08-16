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

char **libxl_xs_kvs_of_flexarray(libxl_gc *gc, flexarray_t *array, int length)
{
    char **kvs;
    int i;

    if (!length)
        return NULL;

    kvs = libxl_calloc(gc, length + 2, sizeof(char *));
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

int libxl_xs_writev(libxl_gc *gc, xs_transaction_t t,
                    char *dir, char *kvs[])
{
    libxl_ctx *ctx = libxl_gc_owner(gc);
    char *path;
    int i;

    if (!kvs)
        return 0;

    for (i = 0; kvs[i] != NULL; i += 2) {
        path = libxl_sprintf(gc, "%s/%s", dir, kvs[i]);
        if (path && kvs[i + 1]) {
            int length = strlen(kvs[i + 1]);
            xs_write(ctx->xsh, t, path, kvs[i + 1], length);
        }
    }
    return 0;
}

int libxl_xs_write(libxl_gc *gc, xs_transaction_t t,
                   char *path, char *fmt, ...)
{
    libxl_ctx *ctx = libxl_gc_owner(gc);
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

char * libxl_xs_read(libxl_gc *gc, xs_transaction_t t, char *path)
{
    libxl_ctx *ctx = libxl_gc_owner(gc);
    char *ptr;

    ptr = xs_read(ctx->xsh, t, path, NULL);
    if (ptr != NULL) {
        libxl_ptr_add(gc, ptr);
        return ptr;
    }
    return 0;
}

char *libxl_xs_get_dompath(libxl_gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl_gc_owner(gc);
    char *s = xs_get_domain_path(ctx->xsh, domid);
    if (!s) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to get dompath for %" PRIu32,
                     domid);
        return NULL;
    }
    libxl_ptr_add(gc, s);
    return s;
}

char **libxl_xs_directory(libxl_gc *gc, xs_transaction_t t, char *path, unsigned int *nb)
{
    libxl_ctx *ctx = libxl_gc_owner(gc);
    char **ret = NULL;
    ret = xs_directory(ctx->xsh, XBT_NULL, path, nb);
    libxl_ptr_add(gc, ret);
    return ret;
}
