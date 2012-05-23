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

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

char **libxl__xs_kvs_of_flexarray(libxl__gc *gc, flexarray_t *array, int length)
{
    char **kvs;
    int i;

    if (!length)
        return NULL;

    kvs = libxl__calloc(gc, length + 2, sizeof(char *));
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

int libxl__xs_writev(libxl__gc *gc, xs_transaction_t t,
                     const char *dir, char *kvs[])
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *path;
    int i;

    if (!kvs)
        return 0;

    for (i = 0; kvs[i] != NULL; i += 2) {
        path = libxl__sprintf(gc, "%s/%s", dir, kvs[i]);
        if (path && kvs[i + 1]) {
            int length = strlen(kvs[i + 1]);
            xs_write(ctx->xsh, t, path, kvs[i + 1], length);
        }
    }
    return 0;
}

int libxl__xs_write(libxl__gc *gc, xs_transaction_t t,
                    const char *path, const char *fmt, ...)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
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

char * libxl__xs_read(libxl__gc *gc, xs_transaction_t t, const char *path)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *ptr;

    ptr = xs_read(ctx->xsh, t, path, NULL);
    if (ptr != NULL) {
        libxl__ptr_add(gc, ptr);
        return ptr;
    }
    return 0;
}

char *libxl__xs_get_dompath(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *s = xs_get_domain_path(ctx->xsh, domid);
    if (!s) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "failed to get dompath for %" PRIu32,
                     domid);
        return NULL;
    }
    libxl__ptr_add(gc, s);
    return s;
}

char **libxl__xs_directory(libxl__gc *gc, xs_transaction_t t,
                           const char *path, unsigned int *nb)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char **ret = NULL;
    ret = xs_directory(ctx->xsh, t, path, nb);
    libxl__ptr_add(gc, ret);
    return ret;
}

bool libxl__xs_mkdir(libxl__gc *gc, xs_transaction_t t,
                     const char *path, struct xs_permissions *perms,
			         unsigned int num_perms)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    if (!xs_mkdir(ctx->xsh, t, path))
        return false;
    return xs_set_permissions(ctx->xsh, t, path, perms, num_perms);
}

char *libxl__xs_libxl_path(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *s = libxl__sprintf(gc, "/libxl/%i", domid);
    if (!s)
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "cannot allocate create paths");
    return s;
}

int libxl__xs_path_cleanup(libxl__gc *gc, xs_transaction_t t, char *user_path)
{
    unsigned int nb = 0;
    char *path, *last, *val;
    int rc;

    /* A path and transaction must be provided by the caller */
    assert(user_path && t);

    path = libxl__strdup(gc, user_path);
    if (!xs_rm(CTX->xsh, t, path)) {
        LOGE(DEBUG, "unable to remove path %s", path);
        rc = ERROR_FAIL;
        goto out;
    }

    for (last = strrchr(path, '/'); last != NULL; last = strrchr(path, '/')) {
        *last = '\0';

        if (!strlen(path)) break;

        val = libxl__xs_read(gc, t, path);
        if (!val || strlen(val) != 0) break;

        if (!libxl__xs_directory(gc, t, path, &nb) || nb != 0) break;

        if (!xs_rm(CTX->xsh, t, path)) {
            LOGE(DEBUG, "unable to remove path %s", path);
            rc = ERROR_FAIL;
            goto out;
        }
    }
    rc = 0;

out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
