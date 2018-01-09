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

char **libxl__xs_kvs_of_flexarray(libxl__gc *gc, flexarray_t *array)
{
    char **kvs;
    int i, length;

    if (!array)
        return NULL;

    length = array->count;
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

int libxl__xs_writev_perms(libxl__gc *gc, xs_transaction_t t,
                           const char *dir, char *kvs[],
                           struct xs_permissions *perms,
                           unsigned int num_perms)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *path;
    int i;

    if (!kvs)
        return 0;

    for (i = 0; kvs[i] != NULL; i += 2) {
        path = GCSPRINTF("%s/%s", dir, kvs[i]);
        if (path && kvs[i + 1]) {
            int length = strlen(kvs[i + 1]);
            xs_write(ctx->xsh, t, path, kvs[i + 1], length);
            if (perms)
                xs_set_permissions(ctx->xsh, t, path, perms, num_perms);
        }
    }
    return 0;
}

int libxl__xs_writev(libxl__gc *gc, xs_transaction_t t,
                     const char *dir, char *kvs[])
{
    return libxl__xs_writev_perms(gc, t, dir, kvs, NULL, 0);
}

int libxl__xs_writev_atonce(libxl__gc *gc,
                            const char *dir, char *kvs[])
{
    int rc;
    xs_transaction_t t = XBT_NULL;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__xs_writev(gc, t, dir, kvs);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc<0) goto out;
    }

out:
    libxl__xs_transaction_abort(gc, &t);

    return rc;

}

int libxl__xs_vprintf(libxl__gc *gc, xs_transaction_t t,
                      const char *path, const char *fmt, va_list ap)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *s;
    bool ok;

    s = libxl__vsprintf(gc, fmt, ap);

    ok = xs_write(ctx->xsh, t, path, s, strlen(s));
    if (!ok) {
        LOGE(ERROR, "xenstore write failed: `%s' = `%s'", path, s);
        return ERROR_FAIL;
    }

    return 0;
}

int libxl__xs_printf(libxl__gc *gc, xs_transaction_t t,
                     const char *path, const char *fmt, ...)
{
    va_list ap;
    int rc;

    va_start(ap, fmt);
    rc = libxl__xs_vprintf(gc, t, path, fmt, ap);
    va_end(ap);

    return rc;
}

char * libxl__xs_read(libxl__gc *gc, xs_transaction_t t, const char *path)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *ptr;

    ptr = xs_read(ctx->xsh, t, path, NULL);
    libxl__ptr_add(gc, ptr);
    return ptr;
}

char *libxl__xs_get_dompath(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *s = xs_get_domain_path(ctx->xsh, domid);
    if (!s) {
        LOGE(ERROR, "failed to get dompath for %"PRIu32, domid);
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

int libxl__xs_mknod(libxl__gc *gc, xs_transaction_t t,
                    const char *path, struct xs_permissions *perms,
                    unsigned int num_perms)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    bool ok;

    ok = xs_write(ctx->xsh, t, path, "", 0);
    if (!ok) {
        LOGE(ERROR, "xenstore write failed: `%s' = ''", path);
        return ERROR_FAIL;
    }

    ok = xs_set_permissions(ctx->xsh, t, path, perms, num_perms);
    if (!ok) {
        LOGE(ERROR, "xenstore set permissions failed on `%s'", path);
        return ERROR_FAIL;
    }

    return 0;
}

char *libxl__xs_libxl_path(libxl__gc *gc, uint32_t domid)
{
    char *s = GCSPRINTF("/libxl/%i", domid);
    if (!s)
        LOG(ERROR, "cannot allocate create paths");
    return s;
}

int libxl__xs_read_mandatory(libxl__gc *gc, xs_transaction_t t,
                             const char *path, const char **result_out)
{
    char *result = libxl__xs_read(gc, t, path);
    if (!result) {
        LOGE(ERROR, "xenstore read failed: `%s'", path);
        return ERROR_FAIL;
    }
    *result_out = result;
    return 0;
}

int libxl__xs_read_checked(libxl__gc *gc, xs_transaction_t t,
                           const char *path, const char **result_out)
{
    char *result = libxl__xs_read(gc, t, path);
    if (!result) {
        if (errno != ENOENT) {
            LOGE(ERROR, "xenstore read failed: `%s'", path);
            return ERROR_FAIL;
        }
    }
    *result_out = result;
    return 0;
}

int libxl__xs_write_checked(libxl__gc *gc, xs_transaction_t t,
                            const char *path, const char *string)
{
    size_t length = strlen(string);
    if (!xs_write(CTX->xsh, t, path, string, length)) {
        LOGE(ERROR, "xenstore write failed: `%s' = `%s'", path, string);
        return ERROR_FAIL;
    }
    return 0;
}

int libxl__xs_rm_checked(libxl__gc *gc, xs_transaction_t t, const char *path)
{
    if (!xs_rm(CTX->xsh, t, path)) {
        if (errno == ENOENT)
            return 0;

        LOGE(ERROR, "xenstore rm failed: `%s'", path);
        return ERROR_FAIL;
    }
    return 0;
}

int libxl__xs_transaction_start(libxl__gc *gc, xs_transaction_t *t)
{
    assert(!*t);
    *t = xs_transaction_start(CTX->xsh);
    if (!*t) {
        LOGE(ERROR, "could not create xenstore transaction");
        return ERROR_FAIL;
    }
    return 0;
}

int libxl__xs_transaction_commit(libxl__gc *gc, xs_transaction_t *t)
{
    assert(*t);

    if (!xs_transaction_end(CTX->xsh, *t, 0)) {
        *t = 0;
        if (errno == EAGAIN)
            return +1;

        LOGE(ERROR, "could not commit xenstore transaction");
        return ERROR_FAIL;
    }

    *t = 0;
    return 0;
}

void libxl__xs_transaction_abort(libxl__gc *gc, xs_transaction_t *t)
{
    if (!*t)
        return;

    if (!xs_transaction_end(CTX->xsh, *t, 1))
        LOGE(ERROR, "could not abort xenstore transaction");

    *t = 0;
}

int libxl__xs_path_cleanup(libxl__gc *gc, xs_transaction_t t,
                           const char *user_path)
{
    unsigned int nb = 0;
    char *path, *last, *val;
    int rc;

    /* A path and transaction must be provided by the caller */
    assert(user_path && t);

    path = libxl__strdup(gc, user_path);
    if (!xs_rm(CTX->xsh, t, path)) {
        if (errno != ENOENT)
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
            if (errno != ENOENT)
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
