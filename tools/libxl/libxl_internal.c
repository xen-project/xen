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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "libxl.h"
#include "libxl_internal.h"
#include "libxl_utils.h"

int libxl_error_set(struct libxl_ctx *ctx, int code)
{
    return 0;
}

int libxl_ptr_add(struct libxl_ctx *ctx, void *ptr)
{
    int i;
    void **re;

    if (!ptr)
        return 0;

    /* fast case: we have space in the array for storing the pointer */
    for (i = 0; i < ctx->alloc_maxsize; i++) {
        if (!ctx->alloc_ptrs[i]) {
            ctx->alloc_ptrs[i] = ptr;
            return 0;
        }
    }
    /* realloc alloc_ptrs manually with calloc/free/replace */
    re = calloc(ctx->alloc_maxsize + 25, sizeof(void *));
    if (!re)
        return -1;
    for (i = 0; i < ctx->alloc_maxsize; i++)
        re[i] = ctx->alloc_ptrs[i];
    /* assign the next pointer */
    re[i] = ptr;

    /* replace the old alloc_ptr */
    free(ctx->alloc_ptrs);
    ctx->alloc_ptrs = re;
    ctx->alloc_maxsize += 25;
    return 0;
}

int libxl_free(struct libxl_ctx *ctx, void *ptr)
{
    int i;

    if (!ptr)
        return 0;

    /* remove the pointer from the tracked ptrs */
    for (i = 0; i < ctx->alloc_maxsize; i++) {
        if (ctx->alloc_ptrs[i] == ptr) {
            ctx->alloc_ptrs[i] = NULL;
            free(ptr);
            return 0;
        }
    }
    /* haven't find the pointer, really bad */
    return -1;
}

int libxl_free_all(struct libxl_ctx *ctx)
{
    void *ptr;
    int i;

    for (i = 0; i < ctx->alloc_maxsize; i++) {
        ptr = ctx->alloc_ptrs[i];
        ctx->alloc_ptrs[i] = NULL;
        free(ptr);
    }
    return 0;
}

void *libxl_zalloc(struct libxl_ctx *ctx, int bytes)
{
    void *ptr = calloc(bytes, 1);
    if (!ptr) {
        libxl_error_set(ctx, ENOMEM);
        return NULL;
    }

    libxl_ptr_add(ctx, ptr);
    return ptr;
}

void *libxl_calloc(struct libxl_ctx *ctx, size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (!ptr) {
        libxl_error_set(ctx, ENOMEM);
        return NULL;
    }

    libxl_ptr_add(ctx, ptr);
    return ptr;
}

char *libxl_sprintf(struct libxl_ctx *ctx, const char *fmt, ...)
{
    char *s;
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (ret < 0) {
        return NULL;
    }

    s = libxl_zalloc(ctx, ret + 1);
    if (s) {
        va_start(ap, fmt);
        ret = vsnprintf(s, ret + 1, fmt, ap);
        va_end(ap);
    }
    return s;
}

char *libxl_dirname(struct libxl_ctx *ctx, const char *s)
{
    char *c;
    char *ptr = libxl_sprintf(ctx, "%s", s);

    c = strrchr(ptr, '/');
    if (!c)
        return NULL;
    *c = '\0';
    return ptr;
}

void xl_logv(struct libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
             const char *file, int line, const char *func,
             char *fmt, va_list ap)
{
    char *enomem = "[out of memory formatting log message]";
    char *base = NULL;
    int rc, esave;
    char fileline[256];

    esave = errno;

    rc = vasprintf(&base, fmt, ap);
    if (rc<0) { base = enomem; goto x; }

    fileline[0] = 0;
    if (file) snprintf(fileline, sizeof(fileline), "%s:%d",file,line);
    fileline[sizeof(fileline)-1] = 0;

 x:
    xtl_log(ctx->lg, msglevel, errnoval, "libxl",
            "%s%s%s%s" "%s",
            fileline, func&&file?":":"", func?func:"", func||file?" ":"",
            base);
    if (base != enomem) free(base);
    errno = esave;
}

void xl_log(struct libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
            const char *file, int line, const char *func,
            char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    xl_logv(ctx, msglevel, errnoval, file, line, func, fmt, ap);
    va_end(ap);
}

char *libxl_abs_path(struct libxl_ctx *ctx, char *s, const char *path)
{
    if (!s || s[0] == '/')
        return s;
    return libxl_sprintf(ctx, "%s/%s", path, s);
}

