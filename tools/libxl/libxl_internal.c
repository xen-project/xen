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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libxl.h"
#include "libxl_internal.h"
#include "libxl_utils.h"

int libxl__error_set(libxl_ctx *ctx, int code)
{
    return 0;
}

int libxl__ptr_add(libxl__gc *gc, void *ptr)
{
    int i;
    void **re;

    if (!ptr)
        return 0;

    /* fast case: we have space in the array for storing the pointer */
    for (i = 0; i < gc->alloc_maxsize; i++) {
        if (!gc->alloc_ptrs[i]) {
            gc->alloc_ptrs[i] = ptr;
            return 0;
        }
    }
    /* realloc alloc_ptrs manually with calloc/free/replace */
    re = calloc(gc->alloc_maxsize + 25, sizeof(void *));
    if (!re)
        return -1;
    for (i = 0; i < gc->alloc_maxsize; i++)
        re[i] = gc->alloc_ptrs[i];
    /* assign the next pointer */
    re[i] = ptr;

    /* replace the old alloc_ptr */
    free(gc->alloc_ptrs);
    gc->alloc_ptrs = re;
    gc->alloc_maxsize += 25;
    return 0;
}

void libxl__free_all(libxl__gc *gc)
{
    void *ptr;
    int i;

    for (i = 0; i < gc->alloc_maxsize; i++) {
        ptr = gc->alloc_ptrs[i];
        gc->alloc_ptrs[i] = NULL;
        free(ptr);
    }
    free(gc->alloc_ptrs);
}

void *libxl__zalloc(libxl__gc *gc, int bytes)
{
    void *ptr = calloc(bytes, 1);
    if (!ptr) {
        libxl__error_set(libxl__gc_owner(gc), ENOMEM);
        return NULL;
    }

    libxl__ptr_add(gc, ptr);
    return ptr;
}

void *libxl__calloc(libxl__gc *gc, size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (!ptr) {
        libxl__error_set(libxl__gc_owner(gc), ENOMEM);
        return NULL;
    }

    libxl__ptr_add(gc, ptr);
    return ptr;
}

char *libxl__sprintf(libxl__gc *gc, const char *fmt, ...)
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

    s = libxl__zalloc(gc, ret + 1);
    if (s) {
        va_start(ap, fmt);
        ret = vsnprintf(s, ret + 1, fmt, ap);
        va_end(ap);
    }
    return s;
}

char *libxl__strdup(libxl__gc *gc, const char *c)
{
    char *s = strdup(c);

    if (s)
        libxl__ptr_add(gc, s);

    return s;
}

char *libxl__dirname(libxl__gc *gc, const char *s)
{
    char *c;
    char *ptr = libxl__strdup(gc, s);

    c = strrchr(ptr, '/');
    if (!c)
        return NULL;
    *c = '\0';
    return ptr;
}

void libxl__logv(libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
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

void libxl__log(libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
            const char *file, int line, const char *func,
            char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    libxl__logv(ctx, msglevel, errnoval, file, line, func, fmt, ap);
    va_end(ap);
}

char *libxl__abs_path(libxl__gc *gc, char *s, const char *path)
{
    if (!s || s[0] == '/')
        return s;
    return libxl__sprintf(gc, "%s/%s", path, s);
}


int libxl__file_reference_map(libxl_file_reference *f)
{
	struct stat st_buf;
	int ret, fd;
	void *data;

	if (f->mapped)
		return 0;

	fd = open(f->path, O_RDONLY);
	if (f < 0)
		return ERROR_FAIL;

	ret = fstat(fd, &st_buf);
	if (ret < 0)
		goto out;

	ret = -1;
	data = mmap(NULL, st_buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == NULL)
		goto out;

	f->mapped = 1;
	f->data = data;
	f->size = st_buf.st_size;

	ret = 0;
out:
	close(fd);

	return ret == 0 ? 0 : ERROR_FAIL;
}

int libxl__file_reference_unmap(libxl_file_reference *f)
{
	int ret;

	if (!f->mapped)
		return 0;

	ret = munmap(f->data, f->size);

	return ret == 0 ? 0 : ERROR_FAIL;
}
