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

void libxl__alloc_failed(libxl_ctx *ctx, const char *func,
                         size_t nmemb, size_t size) {
#define M "libxl: FATAL ERROR: memory allocation failure"
#define L (size ? M " (%s, %lu x %lu)\n" : M " (%s)\n"), \
          func, (unsigned long)nmemb, (unsigned long)size
    libxl__log(ctx, XTL_CRITICAL, ENOMEM, 0,0, func, L);
    fprintf(stderr, L);
    fflush(stderr);
    _exit(-1);
#undef M
#undef L
}

void libxl__ptr_add(libxl__gc *gc, void *ptr)
{
    int i;

    if (!libxl__gc_is_real(gc))
        return;

    if (!ptr)
        return;

    /* fast case: we have space in the array for storing the pointer */
    for (i = 0; i < gc->alloc_maxsize; i++) {
        if (!gc->alloc_ptrs[i]) {
            gc->alloc_ptrs[i] = ptr;
            return;
        }
    }
    int new_maxsize = gc->alloc_maxsize * 2 + 25;
    assert(new_maxsize < INT_MAX / sizeof(void*) / 2);
    gc->alloc_ptrs = realloc(gc->alloc_ptrs, new_maxsize * sizeof(void *));
    if (!gc->alloc_ptrs)
        libxl__alloc_failed(CTX, __func__, new_maxsize, sizeof(void*));

    gc->alloc_ptrs[gc->alloc_maxsize++] = ptr;

    while (gc->alloc_maxsize < new_maxsize)
        gc->alloc_ptrs[gc->alloc_maxsize++] = 0;

    return;
}

void libxl__free_all(libxl__gc *gc)
{
    void *ptr;
    int i;

    assert(libxl__gc_is_real(gc));

    for (i = 0; i < gc->alloc_maxsize; i++) {
        ptr = gc->alloc_ptrs[i];
        gc->alloc_ptrs[i] = NULL;
        free(ptr);
    }
    free(gc->alloc_ptrs);
    gc->alloc_ptrs = 0;
    gc->alloc_maxsize = 0;
}

void *libxl__zalloc(libxl__gc *gc, int bytes)
{
    void *ptr = calloc(bytes, 1);
    if (!ptr) libxl__alloc_failed(CTX, __func__, bytes, 1);

    libxl__ptr_add(gc, ptr);
    return ptr;
}

void *libxl__calloc(libxl__gc *gc, size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (!ptr) libxl__alloc_failed(CTX, __func__, nmemb, size);

    libxl__ptr_add(gc, ptr);
    return ptr;
}

void *libxl__realloc(libxl__gc *gc, void *ptr, size_t new_size)
{
    void *new_ptr = realloc(ptr, new_size);
    int i = 0;

    if (new_ptr == NULL && new_size != 0)
        libxl__alloc_failed(CTX, __func__, new_size, 1);

    if (ptr == NULL) {
        libxl__ptr_add(gc, new_ptr);
    } else if (new_ptr != ptr && libxl__gc_is_real(gc)) {
        for (i = 0; i < gc->alloc_maxsize; i++) {
            if (gc->alloc_ptrs[i] == ptr) {
                gc->alloc_ptrs[i] = new_ptr;
                break;
            }
        }
    }

    return new_ptr;
}

char *libxl__sprintf(libxl__gc *gc, const char *fmt, ...)
{
    char *s;
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    assert(ret >= 0);

    s = libxl__zalloc(gc, ret + 1);
    va_start(ap, fmt);
    ret = vsnprintf(s, ret + 1, fmt, ap);
    va_end(ap);

    return s;
}

char *libxl__strdup(libxl__gc *gc, const char *c)
{
    char *s = strdup(c);

    if (!s) libxl__alloc_failed(CTX, __func__, strlen(c), 1);

    libxl__ptr_add(gc, s);

    return s;
}

char *libxl__strndup(libxl__gc *gc, const char *c, size_t n)
{
    char *s = strndup(c, n);

    if (!s) libxl__alloc_failed(CTX, __func__, n, 1);

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
             const char *fmt, va_list ap)
{
    /* WARNING this function may not call any libxl-provided
     * memory allocation function, as those may
     * call libxl__alloc_failed which calls libxl__logv. */
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
            fileline, func&&file?":":"", func?func:"", func||file?": ":"",
            base);
    if (base != enomem) free(base);
    errno = esave;
}

void libxl__log(libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
            const char *file, int line, const char *func,
            const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    libxl__logv(ctx, msglevel, errnoval, file, line, func, fmt, ap);
    va_end(ap);
}

char *libxl__abs_path(libxl__gc *gc, const char *s, const char *path)
{
    if (!s || s[0] == '/')
        return libxl__strdup(gc, s);
    return libxl__sprintf(gc, "%s/%s", path, s);
}


int libxl__file_reference_map(libxl__file_reference *f)
{
    struct stat st_buf;
    int ret, fd;
    void *data;

    if (f->mapped)
        return 0;

    fd = open(f->path, O_RDONLY);
    if (fd < 0)
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

int libxl__file_reference_unmap(libxl__file_reference *f)
{
    int ret;

    if (!f->mapped)
        return 0;

    ret = munmap(f->data, f->size);
    if (ret == 0) {
        f->mapped = 0;
        f->data = NULL;
        f->size = 0;
        return 0;
    }

    return ERROR_FAIL;
}

_hidden int libxl__parse_mac(const char *s, libxl_mac mac)
{
    const char *tok;
    char *endptr;
    int i;

    for (i = 0, tok = s; *tok && (i < 6); ++i, tok = endptr) {
        mac[i] = strtol(tok, &endptr, 16);
        if (endptr != (tok + 2) || (*endptr != '\0' && *endptr != ':') )
            return ERROR_INVAL;
        if (*endptr == ':')
            endptr++;
    }
    if ( i != 6 )
        return ERROR_INVAL;

    return 0;
}

_hidden int libxl__compare_macs(libxl_mac *a, libxl_mac *b)
{
    int i;

    for (i = 0; i<6; i++) {
        if ((*a)[i] != (*b)[i])
            return (*a)[i] - (*b)[i];
    }

    return 0;
}

_hidden int libxl__init_recursive_mutex(libxl_ctx *ctx, pthread_mutex_t *lock)
{
    pthread_mutexattr_t attr;
    int rc = 0;

    if (pthread_mutexattr_init(&attr) != 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, 
                         "Failed to init mutex attributes\n");
        return ERROR_FAIL;
    }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, 
                         "Failed to set mutex attributes\n");
        rc = ERROR_FAIL;
        goto out;
    }
    if (pthread_mutex_init(lock, &attr) != 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, 
                         "Failed to init mutex\n");
        rc = ERROR_FAIL;
        goto out;
    }
out:
    pthread_mutexattr_destroy(&attr);
    return rc;
}

int libxl__device_model_version_running(libxl__gc *gc, uint32_t domid)
{
    char *path = NULL;
    char *dm_version = NULL;
    libxl_device_model_version value;

    path = libxl__xs_libxl_path(gc, domid);
    path = libxl__sprintf(gc, "%s/dm-version", path);
    dm_version = libxl__xs_read(gc, XBT_NULL, path);
    if (!dm_version) {
        return LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
    }

    if (libxl_device_model_version_from_string(dm_version, &value) < 0) {
        libxl_ctx *ctx = libxl__gc_owner(gc);
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                   "fatal: %s contain a wrong value (%s)", path, dm_version);
        return -1;
    }
    return value;
}

int libxl__hotplug_settings(libxl__gc *gc, xs_transaction_t t)
{
    int rc = 0;
    char *val;

    val = libxl__xs_read(gc, t, DISABLE_UDEV_PATH);
    if (!val && errno != ENOENT) {
        LOGE(ERROR, "cannot read %s from xenstore", DISABLE_UDEV_PATH);
        rc = ERROR_FAIL;
        goto out;
    }
    if (!val) val = "0";

    rc = !!atoi(val);

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
