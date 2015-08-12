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

void *libxl__malloc(libxl__gc *gc, size_t size)
{
    void *ptr = malloc(size);
    if (!ptr) libxl__alloc_failed(CTX, __func__, size, 1);

    libxl__ptr_add(gc, ptr);
    return ptr;
}

void *libxl__zalloc(libxl__gc *gc, size_t size)
{
    void *ptr = calloc(size, 1);
    if (!ptr) libxl__alloc_failed(CTX, __func__, size, 1);

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

char *libxl__vsprintf(libxl__gc *gc, const char *fmt, va_list ap)
{
    char *s;
    va_list aq;
    int ret;

    va_copy(aq, ap);
    ret = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);

    assert(ret >= 0);

    s = libxl__zalloc(gc, ret + 1);
    va_copy(aq, ap);
    ret = vsnprintf(s, ret + 1, fmt, aq);
    va_end(aq);

    return s;
}

char *libxl__sprintf(libxl__gc *gc, const char *fmt, ...)
{
    char *s;
    va_list ap;

    va_start(ap, fmt);
    s = libxl__vsprintf(gc, fmt, ap);
    va_end(ap);

    return s;
}

char *libxl__strdup(libxl__gc *gc, const char *c)
{
    char *s;

    if (!c) return NULL;

    s = strdup(c);

    if (!s) libxl__alloc_failed(CTX, __func__, strlen(c), 1);

    libxl__ptr_add(gc, s);

    return s;
}

char *libxl__strndup(libxl__gc *gc, const char *c, size_t n)
{
    char *s;

    if (!c) return NULL;

    s = strndup(c, n);

    if (!s) libxl__alloc_failed(CTX, __func__, n, 1);

    libxl__ptr_add(gc, s);

    return s;
}

char *libxl__dirname(libxl__gc *gc, const char *s)
{
    char *c = strrchr(s, '/');

    if (!c)
        return NULL;

    return libxl__strndup(gc, s, c - s);
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
    if (s[0] == '/') return libxl__strdup(gc, s);
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
    if (data == MAP_FAILED)
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

_hidden int libxl__mac_is_default(libxl_mac *mac)
{
    return (!(*mac)[0] && !(*mac)[1] && !(*mac)[2] &&
            !(*mac)[3] && !(*mac)[4] && !(*mac)[5]);
}

_hidden int libxl__init_recursive_mutex(libxl_ctx *ctx, pthread_mutex_t *lock)
{
    pthread_mutexattr_t attr;
    int rc = 0;

    if (pthread_mutexattr_init(&attr) != 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR,
                         "Failed to init mutex attributes");
        return ERROR_FAIL;
    }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR,
                         "Failed to set mutex attributes");
        rc = ERROR_FAIL;
        goto out;
    }
    if (pthread_mutex_init(lock, &attr) != 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Failed to init mutex");
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

/* Portability note: this lock utilises flock(2) so a proper implementation of
 * flock(2) is required.
 */
libxl__domain_userdata_lock *libxl__lock_domain_userdata(libxl__gc *gc,
                                                         uint32_t domid)
{
    libxl__domain_userdata_lock *lock = NULL;
    const char *lockfile;
    int fd;
    struct stat stab, fstab;

    lockfile = libxl__userdata_path(gc, domid, "domain-userdata-lock", "l");
    if (!lockfile) goto out;

    lock = libxl__zalloc(NOGC, sizeof(libxl__domain_userdata_lock));
    lock->path = libxl__strdup(NOGC, lockfile);

    while (true) {
        libxl__carefd_begin();
        fd = open(lockfile, O_RDWR|O_CREAT, 0666);
        if (fd < 0)
            LOGE(ERROR, "cannot open lockfile %s, errno=%d", lockfile, errno);
        lock->carefd = libxl__carefd_opened(CTX, fd);
        if (fd < 0) goto out;

        /* Lock the file in exclusive mode, wait indefinitely to
         * acquire the lock
         */
        while (flock(fd, LOCK_EX)) {
            switch (errno) {
            case EINTR:
                /* Signal received, retry */
                continue;
            default:
                /* All other errno: EBADF, EINVAL, ENOLCK, EWOULDBLOCK */
                LOGE(ERROR,
                     "unexpected error while trying to lock %s, fd=%d, errno=%d",
                     lockfile, fd, errno);
                goto out;
            }
        }

        if (fstat(fd, &fstab)) {
            LOGE(ERROR, "cannot fstat %s, fd=%d, errno=%d",
                 lockfile, fd, errno);
            goto out;
        }
        if (stat(lockfile, &stab)) {
            if (errno != ENOENT) {
                LOGE(ERROR, "cannot stat %s, errno=%d", lockfile, errno);
                goto out;
            }
        } else {
            if (stab.st_dev == fstab.st_dev && stab.st_ino == fstab.st_ino)
                break;
        }

        libxl__carefd_close(lock->carefd);
    }

    /* Check the domain is still there, if not we should release the
     * lock and clean up.
     */
    if (libxl_domain_info(CTX, NULL, domid))
        goto out;

    return lock;

out:
    if (lock) libxl__unlock_domain_userdata(lock);
    return NULL;
}

void libxl__unlock_domain_userdata(libxl__domain_userdata_lock *lock)
{
    /* It's important to unlink the file before closing fd to avoid
     * the following race (if close before unlink):
     *
     *   P1 LOCK                         P2 UNLOCK
     *   fd1 = open(lockfile)
     *                                   close(fd2)
     *   flock(fd1)
     *   fstat and stat check success
     *                                   unlink(lockfile)
     *   return lock
     *
     * In above case P1 thinks it has got hold of the lock but
     * actually lock is released by P2 (lockfile unlinked).
     */
    if (lock->path) unlink(lock->path);
    if (lock->carefd) libxl__carefd_close(lock->carefd);
    free(lock->path);
    free(lock);
}

int libxl__get_domain_configuration(libxl__gc *gc, uint32_t domid,
                                    libxl_domain_config *d_config)
{
    uint8_t *data = NULL;
    int rc, len;

    rc = libxl__userdata_retrieve(gc, domid, "libxl-json", &data, &len);
    if (rc) {
        LOGEV(ERROR, rc,
              "failed to retrieve domain configuration for domain %d", domid);
        rc = ERROR_FAIL;
        goto out;
    }

    if (len == 0) {
        /* No logging, not necessary an error from caller's PoV. */
        rc = ERROR_JSON_CONFIG_EMPTY;
        goto out;
    }
    rc = libxl_domain_config_from_json(CTX, d_config, (const char *)data);

out:
    free(data);
    return rc;
}

int libxl__set_domain_configuration(libxl__gc *gc, uint32_t domid,
                                    libxl_domain_config *d_config)
{
    char *d_config_json;
    int rc;

    d_config_json = libxl_domain_config_to_json(CTX, d_config);
    if (!d_config_json) {
        LOGE(ERROR,
             "failed to convert domain configuration to JSON for domain %d",
             domid);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__userdata_store(gc, domid, "libxl-json",
                               (const uint8_t *)d_config_json,
                               strlen(d_config_json) + 1 /* include '\0' */);
    if (rc) {
        LOGEV(ERROR, rc, "failed to store domain configuration for domain %d",
              domid);
        rc = ERROR_FAIL;
        goto out;
    }

out:
    free(d_config_json);
    return rc;
}

void libxl__update_domain_configuration(libxl__gc *gc,
                                        libxl_domain_config *dst,
                                        const libxl_domain_config *src)
{
    int i;

    /* update network interface information */
    for (i = 0; i < src->num_nics; i++)
        libxl__update_config_nic(gc, &dst->nics[i], &src->nics[i]);

    /* update vtpm information */
    for (i = 0; i < src->num_vtpms; i++)
        libxl__update_config_vtpm(gc, &dst->vtpms[i], &src->vtpms[i]);

    /* update guest UUID */
    libxl_uuid_copy(CTX, &dst->c_info.uuid, &src->c_info.uuid);

    /* video ram */
    dst->b_info.video_memkb = src->b_info.video_memkb;
}

char *libxl__device_model_xs_path(libxl__gc *gc, uint32_t dm_domid,
                                  uint32_t domid, const char *format,  ...)
{
    char *s, *fmt;
    va_list ap;

    fmt = GCSPRINTF("/local/domain/%u/device-model/%u%s", dm_domid,
                    domid, format);

    va_start(ap, format);
    s = libxl__vsprintf(gc, fmt, ap);
    va_end(ap);

    return s;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
