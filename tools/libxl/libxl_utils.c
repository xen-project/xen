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

#include "libxl_osdeps.h" /* must come before any other headers */

#include <ctype.h>

#include "libxl_internal.h"
#include "_paths.h"

#ifndef LIBXL_HAVE_NONCONST_LIBXL_BASENAME_RETURN_VALUE
const
#endif
char *libxl_basename(const char *name)
{
    const char *filename;
    if (name == NULL)
        return strdup(".");
    if (name[0] == '\0')
        return strdup(".");

    filename = strrchr(name, '/');
    if (filename)
        return strdup(filename+1);
    return strdup(name);
}

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

char *libxl_domid_to_name(libxl_ctx *ctx, uint32_t domid)
{
    unsigned int len;
    char path[strlen("/local/domain") + 12];
    char *s;

    snprintf(path, sizeof(path), "/local/domain/%d/name", domid);
    s = xs_read(ctx->xsh, XBT_NULL, path, &len);
    return s;
}

char *libxl__domid_to_name(libxl__gc *gc, uint32_t domid)
{
    char *s = libxl_domid_to_name(CTX, domid);
    libxl__ptr_add(gc, s);
    return s;
}

int libxl_name_to_domid(libxl_ctx *ctx, const char *name,
                        uint32_t *domid)
{
    int i, nb_domains;
    char *domname;
    libxl_dominfo *dominfo;
    int ret = ERROR_INVAL;

    dominfo = libxl_list_domain(ctx, &nb_domains);
    if (!dominfo)
        return ERROR_NOMEM;

    for (i = 0; i < nb_domains; i++) {
        domname = libxl_domid_to_name(ctx, dominfo[i].domid);
        if (!domname)
            continue;
        if (strcmp(domname, name) == 0) {
            *domid = dominfo[i].domid;
            ret = 0;
            free(domname);
            break;
        }
        free(domname);
    }
    free(dominfo);
    return ret;
}

int libxl_domain_qualifier_to_domid(libxl_ctx *ctx, const char *name,
                                    uint32_t *domid)
{
    int i, rv;
    for (i=0; name[i]; i++) {
        if (!CTYPE(isdigit, name[i])) {
            goto nondigit_found;
        }
    }
    *domid = strtoul(name, NULL, 10);
    return 0;

 nondigit_found:
    /* this could also check for uuids */
    rv = libxl_name_to_domid(ctx, name, domid);
    return rv;
}

static int qualifier_to_id(const char *p, uint32_t *id_r)
{
    int i, alldigit;

    alldigit = 1;
    for (i = 0; p[i]; i++) {
        if (!isdigit((uint8_t)p[i])) {
            alldigit = 0;
            break;
        }
    }

    if (i > 0 && alldigit) {
        *id_r = strtoul(p, NULL, 10);
        return 0;
    } else {
        /* check here if it's a uuid and do proper conversion */
    }
    return 1;
}

int libxl_cpupool_qualifier_to_cpupoolid(libxl_ctx *ctx, const char *p,
                                         uint32_t *poolid_r,
                                         int *was_name_r)
{
    int was_name;

    was_name = qualifier_to_id(p, poolid_r);
    if (was_name_r) *was_name_r = was_name;
    return was_name ? libxl_name_to_cpupoolid(ctx, p, poolid_r) : 0;
}

char *libxl_cpupoolid_to_name(libxl_ctx *ctx, uint32_t poolid)
{
    unsigned int len;
    char path[strlen("/local/pool") + 12];
    char *s;

    snprintf(path, sizeof(path), "/local/pool/%d/name", poolid);
    s = xs_read(ctx->xsh, XBT_NULL, path, &len);
    if (!s && (poolid == 0))
        return strdup("Pool-0");
    return s;
}

/* This is a bit horrid but without xs_exists it seems like the only way. */
int libxl_cpupoolid_is_valid(libxl_ctx *ctx, uint32_t poolid)
{
    int ret;
    char *s = libxl_cpupoolid_to_name(ctx, poolid);

    ret = (s != NULL);
    free(s);
    return ret;
}

char *libxl__cpupoolid_to_name(libxl__gc *gc, uint32_t poolid)
{
    char *s = libxl_cpupoolid_to_name(CTX, poolid);
    libxl__ptr_add(gc, s);
    return s;
}

int libxl_name_to_cpupoolid(libxl_ctx *ctx, const char *name,
                        uint32_t *poolid)
{
    int i, nb_pools;
    char *poolname;
    libxl_cpupoolinfo *poolinfo;
    int ret = ERROR_INVAL;

    poolinfo = libxl_list_cpupool(ctx, &nb_pools);
    if (!poolinfo)
        return ERROR_NOMEM;

    for (i = 0; i < nb_pools; i++) {
        if (ret && ((poolname = libxl_cpupoolid_to_name(ctx,
            poolinfo[i].poolid)) != NULL)) {
            if (strcmp(poolname, name) == 0) {
                *poolid = poolinfo[i].poolid;
                ret = 0;
            }
            free(poolname);
        }
    }
    libxl_cpupoolinfo_list_free(poolinfo, nb_pools);
    return ret;
}

int libxl_get_stubdom_id(libxl_ctx *ctx, int guest_domid)
{
    GC_INIT(ctx);
    char * stubdom_id_s;
    int ret;

    stubdom_id_s = libxl__xs_read(gc, XBT_NULL,
                                  GCSPRINTF("%s/image/device-model-domid",
                                  libxl__xs_get_dompath(gc, guest_domid)));
    if (stubdom_id_s)
        ret = atoi(stubdom_id_s);
    else
        ret = 0;
    GC_FREE;
    return ret;
}

int libxl_is_stubdom(libxl_ctx *ctx, uint32_t domid, uint32_t *target_domid)
{
    GC_INIT(ctx);
    char *target, *endptr;
    uint32_t value;
    int ret = 0;

    target = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/target",
                            libxl__xs_get_dompath(gc, domid)));
    if (!target)
        goto out;
    value = strtol(target, &endptr, 10);
    if (*endptr != '\0')
        goto out;
    if (target_domid)
        *target_domid = value;
    ret = 1;
out:
    GC_FREE;
    return ret;
}

static int logrename(libxl__gc *gc, const char *old, const char *new)
{
    int r;

    r = rename(old, new);
    if (r) {
        if (errno == ENOENT) return 0; /* ok */

        LOGE(ERROR, "failed to rotate logfile - "
                    "could not rename %s to %s", old, new);
        return ERROR_FAIL;
    }
    return 0;
}

int libxl_create_logfile(libxl_ctx *ctx, const char *name, char **full_name)
{
    GC_INIT(ctx);
    struct stat stat_buf;
    char *logfile, *logfile_new;
    int i, rc;

    logfile = GCSPRINTF(XEN_LOG_DIR "/%s.log", name);
    if (stat(logfile, &stat_buf) == 0) {
        /* file exists, rotate */
        logfile = GCSPRINTF(XEN_LOG_DIR "/%s.log.10", name);
        unlink(logfile);
        for (i = 9; i > 0; i--) {
            logfile = GCSPRINTF(XEN_LOG_DIR "/%s.log.%d", name, i);
            logfile_new = GCSPRINTF(XEN_LOG_DIR "/%s.log.%d", name, i + 1);
            rc = logrename(gc, logfile, logfile_new);
            if (rc)
                goto out;
        }
        logfile = GCSPRINTF(XEN_LOG_DIR "/%s.log", name);
        logfile_new = GCSPRINTF(XEN_LOG_DIR "/%s.log.1", name);

        rc = logrename(gc, logfile, logfile_new);
        if (rc)
            goto out;
    } else {
        if (errno != ENOENT)
            LOGE(WARN, "problem checking existence of logfile %s, "
                       "which might have needed to be rotated",
                 name);
    }
    *full_name = strdup(logfile);
    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_string_to_backend(libxl_ctx *ctx, char *s, libxl_disk_backend *backend)
{
    char *p;
    int rc = 0;

    if (!strcmp(s, "phy")) {
        *backend = LIBXL_DISK_BACKEND_PHY;
    } else if (!strcmp(s, "file")) {
        *backend = LIBXL_DISK_BACKEND_TAP;
    } else if (!strcmp(s, "qdisk")) {
        *backend = LIBXL_DISK_BACKEND_QDISK;
    } else if (!strcmp(s, "tap")) {
        p = strchr(s, ':');
        if (!p) {
            rc = ERROR_INVAL;
            goto out;
        }
        p++;
        if (!strcmp(p, "vhd")) {
            *backend = LIBXL_DISK_BACKEND_TAP;
        } else if (!strcmp(p, "qcow")) {
            *backend = LIBXL_DISK_BACKEND_QDISK;
        } else if (!strcmp(p, "qcow2")) {
            *backend = LIBXL_DISK_BACKEND_QDISK;
        }
    }
out:
    return rc;
}

int libxl_read_file_contents(libxl_ctx *ctx, const char *filename,
                             void **data_r, int *datalen_r) {
    GC_INIT(ctx);
    FILE *f = 0;
    uint8_t *data = 0;
    int datalen = 0;
    int e;
    struct stat stab;
    ssize_t rs;

    f = fopen(filename, "r");
    if (!f) {
        if (errno == ENOENT) return ENOENT;
        LOGE(ERROR, "failed to open %s", filename);
        goto xe;
    }

    if (fstat(fileno(f), &stab)) {
        LOGE(ERROR, "failed to fstat %s", filename);
        goto xe;
    }

    if (!S_ISREG(stab.st_mode)) {
        LOGE(ERROR, "%s is not a plain file", filename);
        errno = ENOTTY;
        goto xe;
    }

    if (stab.st_size > INT_MAX) {
        LOG(ERROR, "file %s is far too large", filename);
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
                LOGE(ERROR, "failed to read %s", filename);
            else if (feof(f))
                LOG(ERROR, "%s changed size while we were reading it",
		    filename);
            else
                abort();
            goto xe;
        }
    }

    if (fclose(f)) {
        f = 0;
        LOGE(ERROR, "failed to close %s", filename);
        goto xe;
    }

    if (data_r) *data_r = data;
    if (datalen_r) *datalen_r = datalen;

    GC_FREE;
    return 0;

 xe:
    GC_FREE;
    e = errno;
    assert(e != ENOENT);
    if (f) fclose(f);
    free(data);
    return e;
}

int libxl__read_sysfs_file_contents(libxl__gc *gc, const char *filename,
                                    void **data_r, int *datalen_r)
{
    FILE *f = 0;
    uint8_t *data = 0;
    int datalen = 0;
    int e;
    struct stat stab;
    ssize_t rs;

    f = fopen(filename, "r");
    if (!f) {
        if (errno == ENOENT) return ENOENT;
        LOGE(ERROR, "failed to open %s", filename);
        goto xe;
    }

    if (fstat(fileno(f), &stab)) {
        LOGE(ERROR, "failed to fstat %s", filename);
        goto xe;
    }

    if (!S_ISREG(stab.st_mode)) {
        LOGE(ERROR, "%s is not a plain file", filename);
        errno = ENOTTY;
        goto xe;
    }

    if (stab.st_size > INT_MAX) {
        LOG(ERROR, "file %s is far too large", filename);
        errno = EFBIG;
        goto xe;
    }

    datalen = stab.st_size;

    if (stab.st_size && data_r) {
        data = libxl__malloc(gc, datalen);

        /* For sysfs file, datalen is always PAGE_SIZE. 'read'
         * will return the number of bytes of the actual content,
         * rs <= datalen is expected.
         */
        rs = fread(data, 1, datalen, f);
        if (rs < datalen) {
            if (ferror(f)) {
                LOGE(ERROR, "failed to read %s", filename);
                goto xe;
            }

            datalen = rs;
            data = libxl__realloc(gc, data, datalen);
        }
    }

    if (fclose(f)) {
        f = 0;
        LOGE(ERROR, "failed to close %s", filename);
        goto xe;
    }

    if (data_r) *data_r = data;
    if (datalen_r) *datalen_r = datalen;

    return 0;

 xe:
    e = errno;
    assert(e != ENOENT);
    if (f) fclose(f);
    return e;
}


#define READ_WRITE_EXACTLY(rw, zero_is_eof, constdata)                    \
                                                                          \
  int libxl_##rw##_exactly(libxl_ctx *ctx, int fd,                 \
                           constdata void *data, ssize_t sz,              \
                           const char *source, const char *what) {        \
      ssize_t got;                                                        \
      GC_INIT(ctx);                                                       \
                                                                          \
      while (sz > 0) {                                                    \
          got = rw(fd, data, sz);                                         \
          if (got == -1) {                                                \
              if (errno == EINTR) continue;                               \
              if (!ctx) { GC_FREE; return errno; }                        \
              LOGE(ERROR, "failed to "#rw" %s%s%s",                       \
                   what ? what : "", what ? " from " : "", source);       \
              GC_FREE;                                                    \
              return errno;                                               \
          }                                                               \
          if (got == 0) {                                                 \
              if (!ctx) { GC_FREE; return  EPROTO; }                      \
              LOG(ERROR, zero_is_eof                                      \
                  ? "file/stream truncated reading %s%s%s"                \
                  : "file/stream write returned 0! writing %s%s%s",       \
                  what ? what : "", what ? " from " : "", source);        \
              GC_FREE;                                                    \
              return EPROTO;                                              \
          }                                                               \
          sz -= got;                                                      \
          data = (char*)data + got;                                       \
      }                                                                   \
      GC_FREE;                                                            \
      return 0;                                                           \
  }

READ_WRITE_EXACTLY(read, 1, /* */)
READ_WRITE_EXACTLY(write, 0, const)

int libxl__remove_file(libxl__gc *gc, const char *path)
{
    for (;;) {
        int r = unlink(path);
        if (!r) return 0;
        if (errno == ENOENT) return 0;
        if (errno == EINTR) continue;
        LOGE(ERROR, "failed to remove file %s", path);
        return ERROR_FAIL;
     }
}

int libxl__remove_file_or_directory(libxl__gc *gc, const char *path)
{
    for (;;) {
        int r = rmdir(path);
        if (!r) return 0;
        if (errno == ENOENT) return 0;
        if (errno == ENOTEMPTY) return libxl__remove_directory(gc, path);
        if (errno == ENOTDIR) return libxl__remove_file(gc, path);
        if (errno == EINTR) continue;
        LOGE(ERROR, "failed to remove %s", path);
        return ERROR_FAIL;
     }
}

int libxl__remove_directory(libxl__gc *gc, const char *dirpath)
{
    int rc = 0;
    DIR *d = 0;

    d = opendir(dirpath);
    if (!d) {
        if (errno == ENOENT)
            goto out;

        LOGE(ERROR, "failed to opendir %s for removal", dirpath);
        rc = ERROR_FAIL;
        goto out;
    }

    struct dirent *de;

    for (;;) {
        errno = 0;
        de = readdir(d);
        if (!de && errno) {
            LOGE(ERROR, "failed to readdir %s for removal", dirpath);
            rc = ERROR_FAIL;
            break;
        }
        if (!de)
            break;

        if (!strcmp(de->d_name, ".") ||
            !strcmp(de->d_name, ".."))
            continue;

        const char *subpath = GCSPRINTF("%s/%s", dirpath, de->d_name);
        if (libxl__remove_file_or_directory(gc, subpath))
            rc = ERROR_FAIL;
    }

    for (;;) {
        int r = rmdir(dirpath);
        if (!r) break;
        if (errno == ENOENT) goto out;
        if (errno == EINTR) continue;
        LOGE(ERROR, "failed to remove emptied directory %s", dirpath);
        rc = ERROR_FAIL;
    }

 out:
    if (d) closedir(d);

    return rc;
}

int libxl_pipe(libxl_ctx *ctx, int pipes[2])
{
    GC_INIT(ctx);
    int ret = 0;
    if (pipe(pipes) < 0) {
        LOG(ERROR, "Failed to create a pipe");
        ret = -1;
    }
    GC_FREE;
    return ret;
}

int libxl_bitmap_alloc(libxl_ctx *ctx, libxl_bitmap *bitmap, int n_bits)
{
    GC_INIT(ctx);
    int sz;

    sz = (n_bits + 7) / 8;
    bitmap->map = libxl__calloc(NOGC, sizeof(*bitmap->map), sz);
    bitmap->size = sz;

    GC_FREE;
    return 0;
}

void libxl_bitmap_init(libxl_bitmap *map)
{
    memset(map, '\0', sizeof(*map));
}

void libxl_bitmap_dispose(libxl_bitmap *map)
{
    if (!map)
        return;

    free(map->map);
    map->map = NULL;
    map->size = 0;
}

void libxl_bitmap_copy(libxl_ctx *ctx, libxl_bitmap *dptr,
                       const libxl_bitmap *sptr)
{
    int sz;

    assert(dptr->size == sptr->size);
    sz = dptr->size = sptr->size;
    memcpy(dptr->map, sptr->map, sz * sizeof(*dptr->map));
}

/* This function copies X bytes from source to destination bitmap,
 * where X is the smaller of the two sizes.
 *
 * If destination's size is larger than source, the extra bytes are
 * untouched.
 */
void libxl__bitmap_copy_best_effort(libxl__gc *gc, libxl_bitmap *dptr,
                                    const libxl_bitmap *sptr)
{
    int sz;

    sz = dptr->size < sptr->size ? dptr->size : sptr->size;
    memcpy(dptr->map, sptr->map, sz * sizeof(*dptr->map));
}

void libxl_bitmap_copy_alloc(libxl_ctx *ctx,
                             libxl_bitmap *dptr,
                             const libxl_bitmap *sptr)
{
    GC_INIT(ctx);

    dptr->map = libxl__calloc(NOGC, sptr->size, sizeof(*sptr->map));
    dptr->size = sptr->size;
    memcpy(dptr->map, sptr->map, sptr->size * sizeof(*sptr->map));

    GC_FREE;
}

int libxl_bitmap_is_full(const libxl_bitmap *bitmap)
{
    int i;

    for (i = 0; i < bitmap->size; i++)
        if (bitmap->map[i] != (uint8_t)-1)
            return 0;
   return 1;
}

int libxl_bitmap_is_empty(const libxl_bitmap *bitmap)
{
    int i;

    for (i = 0; i < bitmap->size; i++)
        if (bitmap->map[i])
            return 0;
    return 1;
}

int libxl_bitmap_test(const libxl_bitmap *bitmap, int bit)
{
    if (bit >= bitmap->size * 8)
        return 0;
    return (bitmap->map[bit / 8] & (1 << (bit & 7))) ? 1 : 0;
}

void libxl_bitmap_set(libxl_bitmap *bitmap, int bit)
{
    if (bit >= bitmap->size * 8)
        return;
    bitmap->map[bit / 8] |= 1 << (bit & 7);
}

void libxl_bitmap_reset(libxl_bitmap *bitmap, int bit)
{
    if (bit >= bitmap->size * 8)
        return;
    bitmap->map[bit / 8] &= ~(1 << (bit & 7));
}

int libxl_bitmap_or(libxl_ctx *ctx, libxl_bitmap *or_map,
                    const libxl_bitmap *map1, const libxl_bitmap *map2)
{
    GC_INIT(ctx);
    int rc;
    uint32_t i;
    const libxl_bitmap *large_map;
    const libxl_bitmap *small_map;

    if (map1->size > map2->size) {
        large_map = map1;
        small_map = map2;
    } else {
        large_map = map2;
        small_map = map1;
    }

    rc = libxl_bitmap_alloc(ctx, or_map, large_map->size * 8);
    if (rc)
        goto out;

    /*
     *  If bitmaps aren't the same size, their union (logical or) will
     *  be size of larger bit map.  Any bit past the end of the
     *  smaller bit map, will match the larger one.
     */
    for (i = 0; i < small_map->size; i++)
        or_map->map[i] = (small_map->map[i] | large_map->map[i]);

    for (i = small_map->size; i < large_map->size; i++)
        or_map->map[i] = large_map->map[i];

out:
    GC_FREE;
    return rc;
}

int libxl_bitmap_and(libxl_ctx *ctx, libxl_bitmap *and_map,
                     const libxl_bitmap *map1, const libxl_bitmap *map2)
{
    GC_INIT(ctx);
    int rc;
    uint32_t i;
    const libxl_bitmap *large_map;
    const libxl_bitmap *small_map;

    if (map1->size > map2->size) {
        large_map = map1;
        small_map = map2;
    } else {
        large_map = map2;
        small_map = map1;
    }

    rc = libxl_bitmap_alloc(ctx, and_map, small_map->size * 8);
    if (rc)
        goto out;

    /*
     *  If bitmaps aren't same size, their 'and' will be size of
     *  smaller bit map
     */
    for (i = 0; i < and_map->size; i++)
        and_map->map[i] = (large_map->map[i] & small_map->map[i]);

out:
    GC_FREE;
    return rc;
}

int libxl_bitmap_count_set(const libxl_bitmap *bitmap)
{
    int i, nr_set_bits = 0;
    libxl_for_each_set_bit(i, *bitmap)
        nr_set_bits++;

    return nr_set_bits;
}

/* NB. caller is responsible for freeing the memory */
char *libxl_bitmap_to_hex_string(libxl_ctx *ctx, const libxl_bitmap *bitmap)
{
    GC_INIT(ctx);
    int i = bitmap->size;
    char *p = libxl__zalloc(NOGC, bitmap->size * 2 + 3);
    char *q = p;
    strncpy(p, "0x", 3);
    p += 2;
    while(--i >= 0) {
        sprintf(p, "%02x", bitmap->map[i]);
        p += 2;
    }
    *p = '\0';
    GC_FREE;
    return q;
}

int libxl_cpu_bitmap_alloc(libxl_ctx *ctx, libxl_bitmap *cpumap, int max_cpus)
{
    GC_INIT(ctx);
    int rc = 0;

    if (max_cpus < 0) {
        rc = ERROR_INVAL;
        LOG(ERROR, "invalid number of cpus provided");
        goto out;
    }
    if (max_cpus == 0)
        max_cpus = libxl_get_max_cpus(ctx);
    if (max_cpus < 0) {
        LOG(ERROR, "failed to retrieve the maximum number of cpus");
        rc = max_cpus;
        goto out;
    }
    /* This can't fail: no need to check and log */
    libxl_bitmap_alloc(ctx, cpumap, max_cpus);

 out:
    GC_FREE;
    return rc;
}

int libxl_node_bitmap_alloc(libxl_ctx *ctx, libxl_bitmap *nodemap,
                            int max_nodes)
{
    GC_INIT(ctx);
    int rc = 0;

    if (max_nodes < 0) {
        rc = ERROR_INVAL;
        LOG(ERROR, "invalid number of nodes provided");
        goto out;
    }

    if (max_nodes == 0)
        max_nodes = libxl_get_max_nodes(ctx);
    if (max_nodes < 0) {
        LOG(ERROR, "failed to retrieve the maximum number of nodes");
        rc = max_nodes;
        goto out;
    }
    /* This can't fail: no need to check and log */
    libxl_bitmap_alloc(ctx, nodemap, max_nodes);

 out:
    GC_FREE;
    return rc;
}

int libxl__count_physical_sockets(libxl__gc *gc, int *sockets)
{
    int rc;
    libxl_physinfo info;

    libxl_physinfo_init(&info);

    rc = libxl_get_physinfo(CTX, &info);
    if (rc)
        return rc;

    *sockets = info.nr_cpus / info.threads_per_core
                            / info.cores_per_socket;

    libxl_physinfo_dispose(&info);
    return 0;
}

int libxl_socket_bitmap_alloc(libxl_ctx *ctx, libxl_bitmap *socketmap,
                              int max_sockets)
{
    GC_INIT(ctx);
    int rc = 0;

    if (max_sockets < 0) {
        rc = ERROR_INVAL;
        LOG(ERROR, "invalid number of sockets provided");
        goto out;
    }

    if (max_sockets == 0) {
        rc = libxl__count_physical_sockets(gc, &max_sockets);
        if (rc) {
            LOGE(ERROR, "failed to get system socket count");
            goto out;
        }
    }
    /* This can't fail: no need to check and log */
    libxl_bitmap_alloc(ctx, socketmap, max_sockets);

 out:
    GC_FREE;
    return rc;

}

int libxl_get_online_socketmap(libxl_ctx *ctx, libxl_bitmap *socketmap)
{
    libxl_cputopology *tinfo = NULL;
    int nr_cpus = 0, i, rc = 0;

    tinfo = libxl_get_cpu_topology(ctx, &nr_cpus);
    if (tinfo == NULL) {
        rc = ERROR_FAIL;
        goto out;
    }

    libxl_bitmap_set_none(socketmap);
    for (i = 0; i < nr_cpus; i++)
        if (tinfo[i].socket != XEN_INVALID_SOCKET_ID
            && !libxl_bitmap_test(socketmap, tinfo[i].socket))
            libxl_bitmap_set(socketmap, tinfo[i].socket);

 out:
    libxl_cputopology_list_free(tinfo, nr_cpus);
    return rc;
}

int libxl_nodemap_to_cpumap(libxl_ctx *ctx,
                            const libxl_bitmap *nodemap,
                            libxl_bitmap *cpumap)
{
    libxl_cputopology *tinfo = NULL;
    int nr_cpus = 0, i, rc = 0;

    tinfo = libxl_get_cpu_topology(ctx, &nr_cpus);
    if (tinfo == NULL) {
        rc = ERROR_FAIL;
        goto out;
    }

    libxl_bitmap_set_none(cpumap);
    for (i = 0; i < nr_cpus; i++) {
        if (libxl_bitmap_test(nodemap, tinfo[i].node))
            libxl_bitmap_set(cpumap, i);
    }
 out:
    libxl_cputopology_list_free(tinfo, nr_cpus);
    return rc;
}

int libxl_node_to_cpumap(libxl_ctx *ctx, int node,
                         libxl_bitmap *cpumap)
{
    libxl_bitmap nodemap;
    int rc = 0;

    libxl_bitmap_init(&nodemap);

    rc = libxl_node_bitmap_alloc(ctx, &nodemap, 0);
    if (rc)
        goto out;

    libxl_bitmap_set_none(&nodemap);
    libxl_bitmap_set(&nodemap, node);

    rc = libxl_nodemap_to_cpumap(ctx, &nodemap, cpumap);

 out:
    libxl_bitmap_dispose(&nodemap);
    return rc;
}

int libxl_cpumap_to_nodemap(libxl_ctx *ctx,
                            const libxl_bitmap *cpumap,
                            libxl_bitmap *nodemap)
{
    libxl_cputopology *tinfo = NULL;
    int nr_cpus = 0, i, rc = 0;

    tinfo = libxl_get_cpu_topology(ctx, &nr_cpus);
    if (tinfo == NULL) {
        rc = ERROR_FAIL;
        goto out;
    }

    libxl_bitmap_set_none(nodemap);
    libxl_for_each_set_bit(i, *cpumap) {
        if (i >= nr_cpus)
            break;
        libxl_bitmap_set(nodemap, tinfo[i].node);
    }
 out:
    libxl_cputopology_list_free(tinfo, nr_cpus);
    return rc;
}

int libxl_get_max_cpus(libxl_ctx *ctx)
{
    int max_cpus = xc_get_max_cpus(ctx->xch);

    return max_cpus < 0 ? ERROR_FAIL : max_cpus;
}

int libxl_get_online_cpus(libxl_ctx *ctx)
{
    int online_cpus = xc_get_online_cpus(ctx->xch);

    return online_cpus < 0 ? ERROR_FAIL : online_cpus;
}

int libxl_get_max_nodes(libxl_ctx *ctx)
{
    int max_nodes = xc_get_max_nodes(ctx->xch);

    return max_nodes < 0 ? ERROR_FAIL : max_nodes;
}

int libxl__enum_from_string(const libxl_enum_string_table *t,
                            const char *s, int *e)
{
    if (!t) return ERROR_INVAL;

    for( ; t->s; t++) {
        if (!strcasecmp(t->s, s)) {
                *e = t->v;
                return 0;
        }
    }
    return ERROR_FAIL;
}

void libxl_cputopology_list_free(libxl_cputopology *list, int nr)
{
    int i;
    for (i = 0; i < nr; i++)
        libxl_cputopology_dispose(&list[i]);
    free(list);
}

void libxl_pcitopology_list_free(libxl_pcitopology *list, int nr)
{
    int i;
    for (i = 0; i < nr; i++)
        libxl_pcitopology_dispose(&list[i]);
    free(list);
}

void libxl_numainfo_list_free(libxl_numainfo *list, int nr)
{
    int i;
    for (i = 0; i < nr; i++)
        libxl_numainfo_dispose(&list[i]);
    free(list);
}

void libxl_vcpuinfo_list_free(libxl_vcpuinfo *list, int nr)
{
    int i;
    for (i = 0; i < nr; i++)
        libxl_vcpuinfo_dispose(&list[i]);
    free(list);
}

int libxl__sendmsg_fds(libxl__gc *gc, int carrier,
                       const void *data, size_t datalen,
                       int nfds, const int fds[], const char *what) {
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    size_t spaceneeded = nfds * sizeof(fds[0]);
    char control[CMSG_SPACE(spaceneeded)];
    struct iovec iov;
    int r;

    iov.iov_base = (void*)data;
    iov.iov_len  = datalen;

    /* compose the message */
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    /* attach open fd */
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(spaceneeded);
    memcpy(CMSG_DATA(cmsg), fds, spaceneeded);

    msg.msg_controllen = cmsg->cmsg_len;

    r = sendmsg(carrier, &msg, 0);
    if (r < 0) {
        LOGE(ERROR, "failed to send fd-carrying message (%s)", what);
        return ERROR_FAIL;
    }

    return 0;
}

int libxl__recvmsg_fds(libxl__gc *gc, int carrier,
                       void *databuf, size_t datalen,
                       int nfds, int fds[], const char *what)
{
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    size_t spaceneeded = nfds * sizeof(fds[0]);
    char control[CMSG_SPACE(spaceneeded)];
    struct iovec iov;
    int r;

    iov.iov_base = databuf;
    iov.iov_len  = datalen;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    for (;;) {
        r = recvmsg(carrier, &msg, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EWOULDBLOCK) return -1;
            LOGE(ERROR,"recvmsg failed (%s)", what);
            return ERROR_FAIL;
        }
        if (r == 0) {
            LOG(ERROR,"recvmsg got EOF (%s)", what);
            return ERROR_FAIL;
        }
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg->cmsg_len <= CMSG_LEN(0)) {
            LOG(ERROR,"recvmsg got no control msg"
                " when expecting fds (%s)", what);
            return ERROR_FAIL;
        }
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            LOG(ERROR, "recvmsg got unexpected"
                " cmsg_level %d (!=%d) or _type %d (!=%d) (%s)",
                cmsg->cmsg_level, SOL_SOCKET,
                cmsg->cmsg_type, SCM_RIGHTS,
                what);
            return ERROR_FAIL;
        }
        if (cmsg->cmsg_len != CMSG_LEN(spaceneeded) ||
            msg.msg_controllen != cmsg->cmsg_len) {
            LOG(ERROR, "recvmsg got unexpected"
                " number of fds or extra control data"
                " (%ld bytes' worth, expected %ld) (%s)",
                (long)CMSG_LEN(spaceneeded), (long)cmsg->cmsg_len,
                what);
            int i, fd;
            unsigned char *p;
            for (i=0, p=CMSG_DATA(cmsg);
                 CMSG_SPACE(i * sizeof(fds[0]));
                 i++, i+=sizeof(fd)) {
                memcpy(&fd, p, sizeof(fd));
                close(fd);
            }
            return ERROR_FAIL;
        }
        memcpy(fds, CMSG_DATA(cmsg), spaceneeded);
        return 0;
    }
}         

void libxl_dominfo_list_free(libxl_dominfo *list, int nr)
{
    int i;
    for (i = 0; i < nr; i++)
        libxl_dominfo_dispose(&list[i]);
    free(list);
}

void libxl_vminfo_list_free(libxl_vminfo *list, int nr)
{
    int i;
    for (i = 0; i < nr; i++)
        libxl_vminfo_dispose(&list[i]);
    free(list);
}

void libxl_cpupoolinfo_list_free(libxl_cpupoolinfo *list, int nr)
{
    int i;
    for (i = 0; i < nr; i++)
        libxl_cpupoolinfo_dispose(&list[i]);
    free(list);
}

int libxl_domid_valid_guest(uint32_t domid)
{
    /* returns 1 if the value _could_ be a valid guest domid, 0 otherwise
     * does not check whether the domain actually exists */
    return domid > 0 && domid < DOMID_FIRST_RESERVED;
}

void libxl_string_copy(libxl_ctx *ctx, char **dst, char * const*src)
{
    GC_INIT(ctx);

    if (*src)
        *dst = libxl__strdup(NOGC, *src);
    else
        *dst = NULL;

    GC_FREE;
}

/*
 * Fill @buf with @len random bytes.
 */
int libxl__random_bytes(libxl__gc *gc, uint8_t *buf, size_t len)
{
    static const char *dev = "/dev/urandom";
    int fd;
    int ret;

    fd = open(dev, O_RDONLY);
    if (fd < 0) {
        LOGE(ERROR, "failed to open \"%s\"", dev);
        return ERROR_FAIL;
    }
    ret = libxl_fd_set_cloexec(CTX, fd, 1);
    if (ret) {
        close(fd);
        return ERROR_FAIL;
    }

    ret = libxl_read_exactly(CTX, fd, buf, len, dev, NULL);

    close(fd);

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
