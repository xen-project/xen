/*
 * Copyright (c) 2019 SUSE Software Solutions Germany GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#define __XEN_TOOLS__ 1

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include <xentoollog.h>
#include <xenhypfs.h>
#include <xencall.h>
#include <xentoolcore_internal.h>

#include <xen/xen.h>
#include <xen/hypfs.h>

#define BUF_SIZE 4096

struct xenhypfs_handle {
    xentoollog_logger *logger, *logger_tofree;
    unsigned int flags;
    xencall_handle *xcall;
};

xenhypfs_handle *xenhypfs_open(xentoollog_logger *logger,
                               unsigned open_flags)
{
    xenhypfs_handle *fshdl = calloc(1, sizeof(*fshdl));

    if (!fshdl)
        return NULL;

    fshdl->flags = open_flags;
    fshdl->logger = logger;
    fshdl->logger_tofree = NULL;

    if (!fshdl->logger) {
        fshdl->logger = fshdl->logger_tofree =
            (xentoollog_logger*)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if (!fshdl->logger)
            goto err;
    }

    fshdl->xcall = xencall_open(fshdl->logger, 0);
    if (!fshdl->xcall)
        goto err;

    /* No need to remember supported version, we only support V1. */
    if (xencall5(fshdl->xcall, __HYPERVISOR_hypfs_op,
                 XEN_HYPFS_OP_get_version, 0, 0, 0, 0) < 0)
        goto err;

    return fshdl;

err:
    xtl_logger_destroy(fshdl->logger_tofree);
    xencall_close(fshdl->xcall);
    free(fshdl);
    return NULL;
}

int xenhypfs_close(xenhypfs_handle *fshdl)
{
    if (!fshdl)
        return 0;

    xencall_close(fshdl->xcall);
    xtl_logger_destroy(fshdl->logger_tofree);
    free(fshdl);
    return 0;
}

static int xenhypfs_get_pathbuf(xenhypfs_handle *fshdl, const char *path,
                                char **path_buf)
{
    int ret = -1;
    int path_sz;

    if (!fshdl) {
        errno = EBADF;
        goto out;
    }

    path_sz = strlen(path) + 1;
    if (path_sz > XEN_HYPFS_MAX_PATHLEN)
    {
        errno = ENAMETOOLONG;
        goto out;
    }

    *path_buf = xencall_alloc_buffer(fshdl->xcall, path_sz);
    if (!*path_buf) {
        errno = ENOMEM;
        goto out;
    }
    strcpy(*path_buf, path);

    ret = path_sz;

 out:
    return ret;
}

static void *xenhypfs_inflate(void *in_data, size_t *sz)
{
    unsigned char *workbuf;
    void *content = NULL;
    unsigned int out_sz;
    z_stream z = { .opaque = NULL };
    int ret;

    workbuf = malloc(BUF_SIZE);
    if (!workbuf)
        return NULL;

    z.next_in = in_data;
    z.avail_in = *sz;
    ret = inflateInit2(&z, MAX_WBITS + 32); /* 32 == gzip */

    for (*sz = 0; ret == Z_OK; *sz += out_sz) {
        z.next_out = workbuf;
        z.avail_out = BUF_SIZE;
        ret = inflate(&z, Z_SYNC_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END)
            break;

        out_sz = z.next_out - workbuf;
        content = realloc(content, *sz + out_sz);
        if (!content) {
            ret = Z_MEM_ERROR;
            break;
        }
        memcpy(content + *sz, workbuf, out_sz);
    }

    inflateEnd(&z);
    if (ret != Z_STREAM_END) {
        free(content);
        content = NULL;
        errno = EIO;
    }
    free(workbuf);
    return content;
}

static void xenhypfs_set_attrs(struct xen_hypfs_direntry *entry,
                               struct xenhypfs_dirent *dirent)
{
    dirent->size = entry->content_len;

    switch(entry->type) {
    case XEN_HYPFS_TYPE_DIR:
        dirent->type = xenhypfs_type_dir;
        break;
    case XEN_HYPFS_TYPE_BLOB:
        dirent->type = xenhypfs_type_blob;
        break;
    case XEN_HYPFS_TYPE_STRING:
        dirent->type = xenhypfs_type_string;
        break;
    case XEN_HYPFS_TYPE_UINT:
        dirent->type = xenhypfs_type_uint;
        break;
    case XEN_HYPFS_TYPE_INT:
        dirent->type = xenhypfs_type_int;
        break;
    case XEN_HYPFS_TYPE_BOOL:
        dirent->type = xenhypfs_type_bool;
        break;
    default:
        dirent->type = xenhypfs_type_blob;
    }

    switch (entry->encoding) {
    case XEN_HYPFS_ENC_PLAIN:
        dirent->encoding = xenhypfs_enc_plain;
        break;
    case XEN_HYPFS_ENC_GZIP:
        dirent->encoding = xenhypfs_enc_gzip;
        break;
    default:
        dirent->encoding = xenhypfs_enc_plain;
        dirent->type = xenhypfs_type_blob;
    }

    dirent->is_writable = entry->max_write_len;
}

void *xenhypfs_read_raw(xenhypfs_handle *fshdl, const char *path,
                        struct xenhypfs_dirent **dirent)
{
    void *retbuf = NULL, *content = NULL;
    char *path_buf = NULL;
    const char *name;
    struct xen_hypfs_direntry *entry;
    int ret;
    int sz, path_sz;

    *dirent = NULL;
    ret = xenhypfs_get_pathbuf(fshdl, path, &path_buf);
    if (ret < 0)
        goto out;

    path_sz = ret;

    for (sz = BUF_SIZE;; sz = sizeof(*entry) + entry->content_len) {
        if (retbuf)
            xencall_free_buffer(fshdl->xcall, retbuf);

        retbuf = xencall_alloc_buffer(fshdl->xcall, sz);
        if (!retbuf) {
            errno = ENOMEM;
            goto out;
        }
        entry = retbuf;

        ret = xencall5(fshdl->xcall, __HYPERVISOR_hypfs_op, XEN_HYPFS_OP_read,
                       (unsigned long)path_buf, path_sz,
                       (unsigned long)retbuf, sz);
        if (!ret)
            break;

        if (ret != ENOBUFS) {
            errno = -ret;
            goto out;
        }
    }

    content = malloc(entry->content_len);
    if (!content)
        goto out;
    memcpy(content, entry + 1, entry->content_len);

    name = strrchr(path, '/');
    if (!name)
        name = path;
    else {
        name++;
        if (!*name)
            name--;
    }
    *dirent = calloc(1, sizeof(struct xenhypfs_dirent) + strlen(name) + 1);
    if (!*dirent) {
        free(content);
        content = NULL;
        errno = ENOMEM;
        goto out;
    }
    (*dirent)->name = (char *)(*dirent + 1);
    strcpy((*dirent)->name, name);
    xenhypfs_set_attrs(entry, *dirent);

 out:
    ret = errno;
    xencall_free_buffer(fshdl->xcall, path_buf);
    xencall_free_buffer(fshdl->xcall, retbuf);
    errno = ret;

    return content;
}

char *xenhypfs_read(xenhypfs_handle *fshdl, const char *path)
{
    char *buf, *ret_buf = NULL;
    struct xenhypfs_dirent *dirent;
    int ret;

    buf = xenhypfs_read_raw(fshdl, path, &dirent);
    if (!buf)
        goto out;

    switch (dirent->encoding) {
    case xenhypfs_enc_plain:
        break;
    case xenhypfs_enc_gzip:
        ret_buf = xenhypfs_inflate(buf, &dirent->size);
        if (!ret_buf)
            goto out;
        free(buf);
        buf = ret_buf;
        ret_buf = NULL;
        break;
    }

    switch (dirent->type) {
    case xenhypfs_type_dir:
        errno = EISDIR;
        break;
    case xenhypfs_type_blob:
        errno = EDOM;
        break;
    case xenhypfs_type_string:
        ret_buf = buf;
        buf = NULL;
        break;
    case xenhypfs_type_uint:
    case xenhypfs_type_bool:
        switch (dirent->size) {
        case 1:
            ret = asprintf(&ret_buf, "%"PRIu8, *(uint8_t *)buf);
            break;
        case 2:
            ret = asprintf(&ret_buf, "%"PRIu16, *(uint16_t *)buf);
            break;
        case 4:
            ret = asprintf(&ret_buf, "%"PRIu32, *(uint32_t *)buf);
            break;
        case 8:
            ret = asprintf(&ret_buf, "%"PRIu64, *(uint64_t *)buf);
            break;
        default:
            ret = -1;
            errno = EDOM;
        }
        if (ret < 0)
            ret_buf = NULL;
        break;
    case xenhypfs_type_int:
        switch (dirent->size) {
        case 1:
            ret = asprintf(&ret_buf, "%"PRId8, *(int8_t *)buf);
            break;
        case 2:
            ret = asprintf(&ret_buf, "%"PRId16, *(int16_t *)buf);
            break;
        case 4:
            ret = asprintf(&ret_buf, "%"PRId32, *(int32_t *)buf);
            break;
        case 8:
            ret = asprintf(&ret_buf, "%"PRId64, *(int64_t *)buf);
            break;
        default:
            ret = -1;
            errno = EDOM;
        }
        if (ret < 0)
            ret_buf = NULL;
        break;
    }

 out:
    ret = errno;
    free(buf);
    free(dirent);
    errno = ret;

    return ret_buf;
}

struct xenhypfs_dirent *xenhypfs_readdir(xenhypfs_handle *fshdl,
                                         const char *path,
                                         unsigned int *num_entries)
{
    void *buf, *curr;
    int ret;
    char *names;
    struct xenhypfs_dirent *ret_buf = NULL, *dirent;
    unsigned int n = 0, name_sz = 0;
    struct xen_hypfs_dirlistentry *entry;

    buf = xenhypfs_read_raw(fshdl, path, &dirent);
    if (!buf)
        goto out;

    if (dirent->type != xenhypfs_type_dir ||
        dirent->encoding != xenhypfs_enc_plain) {
        errno = ENOTDIR;
        goto out;
    }

    if (dirent->size) {
        curr = buf;
        for (n = 1;; n++) {
            entry = curr;
            name_sz += strlen(entry->name) + 1;
            if (!entry->off_next)
                break;

            curr += entry->off_next;
        }
    }

    ret_buf = malloc(n * sizeof(*ret_buf) + name_sz);
    if (!ret_buf)
        goto out;

    *num_entries = n;
    names = (char *)(ret_buf + n);
    curr = buf;
    for (n = 0; n < *num_entries; n++) {
        entry = curr;
        xenhypfs_set_attrs(&entry->e, ret_buf + n);
        ret_buf[n].name = names;
        strcpy(names, entry->name);
        names += strlen(entry->name) + 1;
        curr += entry->off_next;
    }

 out:
    ret = errno;
    free(buf);
    free(dirent);
    errno = ret;

    return ret_buf;
}

int xenhypfs_write(xenhypfs_handle *fshdl, const char *path, const char *val)
{
    void *buf = NULL;
    char *path_buf = NULL, *val_end;
    int ret, saved_errno;
    int sz, path_sz;
    struct xen_hypfs_direntry *entry;
    uint64_t mask;

    ret = xenhypfs_get_pathbuf(fshdl, path, &path_buf);
    if (ret < 0)
        goto out;

    path_sz = ret;
    ret = -1;

    sz = BUF_SIZE;
    buf = xencall_alloc_buffer(fshdl->xcall, sz);
    if (!buf) {
        errno = ENOMEM;
        goto out;
    }

    ret = xencall5(fshdl->xcall, __HYPERVISOR_hypfs_op, XEN_HYPFS_OP_read,
                   (unsigned long)path_buf, path_sz,
                   (unsigned long)buf, sizeof(*entry));
    if (ret && errno != ENOBUFS)
        goto out;
    ret = -1;
    entry = buf;
    if (!entry->max_write_len) {
        errno = EACCES;
        goto out;
    }
    if (entry->encoding != XEN_HYPFS_ENC_PLAIN) {
        /* Writing compressed data currently not supported. */
        errno = EDOM;
        goto out;
    }

    switch (entry->type) {
    case XEN_HYPFS_TYPE_STRING:
        if (sz < strlen(val) + 1) {
            sz = strlen(val) + 1;
            xencall_free_buffer(fshdl->xcall, buf);
            buf = xencall_alloc_buffer(fshdl->xcall, sz);
            if (!buf) {
                errno = ENOMEM;
                goto out;
            }
        }
        sz = strlen(val) + 1;
        strcpy(buf, val);
        break;
    case XEN_HYPFS_TYPE_UINT:
        sz = entry->content_len;
        errno = 0;
        *(unsigned long long *)buf = strtoull(val, &val_end, 0);
        if (errno || !*val || *val_end)
            goto out;
        mask = ~0ULL << (8 * sz);
        if ((*(uint64_t *)buf & mask) && ((*(uint64_t *)buf & mask) != mask)) {
            errno = ERANGE;
            goto out;
        }
        break;
    case XEN_HYPFS_TYPE_INT:
        sz = entry->content_len;
        errno = 0;
        *(unsigned long long *)buf = strtoll(val, &val_end, 0);
        if (errno || !*val || *val_end)
            goto out;
        mask = (sz == 8) ? 0 : ~0ULL << (8 * sz);
        if ((*(uint64_t *)buf & mask) && ((*(uint64_t *)buf & mask) != mask)) {
            errno = ERANGE;
            goto out;
        }
        break;
    case XEN_HYPFS_TYPE_BOOL:
        sz = entry->content_len;
        *(unsigned long long *)buf = 0;
        if (!strcmp(val, "1") || !strcmp(val, "on") || !strcmp(val, "yes") ||
            !strcmp(val, "true") || !strcmp(val, "enable"))
            *(unsigned long long *)buf = 1;
        else if (strcmp(val, "0") && strcmp(val, "no") && strcmp(val, "off") &&
                 strcmp(val, "false") && strcmp(val, "disable")) {
            errno = EDOM;
            goto out;
        }
        break;
    default:
        /* No support for other types (yet). */
        errno = EDOM;
        goto out;
    }

    ret = xencall5(fshdl->xcall, __HYPERVISOR_hypfs_op,
                   XEN_HYPFS_OP_write_contents,
                   (unsigned long)path_buf, path_sz,
                   (unsigned long)buf, sz);

 out:
    saved_errno = errno;
    xencall_free_buffer(fshdl->xcall, path_buf);
    xencall_free_buffer(fshdl->xcall, buf);
    errno = saved_errno;
    return ret;
}
