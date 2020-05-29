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
#ifndef XENHYPFS_H
#define XENHYPFS_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Callers who don't care don't need to #include <xentoollog.h> */
struct xentoollog_logger;

typedef struct xenhypfs_handle xenhypfs_handle;

struct xenhypfs_dirent {
    char *name;
    size_t size;
    enum {
        xenhypfs_type_dir,
        xenhypfs_type_blob,
        xenhypfs_type_string,
        xenhypfs_type_uint,
        xenhypfs_type_int,
        xenhypfs_type_bool
    } type;
    enum {
        xenhypfs_enc_plain,
        xenhypfs_enc_gzip
    } encoding;
    bool is_writable;
};

xenhypfs_handle *xenhypfs_open(struct xentoollog_logger *logger,
                               unsigned int open_flags);
int xenhypfs_close(xenhypfs_handle *fshdl);

/*
 * Return the raw contents of a Xen hypfs entry and its dirent containing
 * the size, type and encoding.
 * Returned buffer and dirent should be freed via free().
 */
void *xenhypfs_read_raw(xenhypfs_handle *fshdl, const char *path,
                        struct xenhypfs_dirent **dirent);

/*
 * Return the contents of a Xen hypfs entry as a string.
 * Returned buffer should be freed via free().
 */
char *xenhypfs_read(xenhypfs_handle *fshdl, const char *path);

/*
 * Return the contents of a Xen hypfs directory in form of an array of
 * dirents.
 * Returned buffer should be freed via free().
 */
struct xenhypfs_dirent *xenhypfs_readdir(xenhypfs_handle *fshdl,
                                         const char *path,
                                         unsigned int *num_entries);

/*
 * Write a Xen hypfs entry with a value. The value is converted from a string
 * to the appropriate type.
 */
int xenhypfs_write(xenhypfs_handle *fshdl, const char *path, const char *val);

#endif /* XENHYPFS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
