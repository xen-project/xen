/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FSIMAGE_PLUGIN_H
#define	_FSIMAGE_PLUGIN_H

#ifdef __cplusplus
extern C {
#endif

#include <sys/types.h>

#include "fsimage.h"

#define	FSIMAGE_PLUGIN_VERSION 1

typedef struct fsi_plugin fsi_plugin_t;

typedef struct fsi_plugin_ops {
	int fpo_version;
	int (*fpo_mount)(fsi_t *, const char *, const char *);
	int (*fpo_umount)(fsi_t *);
	fsi_file_t *(*fpo_open)(fsi_t *, const char *);
	ssize_t (*fpo_read)(fsi_file_t *, void *, size_t);
	ssize_t (*fpo_pread)(fsi_file_t *, void *, size_t, uint64_t);
	int (*fpo_close)(fsi_file_t *);
} fsi_plugin_ops_t;

typedef fsi_plugin_ops_t *
    (*fsi_plugin_init_t)(int, fsi_plugin_t *, const char **);

void fsip_fs_set_data(fsi_t *, void *);
fsi_file_t *fsip_file_alloc(fsi_t *, void *);
void fsip_file_free(fsi_file_t *);
fsi_t *fsip_fs(fsi_file_t *);
uint64_t fsip_fs_offset(fsi_t *);
void *fsip_fs_data(fsi_t *);
void *fsip_file_data(fsi_file_t *);

#ifdef __cplusplus
};
#endif

#endif /* _FSIMAGE_PLUGIN_H */
