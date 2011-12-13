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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FSIMAGE_GRUB_H
#define	_FSIMAGE_GRUB_H

#ifdef __cplusplus
extern C {
#endif

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "fsimage.h"
#include "fsimage_plugin.h"

typedef struct fsig_plugin_ops {
	int fpo_version;
	int (*fpo_mount)(fsi_file_t *, const char *);
	int (*fpo_dir)(fsi_file_t *, char *);
	int (*fpo_read)(fsi_file_t *, char *, int);
} fsig_plugin_ops_t;

#define	STAGE1_5
#define FSYS_BUFLEN 0x40000
#define	SECTOR_BITS 9
#define	SECTOR_SIZE 0x200

#define	FSYS_BUF (fsig_file_buf(ffi))
#define	filepos (*fsig_filepos(ffi))
#define	filemax (*fsig_filemax(ffi))
#define	devread fsig_devread
#define substring fsig_substring
#define	errnum (*fsig_errnum(ffi))
#define	disk_read_func (*fsig_disk_read_junk())
#define	disk_read_hook (*fsig_disk_read_junk())
#define	print_possibilities 0
#define	noisy_printf(fmt...)

#define	grub_memset memset
#define	grub_memmove memmove
#define grub_log2 fsig_log2

extern char **fsig_disk_read_junk(void);
unsigned long fsig_log2(unsigned long);

#define	ERR_FSYS_CORRUPT 1
#define	ERR_OUTSIDE_PART 1
#define	ERR_SYMLINK_LOOP 1
#define	ERR_FILELENGTH 1
#define	ERR_BAD_FILETYPE 1
#define	ERR_FILE_NOT_FOUND 1
#define	ERR_BAD_ARGUMENT 1
#define	ERR_FILESYSTEM_NOT_FOUND 1
#define	ERR_NO_BOOTPATH 1
#define	ERR_DEV_VALUES 1
#define	ERR_WONT_FIT 1
#define	ERR_READ 1
#define	ERR_NEWER_VERSION 1

fsi_plugin_ops_t *fsig_init(fsi_plugin_t *, fsig_plugin_ops_t *);

int fsig_devread(fsi_file_t *, unsigned int, unsigned int, unsigned int, char *);
int fsig_substring(const char *, const char *);

void *fsig_fs_buf(fsi_t *);

fsi_file_t *fsig_file_alloc(fsi_t *);
void *fsig_file_buf(fsi_file_t *);
uint64_t *fsig_filepos(fsi_file_t *);
uint64_t *fsig_filemax(fsi_file_t *);
int *fsig_int1(fsi_file_t *);
int *fsig_int2(fsi_file_t *);
int *fsig_errnum(fsi_file_t *);

#ifdef __cplusplus
};
#endif

#endif /* _FSIMAGE_GRUB_H */
