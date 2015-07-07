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

#include <fsimage_plugin.h>
#include INCLUDE_EXTFS_H
#include <errno.h>
#include <inttypes.h>

static int
ext2lib_mount(fsi_t *fsi, const char *name, const char *options)
{
	int err;
	char opts[30] = "";
	ext2_filsys *fs;
	uint64_t offset = fsip_fs_offset(fsi);

	if (offset)
		snprintf(opts, 29, "offset=%" PRId64, offset);

	fs = malloc(sizeof (*fs));
	if (fs == NULL)
		return (-1);

	err = ext2fs_open2(name, opts, 0, 0, 0, unix_io_manager, fs);

	if (err != 0) {
		free(fs);
		errno = EINVAL;
		return (-1);
	}

	fsip_fs_set_data(fsi, fs);
	return (0);
}

static int
ext2lib_umount(fsi_t *fsi)
{
	ext2_filsys *fs = fsip_fs_data(fsi);
	if (ext2fs_close(*fs) != 0) {
		free(fs);
		errno = EINVAL;
		return (-1);
	}
	free(fs);
	return (0);
}

fsi_file_t *
ext2lib_open(fsi_t *fsi, const char *path)
{
	ext2_ino_t ino;
	ext2_filsys *fs = fsip_fs_data(fsi);
	ext2_file_t *f;
	fsi_file_t *file;
	int err;

	err = ext2fs_namei_follow(*fs, EXT2_ROOT_INO, EXT2_ROOT_INO,
	    path, &ino);

	if (err != 0) {
		errno = ENOENT;
		return (NULL);
	}

	f = malloc(sizeof (*f));
	if (f == NULL)
		return (NULL);

	err = ext2fs_file_open(*fs, ino, 0, f);

	if (err != 0) {
		free(f);
		errno = EINVAL;
		return (NULL);
	}

	file = fsip_file_alloc(fsi, f);
	if (file == NULL)
		free(f);
	return (file);
}

ssize_t
ext2lib_read(fsi_file_t *file, void *buf, size_t nbytes)
{
	ext2_file_t *f = fsip_file_data(file);
	unsigned int n;
	int err;

	err = ext2fs_file_read(*f, buf, nbytes, &n);
	if (err != 0) {
		errno = EINVAL;
		return (-1);
	}

	return (n);
}

ssize_t
ext2lib_pread(fsi_file_t *file, void *buf, size_t nbytes, uint64_t off)
{
	ext2_file_t *f = fsip_file_data(file);
	__u64 tmpoff;
	unsigned int n;
	int err;

	if ((err = ext2fs_file_llseek(*f, 0, EXT2_SEEK_CUR, &tmpoff)) != 0) {
		errno = EINVAL;
		return (-1);
	}

	if ((err = ext2fs_file_llseek(*f, off, EXT2_SEEK_SET, NULL)) != 0) {
		errno = EINVAL;
		return (-1);
	}

	err = ext2fs_file_read(*f, buf, nbytes, &n);

	ext2fs_file_llseek(*f, tmpoff, EXT2_SEEK_SET, NULL);

	if (err != 0) {
		errno = EINVAL;
		return (-1);
	}

	return (n);
}

int
ext2lib_close(fsi_file_t *file)
{
	ext2_file_t *f = fsip_file_data(file);
	ext2fs_file_close(*f);
	free(f);
	return (0);
}

fsi_plugin_ops_t *
fsi_init_plugin(int version, fsi_plugin_t *fp, const char **name)
{
	static fsi_plugin_ops_t ops = {
		FSIMAGE_PLUGIN_VERSION,
		.fpo_mount = ext2lib_mount,
		.fpo_umount = ext2lib_umount,
		.fpo_open = ext2lib_open,
		.fpo_read = ext2lib_read,
		.fpo_pread = ext2lib_pread,
		.fpo_close = ext2lib_close
	};

	*name = "ext2fs-lib";
	return (&ops);
}
