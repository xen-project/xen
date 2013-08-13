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

#ifndef __sun__
#define	_XOPEN_SOURCE 500
#endif
#include <stdlib.h>
#include <strings.h>
#include <errno.h>

#include "fsimage_grub.h"
#include "fsimage_priv.h"

static char *disk_read_junk;

typedef struct fsig_data {
	char fd_buf[FSYS_BUFLEN];
} fsig_data_t;

typedef struct fsig_file_data {
	char ffd_buf[FSYS_BUFLEN];
	uint64_t ffd_curpos;
	uint64_t ffd_filepos;
	uint64_t ffd_filemax;
	int ffd_int1;
	int ffd_int2;
	int ffd_errnum;
} fsig_file_data_t;

fsi_file_t *
fsig_file_alloc(fsi_t *fsi)
{
	fsi_file_t *ffi;
	fsig_file_data_t *data = malloc(sizeof (fsig_file_data_t));

	if (data == NULL)
		return (NULL);

	bzero(data, sizeof (fsig_file_data_t));
	bcopy(fsig_fs_buf(fsi), data->ffd_buf, FSYS_BUFLEN);

	if ((ffi = fsip_file_alloc(fsi, data)) == NULL) {
		free(data);
		return (NULL);
	}

	return (ffi);
}

void *
fsig_fs_buf(fsi_t *fsi)
{
	fsig_data_t *data = fsip_fs_data(fsi);
	return ((void *)data->fd_buf);
}

void *
fsig_file_buf(fsi_file_t *ffi)
{
	fsig_file_data_t *data = fsip_file_data(ffi);
	return ((void *)data->ffd_buf);
}

uint64_t *
fsig_filepos(fsi_file_t *ffi)
{
	fsig_file_data_t *data = fsip_file_data(ffi);
	return (&data->ffd_filepos);
}

uint64_t *
fsig_filemax(fsi_file_t *ffi)
{
	fsig_file_data_t *data = fsip_file_data(ffi);
	return (&data->ffd_filemax);
}

int *
fsig_int1(fsi_file_t *ffi)
{
	fsig_file_data_t *data = fsip_file_data(ffi);
	return (&data->ffd_int1);
}

int *
fsig_int2(fsi_file_t *ffi)
{
	fsig_file_data_t *data = fsip_file_data(ffi);
	return (&data->ffd_int2);
}

int *
fsig_errnum(fsi_file_t *ffi)
{
	fsig_file_data_t *data = fsip_file_data(ffi);
	return (&data->ffd_errnum);
}

char **
fsig_disk_read_junk(void)
{
	return (&disk_read_junk);
}

#if defined(__i386__) || defined(__x86_64__)

#ifdef __amd64
#define BSF "bsfq"
#else
#define BSF "bsfl"
#endif
unsigned long
fsig_log2 (unsigned long word)
{
  __asm__ (BSF " %1,%0"
	   : "=r" (word)
	   : "r" (word));
  return word;
}

#else /* Unoptimized */

unsigned long
fsig_log2 (unsigned long word)
{
  unsigned long result = 0;

  while (!(word & 1UL))
    {
      result++;
      word >>= 1;
    }
  return result;
}
#endif

int
fsig_devread(fsi_file_t *ffi, unsigned int sector, unsigned int offset,
    unsigned int bufsize, char *buf)
{
	off_t off;
	ssize_t ret;
	int n, r;
	char tmp[SECTOR_SIZE];

	off = ffi->ff_fsi->f_off + ((off_t)sector * SECTOR_SIZE) + offset;

	/*
	 * Make reads from a raw disk sector-aligned. This is a requirement
	 * for NetBSD. Split the read up into to three parts to meet this
	 * requirement.
	 */

	n = (off & (SECTOR_SIZE - 1));
	if (n > 0) {
		r = SECTOR_SIZE - n;
		if (r > bufsize)
			r = bufsize;
		ret = pread(ffi->ff_fsi->f_fd, tmp, SECTOR_SIZE, off - n);
		if (ret < n + r)
			return (0);
		memcpy(buf, tmp + n, r);
		buf += r;
		bufsize -= r;
		off += r;
	}

	n = (bufsize & ~(SECTOR_SIZE - 1));
	if (n > 0) {
		ret = pread(ffi->ff_fsi->f_fd, buf, n, off);
		if (ret < n)
			return (0);
		buf += n;
		bufsize -= n;
		off += n;
	}
	if (bufsize > 0) {
		ret = pread(ffi->ff_fsi->f_fd, tmp, SECTOR_SIZE, off);
		if (ret < bufsize)
			return (0);
		memcpy(buf, tmp, bufsize);
	}

	return (1);
}

int
fsig_substring(const char *s1, const char *s2)
{
	while (*s1 == *s2) {
		if (*s1 == '\0')
			return (0);
		s1++;
		s2++;
	}

	if (*s1 == '\0')
		return (-1);

	return (1);
}

static int
fsig_mount(fsi_t *fsi, const char *path, const char *options)
{
	fsig_plugin_ops_t *ops = fsi->f_plugin->fp_data;
	fsi_file_t *ffi;
	fsi->f_data = malloc(sizeof (fsig_data_t));

	if (fsi->f_data == NULL)
		return (-1);

	if ((ffi = fsig_file_alloc(fsi)) == NULL) {
		free(fsi->f_data);
		fsi->f_data = NULL;
		return (-1);
	}

	bzero(fsi->f_data, sizeof (fsig_data_t));

	if (!ops->fpo_mount(ffi, options)) {
		fsip_file_free(ffi);
		fsi_bootstring_free(fsi);
		free(fsi->f_data);
		fsi->f_data = NULL;
		return (-1);
	}

	bcopy(fsig_file_buf(ffi), fsig_fs_buf(fsi), FSYS_BUFLEN);
	fsip_file_free(ffi);
	return (0);
}

static int
fsig_umount(fsi_t *fsi)
{
	fsi_bootstring_free(fsi);
	free(fsi->f_data);
	return (0);
}

static fsi_file_t *
fsig_open(fsi_t *fsi, const char *name)
{
	fsig_plugin_ops_t *ops = fsi->f_plugin->fp_data;
	char *path = strdup(name);
	fsi_file_t *ffi = NULL;

	if (path == NULL || (ffi = fsig_file_alloc(fsi)) == NULL)
		goto out;

	if (ops->fpo_dir(ffi, path) == 0) {
		fsip_file_free(ffi);
		ffi = NULL;
		errno = ENOENT;
	}

out:
	free(path);
	return (ffi);
}

static ssize_t
fsig_pread(fsi_file_t *ffi, void *buf, size_t nbytes, uint64_t off)
{
	fsig_plugin_ops_t *ops = ffi->ff_fsi->f_plugin->fp_data;
	fsig_file_data_t *data = fsip_file_data(ffi);

	data->ffd_filepos = off;

	if (data->ffd_filepos >= data->ffd_filemax)
		return (0);

	/* FIXME: check */
	if (data->ffd_filepos + nbytes > data->ffd_filemax)
		nbytes = data->ffd_filemax - data->ffd_filepos;

	errnum = 0;
	return (ops->fpo_read(ffi, buf, nbytes));
}

static ssize_t
fsig_read(fsi_file_t *ffi, void *buf, size_t nbytes)
{
	fsig_file_data_t *data = fsip_file_data(ffi);
	ssize_t ret;

	ret = fsig_pread(ffi, buf, nbytes, data->ffd_curpos);
	data->ffd_curpos = data->ffd_filepos;
	return (ret);
}

static int
fsig_close(fsi_file_t *ffi)
{
	free(ffi->ff_data);
	fsip_file_free(ffi);
	return (0);
}

static fsi_plugin_ops_t fsig_grub_ops = {
	.fpo_version = FSIMAGE_PLUGIN_VERSION,
	.fpo_mount = fsig_mount,
	.fpo_umount = fsig_umount,
	.fpo_open = fsig_open,
	.fpo_read = fsig_read,
	.fpo_pread = fsig_pread,
	.fpo_close = fsig_close
};

fsi_plugin_ops_t *
fsig_init(fsi_plugin_t *plugin, fsig_plugin_ops_t *ops)
{
	if (ops->fpo_version > FSIMAGE_PLUGIN_VERSION)
		return (NULL);

	plugin->fp_data = ops;

	return (&fsig_grub_ops);
}
