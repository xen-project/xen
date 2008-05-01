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

#include <sys/stat.h>
#include <sys/types.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "fsimage_plugin.h"
#include "fsimage_priv.h"

static pthread_mutex_t fsi_lock = PTHREAD_MUTEX_INITIALIZER;

fsi_t *fsi_open_fsimage(const char *path, uint64_t off, const char *options)
{
	fsi_t *fsi = NULL;
	int fd;
	int err;

	if ((fd = open(path, O_RDONLY)) == -1)
		goto fail;

	if ((fsi = malloc(sizeof(*fsi))) == NULL)
		goto fail;

	fsi->f_fd = fd;
	fsi->f_off = off;
	fsi->f_data = NULL;
	fsi->f_bootstring = NULL;

	pthread_mutex_lock(&fsi_lock);
	err = find_plugin(fsi, path, options);
	pthread_mutex_unlock(&fsi_lock);
	if (err != 0)
		goto fail;

	return (fsi);

fail:
	err = errno;
	if (fd != -1)
		(void) close(fd);
	free(fsi);
	errno = err;
	return (NULL);
}

void fsi_close_fsimage(fsi_t *fsi)
{
	pthread_mutex_lock(&fsi_lock);
        fsi->f_plugin->fp_ops->fpo_umount(fsi);
        (void) close(fsi->f_fd);
	free(fsi);
	pthread_mutex_unlock(&fsi_lock);
}

int fsi_file_exists(fsi_t *fsi, const char *path)
{
	fsi_file_t *ffi;

	if ((ffi = fsi_open_file(fsi, path)) == NULL)
		return (0);

	fsi_close_file(ffi);
	return (1);
}

fsi_file_t *fsi_open_file(fsi_t *fsi, const char *path)
{
	fsi_plugin_ops_t *ops;
	fsi_file_t *ffi;

	pthread_mutex_lock(&fsi_lock);
	ops = fsi->f_plugin->fp_ops;
	ffi = ops->fpo_open(fsi, path);
	pthread_mutex_unlock(&fsi_lock);

	return (ffi);
}

int fsi_close_file(fsi_file_t *ffi)
{
	fsi_plugin_ops_t *ops;
	int err;
 
	pthread_mutex_lock(&fsi_lock);
	ops = ffi->ff_fsi->f_plugin->fp_ops;
	err = ops->fpo_close(ffi);
	pthread_mutex_unlock(&fsi_lock);

	return (err);
}

ssize_t fsi_read_file(fsi_file_t *ffi, void *buf, size_t nbytes)
{
	fsi_plugin_ops_t *ops;
	ssize_t ret;
 
	pthread_mutex_lock(&fsi_lock);
	ops = ffi->ff_fsi->f_plugin->fp_ops;
	ret = ops->fpo_read(ffi, buf, nbytes);
	pthread_mutex_unlock(&fsi_lock);

	return (ret);
}

ssize_t fsi_pread_file(fsi_file_t *ffi, void *buf, size_t nbytes, uint64_t off)
{
	fsi_plugin_ops_t *ops;
	ssize_t ret;
 
	pthread_mutex_lock(&fsi_lock);
	ops = ffi->ff_fsi->f_plugin->fp_ops;
	ret = ops->fpo_pread(ffi, buf, nbytes, off);
	pthread_mutex_unlock(&fsi_lock);

	return (ret);
}

char *
fsi_bootstring_alloc(fsi_t *fsi, size_t len)
{
	fsi->f_bootstring = malloc(len);
	if (fsi->f_bootstring == NULL)
		return (NULL);

	bzero(fsi->f_bootstring, len);
	return (fsi->f_bootstring);
}

void
fsi_bootstring_free(fsi_t *fsi)
{
	if (fsi->f_bootstring != NULL) {
		free(fsi->f_bootstring);
		fsi->f_bootstring = NULL;
	}
}

char *
fsi_fs_bootstring(fsi_t *fsi)
{
	return (fsi->f_bootstring);
}
