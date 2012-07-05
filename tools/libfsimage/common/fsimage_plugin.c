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

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>

#include "fsimage_plugin.h"
#include "fsimage_priv.h"

static fsi_plugin_t *plugins;

void
fsip_fs_set_data(fsi_t *fsi, void *data)
{
	fsi->f_data = data;
}

fsi_file_t *
fsip_file_alloc(fsi_t *fsi, void *data)
{
	fsi_file_t *ffi = malloc(sizeof (fsi_file_t));
	if (ffi == NULL)
		return (NULL);

	bzero(ffi, sizeof (fsi_file_t));

	ffi->ff_fsi = fsi;
	ffi->ff_data = data;
	return (ffi);
}

void
fsip_file_free(fsi_file_t *ffi)
{
	free(ffi);
}

fsi_t *
fsip_fs(fsi_file_t *ffi)
{
	return (ffi->ff_fsi);
}

uint64_t
fsip_fs_offset(fsi_t *fsi)
{
	return (fsi->f_off);
}

void *
fsip_fs_data(fsi_t *fsi)
{
	return (fsi->f_data);
}

void *
fsip_file_data(fsi_file_t *ffi)
{
	return (ffi->ff_data);
}

static int init_plugin(const char *lib)
{
	fsi_plugin_init_t init;
	fsi_plugin_t *fp = malloc(sizeof (fsi_plugin_t));

	if (fp == NULL)
		return (-1);

	bzero(fp, sizeof (fsi_plugin_t));

	if ((fp->fp_dlh = dlopen(lib, RTLD_LAZY | RTLD_LOCAL)) == NULL) {
		free(fp);
		return (0);
	}

	init = dlsym(fp->fp_dlh, "fsi_init_plugin");

	if (init == NULL)
		goto fail;

	fp->fp_ops = init(FSIMAGE_PLUGIN_VERSION, fp, &fp->fp_name);
	if (fp->fp_ops == NULL ||
	    fp->fp_ops->fpo_version > FSIMAGE_PLUGIN_VERSION)
		goto fail;

	fp->fp_next = plugins;
	plugins = fp;

	return (0);
fail:
	(void) dlclose(fp->fp_dlh);
	free(fp);
	return (-1);
}

static int load_plugins(void)
{
	const char *fsdir = getenv("FSIMAGE_FSDIR");
	struct dirent *dp = NULL;
	struct dirent *dpp;
	DIR *dir = NULL;
	char *tmp = NULL;
	size_t name_max;
	int err;
	int ret = -1;

	if (fsdir == NULL)
		fsdir = FSIMAGE_FSDIR;

	if ((name_max = pathconf(fsdir, _PC_NAME_MAX)) == -1)
		goto fail;

	if ((tmp = malloc(name_max + 1)) == NULL)
		goto fail;

	if ((dp = malloc(sizeof (struct dirent) + name_max + 1)) == NULL)
		goto fail;

	if ((dir = opendir(fsdir)) == NULL)
		goto fail;

	bzero(dp, sizeof (struct dirent) + name_max + 1);

	while (readdir_r(dir, dp, &dpp) == 0 && dpp != NULL) {
		if (strcmp(dpp->d_name, ".") == 0)
			continue;
		if (strcmp(dpp->d_name, "..") == 0)
			continue;

		(void) snprintf(tmp, name_max, "%s/%s/fsimage.so", fsdir,
			dpp->d_name);

		if (init_plugin(tmp) != 0)
			goto fail;
	}

	ret = 0;

fail:
	err = errno;
	if (dir != NULL)
		(void) closedir(dir);
	free(tmp);
	free(dp);
	errno = err;
	return (ret);
}

int find_plugin(fsi_t *fsi, const char *path, const char *options)
{
	fsi_plugin_t *fp;
	int ret = 0;

	if (plugins == NULL && (ret = load_plugins()) != 0)
		goto out;

	for (fp = plugins; fp != NULL; fp = fp->fp_next) {
		fsi->f_plugin = fp;
		if (fp->fp_ops->fpo_mount(fsi, path, options) == 0)
			goto out;
	}

	ret = -1;
	errno = ENOTSUP;
out:
	return (ret);
}
