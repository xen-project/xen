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

#ifndef _FSIMAGE_PRIV_H
#define	_FSIMAGE_PRIV_H

#ifdef __cplusplus
extern C {
#endif

#include <sys/types.h>

#include "fsimage.h"
#include "fsimage_plugin.h"

struct fsi_plugin {
	const char *fp_name;
	void *fp_dlh;
	fsi_plugin_ops_t *fp_ops;
	struct fsi_plugin *fp_next;
	void *fp_data;
};

struct fsi {
	int f_fd;
	uint64_t f_off;
	void *f_data;
	fsi_plugin_t *f_plugin;
	char *f_bootstring;
};

struct fsi_file {
	fsi_t *ff_fsi;
	void *ff_data;
};

int find_plugin(fsi_t *, const char *, const char *);

#ifdef __cplusplus
};
#endif

#endif /* _FSIMAGE_PRIV_H */
