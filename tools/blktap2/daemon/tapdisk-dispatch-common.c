/*
 * (c) 2005 Andrew Warfield and Julian Chesterfield
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "tapdisk-dispatch.h"

int
strsep_len(const char *str, char c, unsigned int len)
{
	unsigned int i;
	
	for (i = 0; str[i]; i++)
		if (str[i] == c) {
			if (len == 0)
				return i;
			len--;
		}

	return (len == 0) ? i : -ERANGE;
}

int
make_blktap_device(char *devname, int major, int minor, int perm)
{
	int err;

	err = unlink(devname);
	if (err && errno != ENOENT) {
		EPRINTF("unlink %s failed: %d\n", devname, errno);
		return -errno;
	}

	/* Need to create device */
	err = mkdir(BLKTAP_DEV_DIR, 0755);
	if (err && errno != EEXIST) {
		EPRINTF("Failed to create %s directory\n", BLKTAP_DEV_DIR);
		return -errno;
	}

	err = mknod(devname, perm, makedev(major, minor));
	if (err) {
		int ret = -errno;
		struct stat st;

		EPRINTF("mknod %s failed: %d\n", devname, -errno);

		err = lstat(devname, &st);
		if (err) {
			DPRINTF("lstat %s failed: %d\n", devname, -errno);
			err = access(devname, F_OK);
			if (err)
				DPRINTF("access %s failed: %d\n", devname, -errno);
			else
				DPRINTF("access %s succeeded\n", devname);
		} else
			DPRINTF("lstat %s: %u:%u\n", devname,
				(unsigned int)st.st_rdev >> 8,
				(unsigned int)st.st_rdev & 0xff);

		return ret;
	}

	DPRINTF("Created %s device\n", devname);
	return 0;
}
