/* qcow-create.c
 *
 * Generates a qcow format disk.
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <string.h>
#include "tapdisk.h"

#if 1
#define DFPRINTF(_f, _a...) fprintf ( stderr, _f , ## _a )
#else
#define DFPRINTF(_f, _a...) ((void)0)
#endif


int main(int argc, char *argv[])
{
	int ret = -1;
	uint64_t size;

	if ( (argc < 3) || (argc > 4) ) {
		fprintf(stderr, "Qcow-utils: v1.0.0\n");
		fprintf(stderr, 
			"usage: %s <SIZE(MB)> <FILENAME> "
			"[<BACKING_FILENAME>]\n", 
			argv[0]);
		exit(-1);
	}

	size = atoi(argv[1]);
	size = size << 20;
	DFPRINTF("Creating file size %llu\n",(long long unsigned)size);
	switch(argc) {
	case 3: 
		ret = qcow_create(argv[2],size,NULL,0);
		break;
	case 4:
		ret = qcow_create(argv[2],size,argv[3],0);
		break;		
	}
	if (ret < 0) DPRINTF("Unable to create QCOW file\n");
	else DPRINTF("QCOW file successfully created\n");

	return 0;
}
