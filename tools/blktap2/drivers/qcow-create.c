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
#include <string.h>
#include "tapdisk.h"
#include "qcow.h"

#if 1
#define DFPRINTF(_f, _a...) fprintf ( stderr, _f , ## _a )
#else
#define DFPRINTF(_f, _a...) ((void)0)
#endif

#define MAX_NAME_LEN 1000

void help(void)
{
	fprintf(stderr, "Qcow-utils: v1.0.0\n");
	fprintf(stderr, 
		"usage: qcow-create [-h help] [-r reserve] <SIZE(MB)> <FILENAME> "
		"[<BACKING_FILENAME>]\n"); 
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ret = -1, c, backed = 0;
	int sparse =  1;
	uint64_t size;
	char filename[MAX_NAME_LEN], bfilename[MAX_NAME_LEN];

        for(;;) {
                c = getopt(argc, argv, "hr");
                if (c == -1)
                        break;
                switch(c) {
                case 'h':
                        help();
                        exit(0);
                        break;
                case 'r':
			sparse = 0;
			break;
		default:
			fprintf(stderr, "Unknown option\n");
			help();
		}
	}

	printf("Optind %d, argc %d\n", optind, argc);
	if ( !(optind == (argc - 2) || optind == (argc - 3)) )
		help();

	size = atoi(argv[optind++]);
	size = size << 20;

	if (snprintf(filename, MAX_NAME_LEN, "%s",argv[optind++]) >=
		MAX_NAME_LEN) {
		fprintf(stderr,"Device name too long\n");
		exit(-1);
	}

	if (optind != argc) {
		/*Backing file argument*/
		backed = 1;
		if (snprintf(bfilename, MAX_NAME_LEN, "%s",argv[optind++]) >=
			MAX_NAME_LEN) {
			fprintf(stderr,"Device name too long\n");
			exit(-1);
		}
	}

	DFPRINTF("Creating file size %"PRIu64", name %s\n",(uint64_t)size, filename);
	if (!backed)
		ret = qcow_create(filename,size,NULL,sparse);
	else
		ret = qcow_create(filename,size,bfilename,sparse);

	if (ret < 0)
		DPRINTF("Unable to create QCOW file\n");
	else
		DPRINTF("QCOW file successfully created\n");

	return 0;
}
