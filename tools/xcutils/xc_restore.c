/* 
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2005 by Christian Limpach
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <err.h>

#include <xc.h>

int
main(int argc, char **argv)
{
    unsigned int xc_fd, io_fd, domid, nr_pfns;

    if (argc != 5)
	errx(1, "usage: %s xcfd iofd domid nr_pfns", argv[0]);

    xc_fd = atoi(argv[1]);
    io_fd = atoi(argv[2]);
    domid = atoi(argv[3]);
    nr_pfns = atoi(argv[4]);

    return xc_linux_restore(xc_fd, io_fd, domid, nr_pfns);
}
