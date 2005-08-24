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

#include <xenctrl.h>

int
main(int argc, char **argv)
{
    unsigned int xc_fd, io_fd, domid;

    if (argc != 4)
	errx(1, "usage: %s xcfd iofd domid", argv[0]);

    xc_fd = atoi(argv[1]);
    io_fd = atoi(argv[2]);
    domid = atoi(argv[3]);

    return xc_linux_save(xc_fd, io_fd, domid);
}
