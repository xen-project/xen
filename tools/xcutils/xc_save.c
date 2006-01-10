/* 
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2005 by Christian Limpach
 *
 */

#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <xenguest.h>


/**
 * Issue a suspend request through stdout, and receive the acknowledgement
 * from stdin.  This is handled by XendCheckpoint in the Python layer.
 */
static int suspend(int domid)
{
    char ans[30];

    printf("suspend\n");
    fflush(stdout);

    return (fgets(ans, sizeof(ans), stdin) != NULL &&
            !strncmp(ans, "done\n", 5));
}


int
main(int argc, char **argv)
{
    unsigned int xc_fd, io_fd, domid, maxit, max_f, flags; 

    if (argc != 7)
	errx(1, "usage: %s xcfd iofd domid maxit maxf flags", argv[0]);

    xc_fd = atoi(argv[1]);
    io_fd = atoi(argv[2]);
    domid = atoi(argv[3]);
    maxit = atoi(argv[4]);
    max_f = atoi(argv[5]);
    flags = atoi(argv[6]);

    return xc_linux_save(xc_fd, io_fd, domid, maxit, max_f, flags, &suspend);
}
