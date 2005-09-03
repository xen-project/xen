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
#include <stdio.h>

#include <xenguest.h>

int
main(int argc, char **argv)
{
    unsigned int xc_fd, io_fd, domid, nr_pfns, store_evtchn, console_evtchn;
    int ret;
    unsigned long store_mfn, console_mfn;

    if (argc != 7)
	errx(1,
	     "usage: %s xcfd iofd domid nr_pfns store_evtchn console_evtchn",
	     argv[0]);

    xc_fd = atoi(argv[1]);
    io_fd = atoi(argv[2]);
    domid = atoi(argv[3]);
    nr_pfns = atoi(argv[4]);
    store_evtchn = atoi(argv[5]);
    console_evtchn = atoi(argv[6]);

    ret = xc_linux_restore(xc_fd, io_fd, domid, nr_pfns, store_evtchn,
			   &store_mfn, console_evtchn, &console_mfn);
    if (ret == 0) {
	printf("store-mfn %li\n", store_mfn);
	printf("console-mfn %li\n", console_mfn);
	fflush(stdout);
    }
    return ret;
}
