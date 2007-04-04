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

#include <xenctrl.h>
#include <xenguest.h>

int
main(int argc, char **argv)
{
    unsigned int xc_fd, io_fd, domid, store_evtchn, console_evtchn;
    unsigned int hvm, pae, apic;
    int ret;
    unsigned long p2m_size, store_mfn, console_mfn;

    if ( argc != 9 )
        errx(1, "usage: %s iofd domid p2m_size store_evtchn "
             "console_evtchn hvm pae apic", argv[0]);

    xc_fd = xc_interface_open();
    if ( xc_fd < 0 )
        errx(1, "failed to open control interface");

    io_fd = atoi(argv[1]);
    domid = atoi(argv[2]);
    p2m_size = atoi(argv[3]);
    store_evtchn = atoi(argv[4]);
    console_evtchn = atoi(argv[5]);
    hvm  = atoi(argv[6]);
    pae  = atoi(argv[7]);
    apic = atoi(argv[8]);

    if ( hvm )
        ret = xc_hvm_restore(xc_fd, io_fd, domid, store_evtchn,
                             &store_mfn, pae, apic);
    else
        ret = xc_linux_restore(xc_fd, io_fd, domid, p2m_size,
                               store_evtchn, &store_mfn,
                               console_evtchn, &console_mfn);

    if ( ret == 0 )
    {
	printf("store-mfn %li\n", store_mfn);
        if ( !hvm )
            printf("console-mfn %li\n", console_mfn);
	fflush(stdout);
    }

    xc_interface_close(xc_fd);

    return ret;
}
