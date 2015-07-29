/******************************************************************************
 * tools/xenmon/setmask.c
 * 
 * Simple utility for getting/setting the event mask
 *
 * Copyright (C) 2005 by Hewlett-Packard, Palo Alto and Fort Collins
 *
 * Authors: Lucy Cherkasova, lucy.cherkasova.hp.com
 *          Rob Gardner, rob.gardner@hp.com
 *          Diwaker Gupta, diwaker.gupta@hp.com
 * Date:   August, 2005
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <xenctrl.h>
#include <xen/xen.h>
typedef struct { int counter; } atomic_t;
#include <xen/trace.h>

#define XENMON (TRC_SCHED_DOM_ADD | TRC_SCHED_DOM_REM | TRC_SCHED_SWITCH_INFPREV | TRC_SCHED_SWITCH_INFNEXT | TRC_SCHED_BLOCK | TRC_SCHED_SLEEP | TRC_SCHED_WAKE | TRC_MEM_PAGE_GRANT_TRANSFER)

int main(int argc, char * argv[])
{
    struct xen_sysctl sysctl;
    int ret;

    xc_interface *xc_handle = xc_interface_open(0,0,0);
    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;
    ret = xc_sysctl(xc_handle, &sysctl);
    if ( ret != 0 )
    {
        perror("Failure to get event mask from Xen");
        exit(1);
    }
    else
    {
        printf("Current event mask: 0x%.8x\n", sysctl.u.tbuf_op.evt_mask);
    }

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_evt_mask;
    sysctl.u.tbuf_op.evt_mask = XENMON;

    ret = xc_sysctl(xc_handle, &sysctl);
    printf("Setting mask to 0x%.8x\n", sysctl.u.tbuf_op.evt_mask);
    if ( ret != 0 )
    {
        perror("Failure to get scheduler ID from Xen");
        exit(1);
    }

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;
    ret = xc_sysctl(xc_handle, &sysctl);
    if ( ret != 0 )
    {
        perror("Failure to get event mask from Xen");
        exit(1);
    }
    else
    {
        printf("Current event mask: 0x%.8x\n", sysctl.u.tbuf_op.evt_mask);
    }
    xc_interface_close(xc_handle);
    return 0;
}
