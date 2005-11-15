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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

    dom0_op_t op; 
    int ret;

    int xc_handle = xc_interface_open();
    op.cmd = DOM0_TBUFCONTROL;
    op.interface_version = DOM0_INTERFACE_VERSION;
    op.u.tbufcontrol.op  = DOM0_TBUF_GET_INFO;
    ret = xc_dom0_op(xc_handle, &op);
    if ( ret != 0 )
    {
        perror("Failure to get event mask from Xen");
        exit(1);
    }
    else
    {
        printf("Current event mask: 0x%.8x\n", op.u.tbufcontrol.evt_mask);
    }

    op.cmd = DOM0_TBUFCONTROL;
    op.interface_version = DOM0_INTERFACE_VERSION;
    op.u.tbufcontrol.op  = DOM0_TBUF_SET_EVT_MASK;
    op.u.tbufcontrol.evt_mask = XENMON;

    ret = xc_dom0_op(xc_handle, &op);
    printf("Setting mask to 0x%.8x\n", op.u.tbufcontrol.evt_mask);
    if ( ret != 0 )
    {
        perror("Failure to get scheduler ID from Xen");
        exit(1);
    }

    op.cmd = DOM0_TBUFCONTROL;
    op.interface_version = DOM0_INTERFACE_VERSION;
    op.u.tbufcontrol.op  = DOM0_TBUF_GET_INFO;
    ret = xc_dom0_op(xc_handle, &op);
    if ( ret != 0 )
    {
        perror("Failure to get event mask from Xen");
        exit(1);
    }
    else
    {
        printf("Current event mask: 0x%.8x\n", op.u.tbufcontrol.evt_mask);
    }
    xc_interface_close(xc_handle);
    return 0;
}
