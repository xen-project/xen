/*
 * Copyright (c) 2016 Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/dm.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/nospec.h>

long do_dm_op(
    domid_t domid, unsigned int nr_bufs,
    XEN_GUEST_HANDLE_PARAM(xen_dm_op_buf_t) bufs)
{
    struct dmop_args args;
    int rc;

    if ( nr_bufs > ARRAY_SIZE(args.buf) )
        return -E2BIG;

    args.domid = domid;
    args.nr_bufs = array_index_nospec(nr_bufs, ARRAY_SIZE(args.buf) + 1);

    if ( copy_from_guest_offset(&args.buf[0], bufs, 0, args.nr_bufs) )
        return -EFAULT;

    rc = dm_op(&args);

    if ( rc == -ERESTART )
        rc = hypercall_create_continuation(__HYPERVISOR_dm_op, "iih",
                                           domid, nr_bufs, bufs);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
