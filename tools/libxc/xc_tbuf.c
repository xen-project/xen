/******************************************************************************
 * xc_tbuf.c
 *
 * API for manipulating and accessing trace buffer parameters
 *
 * Copyright (c) 2005, Rob Gardner
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"
#include <xen/trace.h>

static int tbuf_enable(xc_interface *xch, int enable)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    if ( enable )
        sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_enable;
    else
        sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_disable;

    return xc_sysctl(xch, &sysctl);
}

int xc_tbuf_set_size(xc_interface *xch, unsigned long size)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_size;
    sysctl.u.tbuf_op.size = size;

    return xc_sysctl(xch, &sysctl);
}

int xc_tbuf_get_size(xc_interface *xch, unsigned long *size)
{
    struct t_info *t_info;
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;

    rc = xc_sysctl(xch, &sysctl);
    if ( rc != 0 )
        return rc;

    t_info = xc_map_foreign_range(xch, DOMID_XEN,
                    sysctl.u.tbuf_op.size, PROT_READ | PROT_WRITE,
                    sysctl.u.tbuf_op.buffer_mfn);

    if ( t_info == NULL || t_info->tbuf_size == 0 )
        return -1;

    *size = t_info->tbuf_size;

    return 0;
}

int xc_tbuf_enable(xc_interface *xch, unsigned long pages, unsigned long *mfn,
                   unsigned long *size)
{
    DECLARE_SYSCTL;
    int rc;

    /*
     * Ignore errors (at least for now) as we get an error if size is already
     * set (since trace buffers cannot be reallocated). If we really have no
     * buffers at all then tbuf_enable() will fail, so this is safe.
     */
    (void)xc_tbuf_set_size(xch, pages);

    if ( tbuf_enable(xch, 1) != 0 )
        return -1;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;

    rc = xc_sysctl(xch, &sysctl);
    if ( rc == 0 )
    {
        *size = sysctl.u.tbuf_op.size;
        *mfn = sysctl.u.tbuf_op.buffer_mfn;
    }

    return 0;
}

int xc_tbuf_disable(xc_interface *xch)
{
    return tbuf_enable(xch, 0);
}

int xc_tbuf_set_cpu_mask(xc_interface *xch, uint32_t mask)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BUFFER(uint8_t, bytemap);
    int ret = -1;
    uint64_t mask64 = mask;

    bytemap = xc_hypercall_buffer_alloc(xch, bytemap, sizeof(mask64));
    if ( bytemap == NULL )
    {
        PERROR("Could not allocate memory for xc_tbuf_set_cpu_mask hypercall");
        goto out;
    }

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_cpu_mask;

    bitmap_64_to_byte(bytemap, &mask64, sizeof (mask64) * 8);

    set_xen_guest_handle(sysctl.u.tbuf_op.cpu_mask.bitmap, bytemap);
    sysctl.u.tbuf_op.cpu_mask.nr_bits = sizeof(bytemap) * 8;

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_buffer_free(xch, bytemap);

 out:
    return ret;
}

int xc_tbuf_set_evt_mask(xc_interface *xch, uint32_t mask)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_evt_mask;
    sysctl.u.tbuf_op.evt_mask = mask;

    return do_sysctl(xch, &sysctl);
}

