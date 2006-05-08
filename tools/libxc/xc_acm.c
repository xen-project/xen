/******************************************************************************
 *
 * Copyright (C) 2005 IBM Corporation
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Stefan Berger <stefanb@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "xc_private.h"

int xc_acm_op(int xc_handle, struct acm_op *op)
{
    int ret = -1;
    DECLARE_HYPERCALL;

    op->interface_version = ACM_INTERFACE_VERSION;

    hypercall.op = __HYPERVISOR_acm_op;
    hypercall.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(*op)) != 0) {
        PERROR("Could not lock memory for Xen policy hypercall");
        goto out1;
    }

    ret = do_xen_hypercall(xc_handle, &hypercall);
    ret = ioctl(xc_handle, IOCTL_PRIVCMD_HYPERCALL, &hypercall);
    if (ret < 0) {
        goto out2;
    }
 out2:
    safe_munlock(op, sizeof(*op));
 out1:
    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
