/******************************************************************************
 * xc_acm.c
 *
 * Copyright (C) 2005, 2006 IBM Corporation, R Sailer
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "xc_private.h"


int xc_acm_op(int xc_handle, int cmd, void *arg, size_t arg_size)
{
    int ret = -1;
    DECLARE_HYPERCALL;

    hypercall.op = __HYPERVISOR_acm_op;
    hypercall.arg[0] = cmd;
    hypercall.arg[1] = (unsigned long) arg;

    if (mlock(arg, arg_size) != 0) {
        PERROR("xc_acm_op: arg mlock failed");
        goto out;
    }
    ret = do_xen_hypercall(xc_handle, &hypercall);
    safe_munlock(arg, arg_size);
 out:
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
