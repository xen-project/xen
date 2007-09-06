/*
 *
 *  Authors:  Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *            George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <xc_private.h>

#include <flask_op.h>

int flask_load(int xc_handle, char *buf, int size)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_LOAD;
    op.buf = buf;
    op.size = size;
    
    if ( (err = do_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

int flask_context_to_sid(int xc_handle, char *buf, int size, uint32_t *sid)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_CONTEXT_TO_SID;
    op.buf = buf;
    op.size = size;
    
    if ( (err = do_flask_op(xc_handle, &op)) != 0 )
        return err;
    
    sscanf(buf, "%u", sid);

    return 0;
}

int flask_sid_to_context(int xc_handle, int sid, char *buf, int size)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_SID_TO_CONTEXT;
    op.buf = buf;
    op.size = size;
    
    snprintf(buf, size, "%u", sid);

    if ( (err = do_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

int do_flask_op(int xc_handle, flask_op_t *op)
{
    int ret = -1;
    DECLARE_HYPERCALL;

    hypercall.op     = __HYPERVISOR_xsm_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out;
    }

    if ( (ret = do_xen_hypercall(xc_handle, &hypercall)) < 0 )
    {
        if ( errno == EACCES )
            fprintf(stderr, "XSM operation failed!\n");
    }

    safe_munlock(op, sizeof(*op));

 out:
    return ret;
}

