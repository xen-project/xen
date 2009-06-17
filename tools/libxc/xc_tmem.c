/******************************************************************************
 * xc_tmem.c
 *
 * Copyright (C) 2008 Oracle Corp.
 */

#include "xc_private.h"
#include <xen/tmem.h>

static int do_tmem_op(int xc, tmem_op_t *op)
{
    int ret;
    DECLARE_HYPERCALL;

    hypercall.op = __HYPERVISOR_tmem_op;
    hypercall.arg[0] = (unsigned long)op;
    if (lock_pages(op, sizeof(*op)) != 0)
    {
        PERROR("Could not lock memory for Xen hypercall");
        return -EFAULT;
    }
    if ((ret = do_xen_hypercall(xc, &hypercall)) < 0)
    {
        if ( errno == EACCES )
            DPRINTF("tmem operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }
    unlock_pages(op, sizeof(*op));

    return ret;
}

int xc_tmem_control(int xc,
                    int32_t pool_id,
                    uint32_t subop,
                    uint32_t cli_id,
                    uint32_t arg1,
                    uint32_t arg2,
                    void *buf)
{
    tmem_op_t op;
    int rc;

    op.cmd = TMEM_CONTROL;
    op.pool_id = pool_id;
    op.u.ctrl.subop = subop;
    op.u.ctrl.cli_id = cli_id;
    op.u.ctrl.arg1 = arg1;
    op.u.ctrl.arg2 = arg2;
    op.u.ctrl.buf.p = buf;

    if (subop == TMEMC_LIST) {
        if ((arg1 != 0) && (lock_pages(buf, arg1) != 0))
        {
            PERROR("Could not lock memory for Xen hypercall");
            return -ENOMEM;
        }
    }

#ifdef VALGRIND
    if (arg1 != 0)
        memset(buf, 0, arg1);
#endif

    rc = do_tmem_op(xc, &op);

    if (subop == TMEMC_LIST) {
        if (arg1 != 0)
            unlock_pages(buf, arg1);
    }

    return rc;
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
