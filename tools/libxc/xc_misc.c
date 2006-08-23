/******************************************************************************
 * xc_misc.c
 *
 * Miscellaneous control interface functions.
 */

#include "xc_private.h"

int xc_readconsolering(int xc_handle,
                       char **pbuffer,
                       unsigned int *pnr_chars,
                       int clear)
{
    int ret;
    DECLARE_DOM0_OP;
    char *buffer = *pbuffer;
    unsigned int nr_chars = *pnr_chars;

    op.cmd = DOM0_READCONSOLE;
    set_xen_guest_handle(op.u.readconsole.buffer, buffer);
    op.u.readconsole.count  = nr_chars;
    op.u.readconsole.clear  = clear;

    if ( (ret = mlock(buffer, nr_chars)) != 0 )
        return ret;

    if ( (ret = do_dom0_op(xc_handle, &op)) == 0 )
        *pnr_chars = op.u.readconsole.count;

    safe_munlock(buffer, nr_chars);

    return ret;
}

int xc_physinfo(int xc_handle,
                xc_physinfo_t *put_info)
{
    int ret;
    DECLARE_DOM0_OP;

    op.cmd = DOM0_PHYSINFO;
    op.interface_version = DOM0_INTERFACE_VERSION;

    if ( (ret = do_dom0_op(xc_handle, &op)) != 0 )
        return ret;

    memcpy(put_info, &op.u.physinfo, sizeof(*put_info));

    return 0;
}

int xc_sched_id(int xc_handle,
                int *sched_id)
{
    int ret;
    DECLARE_DOM0_OP;

    op.cmd = DOM0_SCHED_ID;
    op.interface_version = DOM0_INTERFACE_VERSION;

    if ( (ret = do_dom0_op(xc_handle, &op)) != 0 )
        return ret;

    *sched_id = op.u.sched_id.sched_id;

    return 0;
}

int xc_perfc_control(int xc_handle,
                     uint32_t opcode,
                     xc_perfc_desc_t *desc,
                     xc_perfc_val_t *val,
                     int *nbr_desc,
                     int *nbr_val)
{
    int rc;
    DECLARE_DOM0_OP;

    op.cmd = DOM0_PERFCCONTROL;
    op.u.perfccontrol.op   = opcode;
    set_xen_guest_handle(op.u.perfccontrol.desc, desc);
    set_xen_guest_handle(op.u.perfccontrol.val, val);

    rc = do_dom0_op(xc_handle, &op);

    if (nbr_desc)
        *nbr_desc = op.u.perfccontrol.nr_counters;
    if (nbr_val)
        *nbr_val = op.u.perfccontrol.nr_vals;

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
