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
    DECLARE_SYSCTL;
    char *buffer = *pbuffer;
    unsigned int nr_chars = *pnr_chars;

    sysctl.cmd = XEN_SYSCTL_readconsole;
    set_xen_guest_handle(sysctl.u.readconsole.buffer, buffer);
    sysctl.u.readconsole.count  = nr_chars;
    sysctl.u.readconsole.clear  = clear;

    if ( (ret = mlock(buffer, nr_chars)) != 0 )
        return ret;

    if ( (ret = do_sysctl(xc_handle, &sysctl)) == 0 )
        *pnr_chars = sysctl.u.readconsole.count;

    safe_munlock(buffer, nr_chars);

    return ret;
}

int xc_physinfo(int xc_handle,
                xc_physinfo_t *put_info)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_physinfo;

    if ( (ret = do_sysctl(xc_handle, &sysctl)) != 0 )
        return ret;

    memcpy(put_info, &sysctl.u.physinfo, sizeof(*put_info));

    return 0;
}

int xc_sched_id(int xc_handle,
                int *sched_id)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_sched_id;

    if ( (ret = do_sysctl(xc_handle, &sysctl)) != 0 )
        return ret;

    *sched_id = sysctl.u.sched_id.sched_id;

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
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_perfc_op;
    sysctl.u.perfc_op.cmd = opcode;
    set_xen_guest_handle(sysctl.u.perfc_op.desc, desc);
    set_xen_guest_handle(sysctl.u.perfc_op.val, val);

    rc = do_sysctl(xc_handle, &sysctl);

    if (nbr_desc)
        *nbr_desc = sysctl.u.perfc_op.nr_counters;
    if (nbr_val)
        *nbr_val = sysctl.u.perfc_op.nr_vals;

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
