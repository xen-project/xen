/******************************************************************************
 * xc_misc.c
 * 
 * Miscellaneous control interface functions.
 */

#include "xc_private.h"

int xc_interface_open(void)
{
    int fd = open("/proc/xen/privcmd", O_RDWR);
    if ( fd == -1 )
        PERROR("Could not obtain handle on privileged command interface");
    return fd;
}

int xc_interface_close(int xc_handle)
{
    return close(xc_handle);
}


#define CONSOLE_RING_CLEAR 1

int xc_readconsolering(int xc_handle,
                       char *str, 
                       unsigned int max_chars, 
                       int clear)
{
    int ret;
    dom0_op_t op;

    op.cmd = DOM0_READCONSOLE;
    op.u.readconsole.str = (unsigned long)str;
    op.u.readconsole.count = max_chars;
    op.u.readconsole.cmd = clear ? CONSOLE_RING_CLEAR : 0;

    if ( (ret = mlock(str, max_chars)) != 0 )
        return ret;

    if ( (ret = do_dom0_op(xc_handle, &op)) >= 0 )
        str[ret] = '\0';

    (void)munlock(str, max_chars);

    return ret;
}    


int xc_physinfo(int xc_handle,
                xc_physinfo_t *put_info)
{
    int ret;
    dom0_op_t op;
    
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
    dom0_op_t op;
    
    op.cmd = DOM0_SCHED_ID;
    op.interface_version = DOM0_INTERFACE_VERSION;
    
    if ( (ret = do_dom0_op(xc_handle, &op)) != 0 )
        return ret;
    
    *sched_id = op.u.sched_id.sched_id;
    
    return 0;
}

int xc_perfc_control(int xc_handle,
                     u32 op,
                     xc_perfc_desc_t *desc)
{
    int rc;
    dom0_op_t dop;

    dop.cmd = DOM0_PERFCCONTROL;
    dop.u.perfccontrol.op   = op;
    dop.u.perfccontrol.desc = desc;

    rc = do_dom0_op(xc_handle, &dop);

    return (rc == 0) ? dop.u.perfccontrol.nr_counters : rc;
}

long long xc_msr_read(int xc_handle, int cpu_mask, int msr)
{
    int rc;    
    dom0_op_t op;
    
    op.cmd = DOM0_MSR;
    op.u.msr.write = 0;
    op.u.msr.msr = msr;
    op.u.msr.cpu_mask = cpu_mask;

    rc = do_dom0_op(xc_handle, &op);

    return (((unsigned long long)op.u.msr.out2)<<32) | op.u.msr.out1 ;
}

int xc_msr_write(int xc_handle, int cpu_mask, int msr, unsigned int low,
                  unsigned int high)
{
    int rc;    
    dom0_op_t op;
    
    op.cmd = DOM0_MSR;
    op.u.msr.write = 1;
    op.u.msr.msr = msr;
    op.u.msr.cpu_mask = cpu_mask;
    op.u.msr.in1 = low;
    op.u.msr.in2 = high;

    rc = do_dom0_op(xc_handle, &op);
    
    return rc;
}
