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
    op.u.readconsole.buffer = buffer;
    op.u.readconsole.count  = nr_chars;
    op.u.readconsole.clear  = clear;

    if ( (ret = mlock(buffer, nr_chars)) != 0 )
        return ret;

    if ( (ret = do_dom0_op(xc_handle, &op)) == 0 )
    {
        *pbuffer   = op.u.readconsole.buffer;
        *pnr_chars = op.u.readconsole.count;
    }

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
                     xc_perfc_desc_t *desc)
{
    int rc;
    DECLARE_DOM0_OP;

    op.cmd = DOM0_PERFCCONTROL;
    op.u.perfccontrol.op   = opcode;
    op.u.perfccontrol.desc = desc;

    rc = do_dom0_op(xc_handle, &op);

    return (rc == 0) ? op.u.perfccontrol.nr_counters : rc;
}

long long xc_msr_read(int xc_handle, int cpu_mask, int msr)
{
    int rc;    
    DECLARE_DOM0_OP;
    
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
    DECLARE_DOM0_OP;
    
    op.cmd = DOM0_MSR;
    op.u.msr.write = 1;
    op.u.msr.msr = msr;
    op.u.msr.cpu_mask = cpu_mask;
    op.u.msr.in1 = low;
    op.u.msr.in2 = high;

    rc = do_dom0_op(xc_handle, &op);
    
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
