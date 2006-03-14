/*
 * Interface to Xen MSR hypercalls.
 * 
 * $Id: cpuperf_xeno.h,v 1.1 2003/10/13 16:49:44 jrb44 Exp $
 * 
 * $Log: cpuperf_xeno.h,v $
 * Revision 1.1  2003/10/13 16:49:44  jrb44
 * Initial revision
 *
 */

#include <xenctrl.h>

static int xc_handle;

void xen_init(void)
{
    if ( (xc_handle = xc_interface_open()) == -1 )
    {
        fprintf(stderr, "Error opening xc interface: %d (%s)\n",
                errno, strerror(errno));
        exit(-1);
    }

}

void dom0_wrmsr(int cpu_mask, int msr, unsigned int low, unsigned int high)
{
    xc_msr_write (xc_handle, cpu_mask, msr, low, high);
}

unsigned long long dom0_rdmsr(int cpu_mask, int msr)
{
    return xc_msr_read(xc_handle, cpu_mask, msr);
}

// End of $RCSfile: cpuperf_xeno.h,v $

