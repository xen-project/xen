#include "xg_private.h"
#include "xenguest.h"

int xc_linux_save(int xc_handle, int io_fd, uint32_t dom, uint32_t max_iters, 
                  uint32_t max_factor, uint32_t flags)
{
    PERROR("xc_linux_save not implemented\n");
    return -1;
}

int xc_linux_restore(int xc_handle, int io_fd, uint32_t dom, unsigned long nr_pfns,
                     unsigned int store_evtchn, unsigned long *store_mfn,
                     unsigned int console_evtchn, unsigned long *console_mfn)
{
    PERROR("xc_linux_restore not implemented\n");
    return -1;
}

int xc_vmx_build(int xc_handle,
                 uint32_t domid,
                 int memsize,
                 const char *image_name,
                 unsigned int control_evtchn,
                 unsigned long flags,
                 unsigned int vcpus,
                 unsigned int store_evtchn,
                 unsigned long *store_mfn)
{
    PERROR("xc_vmx_build not implemented\n");
    return -1;
}

int
xc_plan9_build(int xc_handle,
               uint32_t domid,
               const char *image_name,
               const char *cmdline,
               unsigned int control_evtchn, unsigned long flags)
{
    PERROR("xc_plan9_build not implemented\n");
    return -1;
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
