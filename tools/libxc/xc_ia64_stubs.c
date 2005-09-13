#include "xg_private.h"
#include "xenguest.h"

int xc_linux_save(int xc_handle, int io_fd, u32 dom, u32 max_iters, 
                  u32 max_factor, u32 flags)
{
    PERROR("xc_linux_save not implemented\n");
    return -1;
}

int xc_linux_restore(int xc_handle, int io_fd, u32 dom, unsigned long nr_pfns,
		     unsigned int store_evtchn, unsigned long *store_mfn,
		     unsigned int console_evtchn, unsigned long *console_mfn)
{
    PERROR("xc_linux_restore not implemented\n");
    return -1;
}

int xc_vmx_build(int xc_handle,
                   u32 domid,
                   int memsize,
                   const char *image_name,
                   struct mem_map *mem_mapp,
                   const char *ramdisk_name,
                   const char *cmdline,
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
               u32 domid,
               const char *image_name,
               const char *cmdline,
               unsigned int control_evtchn, unsigned long flags)
{
    PERROR("xc_plan9_build not implemented\n");
    return -1;
}

