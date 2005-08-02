#include "xc_private.h"

int xc_linux_save(int xc_handle, int io_fd, u32 dom)
{
    PERROR("xc_linux_save not implemented\n");
    return -1;
}

int xc_linux_restore(int xc_handle, int io_fd, u32 dom, unsigned long nr_pfns)
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
                   unsigned long flags)
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

