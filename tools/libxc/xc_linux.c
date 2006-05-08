/******************************************************************************
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "xc_private.h"

#include <xen/memory.h>
#include <xen/sys/evtchn.h>

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

void *xc_map_foreign_batch(int xc_handle, uint32_t dom, int prot,
                           unsigned long *arr, int num)
{
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    addr = mmap(NULL, num*PAGE_SIZE, prot, MAP_SHARED, xc_handle, 0);
    if ( addr == MAP_FAILED )
        return NULL;

    ioctlx.num=num;
    ioctlx.dom=dom;
    ioctlx.addr=(unsigned long)addr;
    ioctlx.arr=arr;
    if ( ioctl(xc_handle, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        perror("XXXXXXXX");
        (void)munmap(addr, num*PAGE_SIZE);
        errno = saved_errno;
        return NULL;
    }
    return addr;

}

void *xc_map_foreign_range(int xc_handle, uint32_t dom,
                           int size, int prot,
                           unsigned long mfn)
{
    privcmd_mmap_t ioctlx;
    privcmd_mmap_entry_t entry;
    void *addr;
    addr = mmap(NULL, size, prot, MAP_SHARED, xc_handle, 0);
    if ( addr == MAP_FAILED )
        return NULL;

    ioctlx.num=1;
    ioctlx.dom=dom;
    ioctlx.entry=&entry;
    entry.va=(unsigned long) addr;
    entry.mfn=mfn;
    entry.npages=(size+PAGE_SIZE-1)>>PAGE_SHIFT;
    if ( ioctl(xc_handle, IOCTL_PRIVCMD_MMAP, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        (void)munmap(addr, size);
        errno = saved_errno;
        return NULL;
    }
    return addr;
}

int xc_map_foreign_ranges(int xc_handle, uint32_t dom,
                          privcmd_mmap_entry_t *entries, int nr)
{
    privcmd_mmap_t ioctlx;

    ioctlx.num   = nr;
    ioctlx.dom   = dom;
    ioctlx.entry = entries;

    return ioctl(xc_handle, IOCTL_PRIVCMD_MMAP, &ioctlx);
}

static int do_privcmd(int xc_handle, unsigned int cmd, unsigned long data)
{
    return ioctl(xc_handle, cmd, data);
}

int do_xen_hypercall(int xc_handle, privcmd_hypercall_t *hypercall)
{
    return do_privcmd(xc_handle,
                      IOCTL_PRIVCMD_HYPERCALL,
                      (unsigned long)hypercall);
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
