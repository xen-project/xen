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
#include <unistd.h>
#include <fcntl.h>

int xc_interface_open(void)
{
    int flags, saved_errno;
    int fd = open("/proc/xen/privcmd", O_RDWR);

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface");
        return -1;
    }

    /* Although we return the file handle as the 'xc handle' the API
       does not specify / guarentee that this integer is in fact
       a file handle. Thus we must take responsiblity to ensure
       it doesn't propagate (ie leak) outside the process */
    if ( (flags = fcntl(fd, F_GETFD)) < 0 )
    {
        PERROR("Could not get file handle flags");
        goto error;
    }
    flags |= FD_CLOEXEC;
    if ( fcntl(fd, F_SETFD, flags) < 0 )
    {
        PERROR("Could not set file handle flags");
        goto error;
    }

    return fd;

 error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

int xc_interface_close(int xc_handle)
{
    return close(xc_handle);
}

void *xc_map_foreign_batch(int xc_handle, uint32_t dom, int prot,
                           xen_pfn_t *arr, int num)
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

#define EVTCHN_DEV_NAME  "/dev/xen/evtchn"
#define EVTCHN_DEV_MAJOR 10
#define EVTCHN_DEV_MINOR 201

int xc_evtchn_open(void)
{
    struct stat st;
    int fd;

    /* Make sure any existing device file links to correct device. */
    if ((lstat(EVTCHN_DEV_NAME, &st) != 0) || !S_ISCHR(st.st_mode) ||
        (st.st_rdev != makedev(EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR)))
        (void)unlink(EVTCHN_DEV_NAME);

reopen:
    if ( (fd = open(EVTCHN_DEV_NAME, O_RDWR)) == -1 )
    {
        if ( (errno == ENOENT) &&
            ((mkdir("/dev/xen", 0755) == 0) || (errno == EEXIST)) &&
            (mknod(EVTCHN_DEV_NAME, S_IFCHR|0600,
            makedev(EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR)) == 0) )
            goto reopen;

        PERROR("Could not open event channel interface");
        return -1;
    }

    return fd;
}

int xc_evtchn_close(int xce_handle)
{
    return close(xce_handle);
}

int xc_evtchn_fd(int xce_handle)
{
    return xce_handle;
}

int xc_evtchn_notify(int xce_handle, evtchn_port_t port)
{
    struct ioctl_evtchn_notify notify;

    notify.port = port;

    return ioctl(xce_handle, IOCTL_EVTCHN_NOTIFY, &notify);
}

evtchn_port_t xc_evtchn_bind_interdomain(int xce_handle, int domid,
    evtchn_port_t remote_port)
{
    struct ioctl_evtchn_bind_interdomain bind;

    bind.remote_domain = domid;
    bind.remote_port = remote_port;

    return ioctl(xce_handle, IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
}

int xc_evtchn_unbind(int xce_handle, evtchn_port_t port)
{
    struct ioctl_evtchn_unbind unbind;

    unbind.port = port;

    return ioctl(xce_handle, IOCTL_EVTCHN_UNBIND, &unbind);
}

evtchn_port_t xc_evtchn_bind_virq(int xce_handle, unsigned int virq)
{
    struct ioctl_evtchn_bind_virq bind;

    bind.virq = virq;

    return ioctl(xce_handle, IOCTL_EVTCHN_BIND_VIRQ, &bind);
}

static int dorw(int fd, char *data, size_t size, int do_write)
{
    size_t offset = 0;
    ssize_t len;

    while ( offset < size )
    {
        if (do_write)
            len = write(fd, data + offset, size - offset);
        else
            len = read(fd, data + offset, size - offset);

        if ( len == -1 )
        {
             if ( errno == EINTR )
                 continue;
             return -1;
        }

        offset += len;
    }

    return 0;
}

evtchn_port_t xc_evtchn_pending(int xce_handle)
{
    evtchn_port_t port;

    if ( dorw(xce_handle, (char *)&port, sizeof(port), 0) == -1 )
        return -1;

    return port;
}

int xc_evtchn_unmask(int xce_handle, evtchn_port_t port)
{
    return dorw(xce_handle, (char *)&port, sizeof(port), 1);
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
