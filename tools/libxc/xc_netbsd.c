/******************************************************************************
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"

#include <xen/sys/evtchn.h>
#include <unistd.h>
#include <fcntl.h>

static xc_osdep_handle netbsd_privcmd_open(xc_interface *xch)
{
    int flags, saved_errno;
    int fd = open("/kern/xen/privcmd", O_RDWR);

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface");
        return XC_OSDEP_OPEN_ERROR;
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

    xch->fd = fd; /* Remove after transition to full xc_osdep_ops. */

    return (xc_osinteface_handle)fd;

 error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return XC_OSDEP_OPEN_ERROR;
}

static int netbsd_privcmd_close(xc_interface *xch, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

static int netbsd_privcmd_hypercall(xc_interface *xch, xc_osdep_handle h, privcmd_hypercall_t *hypercall)
{
    int fd = (int)h;
    int error = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);

    if (error < 0)
        return -errno;
    else
        return hypercall->retval;
}

void *xc_map_foreign_batch(xc_interface *xch, uint32_t dom, int prot,
                           xen_pfn_t *arr, int num)
{
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    addr = mmap(NULL, num*PAGE_SIZE, prot, MAP_ANON | MAP_SHARED, -1, 0);
    if ( addr == MAP_FAILED ) {
        PERROR("xc_map_foreign_batch: mmap failed");
        return NULL;
    }

    ioctlx.num=num;
    ioctlx.dom=dom;
    ioctlx.addr=(unsigned long)addr;
    ioctlx.arr=arr;
    if ( ioctl(xch->fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        PERROR("xc_map_foreign_batch: ioctl failed");
        (void)munmap(addr, num*PAGE_SIZE);
        errno = saved_errno;
        return NULL;
    }
    return addr;

}

void *xc_map_foreign_range(xc_interface *xch, uint32_t dom,
                           int size, int prot,
                           unsigned long mfn)
{
    privcmd_mmap_t ioctlx;
    privcmd_mmap_entry_t entry;
    void *addr;
    addr = mmap(NULL, size, prot, MAP_ANON | MAP_SHARED, -1, 0);
    if ( addr == MAP_FAILED ) {
        PERROR("xc_map_foreign_range: mmap failed");
        return NULL;
    }

    ioctlx.num=1;
    ioctlx.dom=dom;
    ioctlx.entry=&entry;
    entry.va=(unsigned long) addr;
    entry.mfn=mfn;
    entry.npages=(size+PAGE_SIZE-1)>>PAGE_SHIFT;
    if ( ioctl(xch->fd, IOCTL_PRIVCMD_MMAP, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        PERROR("xc_map_foreign_range: ioctl failed");
        (void)munmap(addr, size);
        errno = saved_errno;
        return NULL;
    }
    return addr;
}

void *xc_map_foreign_ranges(xc_interface *xch, uint32_t dom,
                            size_t size, int prot, size_t chunksize,
                            privcmd_mmap_entry_t entries[], int nentries)
{
	privcmd_mmap_t ioctlx;
	int i, rc;
	void *addr;

	addr = mmap(NULL, size, prot, MAP_ANON | MAP_SHARED, -1, 0);
	if (addr == MAP_FAILED)
		goto mmap_failed;

	for (i = 0; i < nentries; i++) {
		entries[i].va = (uintptr_t)addr + (i * chunksize);
		entries[i].npages = chunksize >> PAGE_SHIFT;
	}

	ioctlx.num   = nentries;
	ioctlx.dom   = dom;
	ioctlx.entry = entries;

	rc = ioctl(xch->fd, IOCTL_PRIVCMD_MMAP, &ioctlx);
	if (rc)
		goto ioctl_failed;

	return addr;

ioctl_failed:
	rc = munmap(addr, size);
	if (rc == -1)
		ERROR("%s: error in error path\n", __FUNCTION__);

mmap_failed:
	return NULL;
}

static struct xc_osdep_ops netbsd_privcmd_ops = {
    .open = &netbsd_privcmd_open,
    .close = &netbsd_privcmd_close,

    .u.privcmd = {
        .hypercall = &netbsd_privcmd_hypercall;
    },
};

#define EVTCHN_DEV_NAME  "/dev/xenevt"

static xc_osdep_handle netbsd_evtchn_open(xc_evtchn *xce)
{
    int fd = open(EVTCHN_DEV_NAME, O_NONBLOCK|O_RDWR);
    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;

    xce->fd = fd; /* Remove after transition to full xc_osdep_ops. */
    return (xc_osdep_handle)fd;
}

static int netbsd_evtchn_close(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

int xc_evtchn_fd(xc_evtchn *xce)
{
    return xce->fd;
}

int xc_evtchn_notify(xc_evtchn *xce, evtchn_port_t port)
{
    struct ioctl_evtchn_notify notify;

    notify.port = port;

    return ioctl(xce->fd, IOCTL_EVTCHN_NOTIFY, &notify);
}

evtchn_port_or_error_t
xc_evtchn_bind_unbound_port(xc_evtchn * xce, int domid)
{
    struct ioctl_evtchn_bind_unbound_port bind;
    int ret;

    bind.remote_domain = domid;

    ret = ioctl(xce->fd, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &bind);
    if (ret == 0)
	return bind.port;
    else
	return -1;
}

evtchn_port_or_error_t
xc_evtchn_bind_interdomain(xc_evtchn *xce, int domid,
                           evtchn_port_t remote_port)
{
    struct ioctl_evtchn_bind_interdomain bind;
    int ret;

    bind.remote_domain = domid;
    bind.remote_port = remote_port;

    ret = ioctl(xce->fd, IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
    if (ret == 0)
	return bind.port;
    else
	return -1;
}

int xc_evtchn_unbind(xc_evtchn *xce, evtchn_port_t port)
{
    struct ioctl_evtchn_unbind unbind;

    unbind.port = port;

    return ioctl(xce->fd, IOCTL_EVTCHN_UNBIND, &unbind);
}

evtchn_port_or_error_t
xc_evtchn_bind_virq(xc_evtchn *xce, unsigned int virq)
{
    struct ioctl_evtchn_bind_virq bind;
    int err;

    bind.virq = virq;

    err = ioctl(xce->fd, IOCTL_EVTCHN_BIND_VIRQ, &bind);
    if (err)
	return -1;
    else
	return bind.port;
}

evtchn_port_or_error_t
xc_evtchn_pending(xc_evtchn *xce)
{
    evtchn_port_t port;

    if ( read_exact(xce->fd, (char *)&port, sizeof(port)) == -1 )
        return -1;

    return port;
}

int xc_evtchn_unmask(xc_evtchn *xce, evtchn_port_t port)
{
    return write_exact(xce->fd, (char *)&port, sizeof(port));
}

static struct xc_osdep_ops netbsd_evtchn_ops = {
    .open = &netbsd_evtchn_open,
    .close = &netbsd_evtchn_close,
};

/* Optionally flush file to disk and discard page cache */
void discard_file_cache(xc_interface *xch, int fd, int flush) 
{
    off_t cur = 0;
    int saved_errno = errno;

    if ( flush && (fsync(fd) < 0) )
    {
        /*PERROR("Failed to flush file: %s", strerror(errno));*/
        goto out;
    }

    /*
     * Calculate last page boundry of amount written so far
     * unless we are flushing in which case entire cache
     * is discarded.
     */
    if ( !flush )
    {
        if ( ( cur = lseek(fd, 0, SEEK_CUR)) == (off_t)-1 )
            cur = 0;
        cur &= ~(PAGE_SIZE - 1);
    }

    /* Discard from the buffer cache. */
    if ( posix_fadvise(fd, 0, cur, POSIX_FADV_DONTNEED) < 0 )
    {
        /*PERROR("Failed to discard cache: %s", strerror(errno));*/
        goto out;
    }

 out:
    errno = saved_errno;
}

static struct xc_osdep_ops *netbsd_osdep_init(xc_interface *xch, enum xc_osdep_type type)
{
    switch ( type )
    {
    case XC_OSDEP_PRIVCMD:
        return &netbsd_privcmd_ops;
    case XC_OSDEP_EVTCHN:
        return &netbsd_evtchn_ops;
    case XC_OSDEP_GNTTAB:
        ERROR("GNTTAB interface not supported on this platform");
        return NULL;
    default:
        return NULL;
    }
}

xc_osdep_info_t xc_osdep_info = {
    .name = "Netbsd Native OS interface",
    .init = &netbsd_osdep_init,
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
