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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"

#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>

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

    return (xc_osdep_handle)fd;

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

static void *netbsd_privcmd_alloc_hypercall_buffer(xc_interface *xch, xc_osdep_handle h, int npages)
{
    size_t size = npages * XC_PAGE_SIZE;
    void *p;

    p = xc_memalign(xch, XC_PAGE_SIZE, size);
    if (!p)
        return NULL;

    if ( mlock(p, size) < 0 )
    {
        free(p);
        return NULL;
    }
    return p;
}

static void netbsd_privcmd_free_hypercall_buffer(xc_interface *xch, xc_osdep_handle h, void *ptr, int npages)
{
    (void) munlock(ptr, npages * XC_PAGE_SIZE);
    free(ptr);
}

static int netbsd_privcmd_hypercall(xc_interface *xch, xc_osdep_handle h, privcmd_hypercall_t *hypercall)
{
    int fd = (int)h;
    int error = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);

    /*
     * Since NetBSD ioctl can only return 0 on success or < 0 on
     * error, if we want to return a value from ioctl we should
     * do so by setting hypercall->retval, to mimic Linux ioctl
     * implementation.
     */
    if (error < 0)
        return error;
    else
        return hypercall->retval;
}

static void *netbsd_privcmd_map_foreign_batch(xc_interface *xch, xc_osdep_handle h,
                                              uint32_t dom, int prot,
                                              xen_pfn_t *arr, int num)
{
    int fd = (int)h;
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    addr = mmap(NULL, num*XC_PAGE_SIZE, prot, MAP_ANON | MAP_SHARED, -1, 0);
    if ( addr == MAP_FAILED ) {
        PERROR("xc_map_foreign_batch: mmap failed");
        return NULL;
    }

    ioctlx.num=num;
    ioctlx.dom=dom;
    ioctlx.addr=(unsigned long)addr;
    ioctlx.arr=arr;
    if ( ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        PERROR("xc_map_foreign_batch: ioctl failed");
        (void)munmap(addr, num*XC_PAGE_SIZE);
        errno = saved_errno;
        return NULL;
    }
    return addr;

}

static void *netbsd_privcmd_map_foreign_range(xc_interface *xch, xc_osdep_handle h,
                                              uint32_t dom,
                                              int size, int prot,
                                              unsigned long mfn)
{
    int fd = (int)h;
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
    entry.npages=(size+XC_PAGE_SIZE-1)>>XC_PAGE_SHIFT;
    if ( ioctl(fd, IOCTL_PRIVCMD_MMAP, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        PERROR("xc_map_foreign_range: ioctl failed");
        (void)munmap(addr, size);
        errno = saved_errno;
        return NULL;
    }
    return addr;
}

static void *netbsd_privcmd_map_foreign_ranges(xc_interface *xch, xc_osdep_handle h,
                                               uint32_t dom,
                                               size_t size, int prot, size_t chunksize,
                                               privcmd_mmap_entry_t entries[], int nentries)
{
    int fd = (int)h;
	privcmd_mmap_t ioctlx;
	int i, rc;
	void *addr;

	addr = mmap(NULL, size, prot, MAP_ANON | MAP_SHARED, -1, 0);
	if (addr == MAP_FAILED)
		goto mmap_failed;

	for (i = 0; i < nentries; i++) {
		entries[i].va = (uintptr_t)addr + (i * chunksize);
		entries[i].npages = chunksize >> XC_PAGE_SHIFT;
	}

	ioctlx.num   = nentries;
	ioctlx.dom   = dom;
	ioctlx.entry = entries;

	rc = ioctl(fd, IOCTL_PRIVCMD_MMAP, &ioctlx);
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
        .alloc_hypercall_buffer = &netbsd_privcmd_alloc_hypercall_buffer,
        .free_hypercall_buffer = &netbsd_privcmd_free_hypercall_buffer,

        .hypercall = &netbsd_privcmd_hypercall,

        .map_foreign_batch = &netbsd_privcmd_map_foreign_batch,
        .map_foreign_bulk = &xc_map_foreign_bulk_compat,
        .map_foreign_range = &netbsd_privcmd_map_foreign_range,
        .map_foreign_ranges = &netbsd_privcmd_map_foreign_ranges,
    },
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

void *xc_memalign(xc_interface *xch, size_t alignment, size_t size)
{
    return valloc(size);
}

static struct xc_osdep_ops *netbsd_osdep_init(xc_interface *xch, enum xc_osdep_type type)
{
    switch ( type )
    {
    case XC_OSDEP_PRIVCMD:
        return &netbsd_privcmd_ops;
    default:
        return NULL;
    }
}

xc_osdep_info_t xc_osdep_info = {
    .name = "Netbsd Native OS interface",
    .init = &netbsd_osdep_init,
    .fake = 0,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
