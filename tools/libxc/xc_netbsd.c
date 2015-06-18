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

int osdep_privcmd_open(xc_interface *xch)
{
    int flags, saved_errno;
    int fd = open("/kern/xen/privcmd", O_RDWR);

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

    xch->privcmdfd = fd;
    return 0;

 error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

int osdep_privcmd_close(xc_interface *xch)
{
    int fd = xch->privcmdfd;
    return close(fd);
}

void *xc_map_foreign_batch(xc_interface *xch,
                           uint32_t dom, int prot,
                           xen_pfn_t *arr, int num)
{
    int fd = xch->privcmdfd;
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

void *xc_map_foreign_range(xc_interface *xch,
                           uint32_t dom,
                           int size, int prot,
                           unsigned long mfn)
{
    int fd = xch->privcmdfd;
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

void *xc_map_foreign_ranges(xc_interface *xch,
                            uint32_t dom,
                            size_t size, int prot, size_t chunksize,
                            privcmd_mmap_entry_t entries[], int nentries)
{
    int fd = xch->privcmdfd;
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
