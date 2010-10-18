/******************************************************************************
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * xc_gnttab functions:
 * Copyright (c) 2007-2008, D G Murray <Derek.Murray@cl.cam.ac.uk>
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

#include <xen/memory.h>
#include <xen/sys/evtchn.h>
#include <xen/sys/gntdev.h>
#include <unistd.h>
#include <fcntl.h>

int xc_interface_open_core(xc_interface *xch)
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

int xc_interface_close_core(xc_interface *xch, int fd)
{
    return close(fd);
}

static int xc_map_foreign_batch_single(xc_interface *xch, uint32_t dom,
                                       xen_pfn_t *mfn, unsigned long addr)
{
    privcmd_mmapbatch_t ioctlx;
    int rc;

    ioctlx.num = 1;
    ioctlx.dom = dom;
    ioctlx.addr = addr;
    ioctlx.arr = mfn;

    do
    {
        *mfn ^= XEN_DOMCTL_PFINFO_PAGEDTAB;
        usleep(100);
        rc = ioctl(xch->fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);
    }
    while ( (rc < 0) && (errno == ENOENT) );

    return rc;
}

void *xc_map_foreign_batch(xc_interface *xch, uint32_t dom, int prot,
                           xen_pfn_t *arr, int num)
{
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    int rc;

    addr = mmap(NULL, num << PAGE_SHIFT, prot, MAP_SHARED, xch->fd, 0);
    if ( addr == MAP_FAILED )
    {
        PERROR("xc_map_foreign_batch: mmap failed");
        return NULL;
    }

    ioctlx.num = num;
    ioctlx.dom = dom;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = arr;

    rc = ioctl(xch->fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);
    if ( (rc < 0) && (errno == ENOENT) )
    {
        int i;

        for ( i = 0; i < num; i++ )
        {
            if ( (arr[i] & XEN_DOMCTL_PFINFO_LTAB_MASK) ==
                 XEN_DOMCTL_PFINFO_PAGEDTAB )
            {
                unsigned long paged_addr = (unsigned long)addr + (i << PAGE_SHIFT);
                rc = xc_map_foreign_batch_single(xch, dom, &arr[i],
                                                 paged_addr);
                if ( rc < 0 )
                    goto out;
            }
        }
    }

 out:
    if ( rc < 0 )
    {
        int saved_errno = errno;
        PERROR("xc_map_foreign_batch: ioctl failed");
        (void)munmap(addr, num << PAGE_SHIFT);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

void *xc_map_foreign_bulk(xc_interface *xch, uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err, unsigned int num)
{
    privcmd_mmapbatch_v2_t ioctlx;
    void *addr;
    unsigned int i;
    int rc;

    addr = mmap(NULL, (unsigned long)num << PAGE_SHIFT, prot, MAP_SHARED,
                xch->fd, 0);
    if ( addr == MAP_FAILED )
    {
        PERROR("xc_map_foreign_batch: mmap failed");
        return NULL;
    }

    ioctlx.num = num;
    ioctlx.dom = dom;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = arr;
    ioctlx.err = err;

    rc = ioctl(xch->fd, IOCTL_PRIVCMD_MMAPBATCH_V2, &ioctlx);

    if ( rc < 0 && errno == ENOENT )
    {
        for ( i = rc = 0; rc == 0 && i < num; i++ )
        {
            if ( err[i] != -ENOENT )
                continue;

            ioctlx.num = 1;
            ioctlx.dom = dom;
            ioctlx.addr = (unsigned long)addr + ((unsigned long)i<<PAGE_SHIFT);
            ioctlx.arr = arr + i;
            ioctlx.err = err + i;
            do {
                usleep(100);
                rc = ioctl(xch->fd, IOCTL_PRIVCMD_MMAPBATCH_V2, &ioctlx);
            } while ( rc < 0 && err[i] == -ENOENT );
        }
    }

    if ( rc < 0 && errno == EINVAL && (int)num > 0 )
    {
        /*
         * IOCTL_PRIVCMD_MMAPBATCH_V2 is not supported - fall back to
         * IOCTL_PRIVCMD_MMAPBATCH.
         */
        xen_pfn_t *pfn = malloc(num * sizeof(*pfn));

        if ( pfn )
        {
            privcmd_mmapbatch_t ioctlx;

            memcpy(pfn, arr, num * sizeof(*arr));

            ioctlx.num = num;
            ioctlx.dom = dom;
            ioctlx.addr = (unsigned long)addr;
            ioctlx.arr = pfn;

            rc = ioctl(xch->fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);

            rc = rc < 0 ? -errno : 0;

            for ( i = 0; i < num; ++i )
            {
                switch ( pfn[i] ^ arr[i] )
                {
                case 0:
                    err[i] = rc != -ENOENT ? rc : 0;
                    continue;
                default:
                    err[i] = -EINVAL;
                    continue;
                case XEN_DOMCTL_PFINFO_PAGEDTAB:
                    if ( rc != -ENOENT )
                    {
                        err[i] = rc ?: -EINVAL;
                        continue;
                    }
                    rc = xc_map_foreign_batch_single(xch, dom, pfn + i,
                        (unsigned long)addr + ((unsigned long)i<<PAGE_SHIFT));
                    if ( rc < 0 )
                    {
                        rc = -errno;
                        break;
                    }
                    rc = -ENOENT;
                    continue;
                }
                break;
            }

            free(pfn);

            if ( rc == -ENOENT && i == num )
                rc = 0;
            else if ( rc )
            {
                errno = -rc;
                rc = -1;
            }
        }
        else
        {
            errno = -ENOMEM;
            rc = -1;
        }
    }

    if ( rc < 0 )
    {
        int saved_errno = errno;

        PERROR("xc_map_foreign_bulk: ioctl failed");
        (void)munmap(addr, (unsigned long)num << PAGE_SHIFT);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

void *xc_map_foreign_range(xc_interface *xch, uint32_t dom, int size, int prot,
                           unsigned long mfn)
{
    xen_pfn_t *arr;
    int num;
    int i;
    void *ret;

    num = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    arr = calloc(num, sizeof(xen_pfn_t));

    for ( i = 0; i < num; i++ )
        arr[i] = mfn + i;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

void *xc_map_foreign_ranges(xc_interface *xch, uint32_t dom, size_t size, int prot,
                            size_t chunksize, privcmd_mmap_entry_t entries[],
                            int nentries)
{
    xen_pfn_t *arr;
    int num_per_entry;
    int num;
    int i;
    int j;
    void *ret;

    num_per_entry = chunksize >> PAGE_SHIFT;
    num = num_per_entry * nentries;
    arr = calloc(num, sizeof(xen_pfn_t));

    for ( i = 0; i < nentries; i++ )
        for ( j = 0; j < num_per_entry; j++ )
            arr[i * num_per_entry + j] = entries[i].mfn + j;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

static int do_privcmd(xc_interface *xch, int cmd, unsigned long data)
{
    return ioctl(xch->fd, cmd, data);
}

int do_xen_hypercall(xc_interface *xch, privcmd_hypercall_t *hypercall)
{
    return do_privcmd(xch, IOCTL_PRIVCMD_HYPERCALL,
                      (unsigned long)hypercall);
}

#define DEVXEN "/dev/xen/"

int xc_evtchn_open(void)
{
    return open(DEVXEN "evtchn", O_RDWR);
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

evtchn_port_or_error_t
xc_evtchn_bind_unbound_port(int xce_handle, int domid)
{
    struct ioctl_evtchn_bind_unbound_port bind;

    bind.remote_domain = domid;

    return ioctl(xce_handle, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &bind);
}

evtchn_port_or_error_t
xc_evtchn_bind_interdomain(int xce_handle, int domid,
                           evtchn_port_t remote_port)
{
    struct ioctl_evtchn_bind_interdomain bind;

    bind.remote_domain = domid;
    bind.remote_port = remote_port;

    return ioctl(xce_handle, IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
}

evtchn_port_or_error_t
xc_evtchn_bind_virq(int xce_handle, unsigned int virq)
{
    struct ioctl_evtchn_bind_virq bind;

    bind.virq = virq;

    return ioctl(xce_handle, IOCTL_EVTCHN_BIND_VIRQ, &bind);
}

int xc_evtchn_unbind(int xce_handle, evtchn_port_t port)
{
    struct ioctl_evtchn_unbind unbind;

    unbind.port = port;

    return ioctl(xce_handle, IOCTL_EVTCHN_UNBIND, &unbind);
}

evtchn_port_or_error_t
xc_evtchn_pending(int xce_handle)
{
    evtchn_port_t port;

    if ( read_exact(xce_handle, (char *)&port, sizeof(port)) == -1 )
        return -1;

    return port;
}

int xc_evtchn_unmask(int xce_handle, evtchn_port_t port)
{
    return write_exact(xce_handle, (char *)&port, sizeof(port));
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
     * Calculate last page boundary of amount written so far 
     * unless we are flushing in which case entire cache
     * is discarded.
     */
    if ( !flush )
    {
        if ( (cur = lseek(fd, 0, SEEK_CUR)) == (off_t)-1 )
            cur = 0;
        cur &= ~(PAGE_SIZE-1);
    }

    /* Discard from the buffer cache. */
    if ( posix_fadvise64(fd, 0, cur, POSIX_FADV_DONTNEED) < 0 )
    {
        /*PERROR("Failed to discard cache: %s", strerror(errno));*/
        goto out;
    }

 out:
    errno = saved_errno;
}

int xc_gnttab_open(xc_interface *xch)
{
    return open(DEVXEN "gntdev", O_RDWR);
}

int xc_gnttab_close(xc_interface *xch, int xcg_handle)
{
    return close(xcg_handle);
}

void *xc_gnttab_map_grant_ref(xc_interface *xch, int xcg_handle,
                              uint32_t domid, uint32_t ref, int prot)
{
    struct ioctl_gntdev_map_grant_ref map;
    void *addr;

    map.count = 1;
    map.refs[0].domid = domid;
    map.refs[0].ref = ref;

    if ( ioctl(xcg_handle, IOCTL_GNTDEV_MAP_GRANT_REF, &map) ) {
        PERROR("xc_gnttab_map_grant_ref: ioctl MAP_GRANT_REF failed");
        return NULL;
    }

mmap_again:    
    addr = mmap(NULL, PAGE_SIZE, prot, MAP_SHARED, xcg_handle, map.index);
    if ( addr == MAP_FAILED )
    {
        int saved_errno = errno;
        struct ioctl_gntdev_unmap_grant_ref unmap_grant;

        if(saved_errno == EAGAIN)
        {
            usleep(1000);
            goto mmap_again;
        }
         /* Unmap the driver slots used to store the grant information. */
        PERROR("xc_gnttab_map_grant_ref: mmap failed");
        unmap_grant.index = map.index;
        unmap_grant.count = 1;
        ioctl(xcg_handle, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

static void *do_gnttab_map_grant_refs(xc_interface *xch,
                                      int xcg_handle, uint32_t count,
                                      uint32_t *domids, int domids_stride,
                                      uint32_t *refs, int prot)
{
    struct ioctl_gntdev_map_grant_ref *map;
    void *addr = NULL;
    int i;

    map = malloc(sizeof(*map) +
                 (count - 1) * sizeof(struct ioctl_gntdev_map_grant_ref));
    if ( map == NULL )
        return NULL;

    for ( i = 0; i < count; i++ )
    {
        map->refs[i].domid = domids[i * domids_stride];
        map->refs[i].ref = refs[i];
    }

    map->count = count;

    if ( ioctl(xcg_handle, IOCTL_GNTDEV_MAP_GRANT_REF, map) ) {
        PERROR("xc_gnttab_map_grant_refs: ioctl MAP_GRANT_REF failed");
        goto out;
    }

    addr = mmap(NULL, PAGE_SIZE * count, prot, MAP_SHARED, xcg_handle,
                map->index);
    if ( addr == MAP_FAILED )
    {
        int saved_errno = errno;
        struct ioctl_gntdev_unmap_grant_ref unmap_grant;

        /* Unmap the driver slots used to store the grant information. */
        PERROR("xc_gnttab_map_grant_refs: mmap failed");
        unmap_grant.index = map->index;
        unmap_grant.count = count;
        ioctl(xcg_handle, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant);
        errno = saved_errno;
        addr = NULL;
    }

 out:
    free(map);

    return addr;
}

void *xc_gnttab_map_grant_refs(xc_interface *xch,
                               int xcg_handle, uint32_t count, uint32_t *domids,
                               uint32_t *refs, int prot)
{
    return do_gnttab_map_grant_refs(xch, xcg_handle, count, domids, 1, refs, prot);
}

void *xc_gnttab_map_domain_grant_refs(xc_interface *xch,
                                      int xcg_handle, uint32_t count,
                                      uint32_t domid, uint32_t *refs, int prot)
{
    return do_gnttab_map_grant_refs(xch, xcg_handle, count, &domid, 0, refs, prot);
}

int xc_gnttab_munmap(xc_interface *xch,
                     int xcg_handle, void *start_address, uint32_t count)
{
    struct ioctl_gntdev_get_offset_for_vaddr get_offset;
    struct ioctl_gntdev_unmap_grant_ref unmap_grant;
    int rc;

    if ( start_address == NULL )
    {
        errno = EINVAL;
        return -1;
    }

    /* First, it is necessary to get the offset which was initially used to
     * mmap() the pages.
     */
    get_offset.vaddr = (unsigned long)start_address;
    if ( (rc = ioctl(xcg_handle, IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR,
                     &get_offset)) )
        return rc;

    if ( get_offset.count != count )
    {
        errno = EINVAL;
        return -1;
    }

    /* Next, unmap the memory. */
    if ( (rc = munmap(start_address, count * getpagesize())) )
        return rc;

    /* Finally, unmap the driver slots used to store the grant information. */
    unmap_grant.index = get_offset.offset;
    unmap_grant.count = count;
    if ( (rc = ioctl(xcg_handle, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant)) )
        return rc;

    return 0;
}

int xc_gnttab_set_max_grants(xc_interface *xch,
                             int xcg_handle, uint32_t count)
{
    struct ioctl_gntdev_set_max_grants set_max;
    int rc;

    set_max.count = count;
    if ( (rc = ioctl(xcg_handle, IOCTL_GNTDEV_SET_MAX_GRANTS, &set_max)) )
        return rc;

    return 0;
}

int xc_gnttab_op(xc_interface *xch, int cmd, void * op, int op_size, int count)
{
    int ret = 0;
    DECLARE_HYPERCALL;

    hypercall.op = __HYPERVISOR_grant_table_op;
    hypercall.arg[0] = cmd;
    hypercall.arg[1] = (unsigned long)op;
    hypercall.arg[2] = count;

    if ( lock_pages(xch, op, count* op_size) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    ret = do_xen_hypercall(xch, &hypercall);

    unlock_pages(xch, op, count * op_size);

 out1:
    return ret;
}

int xc_gnttab_get_version(xc_interface *xch, int domid)
{
    struct gnttab_get_version query;
    int rc;

    query.dom = domid;
    rc = xc_gnttab_op(xch, GNTTABOP_get_version, &query, sizeof(query),
                      1);
    if ( rc < 0 )
        return rc;
    else
        return query.version;
}

static void *_gnttab_map_table(xc_interface *xch, int domid, int *gnt_num)
{
    int rc, i;
    struct gnttab_query_size query;
    struct gnttab_setup_table setup;
    unsigned long *frame_list = NULL;
    xen_pfn_t *pfn_list = NULL;
    grant_entry_v1_t *gnt = NULL;

    if ( !gnt_num )
        return NULL;

    query.dom = domid;
    rc = xc_gnttab_op(xch, GNTTABOP_query_size, &query, sizeof(query), 1);

    if ( rc || (query.status != GNTST_okay) )
    {
        ERROR("Could not query dom's grant size\n", domid);
        return NULL;
    }

    *gnt_num = query.nr_frames * (PAGE_SIZE / sizeof(grant_entry_v1_t) );

    frame_list = malloc(query.nr_frames * sizeof(unsigned long));
    if ( !frame_list || lock_pages(xch, frame_list,
                                   query.nr_frames * sizeof(unsigned long)) )
    {
        ERROR("Alloc/lock frame_list in xc_gnttab_map_table\n");
        if ( frame_list )
            free(frame_list);
        return NULL;
    }

    pfn_list = malloc(query.nr_frames * sizeof(xen_pfn_t));
    if ( !pfn_list )
    {
        ERROR("Could not lock pfn_list in xc_gnttab_map_table\n");
        goto err;
    }

    setup.dom = domid;
    setup.nr_frames = query.nr_frames;
    set_xen_guest_handle(setup.frame_list, frame_list);

    /* XXX Any race with other setup_table hypercall? */
    rc = xc_gnttab_op(xch, GNTTABOP_setup_table, &setup, sizeof(setup),
                      1);

    if ( rc || (setup.status != GNTST_okay) )
    {
        ERROR("Could not get grant table frame list\n");
        goto err;
    }

    for ( i = 0; i < setup.nr_frames; i++ )
        pfn_list[i] = frame_list[i];

    gnt = xc_map_foreign_pages(xch, domid, PROT_READ, pfn_list,
                               setup.nr_frames);
    if ( !gnt )
    {
        ERROR("Could not map grant table\n");
        goto err;
    }

err:
    if ( frame_list )
    {
        unlock_pages(xch, frame_list, query.nr_frames * sizeof(unsigned long));
        free(frame_list);
    }
    if ( pfn_list )
        free(pfn_list);

    return gnt;
}

grant_entry_v1_t *xc_gnttab_map_table_v1(xc_interface *xch, int domid,
                                         int *gnt_num)
{
    if (xc_gnttab_get_version(xch, domid) == 2)
        return NULL;
    return _gnttab_map_table(xch, domid, gnt_num);
}

grant_entry_v2_t *xc_gnttab_map_table_v2(xc_interface *xch, int domid,
                                         int *gnt_num)
{
    if (xc_gnttab_get_version(xch, domid) != 2)
        return NULL;
    return _gnttab_map_table(xch, domid, gnt_num);
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
