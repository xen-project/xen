/******************************************************************************
 *
 * Copyright 2007-2008 Samuel Thibault <samuel.thibault@eu.citrix.com>.
 * All rights reserved.
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

#undef NDEBUG
#include "xen-external/bsd-sys-queue.h"
#include <mini-os/types.h>
#include <mini-os/os.h>
#include <mini-os/mm.h>
#include <mini-os/lib.h>
#include <mini-os/gntmap.h>
#include <mini-os/events.h>
#include <mini-os/wait.h>
#include <sys/mman.h>

#include <xen/memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <malloc.h>

#include "xc_private.h"

void minios_interface_close_fd(int fd);
void minios_evtchn_close_fd(int fd);
void minios_gnttab_close_fd(int fd);

extern void minios_interface_close_fd(int fd);
extern void minios_evtchn_close_fd(int fd);

extern struct wait_queue_head event_queue;

static xc_osdep_handle minios_privcmd_open(xc_interface *xch)
{
    int fd = alloc_fd(FTYPE_XC);

    if ( fd == -1)
        return XC_OSDEP_OPEN_ERROR;

    return (xc_osdep_handle)fd;
}

static int minios_privcmd_close(xc_interface *xch, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

void minios_interface_close_fd(int fd)
{
    files[fd].type = FTYPE_NONE;
}

static void *minios_privcmd_alloc_hypercall_buffer(xc_interface *xch, xc_osdep_handle h, int npages)
{
    return xc_memalign(xch, PAGE_SIZE, npages * PAGE_SIZE);
}

static void minios_privcmd_free_hypercall_buffer(xc_interface *xch, xc_osdep_handle h, void *ptr, int npages)
{
    free(ptr);
}

static int minios_privcmd_hypercall(xc_interface *xch, xc_osdep_handle h, privcmd_hypercall_t *hypercall)
{
    multicall_entry_t call;
    int i, ret;

    call.op = hypercall->op;
    for (i = 0; i < ARRAY_SIZE(hypercall->arg); i++)
	call.args[i] = hypercall->arg[i];

    ret = HYPERVISOR_multicall(&call, 1);

    if (ret < 0) {
	errno = -ret;
	return -1;
    }
    if ((long) call.result < 0) {
        errno = - (long) call.result;
        return -1;
    }
    return call.result;
}

static void *minios_privcmd_map_foreign_bulk(xc_interface *xch, xc_osdep_handle h,
                                             uint32_t dom, int prot,
                                             const xen_pfn_t *arr, int *err, unsigned int num)
{
    unsigned long pt_prot = 0;
    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;
    return map_frames_ex(arr, num, 1, 0, 1, dom, err, pt_prot);    
}

static void *minios_privcmd_map_foreign_batch(xc_interface *xch,  xc_osdep_handle h,
                                              uint32_t dom, int prot,
                                              xen_pfn_t *arr, int num)
{
    unsigned long pt_prot = 0;
    int err[num];
    int i;
    unsigned long addr;

    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;

    addr = (unsigned long) map_frames_ex(arr, num, 1, 0, 1, dom, err, pt_prot);
    for (i = 0; i < num; i++) {
        if (err[i])
            arr[i] |= 0xF0000000;
    }
    return (void *) addr;
}

static void *minios_privcmd_map_foreign_range(xc_interface *xch, xc_osdep_handle h,
                                              uint32_t dom,
                                              int size, int prot,
                                              unsigned long mfn)
{
    unsigned long pt_prot = 0;

    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;

    assert(!(size % getpagesize()));
    return map_frames_ex(&mfn, size / getpagesize(), 0, 1, 1, dom, NULL, pt_prot);
}

static void *minios_privcmd_map_foreign_ranges(xc_interface *xch, xc_osdep_handle h,
                                               uint32_t dom,
                                               size_t size, int prot, size_t chunksize,
                                               privcmd_mmap_entry_t entries[], int nentries)
{
    unsigned long *mfns;
    int i, j, n;
    unsigned long pt_prot = 0;
    void *ret;

    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;

    mfns = malloc((size / XC_PAGE_SIZE) * sizeof(*mfns));

    n = 0;
    for (i = 0; i < nentries; i++)
        for (j = 0; j < chunksize / XC_PAGE_SIZE; j++)
            mfns[n++] = entries[i].mfn + j;

    ret = map_frames_ex(mfns, n, 1, 0, 1, dom, NULL, pt_prot);
    free(mfns);
    return ret;
}


static struct xc_osdep_ops minios_privcmd_ops = {
    .open = &minios_privcmd_open,
    .close = &minios_privcmd_close,

    .u.privcmd = {
        .alloc_hypercall_buffer = &minios_privcmd_alloc_hypercall_buffer,
        .free_hypercall_buffer = &minios_privcmd_free_hypercall_buffer,

        .hypercall = &minios_privcmd_hypercall,

        .map_foreign_batch = &minios_privcmd_map_foreign_batch,
        .map_foreign_bulk = &minios_privcmd_map_foreign_bulk,
        .map_foreign_range = &minios_privcmd_map_foreign_range,
        .map_foreign_ranges = &minios_privcmd_map_foreign_ranges,
    },
};


/* XXX Note: This is not threadsafe */
static struct evtchn_port_info* port_alloc(int fd) {
    struct evtchn_port_info *port_info;
    port_info = malloc(sizeof(struct evtchn_port_info));
    if (port_info == NULL)
        return NULL;
    port_info->pending = 0;
    port_info->port = -1;
    port_info->bound = 0;

    LIST_INSERT_HEAD(&files[fd].evtchn.ports, port_info, list);
    return port_info;
}

static void port_dealloc(struct evtchn_port_info *port_info) {
    if (port_info->bound)
        unbind_evtchn(port_info->port);
    LIST_REMOVE(port_info, list);
    free(port_info);
}

static xc_osdep_handle minios_evtchn_open(xc_evtchn *xce)
{
    int fd = alloc_fd(FTYPE_EVTCHN);
    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;
    LIST_INIT(&files[fd].evtchn.ports);
    printf("evtchn_open() -> %d\n", fd);
    return (xc_osdep_handle)fd;
}

static int minios_evtchn_close(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

void minios_evtchn_close_fd(int fd)
{
    struct evtchn_port_info *port_info, *tmp;
    LIST_FOREACH_SAFE(port_info, &files[fd].evtchn.ports, list, tmp)
        port_dealloc(port_info);

    files[fd].type = FTYPE_NONE;
}

static int minios_evtchn_fd(xc_evtchn *xce, xc_osdep_handle h)
{
    return (int)h;
}

static int minios_evtchn_notify(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int ret;

    ret = notify_remote_via_evtchn(port);

    if (ret < 0) {
	errno = -ret;
	ret = -1;
    }
    return ret;
}

static void evtchn_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
    int fd = (int)(intptr_t)data;
    struct evtchn_port_info *port_info;
    assert(files[fd].type == FTYPE_EVTCHN);
    mask_evtchn(port);
    LIST_FOREACH(port_info, &files[fd].evtchn.ports, list) {
        if (port_info->port == port)
            goto found;
    }
    printk("Unknown port for handle %d\n", fd);
    return;

 found:
    port_info->pending = 1;
    files[fd].read = 1;
    wake_up(&event_queue);
}

static evtchn_port_or_error_t minios_evtchn_bind_unbound_port(xc_evtchn *xce, xc_osdep_handle h, int domid)
{
    int fd = (int)h;
    struct evtchn_port_info *port_info;
    int ret;
    evtchn_port_t port;

    assert(get_current() == main_thread);
    port_info = port_alloc(fd);
    if (port_info == NULL)
	return -1;

    printf("xc_evtchn_bind_unbound_port(%d)", domid);
    ret = evtchn_alloc_unbound(domid, evtchn_handler, (void*)(intptr_t)fd, &port);
    printf(" = %d\n", ret);

    if (ret < 0) {
	port_dealloc(port_info);
	errno = -ret;
	return -1;
    }
    port_info->bound = 1;
    port_info->port = port;
    unmask_evtchn(port);
    return port;
}

static evtchn_port_or_error_t minios_evtchn_bind_interdomain(xc_evtchn *xce, xc_osdep_handle h, int domid,
    evtchn_port_t remote_port)
{
    int fd = (int)h;
    struct evtchn_port_info *port_info;
    evtchn_port_t local_port;
    int ret;

    assert(get_current() == main_thread);
    port_info = port_alloc(fd);
    if (port_info == NULL)
	return -1;

    printf("xc_evtchn_bind_interdomain(%d, %"PRId32")", domid, remote_port);
    ret = evtchn_bind_interdomain(domid, remote_port, evtchn_handler, (void*)(intptr_t)fd, &local_port);
    printf(" = %d\n", ret);

    if (ret < 0) {
	port_dealloc(port_info);
	errno = -ret;
	return -1;
    }
    port_info->bound = 1;
    port_info->port = local_port;
    unmask_evtchn(local_port);
    return local_port;
}

static int minios_evtchn_unbind(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int fd = (int)h;
    struct evtchn_port_info *port_info;

    LIST_FOREACH(port_info, &files[fd].evtchn.ports, list) {
        if (port_info->port == port) {
            port_dealloc(port_info);
            return 0;
        }
    }
    printf("Warning: couldn't find port %"PRId32" for xc handle %x\n", port, fd);
    errno = EINVAL;
    return -1;
}

static evtchn_port_or_error_t minios_evtchn_bind_virq(xc_evtchn *xce, xc_osdep_handle h, unsigned int virq)
{
    int fd = (int)h;
    struct evtchn_port_info *port_info;
    evtchn_port_t port;

    assert(get_current() == main_thread);
    port_info = port_alloc(fd);
    if (port_info == NULL)
	return -1;

    printf("xc_evtchn_bind_virq(%d)", virq);
    port = bind_virq(virq, evtchn_handler, (void*)(intptr_t)fd);

    if (port < 0) {
	port_dealloc(port_info);
	errno = -port;
	return -1;
    }
    port_info->bound = 1;
    port_info->port = port;
    unmask_evtchn(port);
    return port;
}

static evtchn_port_or_error_t minios_evtchn_pending(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    struct evtchn_port_info *port_info;
    unsigned long flags;
    evtchn_port_t ret = -1;

    local_irq_save(flags);
    files[fd].read = 0;

    LIST_FOREACH(port_info, &files[fd].evtchn.ports, list) {
        if (port_info->port != -1 && port_info->pending) {
            if (ret == -1) {
                ret = port_info->port;
                port_info->pending = 0;
            } else {
                files[fd].read = 1;
                break;
            }
        }
    }
    local_irq_restore(flags);
    return ret;
}

static int minios_evtchn_unmask(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    unmask_evtchn(port);
    return 0;
}

static struct xc_osdep_ops minios_evtchn_ops = {
    .open = &minios_evtchn_open,
    .close = &minios_evtchn_close,

    .u.evtchn = {
        .fd = &minios_evtchn_fd,
        .notify = &minios_evtchn_notify,
        .bind_unbound_port = &minios_evtchn_bind_unbound_port,
        .bind_interdomain = &minios_evtchn_bind_interdomain,
        .bind_virq = &minios_evtchn_bind_virq,
        .unbind = &minios_evtchn_unbind,
        .pending = &minios_evtchn_pending,
        .unmask = &minios_evtchn_unmask,
   },
};

/* Optionally flush file to disk and discard page cache */
void discard_file_cache(xc_interface *xch, int fd, int flush)
{
    if (flush)
        fsync(fd);
}

void *xc_memalign(xc_interface *xch, size_t alignment, size_t size)
{
    return memalign(alignment, size);
}

static xc_osdep_handle minios_gnttab_open(xc_gnttab *xcg)
{
    int fd = alloc_fd(FTYPE_GNTMAP);
    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;
    gntmap_init(&files[fd].gntmap);
    return (xc_osdep_handle)fd;
}

static int minios_gnttab_close(xc_gnttab *xcg, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

void minios_gnttab_close_fd(int fd)
{
    gntmap_fini(&files[fd].gntmap);
    files[fd].type = FTYPE_NONE;
}

static void *minios_gnttab_grant_map(xc_gnttab *xcg, xc_osdep_handle h,
                                     uint32_t count, int flags, int prot,
                                     uint32_t *domids, uint32_t *refs,
                                     uint32_t notify_offset,
                                     evtchn_port_t notify_port)
{
    int fd = (int)h;
    int stride = 1;
    if (flags & XC_GRANT_MAP_SINGLE_DOMAIN)
        stride = 0;
    if (notify_offset != -1 || notify_port != -1) {
        errno = ENOSYS;
        return NULL;
    }
    return gntmap_map_grant_refs(&files[fd].gntmap,
                                 count, domids, stride,
                                 refs, prot & PROT_WRITE);
}

static int minios_gnttab_munmap(xc_gnttab *xcg, xc_osdep_handle h,
                                void *start_address,
                                uint32_t count)
{
    int fd = (int)h;
    int ret;
    ret = gntmap_munmap(&files[fd].gntmap,
                        (unsigned long) start_address,
                        count);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int minios_gnttab_set_max_grants(xc_gnttab *xcg, xc_osdep_handle h,
                             uint32_t count)
{
    int fd = (int)h;
    int ret;
    ret = gntmap_set_max_grants(&files[fd].gntmap,
                                count);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static struct xc_osdep_ops minios_gnttab_ops = {
    .open = &minios_gnttab_open,
    .close = &minios_gnttab_close,

    .u.gnttab = {
        .grant_map = &minios_gnttab_grant_map,
        .munmap = &minios_gnttab_munmap,
        .set_max_grants = &minios_gnttab_set_max_grants,
    },
};

static struct xc_osdep_ops *minios_osdep_init(xc_interface *xch, enum xc_osdep_type type)
{
    switch ( type )
    {
    case XC_OSDEP_PRIVCMD:
        return &minios_privcmd_ops;
    case XC_OSDEP_EVTCHN:
        return &minios_evtchn_ops;
    case XC_OSDEP_GNTTAB:
        return &minios_gnttab_ops;
    default:
        return NULL;
    }
}

xc_osdep_info_t xc_osdep_info = {
    .name = "Minios Native OS interface",
    .init = &minios_osdep_init,
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
