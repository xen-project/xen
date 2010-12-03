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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#undef NDEBUG
#include <mini-os/types.h>
#include <mini-os/os.h>
#include <mini-os/mm.h>
#include <mini-os/lib.h>
#include <mini-os/gntmap.h>
#include <mini-os/events.h>
#include <mini-os/wait.h>
#include <sys/mman.h>
#include <errno.h>

#include <xen/memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>

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

    xch->fd = fd; /* Remove after transition to full xc_osdep_ops. */
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

static int minios_privcmd_hypercall(xc_interface *xch, xc_osdep_handle h, privcmd_hypercall_t *hypercall)
{
    multicall_entry_t call;
    int i, ret;

    call.op = hypercall->op;
    for (i = 0; i < sizeof(hypercall->arg) / sizeof(*hypercall->arg); i++)
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
#ifdef __ia64__
    /* TODO */
#else
    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;
#endif
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

#ifdef __ia64__
    /* TODO */
#else
    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;
#endif
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
#ifdef __ia64__
    /* TODO */
#else
    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;
#endif
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
#ifdef __ia64__
    /* TODO */
#else
    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;
#endif

    mfns = malloc((size / PAGE_SIZE) * sizeof(*mfns));

    n = 0;
    for (i = 0; i < nentries; i++)
        for (j = 0; j < chunksize / PAGE_SIZE; j++)
            mfns[n++] = entries[i].mfn + j;

    ret = map_frames_ex(mfns, n, 1, 0, 1, dom, NULL, pt_prot);
    free(mfns);
    return ret;
}


static struct xc_osdep_ops minios_privcmd_ops = {
    .open = &minios_privcmd_open,
    .close = &minios_privcmd_close,

    .u.privcmd = {
        .hypercall = &minios_privcmd_hypercall,

        .map_foreign_batch = &minios_privcmd_map_foreign_batch,
        .map_foreign_bulk = &minios_privcmd_map_foreign_bulk,
        .map_foreign_range = &minios_privcmd_map_foreign_range,
        .map_foreign_ranges = &minios_privcmd_map_foreign_ranges,
    },
};

static xc_osdep_handle minios_evtchn_open(xc_evtchn *xce)
{
    int fd = alloc_fd(FTYPE_EVTCHN), i;
    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;
    for (i = 0; i < MAX_EVTCHN_PORTS; i++) {
	files[fd].evtchn.ports[i].port = -1;
        files[fd].evtchn.ports[i].bound = 0;
    }
    printf("evtchn_open() -> %d\n", fd);
    xce->fd = fd; /* Remove after transition to full xc_osdep_ops. */
    return (xc_osdep_handle)fd;
}

static int minios_evtchn_close(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

void minios_evtchn_close_fd(int fd)
{
    int i;
    for (i = 0; i < MAX_EVTCHN_PORTS; i++)
        if (files[fd].evtchn.ports[i].bound)
            unbind_evtchn(files[fd].evtchn.ports[i].port);
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

/* XXX Note: This is not threadsafe */
static int port_alloc(int fd) {
    int i;
    for (i= 0; i < MAX_EVTCHN_PORTS; i++)
	if (files[fd].evtchn.ports[i].port == -1)
	    break;
    if (i == MAX_EVTCHN_PORTS) {
	printf("Too many ports in xc handle\n");
	errno = EMFILE;
	return -1;
    }
    files[fd].evtchn.ports[i].pending = 0;
    return i;
}

static void evtchn_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
    int fd = (int)(intptr_t)data;
    int i;
    assert(files[fd].type == FTYPE_EVTCHN);
    mask_evtchn(port);
    for (i= 0; i < MAX_EVTCHN_PORTS; i++)
	if (files[fd].evtchn.ports[i].port == port)
	    break;
    if (i == MAX_EVTCHN_PORTS) {
	printk("Unknown port for handle %d\n", fd);
	return;
    }
    files[fd].evtchn.ports[i].pending = 1;
    files[fd].read = 1;
    wake_up(&event_queue);
}

static evtchn_port_or_error_t minios_evtchn_bind_unbound_port(xc_evtchn *xce, xc_osdep_handle h, int domid)
{
    int fd = (int)h;
    int ret, i;
    evtchn_port_t port;

    assert(get_current() == main_thread);
    i = port_alloc(fd);
    if (i == -1)
	return -1;

    printf("xc_evtchn_bind_unbound_port(%d)", domid);
    ret = evtchn_alloc_unbound(domid, evtchn_handler, (void*)(intptr_t)fd, &port);
    printf(" = %d\n", ret);

    if (ret < 0) {
	errno = -ret;
	return -1;
    }
    files[fd].evtchn.ports[i].bound = 1;
    files[fd].evtchn.ports[i].port = port;
    unmask_evtchn(port);
    return port;
}

static evtchn_port_or_error_t minios_evtchn_bind_interdomain(xc_evtchn *xce, xc_osdep_handle h, int domid,
    evtchn_port_t remote_port)
{
    int fd = (int)h;
    evtchn_port_t local_port;
    int ret, i;

    assert(get_current() == main_thread);
    i = port_alloc(fd);
    if (i == -1)
	return -1;

    printf("xc_evtchn_bind_interdomain(%d, %"PRId32")", domid, remote_port);
    ret = evtchn_bind_interdomain(domid, remote_port, evtchn_handler, (void*)(intptr_t)fd, &local_port);
    printf(" = %d\n", ret);

    if (ret < 0) {
	errno = -ret;
	return -1;
    }
    files[fd].evtchn.ports[i].bound = 1;
    files[fd].evtchn.ports[i].port = local_port;
    unmask_evtchn(local_port);
    return local_port;
}

static int minios_evtchn_unbind(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int fd = (int)h;
    int i;
    for (i = 0; i < MAX_EVTCHN_PORTS; i++)
	if (files[fd].evtchn.ports[i].port == port) {
	    files[fd].evtchn.ports[i].port = -1;
	    break;
	}
    if (i == MAX_EVTCHN_PORTS) {
	printf("Warning: couldn't find port %"PRId32" for xc handle %x\n", port, fd);
	errno = -EINVAL;
	return -1;
    }
    files[fd].evtchn.ports[i].bound = 0;
    unbind_evtchn(port);
    return 0;
}

static evtchn_port_or_error_t minios_evtchn_bind_virq(xc_evtchn *xce, xc_osdep_handle h, unsigned int virq)
{
    int fd = (int)h;
    evtchn_port_t port;
    int i;

    assert(get_current() == main_thread);
    i = port_alloc(fd);
    if (i == -1)
	return -1;

    printf("xc_evtchn_bind_virq(%d)", virq);
    port = bind_virq(virq, evtchn_handler, (void*)(intptr_t)fd);

    if (port < 0) {
	errno = -port;
	return -1;
    }
    files[fd].evtchn.ports[i].bound = 1;
    files[fd].evtchn.ports[i].port = port;
    unmask_evtchn(port);
    return port;
}

static evtchn_port_or_error_t minios_evtchn_pending(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    int i;
    unsigned long flags;
    evtchn_port_t ret = -1;

    local_irq_save(flags);
    files[fd].read = 0;
    for (i = 0; i < MAX_EVTCHN_PORTS; i++) {
        evtchn_port_t port = files[fd].evtchn.ports[i].port;
        if (port != -1 && files[fd].evtchn.ports[i].pending) {
            if (ret == -1) {
                ret = port;
                files[fd].evtchn.ports[i].pending = 0;
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

static xc_osdep_handle minios_gnttab_open(xc_gnttab *xcg)
{
    int fd = alloc_fd(FTYPE_GNTMAP);
    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;
    gntmap_init(&files[fd].gntmap);
    xcg->fd = fd; /* Remove after transition to full xc_osdep_ops. */
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

void *xc_gnttab_map_grant_ref(xc_gnttab *xcg,
                              uint32_t domid,
                              uint32_t ref,
                              int prot)
{
    return gntmap_map_grant_refs(&files[xcg->fd].gntmap,
                                 1,
                                 &domid, 0,
                                 &ref,
                                 prot & PROT_WRITE);
}

void *xc_gnttab_map_grant_refs(xc_gnttab *xcg,
                               uint32_t count,
                               uint32_t *domids,
                               uint32_t *refs,
                               int prot)
{
    return gntmap_map_grant_refs(&files[xcg->fd].gntmap,
                                 count,
                                 domids, 1,
                                 refs,
                                 prot & PROT_WRITE);
}

void *xc_gnttab_map_domain_grant_refs(xc_gnttab *xcg,
                                      uint32_t count,
                                      uint32_t domid,
                                      uint32_t *refs,
                                      int prot)
{
    return gntmap_map_grant_refs(&files[xcg->fd].gntmap,
                                 count,
                                 &domid, 0,
                                 refs,
                                 prot & PROT_WRITE);
}

int xc_gnttab_munmap(xc_gnttab *xcg,
                     void *start_address,
                     uint32_t count)
{
    int ret;
    ret = gntmap_munmap(&files[xcg->fd].gntmap,
                        (unsigned long) start_address,
                        count);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

int xc_gnttab_set_max_grants(xc_gnttab *xcg,
                             uint32_t count)
{
    int ret;
    ret = gntmap_set_max_grants(&files[xcg->fd].gntmap,
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
