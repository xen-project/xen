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
 *
 * Split off from xc_minios.c
 */

#include "xen-external/bsd-sys-queue.h"
#include <mini-os/types.h>
#include <mini-os/os.h>
#include <mini-os/lib.h>
#include <mini-os/events.h>
#include <mini-os/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <malloc.h>

#include "private.h"

extern void minios_evtchn_close_fd(int fd);

extern struct wait_queue_head event_queue;

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

int osdep_evtchn_open(xenevtchn_handle *xce)
{
    int fd = alloc_fd(FTYPE_EVTCHN);
    if ( fd == -1 )
        return -1;
    LIST_INIT(&files[fd].evtchn.ports);
    xce->fd = fd;
    printf("evtchn_open() -> %d\n", fd);
    return 0;
}

int osdep_evtchn_close(xenevtchn_handle *xce)
{
    if ( xce->fd == -1 )
        return 0;

    return close(xce->fd);
}

void minios_evtchn_close_fd(int fd)
{
    struct evtchn_port_info *port_info, *tmp;
    LIST_FOREACH_SAFE(port_info, &files[fd].evtchn.ports, list, tmp)
        port_dealloc(port_info);

    files[fd].type = FTYPE_NONE;
}

int xenevtchn_fd(xenevtchn_handle *xce)
{
    return xce->fd;
}

int xenevtchn_notify(xenevtchn_handle *xce, evtchn_port_t port)
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

xenevtchn_port_or_error_t xenevtchn_bind_unbound_port(xenevtchn_handle *xce, uint32_t domid)
{
    int fd = xce->fd;
    struct evtchn_port_info *port_info;
    int ret;
    evtchn_port_t port;

    assert(get_current() == main_thread);
    port_info = port_alloc(fd);
    if (port_info == NULL)
        return -1;

    printf("xenevtchn_bind_unbound_port(%d)", domid);
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

xenevtchn_port_or_error_t xenevtchn_bind_interdomain(xenevtchn_handle *xce, uint32_t domid,
                                                  evtchn_port_t remote_port)
{
    int fd = xce->fd;
    struct evtchn_port_info *port_info;
    evtchn_port_t local_port;
    int ret;

    assert(get_current() == main_thread);
    port_info = port_alloc(fd);
    if (port_info == NULL)
        return -1;

    printf("xenevtchn_bind_interdomain(%d, %"PRId32")", domid, remote_port);
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

int xenevtchn_unbind(xenevtchn_handle *xce, evtchn_port_t port)
{
    int fd = xce->fd;
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

xenevtchn_port_or_error_t xenevtchn_bind_virq(xenevtchn_handle *xce, unsigned int virq)
{
    int fd = xce->fd;
    struct evtchn_port_info *port_info;
    evtchn_port_t port;

    assert(get_current() == main_thread);
    port_info = port_alloc(fd);
    if (port_info == NULL)
        return -1;

    printf("xenevtchn_bind_virq(%d)", virq);
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

xenevtchn_port_or_error_t xenevtchn_pending(xenevtchn_handle *xce)
{
    int fd = xce->fd;
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

int xenevtchn_unmask(xenevtchn_handle *xce, evtchn_port_t port)
{
    unmask_evtchn(port);
    return 0;
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
