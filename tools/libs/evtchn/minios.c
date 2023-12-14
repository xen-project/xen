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

#include "xen_list.h"
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

XEN_LIST_HEAD(port_list, struct port_info);

struct ports {
    struct port_list list;
};

struct port_info {
    XEN_LIST_ENTRY(struct port_info) list;
    evtchn_port_t port;
    bool pending;
    bool bound;
};

static struct port_info *port_alloc(xenevtchn_handle *xce)
{
    struct port_info *port_info;
    struct file *file = get_file_from_fd(xce->fd);
    struct ports *ports = file->dev;
    unsigned long flags;

    port_info = malloc(sizeof(struct port_info));
    if ( port_info == NULL )
        return NULL;

    port_info->pending = false;
    port_info->port = -1;
    port_info->bound = false;

    local_irq_save(flags);
    XEN_LIST_INSERT_HEAD(&ports->list, port_info, list);
    local_irq_restore(flags);

    return port_info;
}

static void port_dealloc(struct port_info *port_info)
{
    unsigned long flags;

    if ( port_info->bound )
        unbind_evtchn(port_info->port);

    local_irq_save(flags);
    XEN_LIST_REMOVE(port_info, list);
    local_irq_restore(flags);

    free(port_info);
}

static int evtchn_close_fd(struct file *file)
{
    struct port_info *port_info, *tmp;
    struct ports *ports = file->dev;

    XEN_LIST_FOREACH_SAFE(port_info, &ports->list, list, tmp)
        port_dealloc(port_info);

    free(ports);

    return 0;
}

static const struct file_ops evtchn_ops = {
    .name = "evtchn",
    .close = evtchn_close_fd,
    .select_rd = select_read_flag,
};

static unsigned int ftype_evtchn;

__attribute__((constructor))
static void evtchn_initialize(void)
{
    ftype_evtchn = alloc_file_type(&evtchn_ops);
}

/*
 * XENEVTCHN_NO_CLOEXEC is being ignored, as there is no exec() call supported
 * in Mini-OS.
 */
int osdep_evtchn_open(xenevtchn_handle *xce, unsigned int flags)
{
    int fd;
    struct file *file;
    struct ports *ports;

    ports = malloc(sizeof(*ports));
    if ( !ports )
        return -1;

    fd = alloc_fd(ftype_evtchn);
    file = get_file_from_fd(fd);

    if ( !file )
    {
        free(ports);
        return -1;
    }

    file->dev = ports;
    XEN_LIST_INIT(&ports->list);
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

int osdep_evtchn_restrict(xenevtchn_handle *xce, domid_t domid)
{
    errno = EOPNOTSUPP;

    return -1;
}

int xenevtchn_notify(xenevtchn_handle *xce, evtchn_port_t port)
{
    int ret;

    ret = notify_remote_via_evtchn(port);

    if ( ret < 0 )
    {
        errno = -ret;
        ret = -1;
    }

    return ret;
}

static void evtchn_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
    xenevtchn_handle *xce = data;
    struct file *file = get_file_from_fd(xce->fd);
    struct port_info *port_info;
    struct ports *ports;

    assert(file);
    ports = file->dev;
    mask_evtchn(port);

    XEN_LIST_FOREACH(port_info, &ports->list, list)
    {
        if ( port_info->port == port )
            goto found;
    }

    printk("Unknown port %d for handle %d\n", port, xce->fd);
    return;

 found:
    port_info->pending = true;
    file->read = true;
    wake_up(&event_queue);
}

xenevtchn_port_or_error_t xenevtchn_bind_unbound_port(xenevtchn_handle *xce,
                                                      uint32_t domid)
{
    struct port_info *port_info;
    int ret;
    evtchn_port_t port;

    port_info = port_alloc(xce);
    if ( port_info == NULL )
        return -1;

    printf("xenevtchn_bind_unbound_port(%d)", domid);
    ret = evtchn_alloc_unbound(domid, evtchn_handler, xce, &port);
    printf(" = %d\n", ret);

    if ( ret < 0 )
    {
        port_dealloc(port_info);
        errno = -ret;
        return -1;
    }

    port_info->bound = true;
    port_info->port = port;
    unmask_evtchn(port);

    return port;
}

xenevtchn_port_or_error_t xenevtchn_bind_interdomain(xenevtchn_handle *xce,
                                                     uint32_t domid,
                                                     evtchn_port_t remote_port)
{
    struct port_info *port_info;
    evtchn_port_t local_port;
    int ret;

    port_info = port_alloc(xce);
    if ( port_info == NULL )
        return -1;

    printf("xenevtchn_bind_interdomain(%d, %"PRId32")", domid, remote_port);
    ret = evtchn_bind_interdomain(domid, remote_port, evtchn_handler,
                                  xce, &local_port);
    printf(" = %d\n", ret);

    if ( ret < 0 )
    {
        port_dealloc(port_info);
        errno = -ret;
        return -1;
    }

    port_info->bound = true;
    port_info->port = local_port;
    unmask_evtchn(local_port);

    return local_port;
}

int xenevtchn_unbind(xenevtchn_handle *xce, evtchn_port_t port)
{
    int fd = xce->fd;
    struct file *file = get_file_from_fd(fd);
    struct port_info *port_info;
    struct ports *ports = file->dev;
    unsigned long flags;

    local_irq_save(flags);
    XEN_LIST_FOREACH(port_info, &ports->list, list)
    {
        if ( port_info->port == port )
        {
            port_dealloc(port_info);
            local_irq_restore(flags);
            return 0;
        }
    }
    local_irq_restore(flags);

    printf("Warning: couldn't find port %"PRId32" for xc handle %x\n",
           port, fd);
    errno = EINVAL;

    return -1;
}

xenevtchn_port_or_error_t xenevtchn_bind_virq(xenevtchn_handle *xce,
                                              unsigned int virq)
{
    struct port_info *port_info;
    evtchn_port_t port;

    port_info = port_alloc(xce);
    if ( port_info == NULL )
        return -1;

    printf("xenevtchn_bind_virq(%d)", virq);
    port = bind_virq(virq, evtchn_handler, xce);
    printf(" = %d\n", port);

    if ( port < 0 )
    {
        port_dealloc(port_info);
        errno = -port;
        return -1;
    }

    port_info->bound = true;
    port_info->port = port;
    unmask_evtchn(port);

    return port;
}

xenevtchn_port_or_error_t xenevtchn_pending(xenevtchn_handle *xce)
{
    struct file *file = get_file_from_fd(xce->fd);
    struct port_info *port_info;
    struct ports *ports = file->dev;
    unsigned long flags;
    evtchn_port_t ret = -1;

    local_irq_save(flags);

    file->read = false;

    XEN_LIST_FOREACH(port_info, &ports->list, list)
    {
        if ( port_info->port != -1 && port_info->pending )
        {
            if ( ret == -1 )
            {
                ret = port_info->port;
                port_info->pending = false;
            }
            else
            {
                file->read = true;
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
