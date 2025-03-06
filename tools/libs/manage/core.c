/*
 * Copyright (c) 2024 SUSE Software Solutions Germany GmbH
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

#define _GNU_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <xentoollog.h>
#include <xenmanage.h>
#include <xencall.h>
#include <xentoolcore_internal.h>

#include <xen/xen.h>
#include <xen/domctl.h>

struct xenmanage_handle {
    xentoollog_logger *logger, *logger_tofree;
    unsigned int flags;
    xencall_handle *xcall;
};

xenmanage_handle *xenmanage_open(xentoollog_logger *logger,
                                 unsigned int open_flags)
{
    xenmanage_handle *hdl = calloc(1, sizeof(*hdl));
    int saved_errno;

    if ( !hdl )
        return NULL;

    if ( open_flags )
    {
        errno = EINVAL;
        goto err;
    }

    hdl->flags = open_flags;
    hdl->logger = logger;
    hdl->logger_tofree = NULL;

    if ( !hdl->logger )
    {
        hdl->logger = hdl->logger_tofree =
            (xentoollog_logger *)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if ( !hdl->logger )
            goto err;
    }

    hdl->xcall = xencall_open(hdl->logger, 0);
    if ( !hdl->xcall )
        goto err;

    return hdl;

err:
    saved_errno = errno;
    xenmanage_close(hdl);
    errno = saved_errno;

    return NULL;
}

int xenmanage_close(xenmanage_handle *hdl)
{
    if ( !hdl )
        return 0;

    xencall_close(hdl->xcall);
    xtl_logger_destroy(hdl->logger_tofree);
    free(hdl);
    return 0;
}

static int xenmanage_do_domctl_get_domain_state(xenmanage_handle *hdl,
                                                unsigned int domid_in,
                                                unsigned int *domid_out,
                                                unsigned int *state,
                                                uint64_t *unique_id)
{
    struct xen_domctl *buf;
    int saved_errno;
    int ret;

    buf = xencall_alloc_buffer(hdl->xcall, sizeof(*buf));
    if ( !buf )
    {
        errno = ENOMEM;
        return -1;
    }

    memset(buf, 0, sizeof(*buf));

    buf->cmd = XEN_DOMCTL_get_domain_state;
    buf->domain = domid_in;

    ret = xencall1(hdl->xcall, __HYPERVISOR_domctl, (unsigned long)buf);
    saved_errno = errno;
    if ( !ret )
    {
        struct xen_domctl_get_domain_state *st = &buf->u.get_domain_state;

        if ( domid_out )
            *domid_out = buf->domain;
        if ( state )
        {
            *state = 0;
            if ( st->state & XEN_DOMCTL_GETDOMSTATE_STATE_EXIST )
                *state |= XENMANAGE_GETDOMSTATE_STATE_EXIST;
            if ( st->state & XEN_DOMCTL_GETDOMSTATE_STATE_SHUTDOWN )
                *state |= XENMANAGE_GETDOMSTATE_STATE_SHUTDOWN;
            if ( st->state & XEN_DOMCTL_GETDOMSTATE_STATE_DYING )
                *state |= XENMANAGE_GETDOMSTATE_STATE_DYING;
            if ( st->state & XEN_DOMCTL_GETDOMSTATE_STATE_DEAD )
                *state |= XENMANAGE_GETDOMSTATE_STATE_DEAD;
        }
        if ( unique_id )
            *unique_id = st->unique_id;
    }

    xencall_free_buffer(hdl->xcall, buf);

    errno = saved_errno;

    return ret;
}

int xenmanage_get_domain_info(xenmanage_handle *hdl, unsigned int domid,
                              unsigned int *state, uint64_t *unique_id)
{
    if ( !hdl || domid >= DOMID_FIRST_RESERVED )
    {
        errno = EINVAL;
        return -1;
    }

    return xenmanage_do_domctl_get_domain_state(hdl, domid, NULL, state,
                                                unique_id);
}

int xenmanage_poll_changed_domain(xenmanage_handle *hdl, unsigned int *domid,
                                  unsigned int *state, uint64_t *unique_id)
{
    if ( !hdl || !domid )
    {
        errno = EINVAL;
        return -1;
    }

    return xenmanage_do_domctl_get_domain_state(hdl, DOMID_INVALID, domid,
                                                state, unique_id);
}
