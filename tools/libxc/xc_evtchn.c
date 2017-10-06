/******************************************************************************
 * xc_evtchn.c
 *
 * API for manipulating and accessing inter-domain event channels.
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
 * Copyright (c) 2004, K A Fraser.
 */

#include "xc_private.h"

static int do_evtchn_op(xc_interface *xch, int cmd, void *arg,
                        size_t arg_size, int silently_fail)
{
    int ret = -1;
    DECLARE_HYPERCALL_BOUNCE(arg, arg_size, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, arg) )
    {
        PERROR("do_evtchn_op: bouncing arg failed");
        goto out;
    }

    ret = xencall2(xch->xcall, __HYPERVISOR_event_channel_op,
                   cmd, HYPERCALL_BUFFER_AS_ARG(arg));
    if ( ret < 0 && !silently_fail )
        ERROR("do_evtchn_op: HYPERVISOR_event_channel_op failed: %d", ret);

    xc_hypercall_bounce_post(xch, arg);
 out:
    return ret;
}

xc_evtchn_port_or_error_t
xc_evtchn_alloc_unbound(xc_interface *xch,
                        uint32_t dom,
                        uint32_t remote_dom)
{
    int rc;
    struct evtchn_alloc_unbound arg = {
        .dom        = dom,
        .remote_dom = remote_dom,
    };

    rc = do_evtchn_op(xch, EVTCHNOP_alloc_unbound, &arg, sizeof(arg), 0);
    if ( rc == 0 )
        rc = arg.port;

    return rc;
}

int xc_evtchn_reset(xc_interface *xch,
                    uint32_t dom)
{
    struct evtchn_reset arg = { .dom = dom };
    return do_evtchn_op(xch, EVTCHNOP_reset, &arg, sizeof(arg), 0);
}

int xc_evtchn_status(xc_interface *xch, xc_evtchn_status_t *status)
{
    return do_evtchn_op(xch, EVTCHNOP_status, status,
                        sizeof(*status), 1);
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
