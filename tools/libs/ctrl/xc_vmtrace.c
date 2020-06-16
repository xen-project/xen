/******************************************************************************
 * xc_vmtrace.c
 *
 * API for manipulating hardware tracing features
 *
 * Copyright (c) 2020, Michal Leszczynski
 *
 * Copyright 2020 CERT Polska. All rights reserved.
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

int xc_vmtrace_enable(
    xc_interface *xch, uint32_t domid, uint32_t vcpu)
{
    struct xen_domctl domctl = {
        .cmd = XEN_DOMCTL_vmtrace_op,
        .domain = domid,
        .u.vmtrace_op = {
            .cmd = XEN_DOMCTL_vmtrace_enable,
            .vcpu = vcpu,
        },
    };

    return do_domctl(xch, &domctl);
}

int xc_vmtrace_disable(
    xc_interface *xch, uint32_t domid, uint32_t vcpu)
{
    struct xen_domctl domctl = {
        .cmd = XEN_DOMCTL_vmtrace_op,
        .domain = domid,
        .u.vmtrace_op = {
            .cmd = XEN_DOMCTL_vmtrace_disable,
            .vcpu = vcpu,
        },
    };

    return do_domctl(xch, &domctl);
}

int xc_vmtrace_reset_and_enable(
    xc_interface *xch, uint32_t domid, uint32_t vcpu)
{
    struct xen_domctl domctl = {
        .cmd = XEN_DOMCTL_vmtrace_op,
        .domain = domid,
        .u.vmtrace_op = {
            .cmd = XEN_DOMCTL_vmtrace_reset_and_enable,
            .vcpu = vcpu,
        },
    };

    return do_domctl(xch, &domctl);
}

int xc_vmtrace_output_position(
    xc_interface *xch, uint32_t domid, uint32_t vcpu, uint64_t *pos)
{
    struct xen_domctl domctl = {
        .cmd = XEN_DOMCTL_vmtrace_op,
        .domain = domid,
        .u.vmtrace_op = {
            .cmd = XEN_DOMCTL_vmtrace_output_position,
            .vcpu = vcpu,
        },
    };
    int rc = do_domctl(xch, &domctl);

    if ( !rc )
        *pos = domctl.u.vmtrace_op.value;

    return rc;
}

int xc_vmtrace_get_option(
    xc_interface *xch, uint32_t domid, uint32_t vcpu,
    uint64_t key, uint64_t *value)
{
    struct xen_domctl domctl = {
        .cmd = XEN_DOMCTL_vmtrace_op,
        .domain = domid,
        .u.vmtrace_op = {
            .cmd = XEN_DOMCTL_vmtrace_get_option,
            .vcpu = vcpu,
            .key = key,
        },
    };
    int rc = do_domctl(xch, &domctl);

    if ( !rc )
        *value = domctl.u.vmtrace_op.value;

    return rc;
}

int xc_vmtrace_set_option(
    xc_interface *xch, uint32_t domid, uint32_t vcpu,
    uint64_t key, uint64_t value)
{
    struct xen_domctl domctl = {
        .cmd = XEN_DOMCTL_vmtrace_op,
        .domain = domid,
        .u.vmtrace_op = {
            .cmd = XEN_DOMCTL_vmtrace_set_option,
            .vcpu = vcpu,
            .key = key,
            .value = value,
        },
    };

    return do_domctl(xch, &domctl);
}
