/******************************************************************************
 *
 * xc_altp2m.c
 *
 * Interface to altp2m related HVMOPs
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include <stdbool.h>
#include <xen/hvm/hvm_op.h>

int xc_altp2m_get_domain_state(xc_interface *handle, domid_t dom, bool *state)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_get_domain_state;
    arg->domain = dom;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
		  HYPERCALL_BUFFER_AS_ARG(arg));

    if ( !rc )
        *state = arg->u.domain_state.state;

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_set_domain_state(xc_interface *handle, domid_t dom, bool state)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_set_domain_state;
    arg->domain = dom;
    arg->u.domain_state.state = state;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
		  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

/* This is a bit odd to me that it acts on current.. */
int xc_altp2m_set_vcpu_enable_notify(xc_interface *handle, domid_t domid,
                                     uint32_t vcpuid, xen_pfn_t gfn)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_vcpu_enable_notify;
    arg->domain = domid;
    arg->u.enable_notify.vcpu_id = vcpuid;
    arg->u.enable_notify.gfn = gfn;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
		  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_create_view(xc_interface *handle, domid_t domid,
                          xenmem_access_t default_access, uint16_t *view_id)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_create_p2m;
    arg->domain = domid;
    arg->u.view.view = -1;
    arg->u.view.hvmmem_default_access = default_access;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
		  HYPERCALL_BUFFER_AS_ARG(arg));

    if ( !rc )
        *view_id = arg->u.view.view;

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_destroy_view(xc_interface *handle, domid_t domid,
                           uint16_t view_id)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_destroy_p2m;
    arg->domain = domid;
    arg->u.view.view = view_id;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
		  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

/* Switch all vCPUs of the domain to the specified altp2m view */
int xc_altp2m_switch_to_view(xc_interface *handle, domid_t domid,
                             uint16_t view_id)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_switch_p2m;
    arg->domain = domid;
    arg->u.view.view = view_id;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
		  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_set_mem_access(xc_interface *handle, domid_t domid,
                             uint16_t view_id, xen_pfn_t gfn,
                             xenmem_access_t access)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_set_mem_access;
    arg->domain = domid;
    arg->u.set_mem_access.view = view_id;
    arg->u.set_mem_access.hvmmem_access = access;
    arg->u.set_mem_access.gfn = gfn;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
		  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_change_gfn(xc_interface *handle, domid_t domid,
                         uint16_t view_id, xen_pfn_t old_gfn,
                         xen_pfn_t new_gfn)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_change_gfn;
    arg->domain = domid;
    arg->u.change_gfn.view = view_id;
    arg->u.change_gfn.old_gfn = old_gfn;
    arg->u.change_gfn.new_gfn = new_gfn;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
		  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

