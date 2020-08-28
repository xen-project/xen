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

int xc_altp2m_get_domain_state(xc_interface *handle, uint32_t dom, bool *state)
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

int xc_altp2m_set_domain_state(xc_interface *handle, uint32_t dom, bool state)
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

int xc_altp2m_set_vcpu_enable_notify(xc_interface *handle, uint32_t domid,
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

int xc_altp2m_set_vcpu_disable_notify(xc_interface *handle, uint32_t domid,
                                      uint32_t vcpuid)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_vcpu_disable_notify;
    arg->domain = domid;
    arg->u.disable_notify.vcpu_id = vcpuid;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_create_view(xc_interface *handle, uint32_t domid,
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

int xc_altp2m_destroy_view(xc_interface *handle, uint32_t domid,
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
int xc_altp2m_switch_to_view(xc_interface *handle, uint32_t domid,
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

int xc_altp2m_get_suppress_ve(xc_interface *handle, uint32_t domid,
                              uint16_t view_id, xen_pfn_t gfn, bool *sve)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_get_suppress_ve;
    arg->domain = domid;
    arg->u.suppress_ve.view = view_id;
    arg->u.suppress_ve.gfn = gfn;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    if ( !rc )
        *sve = arg->u.suppress_ve.suppress_ve;

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_set_suppress_ve(xc_interface *handle, uint32_t domid,
                              uint16_t view_id, xen_pfn_t gfn, bool sve)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_set_suppress_ve;
    arg->domain = domid;
    arg->u.suppress_ve.view = view_id;
    arg->u.suppress_ve.gfn = gfn;
    arg->u.suppress_ve.suppress_ve = sve;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_set_supress_ve_multi(xc_interface *handle, uint32_t domid,
                                   uint16_t view_id, xen_pfn_t first_gfn,
                                   xen_pfn_t last_gfn, bool sve,
                                   xen_pfn_t *error_gfn, int32_t *error_code)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_set_suppress_ve_multi;
    arg->domain = domid;
    arg->u.suppress_ve_multi.view = view_id;
    arg->u.suppress_ve_multi.first_gfn = first_gfn;
    arg->u.suppress_ve_multi.last_gfn = last_gfn;
    arg->u.suppress_ve_multi.suppress_ve = sve;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    if ( arg->u.suppress_ve_multi.first_error )
    {
        *error_gfn = arg->u.suppress_ve_multi.first_error_gfn;
        *error_code = arg->u.suppress_ve_multi.first_error;
    }

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_set_mem_access(xc_interface *handle, uint32_t domid,
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
    arg->u.mem_access.view = view_id;
    arg->u.mem_access.access = access;
    arg->u.mem_access.gfn = gfn;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_change_gfn(xc_interface *handle, uint32_t domid,
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

int xc_altp2m_set_mem_access_multi(xc_interface *xch, uint32_t domid,
                                   uint16_t view_id, uint8_t *access,
                                   uint64_t *gfns, uint32_t nr)
{
    int rc;

    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);
    DECLARE_HYPERCALL_BOUNCE(access, nr * sizeof(*access),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(gfns, nr * sizeof(*gfns),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_set_mem_access_multi;
    arg->domain = domid;
    arg->u.set_mem_access_multi.view = view_id;
    arg->u.set_mem_access_multi.nr = nr;

    if ( xc_hypercall_bounce_pre(xch, gfns) ||
         xc_hypercall_bounce_pre(xch, access) )
    {
        PERROR("Could not bounce memory for HVMOP_altp2m_set_mem_access_multi");
        return -1;
    }

    set_xen_guest_handle(arg->u.set_mem_access_multi.pfn_list, gfns);
    set_xen_guest_handle(arg->u.set_mem_access_multi.access_list, access);

    rc = xencall2(xch->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(xch, arg);
    xc_hypercall_bounce_post(xch, access);
    xc_hypercall_bounce_post(xch, gfns);

    return rc;
}

int xc_altp2m_get_mem_access(xc_interface *handle, uint32_t domid,
                             uint16_t view_id, xen_pfn_t gfn,
                             xenmem_access_t *access)
{
    int rc;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_get_mem_access;
    arg->domain = domid;
    arg->u.mem_access.view = view_id;
    arg->u.mem_access.gfn = gfn;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                 HYPERCALL_BUFFER_AS_ARG(arg));

    if ( !rc )
        *access = arg->u.mem_access.access;

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_get_vcpu_p2m_idx(xc_interface *handle, uint32_t domid,
                               uint32_t vcpuid, uint16_t *altp2m_idx)
{
    int rc;

    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_get_p2m_idx;
    arg->domain = domid;
    arg->u.get_vcpu_p2m_idx.vcpu_id = vcpuid;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                 HYPERCALL_BUFFER_AS_ARG(arg));
    if ( !rc )
        *altp2m_idx = arg->u.get_vcpu_p2m_idx.altp2m_idx;

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_altp2m_set_visibility(xc_interface *handle, uint32_t domid,
                             uint16_t view_id, bool visible)
{
    int rc;

    DECLARE_HYPERCALL_BUFFER(xen_hvm_altp2m_op_t, arg);

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_ALTP2M_INTERFACE_VERSION;
    arg->cmd = HVMOP_altp2m_set_visibility;
    arg->domain = domid;
    arg->u.set_visibility.altp2m_idx = view_id;
    arg->u.set_visibility.visible = visible;

    rc = xencall2(handle->xcall, __HYPERVISOR_hvm_op, HVMOP_altp2m,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    xc_hypercall_buffer_free(handle, arg);
    return rc;
}
