/*
 * pv/callback.c
 *
 * hypercall handles and helper functions for guest callback
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/event.h>
#include <xen/hypercall.h>
#include <xen/guest_access.h>
#include <compat/callback.h>
#include <compat/nmi.h>

#include <asm/shared.h>

#include <public/callback.h>

static int register_guest_nmi_callback(unsigned long address)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    struct trap_info *t = &curr->arch.pv.trap_ctxt[TRAP_nmi];

    if ( !is_canonical_address(address) )
        return -EINVAL;

    t->vector  = TRAP_nmi;
    t->flags   = 0;
    t->cs      = (is_pv_32bit_domain(d) ?
                  FLAT_COMPAT_KERNEL_CS : FLAT_KERNEL_CS);
    t->address = address;
    TI_SET_IF(t, 1);

    /*
     * If no handler was registered we can 'lose the NMI edge'. Re-assert it
     * now.
     */
    if ( curr->vcpu_id == 0 && arch_get_nmi_reason(d) != 0 )
        curr->arch.nmi_pending = true;

    return 0;
}

static void unregister_guest_nmi_callback(void)
{
    struct vcpu *curr = current;
    struct trap_info *t = &curr->arch.pv.trap_ctxt[TRAP_nmi];

    memset(t, 0, sizeof(*t));
}

static long register_guest_callback(struct callback_register *reg)
{
    long ret = 0;
    struct vcpu *curr = current;

    if ( !is_canonical_address(reg->address) )
        return -EINVAL;

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        curr->arch.pv.event_callback_eip = reg->address;
        break;

    case CALLBACKTYPE_failsafe:
        curr->arch.pv.failsafe_callback_eip = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            curr->arch.pv.vgc_flags |= VGCF_failsafe_disables_events;
        else
            curr->arch.pv.vgc_flags &= ~VGCF_failsafe_disables_events;
        break;

    case CALLBACKTYPE_syscall:
        curr->arch.pv.syscall_callback_eip = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            curr->arch.pv.vgc_flags |= VGCF_syscall_disables_events;
        else
            curr->arch.pv.vgc_flags &= ~VGCF_syscall_disables_events;
        break;

    case CALLBACKTYPE_syscall32:
        curr->arch.pv.syscall32_callback_eip = reg->address;
        curr->arch.pv.syscall32_disables_events =
            !!(reg->flags & CALLBACKF_mask_events);
        break;

    case CALLBACKTYPE_sysenter:
        curr->arch.pv.sysenter_callback_eip = reg->address;
        curr->arch.pv.sysenter_disables_events =
            !!(reg->flags & CALLBACKF_mask_events);
        break;

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long unregister_guest_callback(struct callback_unregister *unreg)
{
    long ret;

    switch ( unreg->type )
    {
    case CALLBACKTYPE_event:
    case CALLBACKTYPE_failsafe:
    case CALLBACKTYPE_syscall:
    case CALLBACKTYPE_syscall32:
    case CALLBACKTYPE_sysenter:
        ret = -EINVAL;
        break;

    case CALLBACKTYPE_nmi:
        unregister_guest_nmi_callback();
        ret = 0;
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

long do_callback_op(int cmd, XEN_GUEST_HANDLE_PARAM(const_void) arg)
{
    long ret;

    switch ( cmd )
    {
    case CALLBACKOP_register:
    {
        struct callback_register reg;

        ret = -EFAULT;
        if ( copy_from_guest(&reg, arg, 1) )
            break;

        ret = register_guest_callback(&reg);
    }
    break;

    case CALLBACKOP_unregister:
    {
        struct callback_unregister unreg;

        ret = -EFAULT;
        if ( copy_from_guest(&unreg, arg, 1) )
            break;

        ret = unregister_guest_callback(&unreg);
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

long do_set_callbacks(unsigned long event_address,
                      unsigned long failsafe_address,
                      unsigned long syscall_address)
{
    struct callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = event_address,
    };
    struct callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = failsafe_address,
    };
    struct callback_register syscall = {
        .type = CALLBACKTYPE_syscall,
        .address = syscall_address,
    };

    register_guest_callback(&event);
    register_guest_callback(&failsafe);
    register_guest_callback(&syscall);

    return 0;
}

static long compat_register_guest_callback(struct compat_callback_register *reg)
{
    long ret = 0;
    struct vcpu *curr = current;

    fixup_guest_code_selector(curr->domain, reg->address.cs);

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        curr->arch.pv.event_callback_cs = reg->address.cs;
        curr->arch.pv.event_callback_eip = reg->address.eip;
        break;

    case CALLBACKTYPE_failsafe:
        curr->arch.pv.failsafe_callback_cs = reg->address.cs;
        curr->arch.pv.failsafe_callback_eip = reg->address.eip;
        if ( reg->flags & CALLBACKF_mask_events )
            curr->arch.pv.vgc_flags |= VGCF_failsafe_disables_events;
        else
            curr->arch.pv.vgc_flags &= ~VGCF_failsafe_disables_events;
        break;

    case CALLBACKTYPE_syscall32:
        curr->arch.pv.syscall32_callback_cs = reg->address.cs;
        curr->arch.pv.syscall32_callback_eip = reg->address.eip;
        curr->arch.pv.syscall32_disables_events =
            (reg->flags & CALLBACKF_mask_events) != 0;
        break;

    case CALLBACKTYPE_sysenter:
        curr->arch.pv.sysenter_callback_cs = reg->address.cs;
        curr->arch.pv.sysenter_callback_eip = reg->address.eip;
        curr->arch.pv.sysenter_disables_events =
            (reg->flags & CALLBACKF_mask_events) != 0;
        break;

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address.eip);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long compat_unregister_guest_callback(
    struct compat_callback_unregister *unreg)
{
    long ret;

    switch ( unreg->type )
    {
    case CALLBACKTYPE_event:
    case CALLBACKTYPE_failsafe:
    case CALLBACKTYPE_syscall32:
    case CALLBACKTYPE_sysenter:
        ret = -EINVAL;
        break;

    case CALLBACKTYPE_nmi:
        unregister_guest_nmi_callback();
        ret = 0;
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

long compat_callback_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    long ret;

    switch ( cmd )
    {
    case CALLBACKOP_register:
    {
        struct compat_callback_register reg;

        ret = -EFAULT;
        if ( copy_from_guest(&reg, arg, 1) )
            break;

        ret = compat_register_guest_callback(&reg);
    }
    break;

    case CALLBACKOP_unregister:
    {
        struct compat_callback_unregister unreg;

        ret = -EFAULT;
        if ( copy_from_guest(&unreg, arg, 1) )
            break;

        ret = compat_unregister_guest_callback(&unreg);
    }
    break;

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

long compat_set_callbacks(unsigned long event_selector,
                          unsigned long event_address,
                          unsigned long failsafe_selector,
                          unsigned long failsafe_address)
{
    struct compat_callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = {
            .cs = event_selector,
            .eip = event_address
        }
    };
    struct compat_callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = {
            .cs = failsafe_selector,
            .eip = failsafe_address
        }
    };

    compat_register_guest_callback(&event);
    compat_register_guest_callback(&failsafe);

    return 0;
}

long do_set_trap_table(XEN_GUEST_HANDLE_PARAM(const_trap_info_t) traps)
{
    struct trap_info cur;
    struct vcpu *curr = current;
    struct trap_info *dst = curr->arch.pv.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, X86_NR_VECTORS * sizeof(*dst));
        return 0;
    }

    for ( ; ; )
    {
        if ( copy_from_guest(&cur, traps, 1) )
        {
            rc = -EFAULT;
            break;
        }

        if ( cur.address == 0 )
            break;

        if ( !is_canonical_address(cur.address) )
            return -EINVAL;

        fixup_guest_code_selector(curr->domain, cur.cs);

        memcpy(&dst[cur.vector], &cur, sizeof(cur));

        guest_handle_add_offset(traps, 1);

        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_set_trap_table, "h", traps);
            break;
        }
    }

    return rc;
}

int compat_set_trap_table(XEN_GUEST_HANDLE(trap_info_compat_t) traps)
{
    struct vcpu *curr = current;
    struct compat_trap_info cur;
    struct trap_info *dst = curr->arch.pv.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, X86_NR_VECTORS * sizeof(*dst));
        return 0;
    }

    for ( ; ; )
    {
        if ( copy_from_guest(&cur, traps, 1) )
        {
            rc = -EFAULT;
            break;
        }

        if ( cur.address == 0 )
            break;

        fixup_guest_code_selector(curr->domain, cur.cs);

        XLAT_trap_info(dst + cur.vector, &cur);

        guest_handle_add_offset(traps, 1);

        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_set_trap_table, "h", traps);
            break;
        }
    }

    return rc;
}

long do_nmi_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xennmi_callback cb;
    long rc = 0;

    switch ( cmd )
    {
    case XENNMI_register_callback:
        rc = -EFAULT;
        if ( copy_from_guest(&cb, arg, 1) )
            break;
        rc = register_guest_nmi_callback(cb.handler_address);
        break;
    case XENNMI_unregister_callback:
        unregister_guest_nmi_callback();
        rc = 0;
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

int compat_nmi_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct compat_nmi_callback cb;
    int rc = 0;

    switch ( cmd )
    {
    case XENNMI_register_callback:
        rc = -EFAULT;
        if ( copy_from_guest(&cb, arg, 1) )
            break;
        rc = register_guest_nmi_callback(cb.handler_address);
        break;
    case XENNMI_unregister_callback:
        unregister_guest_nmi_callback();
        rc = 0;
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
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
