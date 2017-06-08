#include <xen/event.h>
#include <asm/regs.h>
#include <compat/callback.h>
#include <compat/arch-x86_32.h>

static long compat_register_guest_callback(
    struct compat_callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    fixup_guest_code_selector(v->domain, reg->address.cs);

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.pv_vcpu.event_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.event_callback_eip    = reg->address.eip;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.pv_vcpu.failsafe_callback_cs  = reg->address.cs;
        v->arch.pv_vcpu.failsafe_callback_eip = reg->address.eip;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_failsafe_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_failsafe_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall32:
        v->arch.pv_vcpu.syscall32_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.syscall32_callback_eip    = reg->address.eip;
        v->arch.pv_vcpu.syscall32_disables_events =
            (reg->flags & CALLBACKF_mask_events) != 0;
        break;

    case CALLBACKTYPE_sysenter:
        v->arch.pv_vcpu.sysenter_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.sysenter_callback_eip    = reg->address.eip;
        v->arch.pv_vcpu.sysenter_disables_events =
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
        ret = unregister_guest_nmi_callback();
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

int compat_set_trap_table(XEN_GUEST_HANDLE(trap_info_compat_t) traps)
{
    struct compat_trap_info cur;
    struct trap_info *dst = current->arch.pv_vcpu.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, NR_VECTORS * sizeof(*dst));
        init_int80_direct_trap(current);
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

        fixup_guest_code_selector(current->domain, cur.cs);

        XLAT_trap_info(dst + cur.vector, &cur);

        if ( cur.vector == 0x80 )
            init_int80_direct_trap(current);

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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
