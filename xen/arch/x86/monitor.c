/*
 * arch/x86/monitor.c
 *
 * Arch-specific monitor_op domctl handler.
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 * Copyright (c) 2016, Bitdefender S.R.L.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/monitor.h>
#include <public/vm_event.h>

int arch_monitor_init_domain(struct domain *d)
{
    if ( !d->arch.monitor.msr_bitmap )
        d->arch.monitor.msr_bitmap = xzalloc(struct monitor_msr_bitmap);

    if ( !d->arch.monitor.msr_bitmap )
        return -ENOMEM;

    return 0;
}

void arch_monitor_cleanup_domain(struct domain *d)
{
    xfree(d->arch.monitor.msr_bitmap);

    memset(&d->arch.monitor, 0, sizeof(d->arch.monitor));
    memset(&d->monitor, 0, sizeof(d->monitor));
}

static unsigned long *monitor_bitmap_for_msr(const struct domain *d, u32 *msr)
{
    ASSERT(d->arch.monitor.msr_bitmap && msr);

    switch ( *msr )
    {
    case 0 ... 0x1fff:
        BUILD_BUG_ON(sizeof(d->arch.monitor.msr_bitmap->low) * 8 <= 0x1fff);
        return d->arch.monitor.msr_bitmap->low;

    case 0x40000000 ... 0x40001fff:
        BUILD_BUG_ON(
            sizeof(d->arch.monitor.msr_bitmap->hypervisor) * 8 <= 0x1fff);
        *msr &= 0x1fff;
        return d->arch.monitor.msr_bitmap->hypervisor;

    case 0xc0000000 ... 0xc0001fff:
        BUILD_BUG_ON(sizeof(d->arch.monitor.msr_bitmap->high) * 8 <= 0x1fff);
        *msr &= 0x1fff;
        return d->arch.monitor.msr_bitmap->high;

    default:
        return NULL;
    }
}

static int monitor_enable_msr(struct domain *d, u32 msr)
{
    unsigned long *bitmap;
    u32 index = msr;

    if ( !d->arch.monitor.msr_bitmap )
        return -ENXIO;

    bitmap = monitor_bitmap_for_msr(d, &index);

    if ( !bitmap )
        return -EINVAL;

    __set_bit(index, bitmap);

    hvm_enable_msr_interception(d, msr);

    return 0;
}

static int monitor_disable_msr(struct domain *d, u32 msr)
{
    unsigned long *bitmap;

    if ( !d->arch.monitor.msr_bitmap )
        return -ENXIO;

    bitmap = monitor_bitmap_for_msr(d, &msr);

    if ( !bitmap )
        return -EINVAL;

    __clear_bit(msr, bitmap);

    return 0;
}

bool monitored_msr(const struct domain *d, u32 msr)
{
    const unsigned long *bitmap;

    if ( !d->arch.monitor.msr_bitmap )
        return false;

    bitmap = monitor_bitmap_for_msr(d, &msr);

    if ( !bitmap )
        return false;

    return test_bit(msr, bitmap);
}

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop)
{
    struct arch_domain *ad = &d->arch;
    bool requested_status = (XEN_DOMCTL_MONITOR_OP_ENABLE == mop->op);

    switch ( mop->event )
    {
    case XEN_DOMCTL_MONITOR_EVENT_WRITE_CTRLREG:
    {
        unsigned int ctrlreg_bitmask;
        bool old_status;

        if ( unlikely(mop->u.mov_to_cr.index >=
                      ARRAY_SIZE(ad->monitor.write_ctrlreg_mask)) )
            return -EINVAL;

        if ( unlikely(mop->u.mov_to_cr.pad1 || mop->u.mov_to_cr.pad2) )
            return -EINVAL;

        ctrlreg_bitmask = monitor_ctrlreg_bitmask(mop->u.mov_to_cr.index);
        old_status = !!(ad->monitor.write_ctrlreg_enabled & ctrlreg_bitmask);

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);

        if ( mop->u.mov_to_cr.sync )
            ad->monitor.write_ctrlreg_sync |= ctrlreg_bitmask;
        else
            ad->monitor.write_ctrlreg_sync &= ~ctrlreg_bitmask;

        if ( mop->u.mov_to_cr.onchangeonly )
            ad->monitor.write_ctrlreg_onchangeonly |= ctrlreg_bitmask;
        else
            ad->monitor.write_ctrlreg_onchangeonly &= ~ctrlreg_bitmask;

        if ( requested_status )
        {
            ad->monitor.write_ctrlreg_mask[mop->u.mov_to_cr.index] = mop->u.mov_to_cr.bitmask;
            ad->monitor.write_ctrlreg_enabled |= ctrlreg_bitmask;
        }
        else
        {
            ad->monitor.write_ctrlreg_mask[mop->u.mov_to_cr.index] = 0;
            ad->monitor.write_ctrlreg_enabled &= ~ctrlreg_bitmask;
        }

        if ( VM_EVENT_X86_CR3 == mop->u.mov_to_cr.index )
        {
            struct vcpu *v;
            /* Latches new CR3 mask through CR0 code. */
            for_each_vcpu ( d, v )
                hvm_update_guest_cr(v, 0);
        }

        domain_unpause(d);

        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR:
    {
        bool old_status;
        int rc;
        u32 msr = mop->u.mov_to_msr.msr;

        domain_pause(d);

        old_status = monitored_msr(d, msr);

        if ( unlikely(old_status == requested_status) )
        {
            domain_unpause(d);
            return -EEXIST;
        }

        if ( requested_status )
            rc = monitor_enable_msr(d, msr);
        else
            rc = monitor_disable_msr(d, msr);

        domain_unpause(d);

        return rc;
    }

    case XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP:
    {
        bool old_status = ad->monitor.singlestep_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        ad->monitor.singlestep_enabled = requested_status;
        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_DESC_ACCESS:
    {
        bool old_status = ad->monitor.descriptor_access_enabled;
        struct vcpu *v;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        if ( !hvm_funcs.set_descriptor_access_exiting )
            return -EOPNOTSUPP;

        domain_pause(d);
        ad->monitor.descriptor_access_enabled = requested_status;

        for_each_vcpu ( d, v )
            hvm_funcs.set_descriptor_access_exiting(v, requested_status);

        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_SOFTWARE_BREAKPOINT:
    {
        bool old_status = ad->monitor.software_breakpoint_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        ad->monitor.software_breakpoint_enabled = requested_status;
        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_DEBUG_EXCEPTION:
    {
        bool old_status = ad->monitor.debug_exception_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        ad->monitor.debug_exception_enabled = requested_status;
        ad->monitor.debug_exception_sync = requested_status ?
                                            mop->u.debug_exception.sync :
                                            0;
        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_CPUID:
    {
        bool old_status = ad->monitor.cpuid_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        ad->monitor.cpuid_enabled = requested_status;
        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_EMUL_UNIMPLEMENTED:
    {
        bool old_status = ad->monitor.emul_unimplemented_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        ad->monitor.emul_unimplemented_enabled = requested_status;
        domain_unpause(d);
        break;
    }

    default:
        /*
         * Should not be reached unless arch_monitor_get_capabilities() is
         * not properly implemented.
         */
        ASSERT_UNREACHABLE();
        return -EOPNOTSUPP;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
