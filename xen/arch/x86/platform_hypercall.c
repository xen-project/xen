/******************************************************************************
 * platform_hypercall.c
 * 
 * Hardware platform operations. Intended for use by domain-0 kernel.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <public/platform.h>
#include <asm/mtrr.h>
#include "cpu/mtrr/mtrr.h"

#ifndef COMPAT
typedef long ret_t;
DEFINE_SPINLOCK(xenpf_lock);
#else
extern spinlock_t xenpf_lock;
#endif

ret_t do_platform_op(XEN_GUEST_HANDLE(xen_platform_op_t) u_xenpf_op)
{
    ret_t ret = 0;
    struct xen_platform_op curop, *op = &curop;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( copy_from_guest(op, u_xenpf_op, 1) )
        return -EFAULT;

    if ( op->interface_version != XENPF_INTERFACE_VERSION )
        return -EACCES;

    spin_lock(&xenpf_lock);

    switch ( op->cmd )
    {
    case XENPF_settime:
    {
        do_settime(op->u.settime.secs, 
                   op->u.settime.nsecs, 
                   op->u.settime.system_time);
        ret = 0;
    }
    break;

    case XENPF_add_memtype:
    {
        ret = mtrr_add_page(
            op->u.add_memtype.mfn,
            op->u.add_memtype.nr_mfns,
            op->u.add_memtype.type,
            1);
        if ( ret >= 0 )
        {
            op->u.add_memtype.handle = 0;
            op->u.add_memtype.reg    = ret;
            ret = copy_to_guest(u_xenpf_op, op, 1) ? -EFAULT : 0;
            if ( ret != 0 )
                mtrr_del_page(ret, 0, 0);
        }
    }
    break;

    case XENPF_del_memtype:
    {
        if (op->u.del_memtype.handle == 0
            /* mtrr/main.c otherwise does a lookup */
            && (int)op->u.del_memtype.reg >= 0)
        {
            ret = mtrr_del_page(op->u.del_memtype.reg, 0, 0);
            if ( ret > 0 )
                ret = 0;
        }
        else
            ret = -EINVAL;
    }
    break;

    case XENPF_read_memtype:
    {
        unsigned long mfn;
        unsigned int  nr_mfns;
        mtrr_type     type;

        ret = -EINVAL;
        if ( op->u.read_memtype.reg < num_var_ranges )
        {
            mtrr_if->get(op->u.read_memtype.reg, &mfn, &nr_mfns, &type);
            op->u.read_memtype.mfn     = mfn;
            op->u.read_memtype.nr_mfns = nr_mfns;
            op->u.read_memtype.type    = type;
            ret = copy_to_guest(u_xenpf_op, op, 1) ? -EFAULT : 0;
        }
    }
    break;

    case XENPF_microcode_update:
    {
        extern int microcode_update(XEN_GUEST_HANDLE(void), unsigned long len);
#ifndef COMPAT
        ret = microcode_update(op->u.microcode.data,
                               op->u.microcode.length);
#else
        XEN_GUEST_HANDLE(void) data;

        guest_from_compat_handle(data, op->u.microcode.data);
        ret = microcode_update(data, op->u.microcode.length);
#endif
    }
    break;

    case XENPF_platform_quirk:
    {
        extern int opt_noirqbalance;
        int quirk_id = op->u.platform_quirk.quirk_id;
        switch ( quirk_id )
        {
        case QUIRK_NOIRQBALANCING:
            printk("Platform quirk -- Disabling IRQ balancing/affinity.\n");
            opt_noirqbalance = 1;
            setup_ioapic_dest();
            break;
        case QUIRK_IOAPIC_BAD_REGSEL:
        case QUIRK_IOAPIC_GOOD_REGSEL:
#ifndef sis_apic_bug
            sis_apic_bug = (quirk_id == QUIRK_IOAPIC_BAD_REGSEL);
            dprintk(XENLOG_INFO, "Domain 0 says that IO-APIC REGSEL is %s\n",
                    sis_apic_bug ? "bad" : "good");
#else
            BUG_ON(sis_apic_bug != (quirk_id == QUIRK_IOAPIC_BAD_REGSEL));
#endif
            break;
        default:
            ret = -EINVAL;
            break;
        }
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    spin_unlock(&xenpf_lock);

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
