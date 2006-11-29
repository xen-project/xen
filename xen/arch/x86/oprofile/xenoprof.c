/*
 * Copyright (C) 2005 Hewlett-Packard Co.
 * written by Aravind Menon & Jose Renato Santos
 *            (email: xenoprof@groups.hp.com)
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 * x86 specific part
 */

#include <xen/guest_access.h>
#include <xen/sched.h>
#include <public/xenoprof.h>
#include <asm/hvm/support.h>

#include "op_counter.h"

int xenoprof_arch_counter(XEN_GUEST_HANDLE(void) arg)
{
    struct xenoprof_counter counter;

    if ( copy_from_guest(&counter, arg, 1) )
        return -EFAULT;

    if ( counter.ind > OP_MAX_COUNTER )
        return -E2BIG;

    counter_config[counter.ind].count     = counter.count;
    counter_config[counter.ind].enabled   = counter.enabled;
    counter_config[counter.ind].event     = counter.event;
    counter_config[counter.ind].kernel    = counter.kernel;
    counter_config[counter.ind].user      = counter.user;
    counter_config[counter.ind].unit_mask = counter.unit_mask;

    return 0;
}

int xenoprofile_get_mode(struct vcpu *v, struct cpu_user_regs * const regs)
{
    if ( !guest_mode(regs) )
        return 2;

    if ( is_hvm_vcpu(v) )
        return ((regs->cs & 3) != 3);

    return guest_kernel_mode(v, regs);  
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
