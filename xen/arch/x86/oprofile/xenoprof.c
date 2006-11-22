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
