/*
 * arch/x86/vm_event.c
 *
 * Architecture-specific vm_event handling routines
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
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
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <xen/sched.h>
#include <asm/hvm/hvm.h>

/* Implicitly serialized by the domctl lock. */
int vm_event_init_domain(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        if ( v->arch.vm_event.emul_read_data )
            continue;

        v->arch.vm_event.emul_read_data =
            xzalloc(struct vm_event_emul_read_data);

        if ( !v->arch.vm_event.emul_read_data )
            return -ENOMEM;
    }

    return 0;
}

/*
 * Implicitly serialized by the domctl lock,
 * or on domain cleanup paths only.
 */
void vm_event_cleanup_domain(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        xfree(v->arch.vm_event.emul_read_data);
        v->arch.vm_event.emul_read_data = NULL;
    }
}

void vm_event_toggle_singlestep(struct domain *d, struct vcpu *v)
{
    if ( !is_hvm_domain(d) || !atomic_read(&v->vm_event_pause_count) )
        return;

    hvm_toggle_singlestep(v);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
