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
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <asm/hvm/hvm.h>
#include <asm/vm_event.h>

/* Implicitly serialized by the domctl lock. */
int vm_event_init_domain(struct domain *d)
{
    struct vcpu *v;

    if ( !d->arch.event_write_data )
        d->arch.event_write_data =
            vzalloc(sizeof(struct monitor_write_data) * d->max_vcpus);

    if ( !d->arch.event_write_data )
        return -ENOMEM;

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

    vfree(d->arch.event_write_data);
    d->arch.event_write_data = NULL;

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

void vm_event_register_write_resume(struct vcpu *v, vm_event_response_t *rsp)
{
    if ( rsp->flags & VM_EVENT_FLAG_DENY )
    {
        struct monitor_write_data *w =
            &v->domain->arch.event_write_data[v->vcpu_id];

        ASSERT(v->domain->arch.event_write_data != NULL);

        switch ( rsp->reason )
        {
        case VM_EVENT_REASON_MOV_TO_MSR:
            w->do_write.msr = 0;
            break;
        case VM_EVENT_REASON_WRITE_CTRLREG:
            switch ( rsp->u.write_ctrlreg.index )
            {
            case VM_EVENT_X86_CR0:
                w->do_write.cr0 = 0;
                break;
            case VM_EVENT_X86_CR3:
                w->do_write.cr3 = 0;
                break;
            case VM_EVENT_X86_CR4:
                w->do_write.cr4 = 0;
                break;
            }
            break;
        }
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
