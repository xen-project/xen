/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/fdt-domain-build.h>
#include <xen/fdt-kernel.h>
#include <xen/init.h>
#include <xen/sched.h>

#include <asm/current.h>
#include <asm/guest_access.h>

int __init construct_domain(struct domain *d, struct kernel_info *kinfo)
{
    struct vcpu *v = d->vcpu[0];
    struct cpu_user_regs *regs = vcpu_guest_cpu_user_regs(v);

    BUG_ON(v->is_initialised);

    /*
     * At the moment *_load() don't return value and will just panic()
     * inside.
     * TODO: it will be good to change that.
     */
    kernel_load(kinfo);
    initrd_load(kinfo, copy_to_guest_phys);
    dtb_load(kinfo, copy_to_guest_phys);

    regs->sepc = kinfo->entry;

    /* Guest boot cpuid = 0 */
    regs->a0 = 0;
    regs->a1 = kinfo->dtb_paddr;

    for ( unsigned int i = 1; i < d->max_vcpus; i++ )
    {
        const struct vcpu *tmp_v = vcpu_create(d, i);

        if ( !tmp_v )
        {
            printk("Failed to allocate %pdv%u\n", d, i);
            break;
        }
    }

    domain_update_node_affinity(d);

    v->is_initialised = true;
    clear_bit(_VPF_down, &v->pause_flags);

    return 0;
}
