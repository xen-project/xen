/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/fdt-domain-build.h>
#include <xen/fdt-kernel.h>
#include <xen/init.h>
#include <xen/fdt-kernel.h>
#include <xen/libfdt/libfdt.h>
#include <xen/sched.h>

#include <asm/cpufeature.h>
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

int __init make_cpus_node(const struct domain *d, struct kernel_info *kinfo)
{
    int res;
    const struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    uint32_t timebase_frequency;
    bool frequency_valid;
    void *fdt = kinfo->fdt;

    dt_dprintk("Create cpus node\n");

    if ( !cpus )
    {
        dprintk(XENLOG_ERR, "Missing /cpus node in the device tree?\n");
        return -ENOENT;
    }

    frequency_valid = dt_property_read_u32(cpus, "timebase-frequency",
                                           &timebase_frequency);

    res = fdt_begin_node(fdt, "cpus");
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", 1);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#size-cells", 0);
    if ( res )
        return res;

    if ( frequency_valid )
        res = fdt_property_cell(fdt, "timebase-frequency", timebase_frequency);

    for ( unsigned int cpu = 0; cpu < d->max_vcpus; cpu++ )
    {
        char buf[64];

        snprintf(buf, ARRAY_SIZE(buf), "cpu@%u", cpu);
        res = fdt_begin_node(fdt, buf);
        if ( res )
            return res;

        res = fdt_property_cell(fdt, "reg", cpu);
        if ( res )
            return res;

        res = fdt_property_string(fdt, "status", "okay");
        if ( res )
            return res;

        res = fdt_property_string(fdt, "compatible", "riscv");
        if ( res )
            return res;

        BUILD_BUG_ON((sizeof("riscv,") +
                      sizeof_field(struct gstage_mode_desc, name)) >= sizeof(buf));
        snprintf(buf, ARRAY_SIZE(buf), "riscv,%s", max_gstage_mode->name);
        res = fdt_property_string(fdt, "mmu-type", buf);
        if ( res )
            return res;

        res = fdt_property_string(fdt, "riscv,isa", get_guest_isa_str());
        if ( res )
            return res;

        res = fdt_property_string(fdt, "device_type", "cpu");
        if ( res )
            return res;

        /* Start of interrupt-controller */
        res = fdt_begin_node(fdt, "interrupt-controller");
        if ( res )
            return res;

        res = fdt_property_string(fdt, "compatible", "riscv,cpu-intc");
        if ( res )
            return res;

        res = fdt_property_cell(fdt, "#interrupt-cells", 1);
        if ( res )
            return res;

        res = fdt_property(fdt, "interrupt-controller", NULL, 0);
        if ( res )
            return res;

        res = fdt_property_u32(fdt, "phandle", alloc_phandle(kinfo));
        if ( res )
            return res;

        /* End of interrupt-controller */
        res = fdt_end_node(fdt);
        if ( res )
            return res;

        res = fdt_end_node(fdt);
        if ( res )
            return res;
    }

    return fdt_end_node(fdt);
}

int __init make_timer_node(const struct kernel_info *kinfo)
{
    /* There is no need for timer node for RISC-V. */

    return 0;
}
