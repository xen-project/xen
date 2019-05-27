/*
 * xen/arch/arm/gic.c
 *
 * ARM Generic Interrupt Controller support
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <xen/list.h>
#include <xen/device_tree.h>
#include <xen/acpi.h>
#include <xen/cpu.h>
#include <xen/notifier.h>
#include <asm/p2m.h>
#include <asm/domain.h>
#include <asm/platform.h>
#include <asm/device.h>
#include <asm/io.h>
#include <asm/gic.h>
#include <asm/vgic.h>
#include <asm/acpi.h>

DEFINE_PER_CPU(uint64_t, lr_mask);

#undef GIC_DEBUG

const struct gic_hw_operations *gic_hw_ops;

void register_gic_ops(const struct gic_hw_operations *ops)
{
    gic_hw_ops = ops;
}

static void clear_cpu_lr_mask(void)
{
    this_cpu(lr_mask) = 0ULL;
}

enum gic_version gic_hw_version(void)
{
   return gic_hw_ops->info->hw_version;
}

unsigned int gic_number_lines(void)
{
    return gic_hw_ops->info->nr_lines;
}

void gic_save_state(struct vcpu *v)
{
    ASSERT(!local_irq_is_enabled());
    ASSERT(!is_idle_vcpu(v));

    /* No need for spinlocks here because interrupts are disabled around
     * this call and it only accesses struct vcpu fields that cannot be
     * accessed simultaneously by another pCPU.
     */
    v->arch.lr_mask = this_cpu(lr_mask);
    gic_hw_ops->save_state(v);
    isb();
}

void gic_restore_state(struct vcpu *v)
{
    ASSERT(!local_irq_is_enabled());
    ASSERT(!is_idle_vcpu(v));

    this_cpu(lr_mask) = v->arch.lr_mask;
    gic_hw_ops->restore_state(v);

    isb();
}

/* desc->irq needs to be disabled before calling this function */
void gic_set_irq_type(struct irq_desc *desc, unsigned int type)
{
    /*
     * IRQ must be disabled before configuring it (see 4.3.13 in ARM IHI
     * 0048B.b). We rely on the caller to do it.
     */
    ASSERT(test_bit(_IRQ_DISABLED, &desc->status));
    ASSERT(spin_is_locked(&desc->lock));
    ASSERT(type != IRQ_TYPE_INVALID);

    gic_hw_ops->set_irq_type(desc, type);
}

static void gic_set_irq_priority(struct irq_desc *desc, unsigned int priority)
{
    gic_hw_ops->set_irq_priority(desc, priority);
}

/* Program the GIC to route an interrupt to the host (i.e. Xen)
 * - needs to be called with desc.lock held
 */
void gic_route_irq_to_xen(struct irq_desc *desc, unsigned int priority)
{
    ASSERT(priority <= 0xff);     /* Only 8 bits of priority */
    ASSERT(desc->irq < gic_number_lines());/* Can't route interrupts that don't exist */
    ASSERT(test_bit(_IRQ_DISABLED, &desc->status));
    ASSERT(spin_is_locked(&desc->lock));

    desc->handler = gic_hw_ops->gic_host_irq_type;

    gic_set_irq_type(desc, desc->arch.type);
    gic_set_irq_priority(desc, priority);
}

/* Program the GIC to route an interrupt to a guest
 *   - desc.lock must be held
 */
int gic_route_irq_to_guest(struct domain *d, unsigned int virq,
                           struct irq_desc *desc, unsigned int priority)
{
    int ret;

    ASSERT(spin_is_locked(&desc->lock));
    /* Caller has already checked that the IRQ is an SPI */
    ASSERT(virq >= 32);
    ASSERT(virq < vgic_num_irqs(d));
    ASSERT(!is_lpi(virq));

    /*
     * When routing an IRQ to guest, the virtual state is not synced
     * back to the physical IRQ. To prevent get unsync, restrict the
     * routing to when the Domain is been created.
     */
    if ( d->creation_finished )
        return -EBUSY;

    ret = vgic_connect_hw_irq(d, NULL, virq, desc, true);
    if ( ret )
        return ret;

    desc->handler = gic_hw_ops->gic_guest_irq_type;
    set_bit(_IRQ_GUEST, &desc->status);

    if ( !irq_type_set_by_domain(d) )
        gic_set_irq_type(desc, desc->arch.type);
    gic_set_irq_priority(desc, priority);

    return 0;
}

/* This function only works with SPIs for now */
int gic_remove_irq_from_guest(struct domain *d, unsigned int virq,
                              struct irq_desc *desc)
{
    int ret;

    ASSERT(spin_is_locked(&desc->lock));
    ASSERT(test_bit(_IRQ_GUEST, &desc->status));
    ASSERT(!is_lpi(virq));

    /*
     * Removing an interrupt while the domain is running may have
     * undesirable effect on the vGIC emulation.
     */
    if ( !d->is_dying )
        return -EBUSY;

    desc->handler->shutdown(desc);

    /* EOI the IRQ if it has not been done by the guest */
    if ( test_bit(_IRQ_INPROGRESS, &desc->status) )
        gic_hw_ops->deactivate_irq(desc);
    clear_bit(_IRQ_INPROGRESS, &desc->status);

    ret = vgic_connect_hw_irq(d, NULL, virq, desc, false);
    if ( ret )
        return ret;

    clear_bit(_IRQ_GUEST, &desc->status);
    desc->handler = &no_irq_type;

    return 0;
}

int gic_irq_xlate(const u32 *intspec, unsigned int intsize,
                  unsigned int *out_hwirq,
                  unsigned int *out_type)
{
    if ( intsize < 3 )
        return -EINVAL;

    /* Get the interrupt number and add 16 to skip over SGIs */
    *out_hwirq = intspec[1] + 16;

    /* For SPIs, we need to add 16 more to get the GIC irq ID number */
    if ( !intspec[0] )
        *out_hwirq += 16;

    if ( out_type )
        *out_type = intspec[2] & IRQ_TYPE_SENSE_MASK;

    return 0;
}

/* Map extra GIC MMIO, irqs and other hw stuffs to the hardware domain. */
int gic_map_hwdom_extra_mappings(struct domain *d)
{
    if ( gic_hw_ops->map_hwdom_extra_mappings )
        return gic_hw_ops->map_hwdom_extra_mappings(d);

    return 0;
}

static void __init gic_dt_preinit(void)
{
    int rc;
    struct dt_device_node *node;
    uint8_t num_gics = 0;

    dt_for_each_device_node( dt_host, node )
    {
        if ( !dt_get_property(node, "interrupt-controller", NULL) )
            continue;

        if ( !dt_get_parent(node) )
            continue;

        rc = device_init(node, DEVICE_GIC, NULL);
        if ( !rc )
        {
            /* NOTE: Only one GIC is supported */
            num_gics = 1;
            break;
        }
    }
    if ( !num_gics )
        panic("Unable to find compatible GIC in the device tree\n");

    /* Set the GIC as the primary interrupt controller */
    dt_interrupt_controller = node;
    dt_device_set_used_by(node, DOMID_XEN);
}

#ifdef CONFIG_ACPI
static void __init gic_acpi_preinit(void)
{
    struct acpi_subtable_header *header;
    struct acpi_madt_generic_distributor *dist;

    header = acpi_table_get_entry_madt(ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR, 0);
    if ( !header )
        panic("No valid GICD entries exists\n");

    dist = container_of(header, struct acpi_madt_generic_distributor, header);

    if ( acpi_device_init(DEVICE_GIC, NULL, dist->version) )
        panic("Unable to find compatible GIC in the ACPI table\n");
}
#else
static void __init gic_acpi_preinit(void) { }
#endif

/* Find the interrupt controller and set up the callback to translate
 * device tree or ACPI IRQ.
 */
void __init gic_preinit(void)
{
    if ( acpi_disabled )
        gic_dt_preinit();
    else
        gic_acpi_preinit();
}

/* Set up the GIC */
void __init gic_init(void)
{
    if ( gic_hw_ops->init() )
        panic("Failed to initialize the GIC drivers\n");
    /* Clear LR mask for cpu0 */
    clear_cpu_lr_mask();
}

void send_SGI_mask(const cpumask_t *cpumask, enum gic_sgi sgi)
{
    ASSERT(sgi < 16); /* There are only 16 SGIs */

    gic_hw_ops->send_SGI(sgi, SGI_TARGET_LIST, cpumask);
}

void send_SGI_one(unsigned int cpu, enum gic_sgi sgi)
{
    send_SGI_mask(cpumask_of(cpu), sgi);
}

void send_SGI_self(enum gic_sgi sgi)
{
    ASSERT(sgi < 16); /* There are only 16 SGIs */

    gic_hw_ops->send_SGI(sgi, SGI_TARGET_SELF, NULL);
}

void send_SGI_allbutself(enum gic_sgi sgi)
{
   ASSERT(sgi < 16); /* There are only 16 SGIs */

   gic_hw_ops->send_SGI(sgi, SGI_TARGET_OTHERS, NULL);
}

void smp_send_state_dump(unsigned int cpu)
{
    send_SGI_one(cpu, GIC_SGI_DUMP_STATE);
}

/* Set up the per-CPU parts of the GIC for a secondary CPU */
void gic_init_secondary_cpu(void)
{
    gic_hw_ops->secondary_init();
    /* Clear LR mask for secondary cpus */
    clear_cpu_lr_mask();
}

/* Shut down the per-CPU GIC interface */
void gic_disable_cpu(void)
{
    ASSERT(!local_irq_is_enabled());

    gic_hw_ops->disable_interface();
}

static void do_sgi(struct cpu_user_regs *regs, enum gic_sgi sgi)
{
    struct irq_desc *desc = irq_to_desc(sgi);

    perfc_incr(ipis);

    /* Lower the priority */
    gic_hw_ops->eoi_irq(desc);

    /*
     * Ensure any shared data written by the CPU sending
     * the IPI is read after we've read the ACK register on the GIC.
     * Matches the write barrier in send_SGI_* helpers.
     */
    smp_rmb();

    switch (sgi)
    {
    case GIC_SGI_EVENT_CHECK:
        /* Nothing to do, will check for events on return path */
        break;
    case GIC_SGI_DUMP_STATE:
        dump_execstate(regs);
        break;
    case GIC_SGI_CALL_FUNCTION:
        smp_call_function_interrupt();
        break;
    default:
        panic("Unhandled SGI %d on CPU%d\n", sgi, smp_processor_id());
        break;
    }

    /* Deactivate */
    gic_hw_ops->deactivate_irq(desc);
}

/* Accept an interrupt from the GIC and dispatch its handler */
void gic_interrupt(struct cpu_user_regs *regs, int is_fiq)
{
    unsigned int irq;

    do  {
        /* Reading IRQ will ACK it */
        irq = gic_hw_ops->read_irq();

        if ( likely(irq >= 16 && irq < 1020) )
        {
            isb();
            do_IRQ(regs, irq, is_fiq);
        }
        else if ( is_lpi(irq) )
        {
            isb();
            gic_hw_ops->do_LPI(irq);
        }
        else if ( unlikely(irq < 16) )
        {
            do_sgi(regs, irq);
        }
        else
        {
            local_irq_disable();
            break;
        }
    } while (1);
}

static void maintenance_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    /*
     * This is a dummy interrupt handler.
     * Receiving the interrupt is going to cause gic_inject to be called
     * on return to guest that is going to clear the old LRs and inject
     * new interrupts.
     *
     * Do not add code here: maintenance interrupts caused by setting
     * GICH_HCR_UIE, might read as spurious interrupts (1023) because
     * GICH_HCR_UIE is cleared before reading GICC_IAR. As a consequence
     * this handler is not called.
     */
    perfc_incr(maintenance_irqs);
}

void gic_dump_info(struct vcpu *v)
{
    printk("GICH_LRs (vcpu %d) mask=%"PRIx64"\n", v->vcpu_id, v->arch.lr_mask);
    gic_hw_ops->dump_state(v);
}

void init_maintenance_interrupt(void)
{
    request_irq(gic_hw_ops->info->maintenance_irq, 0, maintenance_interrupt,
                "irq-maintenance", NULL);
}

int gic_make_hwdom_dt_node(const struct domain *d,
                           const struct dt_device_node *gic,
                           void *fdt)
{
    ASSERT(gic == dt_interrupt_controller);

    return gic_hw_ops->make_hwdom_dt_node(d, gic, fdt);
}

int gic_make_hwdom_madt(const struct domain *d, u32 offset)
{
    return gic_hw_ops->make_hwdom_madt(d, offset);
}

unsigned long gic_get_hwdom_madt_size(const struct domain *d)
{
    unsigned long madt_size;

    madt_size = sizeof(struct acpi_table_madt)
                + sizeof(struct acpi_madt_generic_interrupt) * d->max_vcpus
                + sizeof(struct acpi_madt_generic_distributor)
                + gic_hw_ops->get_hwdom_extra_madt_size(d);

    return madt_size;
}

int gic_iomem_deny_access(const struct domain *d)
{
    return gic_hw_ops->iomem_deny_access(d);
}

static int cpu_gic_callback(struct notifier_block *nfb,
                            unsigned long action,
                            void *hcpu)
{
    switch ( action )
    {
    case CPU_DYING:
        /* This is reverting the work done in init_maintenance_interrupt */
        release_irq(gic_hw_ops->info->maintenance_irq, NULL);
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_gic_nfb = {
    .notifier_call = cpu_gic_callback,
};

static int __init cpu_gic_notifier_init(void)
{
    register_cpu_notifier(&cpu_gic_nfb);

    return 0;
}
__initcall(cpu_gic_notifier_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
