/*
 *	Intel IO-APIC support for multi-Pentium hosts.
 *
 *	Copyright (C) 1997, 1998, 1999, 2000 Ingo Molnar, Hajnalka Szabo
 *
 *	Many thanks to Stig Venaas for trying out countless experimental
 *	patches and reporting/debugging problems patiently!
 *
 *	(c) 1999, Multiple IO-APIC support, developed by
 *	Ken-ichi Yaku <yaku@css1.kbnes.nec.co.jp> and
 *      Hidemi Kishimoto <kisimoto@css1.kbnes.nec.co.jp>,
 *	further tested and cleaned up by Zach Brown <zab@redhat.com>
 *	and Ingo Molnar <mingo@redhat.com>
 *
 *	Fixes
 *	Maciej W. Rozycki	:	Bits for genuine 82489DX APICs;
 *					thanks to Eric Gilmore
 *					and Rolf G. Tews
 *					for testing these extensively
 *	Paul Diefenbaugh	:	Added full ACPI support
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/sched.h>
#include <xen/acpi.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/keyhandler.h>
#include <asm/mc146818rtc.h>
#include <asm/smp.h>
#include <asm/desc.h>
#include <asm/msi.h>
#include <mach_apic.h>
#include <io_ports.h>
#include <public/physdev.h>

/* Different to Linux: our implementation can be simpler. */
#define make_8259A_irq(irq) (io_apic_irqs &= ~(1<<(irq)))

int (*ioapic_renumber_irq)(int ioapic, int irq);
atomic_t irq_mis_count;

/* Where if anywhere is the i8259 connect in external int mode */
static struct { int pin, apic; } ioapic_i8259 = { -1, -1 };

static DEFINE_SPINLOCK(ioapic_lock);

int skip_ioapic_setup;

#ifndef sis_apic_bug
/*
 * Is the SiS APIC rmw bug present?
 * -1 = don't know, 0 = no, 1 = yes
 */
int sis_apic_bug = -1;
#endif

/*
 * # of IRQ routing registers
 */
int nr_ioapic_registers[MAX_IO_APICS];

int disable_timer_pin_1 __initdata;

/*
 * Rough estimation of how many shared IRQs there are, can
 * be changed anytime.
 */
#define MAX_PLUS_SHARED_IRQS nr_irqs_gsi
#define PIN_MAP_SIZE (MAX_PLUS_SHARED_IRQS + nr_irqs_gsi)

/*
 * This is performance-critical, we want to do it O(1)
 *
 * the indexing order of this array favors 1:1 mappings
 * between pins and IRQs.
 */

static struct irq_pin_list {
    int apic, pin;
    unsigned int next;
} *irq_2_pin;

static unsigned int irq_2_pin_free_entry;

/*
 * The common case is 1:1 IRQ<->pin mappings. Sometimes there are
 * shared ISA-space IRQs, so we have to support them. We are super
 * fast in the common case, and fast for shared ISA-space IRQs.
 */
static void add_pin_to_irq(unsigned int irq, int apic, int pin)
{
    struct irq_pin_list *entry = irq_2_pin + irq;

    while (entry->next) {
        BUG_ON((entry->apic == apic) && (entry->pin == pin));
        entry = irq_2_pin + entry->next;
    }
    
    BUG_ON((entry->apic == apic) && (entry->pin == pin));

    if (entry->pin != -1) {
        if (irq_2_pin_free_entry >= PIN_MAP_SIZE)
            panic("io_apic.c: whoops");
        entry->next = irq_2_pin_free_entry;
        entry = irq_2_pin + entry->next;
        irq_2_pin_free_entry = entry->next;
        entry->next = 0;
    }
    entry->apic = apic;
    entry->pin = pin;
}

/*
 * Reroute an IRQ to a different pin.
 */
static void __init replace_pin_at_irq(unsigned int irq,
                      int oldapic, int oldpin,
                      int newapic, int newpin)
{
    struct irq_pin_list *entry = irq_2_pin + irq;

    while (1) {
        if (entry->apic == oldapic && entry->pin == oldpin) {
            entry->apic = newapic;
            entry->pin = newpin;
        }
        if (!entry->next)
            break;
        entry = irq_2_pin + entry->next;
    }
}

static void __modify_IO_APIC_irq (unsigned int irq, unsigned long enable, unsigned long disable)
{
    struct irq_pin_list *entry = irq_2_pin + irq;
    unsigned int pin, reg;

    for (;;) {
        pin = entry->pin;
        if (pin == -1)
            break;
        reg = io_apic_read(entry->apic, 0x10 + pin*2);
        reg &= ~disable;
        reg |= enable;
        io_apic_modify(entry->apic, 0x10 + pin*2, reg);
        if (!entry->next)
            break;
        entry = irq_2_pin + entry->next;
    }
}

/* mask = 1 */
static void __mask_IO_APIC_irq (unsigned int irq)
{
    __modify_IO_APIC_irq(irq, 0x00010000, 0);
}

/* mask = 0 */
static void __unmask_IO_APIC_irq (unsigned int irq)
{
    __modify_IO_APIC_irq(irq, 0, 0x00010000);
}

/* trigger = 0 */
static void __edge_IO_APIC_irq (unsigned int irq)
{
    __modify_IO_APIC_irq(irq, 0, 0x00008000);
}

/* trigger = 1 */
static void __level_IO_APIC_irq (unsigned int irq)
{
    __modify_IO_APIC_irq(irq, 0x00008000, 0);
}

static void mask_IO_APIC_irq (unsigned int irq)
{
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    __mask_IO_APIC_irq(irq);
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void unmask_IO_APIC_irq (unsigned int irq)
{
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    __unmask_IO_APIC_irq(irq);
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void clear_IO_APIC_pin(unsigned int apic, unsigned int pin)
{
    struct IO_APIC_route_entry entry;
    unsigned long flags;
    
    /* Check delivery_mode to be sure we're not clearing an SMI pin */
    spin_lock_irqsave(&ioapic_lock, flags);
    *(((int*)&entry) + 0) = io_apic_read(apic, 0x10 + 2 * pin);
    *(((int*)&entry) + 1) = io_apic_read(apic, 0x11 + 2 * pin);
    spin_unlock_irqrestore(&ioapic_lock, flags);
    if (entry.delivery_mode == dest_SMI)
        return;

    /*
     * Disable it in the IO-APIC irq-routing table:
     */
    memset(&entry, 0, sizeof(entry));
    entry.mask = 1;
    spin_lock_irqsave(&ioapic_lock, flags);
    io_apic_write(apic, 0x10 + 2 * pin, *(((int *)&entry) + 0));
    io_apic_write(apic, 0x11 + 2 * pin, *(((int *)&entry) + 1));
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void clear_IO_APIC (void)
{
    int apic, pin;

    for (apic = 0; apic < nr_ioapics; apic++)
        for (pin = 0; pin < nr_ioapic_registers[apic]; pin++)
            clear_IO_APIC_pin(apic, pin);
}

#ifdef CONFIG_SMP
fastcall void smp_irq_move_cleanup_interrupt(struct cpu_user_regs *regs)
{
    unsigned vector, me;
    struct cpu_user_regs *old_regs = set_irq_regs(regs);

    ack_APIC_irq();
    irq_enter();

    me = smp_processor_id();
    for (vector = FIRST_DYNAMIC_VECTOR; vector < NR_VECTORS; vector++) {
        unsigned int irq;
        unsigned int irr;
        struct irq_desc *desc;
        struct irq_cfg *cfg;
        irq = __get_cpu_var(vector_irq)[vector];

        if (irq == -1)
            continue;

        desc = irq_to_desc(irq);
        if (!desc)
            continue;

        cfg = desc->chip_data;
        spin_lock(&desc->lock);
        if (!cfg->move_cleanup_count)
            goto unlock;

        if (vector == cfg->vector && cpu_isset(me, cfg->domain))
            goto unlock;

        irr = apic_read(APIC_IRR + (vector / 32 * 0x10));
        /*
         * Check if the vector that needs to be cleanedup is
         * registered at the cpu's IRR. If so, then this is not
         * the best time to clean it up. Lets clean it up in the
         * next attempt by sending another IRQ_MOVE_CLEANUP_VECTOR
         * to myself.
         */
        if (irr  & (1 << (vector % 32))) {
            genapic->send_IPI_self(IRQ_MOVE_CLEANUP_VECTOR);
            goto unlock;
        }
        __get_cpu_var(vector_irq)[vector] = -1;
        cfg->move_cleanup_count--;
unlock:
        spin_unlock(&desc->lock);
    }

    irq_exit();
    set_irq_regs(old_regs);
}

static void send_cleanup_vector(struct irq_cfg *cfg)
{
    cpumask_t cleanup_mask;

    cpus_and(cleanup_mask, cfg->old_domain, cpu_online_map);
    cfg->move_cleanup_count = cpus_weight(cleanup_mask);
    genapic->send_IPI_mask(&cleanup_mask, IRQ_MOVE_CLEANUP_VECTOR);

    cfg->move_in_progress = 0;
}

void irq_complete_move(struct irq_desc **descp)
{
    struct irq_desc *desc = *descp;
    struct irq_cfg *cfg = desc->chip_data;
    unsigned vector, me;

    if (likely(!cfg->move_in_progress))
        return;

    vector = get_irq_regs()->entry_vector;
    me = smp_processor_id();

    if (vector == cfg->vector && cpumask_test_cpu(me, cfg->domain))
        send_cleanup_vector(cfg);
}

unsigned int set_desc_affinity(struct irq_desc *desc, cpumask_t mask)
{
    struct irq_cfg *cfg;
    unsigned int irq;
    int ret;
    unsigned long flags;
    cpumask_t dest_mask;

    if (!cpus_intersects(mask, cpu_online_map))
        return BAD_APICID;

    irq = desc->irq;
    cfg = desc->chip_data;

    local_irq_save(flags);
    lock_vector_lock();
    ret = __assign_irq_vector(irq, cfg, mask);
    unlock_vector_lock();
    local_irq_restore(flags);

    if (ret < 0)
        return BAD_APICID;

    cpus_copy(desc->affinity, mask);
    cpus_and(dest_mask, desc->affinity, cfg->domain);

    return cpu_mask_to_apicid(dest_mask);
}

static void
set_ioapic_affinity_irq_desc(struct irq_desc *desc,
                                        const struct cpumask mask)
{
    unsigned long flags;
    unsigned int dest;
    int pin, irq;
    struct irq_cfg *cfg;
    struct irq_pin_list *entry;

    irq = desc->irq;
    cfg = desc->chip_data;

    spin_lock_irqsave(&ioapic_lock, flags);
    dest = set_desc_affinity(desc, mask);
    if (dest != BAD_APICID) {
        if ( !x2apic_enabled )
            dest = SET_APIC_LOGICAL_ID(dest);
        entry = irq_2_pin + irq;
        for (;;) {
            unsigned int data;
            pin = entry->pin;
            if (pin == -1)
                break;

            io_apic_write(entry->apic, 0x10 + 1 + pin*2, dest);
            data = io_apic_read(entry->apic, 0x10 + pin*2);
            data &= ~IO_APIC_REDIR_VECTOR_MASK;
            data |= cfg->vector & 0xFF;
            io_apic_modify(entry->apic, 0x10 + pin*2, data);

            if (!entry->next)
                break;
            entry = irq_2_pin + entry->next;
        }
    }
    spin_unlock_irqrestore(&ioapic_lock, flags);

}

static void
set_ioapic_affinity_irq(unsigned int irq, const struct cpumask mask)
{
    struct irq_desc *desc;

    desc = irq_to_desc(irq);

    set_ioapic_affinity_irq_desc(desc, mask);
}
#endif /* CONFIG_SMP */

/*
 * Find the IRQ entry number of a certain pin.
 */
static int find_irq_entry(int apic, int pin, int type)
{
    int i;

    for (i = 0; i < mp_irq_entries; i++)
        if (mp_irqs[i].mpc_irqtype == type &&
            (mp_irqs[i].mpc_dstapic == mp_ioapics[apic].mpc_apicid ||
             mp_irqs[i].mpc_dstapic == MP_APIC_ALL) &&
            mp_irqs[i].mpc_dstirq == pin)
            return i;

    return -1;
}

/*
 * Find the pin to which IRQ[irq] (ISA) is connected
 */
static int __init find_isa_irq_pin(int irq, int type)
{
    int i;

    for (i = 0; i < mp_irq_entries; i++) {
        int lbus = mp_irqs[i].mpc_srcbus;

        if ((mp_bus_id_to_type[lbus] == MP_BUS_ISA ||
             mp_bus_id_to_type[lbus] == MP_BUS_EISA ||
             mp_bus_id_to_type[lbus] == MP_BUS_MCA ||
             mp_bus_id_to_type[lbus] == MP_BUS_NEC98
            ) &&
            (mp_irqs[i].mpc_irqtype == type) &&
            (mp_irqs[i].mpc_srcbusirq == irq))

            return mp_irqs[i].mpc_dstirq;
    }
    return -1;
}

static int __init find_isa_irq_apic(int irq, int type)
{
    int i;

    for (i = 0; i < mp_irq_entries; i++) {
        int lbus = mp_irqs[i].mpc_srcbus;

        if ((mp_bus_id_to_type[lbus] == MP_BUS_ISA ||
             mp_bus_id_to_type[lbus] == MP_BUS_EISA ||
             mp_bus_id_to_type[lbus] == MP_BUS_MCA ||
             mp_bus_id_to_type[lbus] == MP_BUS_NEC98
            ) &&
            (mp_irqs[i].mpc_irqtype == type) &&
            (mp_irqs[i].mpc_srcbusirq == irq))
            break;
    }
    if (i < mp_irq_entries) {
        int apic;
        for(apic = 0; apic < nr_ioapics; apic++) {
            if (mp_ioapics[apic].mpc_apicid == mp_irqs[i].mpc_dstapic)
                return apic;
        }
    }

    return -1;
}

/*
 * Find a specific PCI IRQ entry.
 * Not an __init, possibly needed by modules
 */
static int pin_2_irq(int idx, int apic, int pin);

/*
 * This function currently is only a helper for the i386 smp boot process where 
 * we need to reprogram the ioredtbls to cater for the cpus which have come online
 * so mask in all cases should simply be TARGET_CPUS
 */
#ifdef CONFIG_SMP
void /*__init*/ setup_ioapic_dest(void)
{
    int pin, ioapic, irq, irq_entry;
    struct irq_cfg *cfg;

    if (skip_ioapic_setup == 1)
        return;

    for (ioapic = 0; ioapic < nr_ioapics; ioapic++) {
        for (pin = 0; pin < nr_ioapic_registers[ioapic]; pin++) {
            irq_entry = find_irq_entry(ioapic, pin, mp_INT);
            if (irq_entry == -1)
                continue;
            irq = pin_2_irq(irq_entry, ioapic, pin);
            cfg = irq_cfg(irq);
            BUG_ON(cpus_empty(cfg->domain));
            set_ioapic_affinity_irq(irq, cfg->domain);
        }

    }
}
#endif

/*
 * EISA Edge/Level control register, ELCR
 */
static int EISA_ELCR(unsigned int irq)
{
    if (irq < 16) {
        unsigned int port = 0x4d0 + (irq >> 3);
        return (inb(port) >> (irq & 7)) & 1;
    }
    apic_printk(APIC_VERBOSE, KERN_INFO
                "Broken MPtable reports ISA irq %d\n", irq);
    return 0;
}

/* EISA interrupts are always polarity zero and can be edge or level
 * trigger depending on the ELCR value.  If an interrupt is listed as
 * EISA conforming in the MP table, that means its trigger type must
 * be read in from the ELCR */

#define default_EISA_trigger(idx)    (EISA_ELCR(mp_irqs[idx].mpc_srcbusirq))
#define default_EISA_polarity(idx)	(0)

/* ISA interrupts are always polarity zero edge triggered,
 * when listed as conforming in the MP table. */

#define default_ISA_trigger(idx)	(0)
#define default_ISA_polarity(idx)	(0)

/* PCI interrupts are always polarity one level triggered,
 * when listed as conforming in the MP table. */

#define default_PCI_trigger(idx)	(1)
#define default_PCI_polarity(idx)	(1)

/* MCA interrupts are always polarity zero level triggered,
 * when listed as conforming in the MP table. */

#define default_MCA_trigger(idx)	(1)
#define default_MCA_polarity(idx)	(0)

/* NEC98 interrupts are always polarity zero edge triggered,
 * when listed as conforming in the MP table. */

#define default_NEC98_trigger(idx)     (0)
#define default_NEC98_polarity(idx)    (0)

static int __init MPBIOS_polarity(int idx)
{
    int bus = mp_irqs[idx].mpc_srcbus;
    int polarity;

    /*
     * Determine IRQ line polarity (high active or low active):
     */
    switch (mp_irqs[idx].mpc_irqflag & 3)
    {
    case 0: /* conforms, ie. bus-type dependent polarity */
    {
        switch (mp_bus_id_to_type[bus])
        {
        case MP_BUS_ISA: /* ISA pin */
        {
            polarity = default_ISA_polarity(idx);
            break;
        }
        case MP_BUS_EISA: /* EISA pin */
        {
            polarity = default_EISA_polarity(idx);
            break;
        }
        case MP_BUS_PCI: /* PCI pin */
        {
            polarity = default_PCI_polarity(idx);
            break;
        }
        case MP_BUS_MCA: /* MCA pin */
        {
            polarity = default_MCA_polarity(idx);
            break;
        }
        case MP_BUS_NEC98: /* NEC 98 pin */
        {
            polarity = default_NEC98_polarity(idx);
            break;
        }
        default:
        {
            printk(KERN_WARNING "broken BIOS!!\n");
            polarity = 1;
            break;
        }
        }
        break;
    }
    case 1: /* high active */
    {
        polarity = 0;
        break;
    }
    case 2: /* reserved */
    {
        printk(KERN_WARNING "broken BIOS!!\n");
        polarity = 1;
        break;
    }
    case 3: /* low active */
    {
        polarity = 1;
        break;
    }
    default: /* invalid */
    {
        printk(KERN_WARNING "broken BIOS!!\n");
        polarity = 1;
        break;
    }
    }
    return polarity;
}

static int MPBIOS_trigger(int idx)
{
    int bus = mp_irqs[idx].mpc_srcbus;
    int trigger;

    /*
     * Determine IRQ trigger mode (edge or level sensitive):
     */
    switch ((mp_irqs[idx].mpc_irqflag>>2) & 3)
    {
    case 0: /* conforms, ie. bus-type dependent */
    {
        switch (mp_bus_id_to_type[bus])
        {
        case MP_BUS_ISA: /* ISA pin */
        {
            trigger = default_ISA_trigger(idx);
            break;
        }
        case MP_BUS_EISA: /* EISA pin */
        {
            trigger = default_EISA_trigger(idx);
            break;
        }
        case MP_BUS_PCI: /* PCI pin */
        {
            trigger = default_PCI_trigger(idx);
            break;
        }
        case MP_BUS_MCA: /* MCA pin */
        {
            trigger = default_MCA_trigger(idx);
            break;
        }
        case MP_BUS_NEC98: /* NEC 98 pin */
        {
            trigger = default_NEC98_trigger(idx);
            break;
        }
        default:
        {
            printk(KERN_WARNING "broken BIOS!!\n");
            trigger = 1;
            break;
        }
        }
        break;
    }
    case 1: /* edge */
    {
        trigger = 0;
        break;
    }
    case 2: /* reserved */
    {
        printk(KERN_WARNING "broken BIOS!!\n");
        trigger = 1;
        break;
    }
    case 3: /* level */
    {
        trigger = 1;
        break;
    }
    default: /* invalid */
    {
        printk(KERN_WARNING "broken BIOS!!\n");
        trigger = 0;
        break;
    }
    }
    return trigger;
}

static inline int irq_polarity(int idx)
{
    return MPBIOS_polarity(idx);
}

static inline int irq_trigger(int idx)
{
    return MPBIOS_trigger(idx);
}

static int pin_2_irq(int idx, int apic, int pin)
{
    int irq, i;
    int bus = mp_irqs[idx].mpc_srcbus;

    /*
     * Debugging check, we are in big trouble if this message pops up!
     */
    if (mp_irqs[idx].mpc_dstirq != pin)
        printk(KERN_ERR "broken BIOS or MPTABLE parser, ayiee!!\n");

    switch (mp_bus_id_to_type[bus])
    {
    case MP_BUS_ISA: /* ISA pin */
    case MP_BUS_EISA:
    case MP_BUS_MCA:
    case MP_BUS_NEC98:
    {
        irq = mp_irqs[idx].mpc_srcbusirq;
        break;
    }
    case MP_BUS_PCI: /* PCI pin */
    {
        /*
         * PCI IRQs are mapped in order
         */
        i = irq = 0;
        while (i < apic)
            irq += nr_ioapic_registers[i++];
        irq += pin;

        /*
         * For MPS mode, so far only needed by ES7000 platform
         */
        if (ioapic_renumber_irq)
            irq = ioapic_renumber_irq(apic, irq);

        break;
    }
    default:
    {
        printk(KERN_ERR "unknown bus type %d.\n",bus);
        irq = 0;
        break;
    }
    }

    return irq;
}

static inline int IO_APIC_irq_trigger(int irq)
{
    int apic, idx, pin;

    for (apic = 0; apic < nr_ioapics; apic++) {
        for (pin = 0; pin < nr_ioapic_registers[apic]; pin++) {
            idx = find_irq_entry(apic,pin,mp_INT);
            if ((idx != -1) && (irq == pin_2_irq(idx,apic,pin)))
                return irq_trigger(idx);
        }
    }
    /*
     * nonexistent IRQs are edge default
     */
    return 0;
}

static struct hw_interrupt_type ioapic_level_type;
static struct hw_interrupt_type ioapic_edge_type;

#define IOAPIC_AUTO	-1
#define IOAPIC_EDGE	0
#define IOAPIC_LEVEL	1

#define SET_DEST(x, y, value) \
    do { if ( x2apic_enabled ) x = value; else y = value; } while(0)

static inline void ioapic_register_intr(int irq, unsigned long trigger)
{
    if ((trigger == IOAPIC_AUTO && IO_APIC_irq_trigger(irq)) ||
        trigger == IOAPIC_LEVEL)
        irq_desc[irq].handler = &ioapic_level_type;
    else
        irq_desc[irq].handler = &ioapic_edge_type;
}

static void __init setup_IO_APIC_irqs(void)
{
    struct IO_APIC_route_entry entry;
    int apic, pin, idx, irq, first_notcon = 1, vector;
    unsigned long flags;
    struct irq_cfg *cfg;

    apic_printk(APIC_VERBOSE, KERN_DEBUG "init IO_APIC IRQs\n");

    for (apic = 0; apic < nr_ioapics; apic++) {
        for (pin = 0; pin < nr_ioapic_registers[apic]; pin++) {

            /*
             * add it to the IO-APIC irq-routing table:
             */
            memset(&entry,0,sizeof(entry));

            entry.delivery_mode = INT_DELIVERY_MODE;
            entry.dest_mode = INT_DEST_MODE;
            entry.mask = 0;                /* enable IRQ */

            idx = find_irq_entry(apic,pin,mp_INT);
            if (idx == -1) {
                if (first_notcon) {
                    apic_printk(APIC_VERBOSE, KERN_DEBUG
                                " IO-APIC (apicid-pin) %d-%d",
                                mp_ioapics[apic].mpc_apicid,
                                pin);
                    first_notcon = 0;
                } else
                    apic_printk(APIC_VERBOSE, ", %d-%d",
                                mp_ioapics[apic].mpc_apicid, pin);
                continue;
            }

            entry.trigger = irq_trigger(idx);
            entry.polarity = irq_polarity(idx);

            if (irq_trigger(idx)) {
                entry.trigger = 1;
                entry.mask = 1;
            }

            irq = pin_2_irq(idx, apic, pin);
            /*
             * skip adding the timer int on secondary nodes, which causes
             * a small but painful rift in the time-space continuum
             */
            if (multi_timer_check(apic, irq))
                continue;
            else
                add_pin_to_irq(irq, apic, pin);

            if (!apic && !IO_APIC_IRQ(irq))
                continue;

            if (IO_APIC_IRQ(irq)) {
                vector = assign_irq_vector(irq);
                BUG_ON(vector < 0);
                entry.vector = vector;
                ioapic_register_intr(irq, IOAPIC_AUTO);

                if (!apic && (irq < 16))
                    disable_8259A_irq(irq);
            }
            cfg = irq_cfg(irq);
            SET_DEST(entry.dest.dest32, entry.dest.logical.logical_dest,
                cpu_mask_to_apicid(cfg->domain));
            spin_lock_irqsave(&ioapic_lock, flags);
            io_apic_write(apic, 0x11+2*pin, *(((int *)&entry)+1));
            io_apic_write(apic, 0x10+2*pin, *(((int *)&entry)+0));
            set_native_irq_info(irq, TARGET_CPUS);
            spin_unlock_irqrestore(&ioapic_lock, flags);
	}
    }

    if (!first_notcon)
        apic_printk(APIC_VERBOSE, " not connected.\n");
}

/*
 * Set up the 8259A-master output pin:
 */
static void __init setup_ExtINT_IRQ0_pin(unsigned int apic, unsigned int pin, int vector)
{
    struct IO_APIC_route_entry entry;
    unsigned long flags;

    memset(&entry,0,sizeof(entry));

    disable_8259A_irq(0);

    /* mask LVT0 */
    apic_write_around(APIC_LVT0, APIC_LVT_MASKED | APIC_DM_EXTINT);

    /*
     * We use logical delivery to get the timer IRQ
     * to the first CPU.
     */
    entry.dest_mode = INT_DEST_MODE;
    entry.mask = 0;					/* unmask IRQ now */
    SET_DEST(entry.dest.dest32, entry.dest.logical.logical_dest,
        cpu_mask_to_apicid(TARGET_CPUS));
    entry.delivery_mode = INT_DELIVERY_MODE;
    entry.polarity = 0;
    entry.trigger = 0;
    entry.vector = vector;

    /*
     * The timer IRQ doesn't have to know that behind the
     * scene we have a 8259A-master in AEOI mode ...
     */
    irq_desc[0].handler = &ioapic_edge_type;

    /*
     * Add it to the IO-APIC irq-routing table:
     */
    spin_lock_irqsave(&ioapic_lock, flags);
    io_apic_write(apic, 0x11+2*pin, *(((int *)&entry)+1));
    io_apic_write(apic, 0x10+2*pin, *(((int *)&entry)+0));
    spin_unlock_irqrestore(&ioapic_lock, flags);

    enable_8259A_irq(0);
}

static inline void UNEXPECTED_IO_APIC(void)
{
}

static void /*__init*/ __print_IO_APIC(void)
{
    int apic, i;
    union IO_APIC_reg_00 reg_00;
    union IO_APIC_reg_01 reg_01;
    union IO_APIC_reg_02 reg_02;
    union IO_APIC_reg_03 reg_03;
    unsigned long flags;

    printk(KERN_DEBUG "number of MP IRQ sources: %d.\n", mp_irq_entries);
    for (i = 0; i < nr_ioapics; i++)
        printk(KERN_DEBUG "number of IO-APIC #%d registers: %d.\n",
               mp_ioapics[i].mpc_apicid, nr_ioapic_registers[i]);

    /*
     * We are a bit conservative about what we expect.  We have to
     * know about every hardware change ASAP.
     */
    printk(KERN_INFO "testing the IO APIC.......................\n");

    for (apic = 0; apic < nr_ioapics; apic++) {

	spin_lock_irqsave(&ioapic_lock, flags);
	reg_00.raw = io_apic_read(apic, 0);
	reg_01.raw = io_apic_read(apic, 1);
	if (reg_01.bits.version >= 0x10)
            reg_02.raw = io_apic_read(apic, 2);
	if (reg_01.bits.version >= 0x20)
            reg_03.raw = io_apic_read(apic, 3);
	spin_unlock_irqrestore(&ioapic_lock, flags);

	printk(KERN_DEBUG "IO APIC #%d......\n", mp_ioapics[apic].mpc_apicid);
	printk(KERN_DEBUG ".... register #00: %08X\n", reg_00.raw);
	printk(KERN_DEBUG ".......    : physical APIC id: %02X\n", reg_00.bits.ID);
	printk(KERN_DEBUG ".......    : Delivery Type: %X\n", reg_00.bits.delivery_type);
	printk(KERN_DEBUG ".......    : LTS          : %X\n", reg_00.bits.LTS);
	if (reg_00.bits.ID >= get_physical_broadcast())
            UNEXPECTED_IO_APIC();
	if (reg_00.bits.__reserved_1 || reg_00.bits.__reserved_2)
            UNEXPECTED_IO_APIC();

	printk(KERN_DEBUG ".... register #01: %08X\n", reg_01.raw);
	printk(KERN_DEBUG ".......     : max redirection entries: %04X\n", reg_01.bits.entries);
	if (	(reg_01.bits.entries != 0x0f) && /* older (Neptune) boards */
		(reg_01.bits.entries != 0x17) && /* typical ISA+PCI boards */
		(reg_01.bits.entries != 0x1b) && /* Compaq Proliant boards */
		(reg_01.bits.entries != 0x1f) && /* dual Xeon boards */
		(reg_01.bits.entries != 0x22) && /* bigger Xeon boards */
		(reg_01.bits.entries != 0x2E) &&
		(reg_01.bits.entries != 0x3F)
            )
            UNEXPECTED_IO_APIC();

	printk(KERN_DEBUG ".......     : PRQ implemented: %X\n", reg_01.bits.PRQ);
	printk(KERN_DEBUG ".......     : IO APIC version: %04X\n", reg_01.bits.version);
	if (	(reg_01.bits.version != 0x01) && /* 82489DX IO-APICs */
		(reg_01.bits.version != 0x10) && /* oldest IO-APICs */
		(reg_01.bits.version != 0x11) && /* Pentium/Pro IO-APICs */
		(reg_01.bits.version != 0x13) && /* Xeon IO-APICs */
		(reg_01.bits.version != 0x20)    /* Intel P64H (82806 AA) */
            )
            UNEXPECTED_IO_APIC();
	if (reg_01.bits.__reserved_1 || reg_01.bits.__reserved_2)
            UNEXPECTED_IO_APIC();

	/*
	 * Some Intel chipsets with IO APIC VERSION of 0x1? don't have reg_02,
	 * but the value of reg_02 is read as the previous read register
	 * value, so ignore it if reg_02 == reg_01.
	 */
	if (reg_01.bits.version >= 0x10 && reg_02.raw != reg_01.raw) {
            printk(KERN_DEBUG ".... register #02: %08X\n", reg_02.raw);
            printk(KERN_DEBUG ".......     : arbitration: %02X\n", reg_02.bits.arbitration);
            if (reg_02.bits.__reserved_1 || reg_02.bits.__reserved_2)
                UNEXPECTED_IO_APIC();
	}

	/*
	 * Some Intel chipsets with IO APIC VERSION of 0x2? don't have reg_02
	 * or reg_03, but the value of reg_0[23] is read as the previous read
	 * register value, so ignore it if reg_03 == reg_0[12].
	 */
	if (reg_01.bits.version >= 0x20 && reg_03.raw != reg_02.raw &&
	    reg_03.raw != reg_01.raw) {
            printk(KERN_DEBUG ".... register #03: %08X\n", reg_03.raw);
            printk(KERN_DEBUG ".......     : Boot DT    : %X\n", reg_03.bits.boot_DT);
            if (reg_03.bits.__reserved_1)
                UNEXPECTED_IO_APIC();
	}

	printk(KERN_DEBUG ".... IRQ redirection table:\n");

	printk(KERN_DEBUG " NR Log Phy Mask Trig IRR Pol"
               " Stat Dest Deli Vect:   \n");

	for (i = 0; i <= reg_01.bits.entries; i++) {
            struct IO_APIC_route_entry entry;

            spin_lock_irqsave(&ioapic_lock, flags);
            *(((int *)&entry)+0) = io_apic_read(apic, 0x10+i*2);
            *(((int *)&entry)+1) = io_apic_read(apic, 0x11+i*2);
            spin_unlock_irqrestore(&ioapic_lock, flags);

            printk(KERN_DEBUG " %02x %03X %02X  ",
                   i,
                   entry.dest.logical.logical_dest,
                   entry.dest.physical.physical_dest
		);

            printk("%1d    %1d    %1d   %1d   %1d    %1d    %1d    %02X\n",
                   entry.mask,
                   entry.trigger,
                   entry.irr,
                   entry.polarity,
                   entry.delivery_status,
                   entry.dest_mode,
                   entry.delivery_mode,
                   entry.vector
		);
	}
    }
    printk(KERN_INFO "Using vector-based indexing\n");
    printk(KERN_DEBUG "IRQ to pin mappings:\n");
    for (i = 0; i < nr_irqs_gsi; i++) {
        struct irq_pin_list *entry = irq_2_pin + i;
        if (entry->pin < 0)
            continue;
        printk(KERN_DEBUG "IRQ%d ", IO_APIC_VECTOR(i));
        for (;;) {
            printk("-> %d:%d", entry->apic, entry->pin);
            if (!entry->next)
                break;
            entry = irq_2_pin + entry->next;
        }
        printk("\n");
    }

    printk(KERN_INFO ".................................... done.\n");

    return;
}

void print_IO_APIC(void)
{
    if (apic_verbosity != APIC_QUIET)
        __print_IO_APIC();
}

static void _print_IO_APIC_keyhandler(unsigned char key)
{
    __print_IO_APIC();
}
static struct keyhandler print_IO_APIC_keyhandler = {
    .diagnostic = 1,
    .u.fn = _print_IO_APIC_keyhandler,
    .desc = "print ioapic info"
};

static void __init enable_IO_APIC(void)
{
    int i8259_apic, i8259_pin;
    int i, apic;
    unsigned long flags;

    /* Initialise dynamic irq_2_pin free list. */
    irq_2_pin = xmalloc_array(struct irq_pin_list, PIN_MAP_SIZE);
    memset(irq_2_pin, 0, PIN_MAP_SIZE * sizeof(*irq_2_pin));
        
    for (i = 0; i < PIN_MAP_SIZE; i++)
        irq_2_pin[i].pin = -1;
    for (i = irq_2_pin_free_entry = nr_irqs_gsi; i < PIN_MAP_SIZE; i++)
        irq_2_pin[i].next = i + 1;

    for(apic = 0; apic < nr_ioapics; apic++) {
        int pin;
        /* See if any of the pins is in ExtINT mode */
        for (pin = 0; pin < nr_ioapic_registers[apic]; pin++) {
            struct IO_APIC_route_entry entry;
            spin_lock_irqsave(&ioapic_lock, flags);
            *(((int *)&entry) + 0) = io_apic_read(apic, 0x10 + 2 * pin);
            *(((int *)&entry) + 1) = io_apic_read(apic, 0x11 + 2 * pin);
            spin_unlock_irqrestore(&ioapic_lock, flags);


            /* If the interrupt line is enabled and in ExtInt mode
             * I have found the pin where the i8259 is connected.
             */
            if ((entry.mask == 0) && (entry.delivery_mode == dest_ExtINT)) {
                ioapic_i8259.apic = apic;
                ioapic_i8259.pin  = pin;
                goto found_i8259;
            }
        }
    }
 found_i8259:
    /* Look to see what if the MP table has reported the ExtINT */
    /* If we could not find the appropriate pin by looking at the ioapic
     * the i8259 probably is not connected the ioapic but give the
     * mptable a chance anyway.
     */
    i8259_pin  = find_isa_irq_pin(0, mp_ExtINT);
    i8259_apic = find_isa_irq_apic(0, mp_ExtINT);
    /* Trust the MP table if nothing is setup in the hardware */
    if ((ioapic_i8259.pin == -1) && (i8259_pin >= 0)) {
        printk(KERN_WARNING "ExtINT not setup in hardware but reported by MP table\n");
        ioapic_i8259.pin  = i8259_pin;
        ioapic_i8259.apic = i8259_apic;
    }
    /* Complain if the MP table and the hardware disagree */
    if (((ioapic_i8259.apic != i8259_apic) || (ioapic_i8259.pin != i8259_pin)) &&
        (i8259_pin >= 0) && (ioapic_i8259.pin >= 0))
    {
        printk(KERN_WARNING "ExtINT in hardware and MP table differ\n");
    }

    /*
     * Do not trust the IO-APIC being empty at bootup
     */
    clear_IO_APIC();
}

/*
 * Not an __init, needed by the reboot code
 */
void disable_IO_APIC(void)
{
    /*
     * Clear the IO-APIC before rebooting:
     */
    clear_IO_APIC();

    /*
     * If the i8259 is routed through an IOAPIC
     * Put that IOAPIC in virtual wire mode
     * so legacy interrupts can be delivered.
     */
    if (ioapic_i8259.pin != -1) {
        struct IO_APIC_route_entry entry;
        unsigned long flags;

        memset(&entry, 0, sizeof(entry));
        entry.mask            = 0; /* Enabled */
        entry.trigger         = 0; /* Edge */
        entry.irr             = 0;
        entry.polarity        = 0; /* High */
        entry.delivery_status = 0;
        entry.dest_mode       = 0; /* Physical */
        entry.delivery_mode   = dest_ExtINT; /* ExtInt */
        entry.vector          = 0;
        SET_DEST(entry.dest.dest32, entry.dest.physical.physical_dest,
            get_apic_id());

        /*
         * Add it to the IO-APIC irq-routing table:
         */
        spin_lock_irqsave(&ioapic_lock, flags);
        io_apic_write(ioapic_i8259.apic, 0x11+2*ioapic_i8259.pin,
                      *(((int *)&entry)+1));
        io_apic_write(ioapic_i8259.apic, 0x10+2*ioapic_i8259.pin,
                      *(((int *)&entry)+0));
        spin_unlock_irqrestore(&ioapic_lock, flags);
    }
    disconnect_bsp_APIC(ioapic_i8259.pin != -1);
}

/*
 * function to set the IO-APIC physical IDs based on the
 * values stored in the MPC table.
 *
 * by Matt Domsch <Matt_Domsch@dell.com>  Tue Dec 21 12:25:05 CST 1999
 */

#ifndef CONFIG_X86_NUMAQ
static void __init setup_ioapic_ids_from_mpc(void)
{
    union IO_APIC_reg_00 reg_00;
    physid_mask_t phys_id_present_map;
    int apic;
    int i;
    unsigned char old_id;
    unsigned long flags;

    /*
     * Don't check I/O APIC IDs for xAPIC systems. They have
     * no meaning without the serial APIC bus.
     */
    if (!(boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
        || APIC_XAPIC(apic_version[boot_cpu_physical_apicid]))
        return;

    /*
     * This is broken; anything with a real cpu count has to
     * circumvent this idiocy regardless.
     */
    phys_id_present_map = ioapic_phys_id_map(phys_cpu_present_map);

    /*
     * Set the IOAPIC ID to the value stored in the MPC table.
     */
    for (apic = 0; apic < nr_ioapics; apic++) {

        /* Read the register 0 value */
        spin_lock_irqsave(&ioapic_lock, flags);
        reg_00.raw = io_apic_read(apic, 0);
        spin_unlock_irqrestore(&ioapic_lock, flags);
		
        old_id = mp_ioapics[apic].mpc_apicid;

        if (mp_ioapics[apic].mpc_apicid >= get_physical_broadcast()) {
            printk(KERN_ERR "BIOS bug, IO-APIC#%d ID is %d in the MPC table!...\n",
                   apic, mp_ioapics[apic].mpc_apicid);
            printk(KERN_ERR "... fixing up to %d. (tell your hw vendor)\n",
                   reg_00.bits.ID);
            mp_ioapics[apic].mpc_apicid = reg_00.bits.ID;
        }

        /*
         * Sanity check, is the ID really free? Every APIC in a
         * system must have a unique ID or we get lots of nice
         * 'stuck on smp_invalidate_needed IPI wait' messages.
         */
        if (check_apicid_used(phys_id_present_map,
                              mp_ioapics[apic].mpc_apicid)) {
            printk(KERN_ERR "BIOS bug, IO-APIC#%d ID %d is already used!...\n",
                   apic, mp_ioapics[apic].mpc_apicid);
            for (i = 0; i < get_physical_broadcast(); i++)
                if (!physid_isset(i, phys_id_present_map))
                    break;
            if (i >= get_physical_broadcast())
                panic("Max APIC ID exceeded!\n");
            printk(KERN_ERR "... fixing up to %d. (tell your hw vendor)\n",
                   i);
            physid_set(i, phys_id_present_map);
            mp_ioapics[apic].mpc_apicid = i;
        } else {
            physid_mask_t tmp;
            tmp = apicid_to_cpu_present(mp_ioapics[apic].mpc_apicid);
            apic_printk(APIC_VERBOSE, "Setting %d in the "
                        "phys_id_present_map\n",
                        mp_ioapics[apic].mpc_apicid);
            physids_or(phys_id_present_map, phys_id_present_map, tmp);
        }


        /*
         * We need to adjust the IRQ routing table
         * if the ID changed.
         */
        if (old_id != mp_ioapics[apic].mpc_apicid)
            for (i = 0; i < mp_irq_entries; i++)
                if (mp_irqs[i].mpc_dstapic == old_id)
                    mp_irqs[i].mpc_dstapic
                        = mp_ioapics[apic].mpc_apicid;

        /*
         * Read the right value from the MPC table and
         * write it into the ID register.
         */
        apic_printk(APIC_VERBOSE, KERN_INFO
                    "...changing IO-APIC physical APIC ID to %d ...",
                    mp_ioapics[apic].mpc_apicid);

        reg_00.bits.ID = mp_ioapics[apic].mpc_apicid;
        spin_lock_irqsave(&ioapic_lock, flags);
        io_apic_write(apic, 0, reg_00.raw);
        spin_unlock_irqrestore(&ioapic_lock, flags);

        /*
         * Sanity check
         */
        spin_lock_irqsave(&ioapic_lock, flags);
        reg_00.raw = io_apic_read(apic, 0);
        spin_unlock_irqrestore(&ioapic_lock, flags);
        if (reg_00.bits.ID != mp_ioapics[apic].mpc_apicid)
            printk("could not set ID!\n");
        else
            apic_printk(APIC_VERBOSE, " ok.\n");
    }
}
#else
static void __init setup_ioapic_ids_from_mpc(void) { }
#endif

/*
 * There is a nasty bug in some older SMP boards, their mptable lies
 * about the timer IRQ. We do the following to work around the situation:
 *
 *	- timer IRQ defaults to IO-APIC IRQ
 *	- if this function detects that timer IRQs are defunct, then we fall
 *	  back to ISA timer IRQs
 */
static int __init timer_irq_works(void)
{
    extern unsigned long pit0_ticks;
    unsigned long t1, flags;

    t1 = pit0_ticks;
    mb();

    local_save_flags(flags);
    local_irq_enable();
    /* Let ten ticks pass... */
    mdelay((10 * 1000) / HZ);
    local_irq_restore(flags);

    /*
     * Expect a few ticks at least, to be sure some possible
     * glue logic does not lock up after one or two first
     * ticks in a non-ExtINT mode.  Also the local APIC
     * might have cached one ExtINT interrupt.  Finally, at
     * least one tick may be lost due to delays.
     */
    mb();
    if (pit0_ticks - t1 > 4)
        return 1;

    return 0;
}

/*
 * In the SMP+IOAPIC case it might happen that there are an unspecified
 * number of pending IRQ events unhandled. These cases are very rare,
 * so we 'resend' these IRQs via IPIs, to the same CPU. It's much
 * better to do it this way as thus we do not have to be aware of
 * 'pending' interrupts in the IRQ path, except at this point.
 */
/*
 * Edge triggered needs to resend any interrupt
 * that was delayed but this is now handled in the device
 * independent code.
 */

/*
 * Starting up a edge-triggered IO-APIC interrupt is
 * nasty - we need to make sure that we get the edge.
 * If it is already asserted for some reason, we need
 * return 1 to indicate that is was pending.
 *
 * This is not complete - we should be able to fake
 * an edge even if it isn't on the 8259A...
 */
static unsigned int startup_edge_ioapic_irq(unsigned int irq)
{
    int was_pending = 0;
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    if (irq < 16) {
        disable_8259A_irq(irq);
        if (i8259A_irq_pending(irq))
            was_pending = 1;
    }
    __unmask_IO_APIC_irq(irq);
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return was_pending;
}

/*
 * Once we have recorded IRQ_PENDING already, we can mask the
 * interrupt for real. This prevents IRQ storms from unhandled
 * devices.
 */
static void ack_edge_ioapic_irq(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);
    
    irq_complete_move(&desc);

    if ((desc->status & (IRQ_PENDING | IRQ_DISABLED))
        == (IRQ_PENDING | IRQ_DISABLED))
        mask_IO_APIC_irq(irq);
    ack_APIC_irq();
}

/*
 * Level triggered interrupts can just be masked,
 * and shutting down and starting up the interrupt
 * is the same as enabling and disabling them -- except
 * with a startup need to return a "was pending" value.
 *
 * Level triggered interrupts are special because we
 * do not touch any IO-APIC register while handling
 * them. We ack the APIC in the end-IRQ handler, not
 * in the start-IRQ-handler. Protection against reentrance
 * from the same interrupt is still provided, both by the
 * generic IRQ layer and by the fact that an unacked local
 * APIC does not accept IRQs.
 */
static unsigned int startup_level_ioapic_irq (unsigned int irq)
{
    unmask_IO_APIC_irq(irq);

    return 0; /* don't check for pending */
}

int ioapic_ack_new = 1;
static void setup_ioapic_ack(char *s)
{
    if ( !strcmp(s, "old") )
        ioapic_ack_new = 0;
    else if ( !strcmp(s, "new") )
        ioapic_ack_new = 1;
    else
        printk("Unknown ioapic_ack value specified: '%s'\n", s);
}
custom_param("ioapic_ack", setup_ioapic_ack);

static void mask_and_ack_level_ioapic_irq (unsigned int irq)
{
    unsigned long v;
    int i;
    struct irq_desc *desc = irq_to_desc(irq);

    irq_complete_move(&desc);

    if ( ioapic_ack_new )
        return;

    mask_IO_APIC_irq(irq);

/*
 * It appears there is an erratum which affects at least version 0x11
 * of I/O APIC (that's the 82093AA and cores integrated into various
 * chipsets).  Under certain conditions a level-triggered interrupt is
 * erroneously delivered as edge-triggered one but the respective IRR
 * bit gets set nevertheless.  As a result the I/O unit expects an EOI
 * message but it will never arrive and further interrupts are blocked
 * from the source.  The exact reason is so far unknown, but the
 * phenomenon was observed when two consecutive interrupt requests
 * from a given source get delivered to the same CPU and the source is
 * temporarily disabled in between.
 *
 * A workaround is to simulate an EOI message manually.  We achieve it
 * by setting the trigger mode to edge and then to level when the edge
 * trigger mode gets detected in the TMR of a local APIC for a
 * level-triggered interrupt.  We mask the source for the time of the
 * operation to prevent an edge-triggered interrupt escaping meanwhile.
 * The idea is from Manfred Spraul.  --macro
 */
    i = IO_APIC_VECTOR(irq);

    v = apic_read(APIC_TMR + ((i & ~0x1f) >> 1));

    ack_APIC_irq();

    if (!(v & (1 << (i & 0x1f)))) {
        atomic_inc(&irq_mis_count);
        spin_lock(&ioapic_lock);
        __edge_IO_APIC_irq(irq);
        __level_IO_APIC_irq(irq);
        spin_unlock(&ioapic_lock);
    }
}

static void end_level_ioapic_irq (unsigned int irq)
{
    unsigned long v;
    int i;

    if ( !ioapic_ack_new )
    {
        if ( !(irq_desc[irq].status & IRQ_DISABLED) )
            unmask_IO_APIC_irq(irq);
        return;
    }

/*
 * It appears there is an erratum which affects at least version 0x11
 * of I/O APIC (that's the 82093AA and cores integrated into various
 * chipsets).  Under certain conditions a level-triggered interrupt is
 * erroneously delivered as edge-triggered one but the respective IRR
 * bit gets set nevertheless.  As a result the I/O unit expects an EOI
 * message but it will never arrive and further interrupts are blocked
 * from the source.  The exact reason is so far unknown, but the
 * phenomenon was observed when two consecutive interrupt requests
 * from a given source get delivered to the same CPU and the source is
 * temporarily disabled in between.
 *
 * A workaround is to simulate an EOI message manually.  We achieve it
 * by setting the trigger mode to edge and then to level when the edge
 * trigger mode gets detected in the TMR of a local APIC for a
 * level-triggered interrupt.  We mask the source for the time of the
 * operation to prevent an edge-triggered interrupt escaping meanwhile.
 * The idea is from Manfred Spraul.  --macro
 */
    i = IO_APIC_VECTOR(irq);

    v = apic_read(APIC_TMR + ((i & ~0x1f) >> 1));

    ack_APIC_irq();

    if (!(v & (1 << (i & 0x1f)))) {
        atomic_inc(&irq_mis_count);
        spin_lock(&ioapic_lock);
        __mask_IO_APIC_irq(irq);
        __edge_IO_APIC_irq(irq);
        __level_IO_APIC_irq(irq);
        if ( !(irq_desc[irq].status & IRQ_DISABLED) )
            __unmask_IO_APIC_irq(irq);
        spin_unlock(&ioapic_lock);
    }
}

static void disable_edge_ioapic_irq(unsigned int irq)
{
}

static void end_edge_ioapic_irq(unsigned int irq)
 {
 }

/*
 * Level and edge triggered IO-APIC interrupts need different handling,
 * so we use two separate IRQ descriptors. Edge triggered IRQs can be
 * handled with the level-triggered descriptor, but that one has slightly
 * more overhead. Level-triggered interrupts cannot be handled with the
 * edge-triggered handler, without risking IRQ storms and other ugly
 * races.
 */
static struct hw_interrupt_type ioapic_edge_type = {
    .typename 	= "IO-APIC-edge",
    .startup 	= startup_edge_ioapic_irq,
    .shutdown 	= disable_edge_ioapic_irq,
    .enable 	= unmask_IO_APIC_irq,
    .disable 	= disable_edge_ioapic_irq,
    .ack 		= ack_edge_ioapic_irq,
    .end 		= end_edge_ioapic_irq,
    .set_affinity 	= set_ioapic_affinity_irq,
};

static struct hw_interrupt_type ioapic_level_type = {
    .typename 	= "IO-APIC-level",
    .startup 	= startup_level_ioapic_irq,
    .shutdown 	= mask_IO_APIC_irq,
    .enable 	= unmask_IO_APIC_irq,
    .disable 	= mask_IO_APIC_irq,
    .ack 		= mask_and_ack_level_ioapic_irq,
    .end 		= end_level_ioapic_irq,
    .set_affinity 	= set_ioapic_affinity_irq,
};

static unsigned int startup_msi_irq(unsigned int irq)
{
    unmask_msi_irq(irq);
    return 0;
}

static void ack_msi_irq(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);

    irq_complete_move(&desc);

    if ( msi_maskable_irq(desc->msi_desc) )
        ack_APIC_irq(); /* ACKTYPE_NONE */
}

static void end_msi_irq(unsigned int irq)
{
    if ( !msi_maskable_irq(irq_desc[irq].msi_desc) )
        ack_APIC_irq(); /* ACKTYPE_EOI */
}

static void shutdown_msi_irq(unsigned int irq)
{
    mask_msi_irq(irq);
}

static void set_msi_affinity_irq(unsigned int irq, cpumask_t cpu_mask)
{
    set_msi_affinity(irq, cpu_mask);
}

/*
 * IRQ Chip for MSI PCI/PCI-X/PCI-Express Devices,
 * which implement the MSI or MSI-X Capability Structure.
 */
struct hw_interrupt_type pci_msi_type = {
    .typename   = "PCI-MSI",
    .startup    = startup_msi_irq,
    .shutdown   = shutdown_msi_irq,
    .enable	    = unmask_msi_irq,
    .disable    = mask_msi_irq,
    .ack        = ack_msi_irq,
    .end        = end_msi_irq,
    .set_affinity   = set_msi_affinity_irq,
};

static inline void init_IO_APIC_traps(void)
{
    int irq;
    /* Xen: This is way simpler than the Linux implementation. */
    for (irq = 0; irq < 16 ; irq++)
        if (IO_APIC_IRQ(irq) && !IO_APIC_VECTOR(irq))
            make_8259A_irq(irq);
}

static void enable_lapic_irq(unsigned int irq)
{
    unsigned long v;

    v = apic_read(APIC_LVT0);
    apic_write_around(APIC_LVT0, v & ~APIC_LVT_MASKED);
}

static void disable_lapic_irq(unsigned int irq)
{
    unsigned long v;

    v = apic_read(APIC_LVT0);
    apic_write_around(APIC_LVT0, v | APIC_LVT_MASKED);
}

static void ack_lapic_irq(unsigned int irq)
{
    ack_APIC_irq();
}

static void end_lapic_irq(unsigned int irq) { /* nothing */ }

static struct hw_interrupt_type lapic_irq_type = {
    .typename 	= "local-APIC-edge",
    .startup 	= NULL, /* startup_irq() not used for IRQ0 */
    .shutdown 	= NULL, /* shutdown_irq() not used for IRQ0 */
    .enable 	= enable_lapic_irq,
    .disable 	= disable_lapic_irq,
    .ack 		= ack_lapic_irq,
    .end 		= end_lapic_irq,
};

/*
 * This looks a bit hackish but it's about the only one way of sending
 * a few INTA cycles to 8259As and any associated glue logic.  ICR does
 * not support the ExtINT mode, unfortunately.  We need to send these
 * cycles as some i82489DX-based boards have glue logic that keeps the
 * 8259A interrupt line asserted until INTA.  --macro
 */
static inline void unlock_ExtINT_logic(void)
{
    int apic, pin, i;
    struct IO_APIC_route_entry entry0, entry1;
    unsigned char save_control, save_freq_select;
    unsigned long flags;

    pin = find_isa_irq_pin(8, mp_INT);
    apic = find_isa_irq_apic(8, mp_INT);
    if (pin == -1)
        return;

    spin_lock_irqsave(&ioapic_lock, flags);
    *(((int *)&entry0) + 1) = io_apic_read(apic, 0x11 + 2 * pin);
    *(((int *)&entry0) + 0) = io_apic_read(apic, 0x10 + 2 * pin);
    spin_unlock_irqrestore(&ioapic_lock, flags);
    clear_IO_APIC_pin(apic, pin);

    memset(&entry1, 0, sizeof(entry1));

    entry1.dest_mode = 0;			/* physical delivery */
    entry1.mask = 0;			/* unmask IRQ now */
    SET_DEST(entry1.dest.dest32, entry1.dest.physical.physical_dest,
        hard_smp_processor_id());
    entry1.delivery_mode = dest_ExtINT;
    entry1.polarity = entry0.polarity;
    entry1.trigger = 0;
    entry1.vector = 0;

    spin_lock_irqsave(&ioapic_lock, flags);
    io_apic_write(apic, 0x11 + 2 * pin, *(((int *)&entry1) + 1));
    io_apic_write(apic, 0x10 + 2 * pin, *(((int *)&entry1) + 0));
    spin_unlock_irqrestore(&ioapic_lock, flags);

    save_control = CMOS_READ(RTC_CONTROL);
    save_freq_select = CMOS_READ(RTC_FREQ_SELECT);
    CMOS_WRITE((save_freq_select & ~RTC_RATE_SELECT) | 0x6,
               RTC_FREQ_SELECT);
    CMOS_WRITE(save_control | RTC_PIE, RTC_CONTROL);

    i = 100;
    while (i-- > 0) {
        mdelay(10);
        if ((CMOS_READ(RTC_INTR_FLAGS) & RTC_PF) == RTC_PF)
            i -= 10;
    }

    CMOS_WRITE(save_control, RTC_CONTROL);
    CMOS_WRITE(save_freq_select, RTC_FREQ_SELECT);
    clear_IO_APIC_pin(apic, pin);

    spin_lock_irqsave(&ioapic_lock, flags);
    io_apic_write(apic, 0x11 + 2 * pin, *(((int *)&entry0) + 1));
    io_apic_write(apic, 0x10 + 2 * pin, *(((int *)&entry0) + 0));
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

int timer_uses_ioapic_pin_0;

/*
 * This code may look a bit paranoid, but it's supposed to cooperate with
 * a wide range of boards and BIOS bugs.  Fortunately only the timer IRQ
 * is so screwy.  Thanks to Brian Perkins for testing/hacking this beast
 * fanatically on his truly buggy board.
 */
static inline void check_timer(void)
{
    int apic1, pin1, apic2, pin2;
    int vector, ret;
    unsigned long flags;

    local_irq_save(flags);

    /*
     * get/set the timer IRQ vector:
     */
    disable_8259A_irq(0);
    vector = FIRST_HIPRIORITY_VECTOR;
    clear_irq_vector(0);

    if ((ret = bind_irq_vector(0, vector, (cpumask_t)CPU_MASK_ALL)))
        printk(KERN_ERR"..IRQ0 is not set correctly with ioapic!!!, err:%d\n", ret);
    
    irq_desc[0].depth  = 0;
    irq_desc[0].status &= ~IRQ_DISABLED;
    irq_desc[0].handler = &ioapic_edge_type;

    /*
     * Subtle, code in do_timer_interrupt() expects an AEOI
     * mode for the 8259A whenever interrupts are routed
     * through I/O APICs.  Also IRQ0 has to be enabled in
     * the 8259A which implies the virtual wire has to be
     * disabled in the local APIC.
     */
    apic_write_around(APIC_LVT0, APIC_LVT_MASKED | APIC_DM_EXTINT);
    init_8259A(1);
    /* XEN: Ripped out the legacy missed-tick logic, so below is not needed. */
    /*timer_ack = 1;*/
    /*enable_8259A_irq(0);*/

    pin1  = find_isa_irq_pin(0, mp_INT);
    apic1 = find_isa_irq_apic(0, mp_INT);
    pin2  = ioapic_i8259.pin;
    apic2 = ioapic_i8259.apic;

    if (pin1 == 0)
        timer_uses_ioapic_pin_0 = 1;

    printk(KERN_INFO "..TIMER: vector=0x%02X apic1=%d pin1=%d apic2=%d pin2=%d\n",
           vector, apic1, pin1, apic2, pin2);

    if (pin1 != -1) {
        /*
         * Ok, does IRQ0 through the IOAPIC work?
         */
        unmask_IO_APIC_irq(0);
        if (timer_irq_works()) {
            local_irq_restore(flags);
            if (disable_timer_pin_1 > 0)
                clear_IO_APIC_pin(apic1, pin1);
            return;
        }
        clear_IO_APIC_pin(apic1, pin1);
        printk(KERN_ERR "..MP-BIOS bug: 8254 timer not connected to "
               "IO-APIC\n");
    }

    printk(KERN_INFO "...trying to set up timer (IRQ0) through the 8259A ... ");
    if (pin2 != -1) {
        printk("\n..... (found pin %d) ...", pin2);
        /*
         * legacy devices should be connected to IO APIC #0
         */
        setup_ExtINT_IRQ0_pin(apic2, pin2, vector);
        if (timer_irq_works()) {
            local_irq_restore(flags);
            printk("works.\n");
            if (pin1 != -1)
                replace_pin_at_irq(0, apic1, pin1, apic2, pin2);
            else
                add_pin_to_irq(0, apic2, pin2);
            return;
        }
        /*
         * Cleanup, just in case ...
         */
        clear_IO_APIC_pin(apic2, pin2);
    }
    printk(" failed.\n");

    if (nmi_watchdog == NMI_IO_APIC) {
        printk(KERN_WARNING "timer doesn't work through the IO-APIC - disabling NMI Watchdog!\n");
        nmi_watchdog = 0;
    }

    printk(KERN_INFO "...trying to set up timer as Virtual Wire IRQ...");

    disable_8259A_irq(0);
    irq_desc[0].handler = &lapic_irq_type;
    apic_write_around(APIC_LVT0, APIC_DM_FIXED | vector);	/* Fixed mode */
    enable_8259A_irq(0);

    if (timer_irq_works()) {
        local_irq_restore(flags);
        printk(" works.\n");
        return;
    }
    apic_write_around(APIC_LVT0, APIC_LVT_MASKED | APIC_DM_FIXED | vector);
    printk(" failed.\n");

    printk(KERN_INFO "...trying to set up timer as ExtINT IRQ...");

    /*timer_ack = 0;*/
    init_8259A(0);
    make_8259A_irq(0);
    apic_write_around(APIC_LVT0, APIC_DM_EXTINT);

    unlock_ExtINT_logic();

    local_irq_restore(flags);

    if (timer_irq_works()) {
        printk(" works.\n");
        return;
    }
    printk(" failed :(.\n");
    panic("IO-APIC + timer doesn't work!  Boot with apic=debug and send a "
          "report.  Then try booting with the 'noapic' option");
}

/*
 *
 * IRQ's that are handled by the PIC in the MPS IOAPIC case.
 * - IRQ2 is the cascade IRQ, and cannot be a io-apic IRQ.
 *   Linux doesn't really care, as it's not actually used
 *   for any interrupt handling anyway.
 */
#define PIC_IRQS	(1 << PIC_CASCADE_IR)

static struct IO_APIC_route_entry *ioapic_pm_state;

static void __init ioapic_pm_state_alloc(void)
{
    int i, nr_entry = 0;

    for (i = 0; i < nr_ioapics; i++)
        nr_entry += nr_ioapic_registers[i];

    ioapic_pm_state = _xmalloc(sizeof(struct IO_APIC_route_entry)*nr_entry,
                               sizeof(struct IO_APIC_route_entry));
    BUG_ON(ioapic_pm_state == NULL);
}

void __init setup_IO_APIC(void)
{
    enable_IO_APIC();

    if (acpi_ioapic)
        io_apic_irqs = ~0;	/* all IRQs go through IOAPIC */
    else
        io_apic_irqs = ~PIC_IRQS;

    printk("ENABLING IO-APIC IRQs\n");
    printk(" -> Using %s ACK method\n", ioapic_ack_new ? "new" : "old");

    /*
     * Set up IO-APIC IRQ routing.
     */
    if (!acpi_ioapic)
        setup_ioapic_ids_from_mpc();
    sync_Arb_IDs();
    setup_IO_APIC_irqs();
    init_IO_APIC_traps();
    check_timer();
    print_IO_APIC();
    ioapic_pm_state_alloc();

    register_keyhandler('z', &print_IO_APIC_keyhandler);
}

void ioapic_suspend(void)
{
    struct IO_APIC_route_entry *entry = ioapic_pm_state;
    unsigned long flags;
    int apic, i;

    spin_lock_irqsave(&ioapic_lock, flags);
    for (apic = 0; apic < nr_ioapics; apic++) {
        for (i = 0; i < nr_ioapic_registers[apic]; i ++, entry ++ ) {
            *(((int *)entry) + 1) = io_apic_read(apic, 0x11 + 2 * i);
            *(((int *)entry) + 0) = io_apic_read(apic, 0x10 + 2 * i);
        }
    }
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

void ioapic_resume(void)
{
    struct IO_APIC_route_entry *entry = ioapic_pm_state;
    unsigned long flags;
    union IO_APIC_reg_00 reg_00;
    int i, apic;

    spin_lock_irqsave(&ioapic_lock, flags);
    for (apic = 0; apic < nr_ioapics; apic++){
        reg_00.raw = io_apic_read(apic, 0);
        if (reg_00.bits.ID != mp_ioapics[apic].mpc_apicid) {
            reg_00.bits.ID = mp_ioapics[apic].mpc_apicid;
            io_apic_write(apic, 0, reg_00.raw);
        }
        for (i = 0; i < nr_ioapic_registers[apic]; i++, entry++) {
            io_apic_write(apic, 0x11+2*i, *(((int *)entry)+1));
            io_apic_write(apic, 0x10+2*i, *(((int *)entry)+0));
        }
    }
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

/* --------------------------------------------------------------------------
                          ACPI-based IOAPIC Configuration
   -------------------------------------------------------------------------- */

#ifdef CONFIG_ACPI_BOOT

int __init io_apic_get_unique_id (int ioapic, int apic_id)
{
    union IO_APIC_reg_00 reg_00;
    static physid_mask_t apic_id_map = PHYSID_MASK_NONE;
    physid_mask_t tmp;
    unsigned long flags;
    int i = 0;

    /*
     * The P4 platform supports up to 256 APIC IDs on two separate APIC 
     * buses (one for LAPICs, one for IOAPICs), where predecessors only 
     * supports up to 16 on one shared APIC bus.
     * 
     * TBD: Expand LAPIC/IOAPIC support on P4-class systems to take full
     *      advantage of new APIC bus architecture.
     */

    if (physids_empty(apic_id_map))
        apic_id_map = ioapic_phys_id_map(phys_cpu_present_map);

    spin_lock_irqsave(&ioapic_lock, flags);
    reg_00.raw = io_apic_read(ioapic, 0);
    spin_unlock_irqrestore(&ioapic_lock, flags);

    if (apic_id >= get_physical_broadcast()) {
        printk(KERN_WARNING "IOAPIC[%d]: Invalid apic_id %d, trying "
               "%d\n", ioapic, apic_id, reg_00.bits.ID);
        apic_id = reg_00.bits.ID;
    }

    /*
     * Every APIC in a system must have a unique ID or we get lots of nice 
     * 'stuck on smp_invalidate_needed IPI wait' messages.
     */
    if (check_apicid_used(apic_id_map, apic_id)) {

        for (i = 0; i < get_physical_broadcast(); i++) {
            if (!check_apicid_used(apic_id_map, i))
                break;
        }

        if (i == get_physical_broadcast())
            panic("Max apic_id exceeded!\n");

        printk(KERN_WARNING "IOAPIC[%d]: apic_id %d already used, "
               "trying %d\n", ioapic, apic_id, i);

        apic_id = i;
    } 

    tmp = apicid_to_cpu_present(apic_id);
    physids_or(apic_id_map, apic_id_map, tmp);

    if (reg_00.bits.ID != apic_id) {
        reg_00.bits.ID = apic_id;

        spin_lock_irqsave(&ioapic_lock, flags);
        io_apic_write(ioapic, 0, reg_00.raw);
        reg_00.raw = io_apic_read(ioapic, 0);
        spin_unlock_irqrestore(&ioapic_lock, flags);

        /* Sanity check */
        if (reg_00.bits.ID != apic_id) {
            printk("IOAPIC[%d]: Unable to change apic_id!\n", ioapic);
            return -1;
        }
    }

    apic_printk(APIC_VERBOSE, KERN_INFO
                "IOAPIC[%d]: Assigned apic_id %d\n", ioapic, apic_id);

    return apic_id;
}


int __init io_apic_get_version (int ioapic)
{
    union IO_APIC_reg_01	reg_01;
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    reg_01.raw = io_apic_read(ioapic, 1);
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return reg_01.bits.version;
}


int __init io_apic_get_redir_entries (int ioapic)
{
    union IO_APIC_reg_01	reg_01;
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    reg_01.raw = io_apic_read(ioapic, 1);
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return reg_01.bits.entries;
}


int io_apic_set_pci_routing (int ioapic, int pin, int irq, int edge_level, int active_high_low)
{
    struct IO_APIC_route_entry entry;
    unsigned long flags;
    int vector;

    if (!IO_APIC_IRQ(irq)) {
        printk(KERN_ERR "IOAPIC[%d]: Invalid reference to IRQ 0\n",
               ioapic);
        return -EINVAL;
    }

    /*
     * Generate a PCI IRQ routing entry and program the IOAPIC accordingly.
     * Note that we mask (disable) IRQs now -- these get enabled when the
     * corresponding device driver registers for this IRQ.
     */

    memset(&entry,0,sizeof(entry));

    entry.delivery_mode = INT_DELIVERY_MODE;
    entry.dest_mode = INT_DEST_MODE;
    SET_DEST(entry.dest.dest32, entry.dest.logical.logical_dest,
        cpu_mask_to_apicid(TARGET_CPUS));
    entry.trigger = edge_level;
    entry.polarity = active_high_low;
    entry.mask  = 1;

    /*
     * IRQs < 16 are already in the irq_2_pin[] map
     */
    if (irq >= 16)
        add_pin_to_irq(irq, ioapic, pin);

    vector = assign_irq_vector(irq);
    if (vector < 0)
        return vector;
    entry.vector = vector;

    apic_printk(APIC_DEBUG, KERN_DEBUG "IOAPIC[%d]: Set PCI routing entry "
		"(%d-%d -> 0x%x -> IRQ %d Mode:%i Active:%i)\n", ioapic,
		mp_ioapics[ioapic].mpc_apicid, pin, entry.vector, irq,
		edge_level, active_high_low);

    ioapic_register_intr(irq, edge_level);

    if (!ioapic && (irq < 16))
        disable_8259A_irq(irq);

    spin_lock_irqsave(&ioapic_lock, flags);
    io_apic_write(ioapic, 0x11+2*pin, *(((int *)&entry)+1));
    io_apic_write(ioapic, 0x10+2*pin, *(((int *)&entry)+0));
    set_native_irq_info(irq, TARGET_CPUS);
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return 0;
}

#endif /*CONFIG_ACPI_BOOT*/

static int ioapic_physbase_to_id(unsigned long physbase)
{
    int apic;
    for ( apic = 0; apic < nr_ioapics; apic++ )
        if ( mp_ioapics[apic].mpc_apicaddr == physbase )
            return apic;
    return -EINVAL;
}

unsigned apic_gsi_base(int apic);

static int apic_pin_2_gsi_irq(int apic, int pin)
{
    int idx, irq;

    if (apic < 0)
       return -EINVAL;

    irq = apic_gsi_base(apic) + pin;
    if (apic == 0) {
        idx = find_irq_entry(apic, pin, mp_INT);
        if (idx >= 0)
            irq = pin_2_irq(idx, apic, pin);
    }
    return irq;
}

int ioapic_guest_read(unsigned long physbase, unsigned int reg, u32 *pval)
{
    int apic;
    unsigned long flags;

    if ( (apic = ioapic_physbase_to_id(physbase)) < 0 )
        return apic;

    spin_lock_irqsave(&ioapic_lock, flags);
    *pval = io_apic_read(apic, reg);
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return 0;
}

#define WARN_BOGUS_WRITE(f, a...)                                       \
    dprintk(XENLOG_INFO, "\n%s: "                                        \
            "apic=%d, pin=%d, irq=%d\n"                 \
            "%s: new_entry=%08x\n"                      \
            "%s: " f, __FUNCTION__, apic, pin, irq,        \
            __FUNCTION__, *(u32 *)&rte,           \
            __FUNCTION__ , ##a )

int ioapic_guest_write(unsigned long physbase, unsigned int reg, u32 val)
{
    int apic, pin, irq, ret, vector, pirq;
    struct IO_APIC_route_entry rte = { 0 };
    unsigned long flags;
    struct irq_cfg *cfg;
    struct irq_desc *desc;

    if ( (apic = ioapic_physbase_to_id(physbase)) < 0 )
        return apic;

    /* Only write to the first half of a route entry. */
    if ( (reg < 0x10) || (reg & 1) )
        return 0;
    
    pin = (reg - 0x10) >> 1;

    /* Write first half from guest; second half is target info. */
    *(u32 *)&rte = val;

    /*
     * What about weird destination types?
     *  SMI:    Ignore? Ought to be set up by the BIOS.
     *  NMI:    Ignore? Watchdog functionality is Xen's concern.
     *  INIT:   Definitely ignore: probably a guest OS bug.
     *  ExtINT: Ignore? Linux only asserts this at start of day.
     * For now, print a message and return an error. We can fix up on demand.
     */
    if ( rte.delivery_mode > dest_LowestPrio )
    {
        printk("ERROR: Attempt to write weird IOAPIC destination mode!\n");
        printk("       APIC=%d/%d, lo-reg=%x\n", apic, pin, val);
        return -EINVAL;
    }

    /*
     * The guest does not know physical APIC arrangement (flat vs. cluster).
     * Apply genapic conventions for this platform.
     */
    rte.delivery_mode = INT_DELIVERY_MODE;
    rte.dest_mode     = INT_DEST_MODE;

    irq = apic_pin_2_gsi_irq(apic, pin);
    if ( irq < 0 )
        return irq;

    desc = irq_to_desc(irq);
    cfg = desc->chip_data;

    /*
     * Since PHYSDEVOP_alloc_irq_vector is dummy, rte.vector is the pirq
     * which corresponds to this ioapic pin, retrieve it for building
     * pirq and irq mapping. Where the GSI is greater than 256, we assume
     * that dom0 pirq == irq.
     */
    pirq = (irq >= 256) ? irq : rte.vector;
    if ( (pirq < 0) || (pirq >= dom0->nr_pirqs) )
        return -EINVAL;
    
    if ( desc->action )
    {
        WARN_BOGUS_WRITE("Attempt to modify IO-APIC pin for in-use IRQ!\n");
        return 0;
    }

    if ( cfg->vector <= 0 || cfg->vector > LAST_DYNAMIC_VECTOR ) {

        printk("allocated vector for irq:%d\n", irq);
        
        vector = assign_irq_vector(irq);
        if ( vector < 0 )
            return vector;

        add_pin_to_irq(irq, apic, pin);
    }
    spin_lock(&pcidevs_lock);
    spin_lock(&dom0->event_lock);
    ret = map_domain_pirq(dom0, pirq, irq,
            MAP_PIRQ_TYPE_GSI, NULL);
    spin_unlock(&dom0->event_lock);
    spin_unlock(&pcidevs_lock);
    if ( ret < 0 )
        return ret;

    spin_lock_irqsave(&ioapic_lock, flags);
    /* Set the correct irq-handling type. */
    desc->handler = rte.trigger ? 
        &ioapic_level_type: &ioapic_edge_type;

    /* Mask iff level triggered. */
    rte.mask = rte.trigger;
    /* Set the vector field to the real vector! */
    rte.vector = cfg->vector;

    SET_DEST(rte.dest.dest32, rte.dest.logical.logical_dest,
        cpu_mask_to_apicid(cfg->domain));

    io_apic_write(apic, 0x10 + 2 * pin, *(((int *)&rte) + 0));
    io_apic_write(apic, 0x11 + 2 * pin, *(((int *)&rte) + 1));
    
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return 0;
}

void dump_ioapic_irq_info(void)
{
    struct irq_pin_list *entry;
    struct IO_APIC_route_entry rte;
    unsigned int irq, pin, printed = 0;
    unsigned long flags;

    for ( irq = 0; irq < nr_irqs_gsi; irq++ )
    {
        entry = &irq_2_pin[irq];
        if ( entry->pin == -1 )
            continue;

        if ( !printed++ )
            printk("IO-APIC interrupt information:\n");

        printk("    IRQ%3d Vec%3d:\n", irq, irq_to_vector(irq));

        for ( ; ; )
        {
            pin = entry->pin;

            printk("      Apic 0x%02x, Pin %2d: ", entry->apic, pin);

            spin_lock_irqsave(&ioapic_lock, flags);
            *(((int *)&rte) + 0) = io_apic_read(entry->apic, 0x10 + 2 * pin);
            *(((int *)&rte) + 1) = io_apic_read(entry->apic, 0x11 + 2 * pin);
            spin_unlock_irqrestore(&ioapic_lock, flags);

            printk("vector=%u, delivery_mode=%u, dest_mode=%s, "
                   "delivery_status=%d, polarity=%d, irr=%d, "
                   "trigger=%s, mask=%d, dest_id:%d\n",
                   rte.vector, rte.delivery_mode,
                   rte.dest_mode ? "logical" : "physical",
                   rte.delivery_status, rte.polarity, rte.irr,
                   rte.trigger ? "level" : "edge", rte.mask,
                   rte.dest.logical.logical_dest);

            if ( entry->next == 0 )
                break;
            entry = &irq_2_pin[entry->next];
        }
    }
}

unsigned highest_gsi(void);

void __init init_ioapic_mappings(void)
{
    unsigned long ioapic_phys;
    unsigned int i, idx = FIX_IO_APIC_BASE_0;
    union IO_APIC_reg_01 reg_01;

    if ( smp_found_config )
        nr_irqs_gsi = 0;
    for ( i = 0; i < nr_ioapics; i++ )
    {
        if ( smp_found_config )
        {
            ioapic_phys = mp_ioapics[i].mpc_apicaddr;
            if ( !ioapic_phys )
            {
                printk(KERN_ERR "WARNING: bogus zero IO-APIC address "
                       "found in MPTABLE, disabling IO/APIC support!\n");
                smp_found_config = 0;
                skip_ioapic_setup = 1;
                goto fake_ioapic_page;
            }
        }
        else
        {
 fake_ioapic_page:
            ioapic_phys = __pa(alloc_xenheap_page());
            clear_page(__va(ioapic_phys));
        }
        set_fixmap_nocache(idx, ioapic_phys);
        apic_printk(APIC_VERBOSE, "mapped IOAPIC to %08lx (%08lx)\n",
                    __fix_to_virt(idx), ioapic_phys);
        idx++;

        if ( smp_found_config )
        {
            /* The number of IO-APIC IRQ registers (== #pins): */
            reg_01.raw = io_apic_read(i, 1);
            nr_ioapic_registers[i] = reg_01.bits.entries + 1;
            nr_irqs_gsi += nr_ioapic_registers[i];
        }
    }

    nr_irqs_gsi = max(nr_irqs_gsi, highest_gsi());

    if ( !smp_found_config || skip_ioapic_setup || nr_irqs_gsi < 16 )
        nr_irqs_gsi = 16;
    else if ( nr_irqs_gsi > MAX_GSI_IRQS)
    {
        /* for PHYSDEVOP_pirq_eoi_gmfn guest assumptions */
        printk(KERN_WARNING "Limiting number of GSI IRQs found (%u) to %lu\n",
               nr_irqs_gsi, MAX_GSI_IRQS);
        nr_irqs_gsi = MAX_GSI_IRQS;
    }

    if (nr_irqs < 2 * nr_irqs_gsi)
        nr_irqs = 2 * nr_irqs_gsi;

    if (nr_irqs > MAX_NR_IRQS)
        nr_irqs = MAX_NR_IRQS;
}
