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

#include <xen/lib.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/sched.h>
#include <xen/acpi.h>
#include <xen/keyhandler.h>
#include <xen/softirq.h>
#include <asm/mc146818rtc.h>
#include <asm/smp.h>
#include <asm/desc.h>
#include <asm/msi.h>
#include <asm/setup.h>
#include <mach_apic.h>
#include <io_ports.h>
#include <public/physdev.h>
#include <xen/trace.h>

/* Where if anywhere is the i8259 connect in external int mode */
static struct { int pin, apic; } ioapic_i8259 = { -1, -1 };

static DEFINE_SPINLOCK(ioapic_lock);

bool __read_mostly skip_ioapic_setup;
bool __initdata ioapic_ack_new = true;
bool __initdata ioapic_ack_forced;

/*
 * # of IRQ routing registers
 */
int __read_mostly nr_ioapic_entries[MAX_IO_APICS];
int __read_mostly nr_ioapics;

/*
 * Rough estimation of how many shared IRQs there are, can
 * be changed anytime.
 */
#define MAX_PLUS_SHARED_IRQS nr_irqs_gsi
#define PIN_MAP_SIZE (MAX_PLUS_SHARED_IRQS + nr_irqs_gsi)


#define ioapic_has_eoi_reg(apic) (mp_ioapics[(apic)].mpc_apicver >= 0x20)

static int apic_pin_2_gsi_irq(int apic, int pin);

static vmask_t *__read_mostly vector_map[MAX_IO_APICS];

static void share_vector_maps(unsigned int src, unsigned int dst)
{
    unsigned int pin;

    if (vector_map[src] == vector_map[dst])
        return;

    bitmap_or(vector_map[src]->_bits, vector_map[src]->_bits,
              vector_map[dst]->_bits, NR_VECTORS);

    for (pin = 0; pin < nr_ioapic_entries[dst]; ++pin) {
        int irq = apic_pin_2_gsi_irq(dst, pin);
        struct irq_desc *desc;

        if (irq < 0)
            continue;
        desc = irq_to_desc(irq);
        if (desc->arch.used_vectors == vector_map[dst])
            desc->arch.used_vectors = vector_map[src];
    }

    vector_map[dst] = vector_map[src];
}

/*
 * This is performance-critical, we want to do it O(1)
 *
 * the indexing order of this array favors 1:1 mappings
 * between pins and IRQs.
 */

static struct irq_pin_list {
    int apic, pin;
    unsigned int next;
} *__read_mostly irq_2_pin;

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
            panic("io_apic.c: whoops\n");
        entry->next = irq_2_pin_free_entry;
        entry = irq_2_pin + entry->next;
        irq_2_pin_free_entry = entry->next;
        entry->next = 0;
    }
    entry->apic = apic;
    entry->pin = pin;
    share_vector_maps(irq_2_pin[irq].apic, apic);
}

static void remove_pin_from_irq(unsigned int irq, int apic, int pin)
{
    struct irq_pin_list *entry, *prev;

    for (entry = &irq_2_pin[irq]; ; entry = &irq_2_pin[entry->next]) {
        if ((entry->apic == apic) && (entry->pin == pin))
            break;
        BUG_ON(!entry->next);
    }

    entry->pin = entry->apic = -1;

    if (entry != &irq_2_pin[irq]) {
        /* Removed entry is not at head of list. */
        prev = &irq_2_pin[irq];
        while (&irq_2_pin[prev->next] != entry)
            prev = &irq_2_pin[prev->next];
        prev->next = entry->next;
    } else if (entry->next) {
        /* Removed entry is at head of multi-item list. */
        prev  = entry;
        entry = &irq_2_pin[entry->next];
        *prev = *entry;
        entry->pin = entry->apic = -1;
    } else
        return;

    entry->next = irq_2_pin_free_entry;
    irq_2_pin_free_entry = entry - irq_2_pin;
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
            share_vector_maps(oldapic, newapic);
        }
        if (!entry->next)
            break;
        entry = irq_2_pin + entry->next;
    }
}

vmask_t *io_apic_get_used_vector_map(unsigned int irq)
{
    struct irq_pin_list *entry = irq_2_pin + irq;

    if (entry->pin == -1)
        return NULL;

    return vector_map[entry->apic];
}

struct IO_APIC_route_entry **alloc_ioapic_entries(void)
{
    int apic;
    struct IO_APIC_route_entry **ioapic_entries;

    ioapic_entries = xmalloc_array(struct IO_APIC_route_entry *, nr_ioapics);
    if (!ioapic_entries)
        return 0;

    for (apic = 0; apic < nr_ioapics; apic++) {
        ioapic_entries[apic] =
            xmalloc_array(struct IO_APIC_route_entry,
                          nr_ioapic_entries[apic]);
        if (!ioapic_entries[apic] && nr_ioapic_entries[apic])
            goto nomem;
    }

    return ioapic_entries;

nomem:
    while (--apic >= 0)
        xfree(ioapic_entries[apic]);
    xfree(ioapic_entries);

    return 0;
}

union entry_union {
    struct { u32 w1, w2; };
    struct IO_APIC_route_entry entry;
};

struct IO_APIC_route_entry __ioapic_read_entry(
    unsigned int apic, unsigned int pin, bool raw)
{
    unsigned int (*read)(unsigned int, unsigned int)
        = raw ? __io_apic_read : io_apic_read;
    union entry_union eu;
    eu.w1 = (*read)(apic, 0x10 + 2 * pin);
    eu.w2 = (*read)(apic, 0x11 + 2 * pin);
    return eu.entry;
}

static struct IO_APIC_route_entry ioapic_read_entry(
    unsigned int apic, unsigned int pin, bool raw)
{
    struct IO_APIC_route_entry entry;
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    entry = __ioapic_read_entry(apic, pin, raw);
    spin_unlock_irqrestore(&ioapic_lock, flags);
    return entry;
}

void __ioapic_write_entry(
    unsigned int apic, unsigned int pin, bool raw,
    struct IO_APIC_route_entry e)
{
    void (*write)(unsigned int, unsigned int, unsigned int)
        = raw ? __io_apic_write : io_apic_write;
    union entry_union eu = { .entry = e };

    (*write)(apic, 0x11 + 2*pin, eu.w2);
    (*write)(apic, 0x10 + 2*pin, eu.w1);
}

static void ioapic_write_entry(
    unsigned int apic, unsigned int pin, bool raw,
    struct IO_APIC_route_entry e)
{
    unsigned long flags;
    spin_lock_irqsave(&ioapic_lock, flags);
    __ioapic_write_entry(apic, pin, raw, e);
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

/* EOI an IO-APIC entry.  Vector may be -1, indicating that it should be
 * worked out using the pin.  This function expects that the ioapic_lock is
 * being held, and interrupts are disabled (or there is a good reason not
 * to), and that if both pin and vector are passed, that they refer to the
 * same redirection entry in the IO-APIC. */
static void __io_apic_eoi(unsigned int apic, unsigned int vector, unsigned int pin)
{
    /* Prefer the use of the EOI register if available */
    if ( ioapic_has_eoi_reg(apic) )
    {
        /* If vector is unknown, read it from the IO-APIC */
        if ( vector == IRQ_VECTOR_UNASSIGNED )
            vector = __ioapic_read_entry(apic, pin, TRUE).vector;

        *(IO_APIC_BASE(apic)+16) = vector;
    }
    else
    {
        /* Else fake an EOI by switching to edge triggered mode
         * and back */
        struct IO_APIC_route_entry entry;
        bool need_to_unmask = false;

        entry = __ioapic_read_entry(apic, pin, TRUE);

        if ( ! entry.mask )
        {
            /* If entry is not currently masked, mask it and make
             * a note to unmask it later */
            entry.mask = 1;
            __ioapic_write_entry(apic, pin, TRUE, entry);
            need_to_unmask = true;
        }

        /* Flip the trigger mode to edge and back */
        entry.trigger = 0;
        __ioapic_write_entry(apic, pin, TRUE, entry);
        entry.trigger = 1;
        __ioapic_write_entry(apic, pin, TRUE, entry);

        if ( need_to_unmask )
        {
            /* Unmask if neccesary */
            entry.mask = 0;
            __ioapic_write_entry(apic, pin, TRUE, entry);
        }
    }
}

/*
 * Saves all the IO-APIC RTE's
 */
int save_IO_APIC_setup(struct IO_APIC_route_entry **ioapic_entries)
{
    int apic, pin;

    if (!ioapic_entries)
        return -ENOMEM;

    for (apic = 0; apic < nr_ioapics; apic++) {
        if (!nr_ioapic_entries[apic])
            continue;

        if (!ioapic_entries[apic])
            return -ENOMEM;

        for (pin = 0; pin < nr_ioapic_entries[apic]; pin++)
	    ioapic_entries[apic][pin] = __ioapic_read_entry(apic, pin, 1);
    }

    return 0;
}

/*
 * Mask all IO APIC entries.
 */
void mask_IO_APIC_setup(struct IO_APIC_route_entry **ioapic_entries)
{
    int apic, pin;

    if (!ioapic_entries)
        return;

    for (apic = 0; apic < nr_ioapics; apic++) {
        if (!nr_ioapic_entries[apic])
            continue;

        if (!ioapic_entries[apic])
            break;

        for (pin = 0; pin < nr_ioapic_entries[apic]; pin++) {
            struct IO_APIC_route_entry entry;

            entry = ioapic_entries[apic][pin];
            if (!entry.mask) {
                entry.mask = 1;

                ioapic_write_entry(apic, pin, 1, entry);
            }
        }
    }
}

/*
 * Restore IO APIC entries which was saved in ioapic_entries.
 */
int restore_IO_APIC_setup(struct IO_APIC_route_entry **ioapic_entries)
{
    int apic, pin;

    if (!ioapic_entries)
        return -ENOMEM;

    for (apic = 0; apic < nr_ioapics; apic++) {
        if (!nr_ioapic_entries[apic])
            continue;

        if (!ioapic_entries[apic])
            return -ENOMEM;

        for (pin = 0; pin < nr_ioapic_entries[apic]; pin++)
	    ioapic_write_entry(apic, pin, 1, ioapic_entries[apic][pin]);
    }

    return 0;
}

void free_ioapic_entries(struct IO_APIC_route_entry **ioapic_entries)
{
    int apic;

    for (apic = 0; apic < nr_ioapics; apic++)
        xfree(ioapic_entries[apic]);

    xfree(ioapic_entries);
}

static void modify_IO_APIC_irq(unsigned int irq, unsigned int enable,
                               unsigned int disable)
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
    modify_IO_APIC_irq(irq, IO_APIC_REDIR_MASKED, 0);
}

/* mask = 0 */
static void __unmask_IO_APIC_irq (unsigned int irq)
{
    modify_IO_APIC_irq(irq, 0, IO_APIC_REDIR_MASKED);
}

/* trigger = 0 */
static void __edge_IO_APIC_irq (unsigned int irq)
{
    modify_IO_APIC_irq(irq, 0, IO_APIC_REDIR_LEVEL_TRIGGER);
}

/* trigger = 1 */
static void __level_IO_APIC_irq (unsigned int irq)
{
    modify_IO_APIC_irq(irq, IO_APIC_REDIR_LEVEL_TRIGGER, 0);
}

static void mask_IO_APIC_irq(struct irq_desc *desc)
{
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    __mask_IO_APIC_irq(desc->irq);
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void unmask_IO_APIC_irq(struct irq_desc *desc)
{
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    __unmask_IO_APIC_irq(desc->irq);
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void __eoi_IO_APIC_irq(struct irq_desc *desc)
{
    struct irq_pin_list *entry = irq_2_pin + desc->irq;
    unsigned int pin, vector = desc->arch.vector;

    for (;;) {
        pin = entry->pin;
        if (pin == -1)
            break;
        __io_apic_eoi(entry->apic, vector, pin);
        if (!entry->next)
            break;
        entry = irq_2_pin + entry->next;
    }
}

static void eoi_IO_APIC_irq(struct irq_desc *desc)
{
    unsigned long flags;
    spin_lock_irqsave(&ioapic_lock, flags);
    __eoi_IO_APIC_irq(desc);
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void clear_IO_APIC_pin(unsigned int apic, unsigned int pin)
{
    struct IO_APIC_route_entry entry;

    /* Check delivery_mode to be sure we're not clearing an SMI pin */
    entry = __ioapic_read_entry(apic, pin, FALSE);
    if (entry.delivery_mode == dest_SMI)
        return;

    /*
     * Make sure the entry is masked and re-read the contents to check
     * if it is a level triggered pin and if the remoteIRR is set.
     */
    if (!entry.mask) {
        entry.mask = 1;
        __ioapic_write_entry(apic, pin, FALSE, entry);
    }
    entry = __ioapic_read_entry(apic, pin, TRUE);

    if (entry.irr) {
        /* Make sure the trigger mode is set to level. */
        if (!entry.trigger) {
            entry.trigger = 1;
            __ioapic_write_entry(apic, pin, TRUE, entry);
        }
        __io_apic_eoi(apic, entry.vector, pin);
    }

    /*
     * Disable it in the IO-APIC irq-routing table:
     */
    memset(&entry, 0, sizeof(entry));
    entry.mask = 1;
    __ioapic_write_entry(apic, pin, TRUE, entry);

    entry = __ioapic_read_entry(apic, pin, TRUE);
    if (entry.irr)
        printk(KERN_ERR "IO-APIC%02x-%u: Unable to reset IRR\n",
               IO_APIC_ID(apic), pin);
}

static void clear_IO_APIC (void)
{
    int apic, pin;

    for (apic = 0; apic < nr_ioapics; apic++) {
        for (pin = 0; pin < nr_ioapic_entries[apic]; pin++)
            clear_IO_APIC_pin(apic, pin);
    }
}

static void
set_ioapic_affinity_irq(struct irq_desc *desc, const cpumask_t *mask)
{
    unsigned int dest;
    int pin, irq;
    struct irq_pin_list *entry;

    irq = desc->irq;

    spin_lock(&ioapic_lock);

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
            data |= MASK_INSR(desc->arch.vector, IO_APIC_REDIR_VECTOR_MASK);
            io_apic_modify(entry->apic, 0x10 + pin*2, data);

            if (!entry->next)
                break;
            entry = irq_2_pin + entry->next;
        }
    }

    spin_unlock(&ioapic_lock);
}

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
            if (!nr_ioapic_entries[apic])
                continue;
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
void /*__init*/ setup_ioapic_dest(void)
{
    int pin, ioapic, irq, irq_entry;

    if (skip_ioapic_setup)
        return;

    for (ioapic = 0; ioapic < nr_ioapics; ioapic++) {
        for (pin = 0; pin < nr_ioapic_entries[ioapic]; pin++) {
            struct irq_desc *desc;
            unsigned long flags;

            irq_entry = find_irq_entry(ioapic, pin, mp_INT);
            if (irq_entry == -1)
                continue;
            irq = pin_2_irq(irq_entry, ioapic, pin);
            desc = irq_to_desc(irq);

            spin_lock_irqsave(&desc->lock, flags);
            BUG_ON(!cpumask_intersects(desc->arch.cpu_mask, &cpu_online_map));
            set_ioapic_affinity_irq(desc, desc->arch.cpu_mask);
            spin_unlock_irqrestore(&desc->lock, flags);
        }
    }
}

/*
 * EISA Edge/Level control register, ELCR
 */
static int EISA_ELCR(unsigned int irq)
{
    if (platform_legacy_irq(irq)) {
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
            irq += nr_ioapic_entries[i++];
        irq += pin;
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
        for (pin = 0; pin < nr_ioapic_entries[apic]; pin++) {
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
static hw_irq_controller ioapic_edge_type;

#define IOAPIC_AUTO	-1
#define IOAPIC_EDGE	0
#define IOAPIC_LEVEL	1

#define SET_DEST(ent, mode, val) do { \
    if (x2apic_enabled) \
        (ent).dest.dest32 = (val); \
    else \
        (ent).dest.mode.mode##_dest = (val); \
} while (0)

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

    apic_printk(APIC_VERBOSE, KERN_DEBUG "init IO_APIC IRQs\n");

    for (apic = 0; apic < nr_ioapics; apic++) {
        for (pin = 0; pin < nr_ioapic_entries[apic]; pin++) {
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

            if (!IO_APIC_IRQ(irq))
                continue;

            vector = assign_irq_vector(irq, NULL);
            BUG_ON(vector < 0);
            entry.vector = vector;
            ioapic_register_intr(irq, IOAPIC_AUTO);

            if (platform_legacy_irq(irq))
                disable_8259A_irq(irq_to_desc(irq));

            SET_DEST(entry, logical, cpu_mask_to_apicid(TARGET_CPUS));
            spin_lock_irqsave(&ioapic_lock, flags);
            __ioapic_write_entry(apic, pin, 0, entry);
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

    memset(&entry,0,sizeof(entry));

    disable_8259A_irq(irq_to_desc(0));

    /* mask LVT0 */
    apic_write(APIC_LVT0, APIC_LVT_MASKED | APIC_DM_EXTINT);

    /*
     * We use logical delivery to get the timer IRQ
     * to the first CPU.
     */
    entry.dest_mode = INT_DEST_MODE;
    entry.mask = 0;					/* unmask IRQ now */
    SET_DEST(entry, logical, cpu_mask_to_apicid(TARGET_CPUS));
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
    ioapic_write_entry(apic, pin, 0, entry);

    enable_8259A_irq(irq_to_desc(0));
}

static inline void UNEXPECTED_IO_APIC(void)
{
}

static void /*__init*/ __print_IO_APIC(bool boot)
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
               mp_ioapics[i].mpc_apicid, nr_ioapic_entries[i]);

    /*
     * We are a bit conservative about what we expect.  We have to
     * know about every hardware change ASAP.
     */
    printk(KERN_INFO "testing the IO APIC.......................\n");

    for (apic = 0; apic < nr_ioapics; apic++) {
        if ( !boot )
            process_pending_softirqs();

        if (!nr_ioapic_entries[apic])
            continue;

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

	printk(KERN_DEBUG " NR %s Msk Trg IRR Pol Stat DstM DelM Vec\n",
               x2apic_enabled ? " DestID" : "Dst");

	for (i = 0; i <= reg_01.bits.entries; i++) {
            struct IO_APIC_route_entry entry;

            entry = ioapic_read_entry(apic, i, 0);

            if ( x2apic_enabled )
                printk(KERN_DEBUG " %02x %08x", i, entry.dest.dest32);
            else
                printk(KERN_DEBUG " %02x  %02x ", i,
                       entry.dest.logical.logical_dest);

            printk(" %d   %d   %d   %d   %d    %d    %d    %02X\n",
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

        if ( !boot && !(i & 0x1f) )
            process_pending_softirqs();

        if (entry->pin < 0)
            continue;
        printk(KERN_DEBUG "IRQ%d ", irq_to_desc(i)->arch.vector);
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

static void __init print_IO_APIC(void)
{
    if (apic_verbosity != APIC_QUIET)
        __print_IO_APIC(1);
}

static void _print_IO_APIC_keyhandler(unsigned char key)
{
    __print_IO_APIC(0);
}

static void __init enable_IO_APIC(void)
{
    int i8259_apic, i8259_pin;
    int i, apic;

    /* Initialise dynamic irq_2_pin free list. */
    irq_2_pin = xzalloc_array(struct irq_pin_list, PIN_MAP_SIZE);
        
    for (i = 0; i < PIN_MAP_SIZE; i++)
        irq_2_pin[i].pin = -1;
    for (i = irq_2_pin_free_entry = nr_irqs_gsi; i < PIN_MAP_SIZE; i++)
        irq_2_pin[i].next = i + 1;

    if (directed_eoi_enabled) {
        for (apic = 0; apic < nr_ioapics; apic++) {
            if (!nr_ioapic_entries[apic])
                continue;
            vector_map[apic] = xzalloc(vmask_t);
            BUG_ON(!vector_map[apic]);
        }
    } else {
        vector_map[0] = xzalloc(vmask_t);
        BUG_ON(!vector_map[0]);
        for (apic = 1; apic < nr_ioapics; apic++)
            vector_map[apic] = vector_map[0];
    }

    for(apic = 0; apic < nr_ioapics; apic++) {
        int pin;
        /* See if any of the pins is in ExtINT mode */
        for (pin = 0; pin < nr_ioapic_entries[apic]; pin++) {
            struct IO_APIC_route_entry entry = ioapic_read_entry(apic, pin, 0);

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

        memset(&entry, 0, sizeof(entry));
        entry.mask            = 0; /* Enabled */
        entry.trigger         = 0; /* Edge */
        entry.irr             = 0;
        entry.polarity        = 0; /* High */
        entry.delivery_status = 0;
        entry.dest_mode       = 0; /* Physical */
        entry.delivery_mode   = dest_ExtINT; /* ExtInt */
        entry.vector          = 0;
        SET_DEST(entry, physical, get_apic_id());

        /*
         * Add it to the IO-APIC irq-routing table:
         */
        ioapic_write_entry(ioapic_i8259.apic, ioapic_i8259.pin, 0, entry);
    }
    disconnect_bsp_APIC(ioapic_i8259.pin != -1);
}

/*
 * function to set the IO-APIC physical IDs based on the
 * values stored in the MPC table.
 *
 * by Matt Domsch <Matt_Domsch@dell.com>  Tue Dec 21 12:25:05 CST 1999
 */

static void __init setup_ioapic_ids_from_mpc(void)
{
    union IO_APIC_reg_00 reg_00;
    static physid_mask_t __initdata phys_id_present_map;
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
    ioapic_phys_id_map(&phys_id_present_map);

    /*
     * Set the IOAPIC ID to the value stored in the MPC table.
     */
    for (apic = 0; apic < nr_ioapics; apic++) {
        if (!nr_ioapic_entries[apic])
            continue;

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
        if (check_apicid_used(&phys_id_present_map,
                              mp_ioapics[apic].mpc_apicid)) {
            printk(KERN_ERR "BIOS bug, IO-APIC#%d ID %d is already used!...\n",
                   apic, mp_ioapics[apic].mpc_apicid);
            for (i = 0; i < get_physical_broadcast(); i++)
                if (!physid_isset(i, phys_id_present_map))
                    break;
            if (i >= get_physical_broadcast())
                panic("Max APIC ID exceeded\n");
            printk(KERN_ERR "... fixing up to %d. (tell your hw vendor)\n",
                   i);
            mp_ioapics[apic].mpc_apicid = i;
        } else {
            apic_printk(APIC_VERBOSE, "Setting %d in the "
                        "phys_id_present_map\n",
                        mp_ioapics[apic].mpc_apicid);
        }
        set_apicid(mp_ioapics[apic].mpc_apicid, &phys_id_present_map);

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
    unsigned long t1, flags;

    t1 = ACCESS_ONCE(pit0_ticks);

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
    if ( (ACCESS_ONCE(pit0_ticks) - t1) > 4 )
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
static unsigned int startup_edge_ioapic_irq(struct irq_desc *desc)
{
    int was_pending = 0;
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    if (platform_legacy_irq(desc->irq)) {
        disable_8259A_irq(desc);
        if (i8259A_irq_pending(desc->irq))
            was_pending = 1;
    }
    __unmask_IO_APIC_irq(desc->irq);
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return was_pending;
}

/*
 * Once we have recorded IRQ_PENDING already, we can mask the
 * interrupt for real. This prevents IRQ storms from unhandled
 * devices.
 */
static void ack_edge_ioapic_irq(struct irq_desc *desc)
{
    irq_complete_move(desc);
    move_native_irq(desc);

    if ((desc->status & (IRQ_PENDING | IRQ_DISABLED))
        == (IRQ_PENDING | IRQ_DISABLED))
        mask_IO_APIC_irq(desc);
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
static unsigned int startup_level_ioapic_irq(struct irq_desc *desc)
{
    unmask_IO_APIC_irq(desc);

    return 0; /* don't check for pending */
}

static int __init setup_ioapic_ack(const char *s)
{
    if ( !strcmp(s, "old") )
    {
        ioapic_ack_new = false;
        ioapic_ack_forced = true;
    }
    else if ( !strcmp(s, "new") )
    {
        ioapic_ack_new = true;
        ioapic_ack_forced = true;
    }
    else
        return -EINVAL;

    return 0;
}
custom_param("ioapic_ack", setup_ioapic_ack);

static bool io_apic_level_ack_pending(unsigned int irq)
{
    struct irq_pin_list *entry;
    unsigned long flags;

    spin_lock_irqsave(&ioapic_lock, flags);
    entry = &irq_2_pin[irq];
    for (;;) {
        unsigned int reg;
        int pin;

        if (!entry)
            break;

        pin = entry->pin;
        if (pin == -1)
            continue;
        reg = io_apic_read(entry->apic, 0x10 + pin*2);
        /* Is the remote IRR bit set? */
        if (reg & IO_APIC_REDIR_REMOTE_IRR) {
            spin_unlock_irqrestore(&ioapic_lock, flags);
            return 1;
        }
        if (!entry->next)
            break;
        entry = irq_2_pin + entry->next;
    }
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return 0;
}

static void mask_and_ack_level_ioapic_irq(struct irq_desc *desc)
{
    unsigned long v;
    int i;

    irq_complete_move(desc);

    if ( !directed_eoi_enabled )
        mask_IO_APIC_irq(desc);

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
    i = desc->arch.vector;

    v = apic_read(APIC_TMR + ((i & ~0x1f) >> 1));

    ack_APIC_irq();
    
    if ( directed_eoi_enabled )
        return;

    if ((desc->status & IRQ_MOVE_PENDING) &&
       !io_apic_level_ack_pending(desc->irq))
        move_masked_irq(desc);

    if ( !(v & (1 << (i & 0x1f))) ) {
        spin_lock(&ioapic_lock);
        __edge_IO_APIC_irq(desc->irq);
        __level_IO_APIC_irq(desc->irq);
        spin_unlock(&ioapic_lock);
    }
}

static void end_level_ioapic_irq_old(struct irq_desc *desc, u8 vector)
{
    if ( directed_eoi_enabled )
    {
        if ( !(desc->status & (IRQ_DISABLED|IRQ_MOVE_PENDING)) )
        {
            eoi_IO_APIC_irq(desc);
            return;
        }

        mask_IO_APIC_irq(desc);
        eoi_IO_APIC_irq(desc);
        if ( (desc->status & IRQ_MOVE_PENDING) &&
             !io_apic_level_ack_pending(desc->irq) )
            move_masked_irq(desc);
    }

    if ( !(desc->status & IRQ_DISABLED) )
        unmask_IO_APIC_irq(desc);
}

static void end_level_ioapic_irq_new(struct irq_desc *desc, u8 vector)
{
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
    unsigned int v, i = desc->arch.vector;

    /* Manually EOI the old vector if we are moving to the new */
    if ( vector && i != vector )
        eoi_IO_APIC_irq(desc);

    v = apic_read(APIC_TMR + ((i & ~0x1f) >> 1));

    ack_APIC_irq();

    if ( (desc->status & IRQ_MOVE_PENDING) &&
         !io_apic_level_ack_pending(desc->irq) )
        move_native_irq(desc);

    if (!(v & (1 << (i & 0x1f)))) {
        spin_lock(&ioapic_lock);
        __mask_IO_APIC_irq(desc->irq);
        __edge_IO_APIC_irq(desc->irq);
        __level_IO_APIC_irq(desc->irq);
        if ( !(desc->status & IRQ_DISABLED) )
            __unmask_IO_APIC_irq(desc->irq);
        spin_unlock(&ioapic_lock);
    }
}

/*
 * Level and edge triggered IO-APIC interrupts need different handling,
 * so we use two separate IRQ descriptors. Edge triggered IRQs can be
 * handled with the level-triggered descriptor, but that one has slightly
 * more overhead. Level-triggered interrupts cannot be handled with the
 * edge-triggered handler, without risking IRQ storms and other ugly
 * races.
 */
static hw_irq_controller ioapic_edge_type = {
    .typename 	= "IO-APIC-edge",
    .startup 	= startup_edge_ioapic_irq,
    .shutdown 	= irq_shutdown_none,
    .enable 	= unmask_IO_APIC_irq,
    .disable 	= irq_disable_none,
    .ack 		= ack_edge_ioapic_irq,
    .set_affinity 	= set_ioapic_affinity_irq,
};

static struct hw_interrupt_type __read_mostly ioapic_level_type = {
    .typename 	= "IO-APIC-level",
    .startup 	= startup_level_ioapic_irq,
    .shutdown 	= mask_IO_APIC_irq,
    .enable 	= unmask_IO_APIC_irq,
    .disable 	= mask_IO_APIC_irq,
    .ack 		= mask_and_ack_level_ioapic_irq,
    .end 		= end_level_ioapic_irq_old,
    .set_affinity 	= set_ioapic_affinity_irq,
};

static inline void init_IO_APIC_traps(void)
{
    int irq;
    /* Xen: This is way simpler than the Linux implementation. */
    for (irq = 0; platform_legacy_irq(irq); irq++)
        if (IO_APIC_IRQ(irq) && !irq_to_vector(irq))
            make_8259A_irq(irq);
}

static void enable_lapic_irq(struct irq_desc *desc)
{
    unsigned long v;

    v = apic_read(APIC_LVT0);
    apic_write(APIC_LVT0, v & ~APIC_LVT_MASKED);
}

static void disable_lapic_irq(struct irq_desc *desc)
{
    unsigned long v;

    v = apic_read(APIC_LVT0);
    apic_write(APIC_LVT0, v | APIC_LVT_MASKED);
}

static void ack_lapic_irq(struct irq_desc *desc)
{
    ack_APIC_irq();
}

static hw_irq_controller lapic_irq_type = {
    .typename 	= "local-APIC-edge",
    .startup 	= NULL, /* startup_irq() not used for IRQ0 */
    .shutdown 	= NULL, /* shutdown_irq() not used for IRQ0 */
    .enable 	= enable_lapic_irq,
    .disable 	= disable_lapic_irq,
    .ack 		= ack_lapic_irq,
};

/*
 * This looks a bit hackish but it's about the only one way of sending
 * a few INTA cycles to 8259As and any associated glue logic.  ICR does
 * not support the ExtINT mode, unfortunately.  We need to send these
 * cycles as some i82489DX-based boards have glue logic that keeps the
 * 8259A interrupt line asserted until INTA.  --macro
 */
static void __init unlock_ExtINT_logic(void)
{
    int apic, pin, i;
    struct IO_APIC_route_entry entry0, entry1;
    unsigned char save_control, save_freq_select;

    pin = find_isa_irq_pin(8, mp_INT);
    apic = find_isa_irq_apic(8, mp_INT);
    if ( pin == -1 || apic == -1 )
        return;

    entry0 = ioapic_read_entry(apic, pin, 0);
    clear_IO_APIC_pin(apic, pin);

    memset(&entry1, 0, sizeof(entry1));

    entry1.dest_mode = 0;			/* physical delivery */
    entry1.mask = 0;			/* unmask IRQ now */
    SET_DEST(entry1, physical, get_apic_id());
    entry1.delivery_mode = dest_ExtINT;
    entry1.polarity = entry0.polarity;
    entry1.trigger = 0;
    entry1.vector = 0;

    ioapic_write_entry(apic, pin, 0, entry1);

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

    ioapic_write_entry(apic, pin, 0, entry0);
}

/*
 * This code may look a bit paranoid, but it's supposed to cooperate with
 * a wide range of boards and BIOS bugs.  Fortunately only the timer IRQ
 * is so screwy.  Thanks to Brian Perkins for testing/hacking this beast
 * fanatically on his truly buggy board.
 */
static void __init check_timer(void)
{
    int apic1, pin1, apic2, pin2;
    int vector, ret;
    unsigned long flags;

    local_irq_save(flags);

    /*
     * get/set the timer IRQ vector:
     */
    disable_8259A_irq(irq_to_desc(0));
    vector = IRQ0_VECTOR;
    clear_irq_vector(0);

    if ((ret = bind_irq_vector(0, vector, &cpumask_all)))
        printk(KERN_ERR"..IRQ0 is not set correctly with ioapic!!!, err:%d\n", ret);
    
    irq_desc[0].status &= ~IRQ_DISABLED;

    /*
     * Subtle, code in do_timer_interrupt() expects an AEOI
     * mode for the 8259A whenever interrupts are routed
     * through I/O APICs.  Also IRQ0 has to be enabled in
     * the 8259A which implies the virtual wire has to be
     * disabled in the local APIC.
     */
    apic_write(APIC_LVT0, APIC_LVT_MASKED | APIC_DM_EXTINT);
    init_8259A(1);
    /* XEN: Ripped out the legacy missed-tick logic, so below is not needed. */
    /*timer_ack = 1;*/
    /*enable_8259A_irq(irq_to_desc(0));*/

    pin1  = find_isa_irq_pin(0, mp_INT);
    apic1 = find_isa_irq_apic(0, mp_INT);
    pin2  = ioapic_i8259.pin;
    apic2 = ioapic_i8259.apic;

    printk(KERN_INFO "..TIMER: vector=0x%02X apic1=%d pin1=%d apic2=%d pin2=%d\n",
           vector, apic1, pin1, apic2, pin2);

    if (pin1 != -1) {
        /*
         * Ok, does IRQ0 through the IOAPIC work?
         */
        unmask_IO_APIC_irq(irq_to_desc(0));
        if (timer_irq_works()) {
            local_irq_restore(flags);
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

    disable_8259A_irq(irq_to_desc(0));
    irq_desc[0].handler = &lapic_irq_type;
    apic_write(APIC_LVT0, APIC_DM_FIXED | vector);	/* Fixed mode */
    enable_8259A_irq(irq_to_desc(0));

    if (timer_irq_works()) {
        local_irq_restore(flags);
        printk(" works.\n");
        return;
    }
    apic_write(APIC_LVT0, APIC_LVT_MASKED | APIC_DM_FIXED | vector);
    printk(" failed.\n");

    printk(KERN_INFO "...trying to set up timer as ExtINT IRQ...");

    /*timer_ack = 0;*/
    init_8259A(0);
    make_8259A_irq(0);
    apic_write(APIC_LVT0, APIC_DM_EXTINT);

    unlock_ExtINT_logic();

    local_irq_restore(flags);

    if (timer_irq_works()) {
        printk(" works.\n");
        return;
    }
    printk(" failed :(.\n");
    panic("IO-APIC + timer doesn't work!  Boot with apic_verbosity=debug "
          "and send a report.  Then try booting with the 'noapic' option\n");
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
        nr_entry += nr_ioapic_entries[i];

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

    if (ioapic_ack_new) {
        ioapic_level_type.ack = irq_complete_move;
        ioapic_level_type.end = end_level_ioapic_irq_new;
    }

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

    register_keyhandler('z', _print_IO_APIC_keyhandler, "dump IOAPIC info", 1);
}

void ioapic_suspend(void)
{
    struct IO_APIC_route_entry *entry = ioapic_pm_state;
    unsigned long flags;
    int apic, i;

    spin_lock_irqsave(&ioapic_lock, flags);
    for (apic = 0; apic < nr_ioapics; apic++) {
        for (i = 0; i < nr_ioapic_entries[apic]; i ++, entry ++ ) {
            *(((int *)entry) + 1) = __io_apic_read(apic, 0x11 + 2 * i);
            *(((int *)entry) + 0) = __io_apic_read(apic, 0x10 + 2 * i);
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
        if (!nr_ioapic_entries[apic])
            continue;
        reg_00.raw = __io_apic_read(apic, 0);
        if (reg_00.bits.ID != mp_ioapics[apic].mpc_apicid) {
            reg_00.bits.ID = mp_ioapics[apic].mpc_apicid;
            __io_apic_write(apic, 0, reg_00.raw);
        }
        for (i = 0; i < nr_ioapic_entries[apic]; i++, entry++) {
            __io_apic_write(apic, 0x11+2*i, *(((int *)entry)+1));
            __io_apic_write(apic, 0x10+2*i, *(((int *)entry)+0));
        }
    }
    spin_unlock_irqrestore(&ioapic_lock, flags);
}

/* --------------------------------------------------------------------------
                          ACPI-based IOAPIC Configuration
   -------------------------------------------------------------------------- */


int __init io_apic_get_unique_id (int ioapic, int apic_id)
{
    union IO_APIC_reg_00 reg_00;
    static physid_mask_t __initdata apic_id_map = PHYSID_MASK_NONE;
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
        ioapic_phys_id_map(&apic_id_map);

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
    if (check_apicid_used(&apic_id_map, apic_id)) {

        for (i = 0; i < get_physical_broadcast(); i++) {
            if (!check_apicid_used(&apic_id_map, i))
                break;
        }

        if (i == get_physical_broadcast())
            panic("Max apic_id exceeded\n");

        printk(KERN_WARNING "IOAPIC[%d]: apic_id %d already used, "
               "trying %d\n", ioapic, apic_id, i);

        apic_id = i;
    } 

    set_apicid(apic_id, &apic_id_map);

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
    struct irq_desc *desc = irq_to_desc(irq);
    struct IO_APIC_route_entry entry;
    unsigned long flags;
    int vector;

    if (!IO_APIC_IRQ(irq)) {
        printk(KERN_ERR "IOAPIC[%d]: Invalid reference to IRQ %d\n",
               ioapic, irq);
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
    entry.trigger = edge_level;
    entry.polarity = active_high_low;
    entry.mask  = 1;

    /*
     * IRQs < 16 are already in the irq_2_pin[] map
     */
    if (!platform_legacy_irq(irq))
        add_pin_to_irq(irq, ioapic, pin);

    vector = assign_irq_vector(irq, NULL);
    if (vector < 0)
        return vector;
    entry.vector = vector;

    if (cpumask_intersects(desc->arch.cpu_mask, TARGET_CPUS)) {
        cpumask_t *mask = this_cpu(scratch_cpumask);

        cpumask_and(mask, desc->arch.cpu_mask, TARGET_CPUS);
        SET_DEST(entry, logical, cpu_mask_to_apicid(mask));
    } else {
        printk(XENLOG_ERR "IRQ%d: no target CPU (%*pb vs %*pb)\n",
               irq, CPUMASK_PR(desc->arch.cpu_mask), CPUMASK_PR(TARGET_CPUS));
        desc->status |= IRQ_DISABLED;
    }

    apic_printk(APIC_DEBUG, KERN_DEBUG "IOAPIC[%d]: Set PCI routing entry "
		"(%d-%d -> %#x -> IRQ %d Mode:%i Active:%i)\n", ioapic,
		mp_ioapics[ioapic].mpc_apicid, pin, entry.vector, irq,
		edge_level, active_high_low);

    ioapic_register_intr(irq, edge_level);

    if (!ioapic && platform_legacy_irq(irq))
        disable_8259A_irq(desc);

    spin_lock_irqsave(&ioapic_lock, flags);
    __ioapic_write_entry(ioapic, pin, 0, entry);
    spin_unlock(&ioapic_lock);

    spin_lock(&desc->lock);
    if (!(desc->status & (IRQ_DISABLED | IRQ_GUEST)))
        desc->handler->startup(desc);
    spin_unlock_irqrestore(&desc->lock, flags);

    return 0;
}

static int ioapic_physbase_to_id(unsigned long physbase)
{
    int apic;
    for ( apic = 0; apic < nr_ioapics; apic++ )
    {
        if ( !nr_ioapic_entries[apic] )
            continue;
        if ( mp_ioapics[apic].mpc_apicaddr == physbase )
            return apic;
    }
    return -EINVAL;
}

static int apic_pin_2_gsi_irq(int apic, int pin)
{
    int idx;

    if (apic < 0)
       return -EINVAL;

    idx = find_irq_entry(apic, pin, mp_INT);

    return idx >= 0 ? pin_2_irq(idx, apic, pin)
                    : io_apic_gsi_base(apic) + pin;
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

#define WARN_BOGUS_WRITE(f, a...)                             \
    dprintk(XENLOG_INFO, "IO-APIC: apic=%d, pin=%d, irq=%d\n" \
            XENLOG_INFO "IO-APIC: new_entry=%08x\n"           \
            XENLOG_INFO "IO-APIC: " f "\n",                   \
            apic, pin, irq, *(u32 *)&rte, ##a )

int ioapic_guest_write(unsigned long physbase, unsigned int reg, u32 val)
{
    int apic, pin, irq, ret, pirq;
    struct IO_APIC_route_entry rte = { 0 };
    unsigned long flags;
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

    /*
     * Since PHYSDEVOP_alloc_irq_vector is dummy, rte.vector is the pirq
     * which corresponds to this ioapic pin, retrieve it for building
     * pirq and irq mapping. Where the GSI is greater than 256, we assume
     * that dom0 pirq == irq.
     */
    if ( !rte.mask )
    {
        pirq = (irq >= 256) ? irq : rte.vector;
        if ( pirq >= hardware_domain->nr_pirqs )
            return -EINVAL;
    }
    else
        pirq = -1;
    
    if ( desc->action )
    {
        spin_lock_irqsave(&ioapic_lock, flags);
        ret = io_apic_read(apic, 0x10 + 2 * pin);
        spin_unlock_irqrestore(&ioapic_lock, flags);
        rte.vector = desc->arch.vector;
        if ( *(u32*)&rte != ret )
            WARN_BOGUS_WRITE("old_entry=%08x pirq=%d\n" XENLOG_INFO
                             "IO-APIC: Attempt to modify IO-APIC pin for in-use IRQ!",
                             ret, pirq);
        return 0;
    }

    if ( desc->arch.vector <= 0 || desc->arch.vector > LAST_DYNAMIC_VECTOR )
    {
        int vector = desc->arch.vector;

        if ( vector < FIRST_HIPRIORITY_VECTOR )
            add_pin_to_irq(irq, apic, pin);
        else
            desc->arch.vector = IRQ_VECTOR_UNASSIGNED;
        ret = assign_irq_vector(irq, NULL);
        if ( ret < 0 )
        {
            if ( vector < FIRST_HIPRIORITY_VECTOR )
                remove_pin_from_irq(irq, apic, pin);
            else
                desc->arch.vector = vector;
            return ret;
        }

        printk(XENLOG_INFO "allocated vector %02x for irq %d\n", ret, irq);
    }
    if ( pirq >= 0 )
    {
        spin_lock(&hardware_domain->event_lock);
        ret = map_domain_pirq(hardware_domain, pirq, irq,
                              MAP_PIRQ_TYPE_GSI, NULL);
        spin_unlock(&hardware_domain->event_lock);
        if ( ret < 0 )
            return ret;
    }

    spin_lock_irqsave(&ioapic_lock, flags);
    /* Set the correct irq-handling type. */
    desc->handler = rte.trigger ? 
        &ioapic_level_type: &ioapic_edge_type;

    /* Mask iff level triggered. */
    rte.mask = rte.trigger;
    /* Set the vector field to the real vector! */
    rte.vector = desc->arch.vector;

    if ( cpumask_intersects(desc->arch.cpu_mask, TARGET_CPUS) )
    {
        cpumask_t *mask = this_cpu(scratch_cpumask);

        cpumask_and(mask, desc->arch.cpu_mask, TARGET_CPUS);
        SET_DEST(rte, logical, cpu_mask_to_apicid(mask));
    }
    else
    {
        gprintk(XENLOG_ERR, "IRQ%d: no target CPU (%*pb vs %*pb)\n",
               irq, CPUMASK_PR(desc->arch.cpu_mask), CPUMASK_PR(TARGET_CPUS));
        desc->status |= IRQ_DISABLED;
        rte.mask = 1;
    }

    __ioapic_write_entry(apic, pin, 0, rte);
    
    spin_unlock_irqrestore(&ioapic_lock, flags);

    return 0;
}

static const char * delivery_mode_2_str(
    const enum ioapic_irq_destination_types mode)
{
    switch ( mode )
    {
    case dest_Fixed: return "Fixed";
    case dest_LowestPrio: return "LoPri";
    case dest_SMI: return "SMI";
    case dest_NMI: return "NMI";
    case dest_INIT: return "INIT";
    case dest_ExtINT: return "ExINT";
    case dest__reserved_1:
    case dest__reserved_2: return "Resvd";
    default: return "INVAL";
    }
}

void dump_ioapic_irq_info(void)
{
    struct irq_pin_list *entry;
    struct IO_APIC_route_entry rte;
    unsigned int irq, pin, printed = 0;

    if ( !irq_2_pin )
        return;

    for ( irq = 0; irq < nr_irqs_gsi; irq++ )
    {
        if ( !(irq & 0x1f) )
            process_pending_softirqs();

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

            rte = ioapic_read_entry(entry->apic, pin, 0);

            printk("vec=%02x delivery=%-5s dest=%c status=%d "
                   "polarity=%d irr=%d trig=%c mask=%d dest_id:%0*x\n",
                   rte.vector, delivery_mode_2_str(rte.delivery_mode),
                   rte.dest_mode ? 'L' : 'P',
                   rte.delivery_status, rte.polarity, rte.irr,
                   rte.trigger ? 'L' : 'E', rte.mask,
                   x2apic_enabled ? 8 : 2,
                   x2apic_enabled ? rte.dest.dest32
                                  : rte.dest.logical.logical_dest);

            if ( entry->next == 0 )
                break;
            entry = &irq_2_pin[entry->next];
        }
    }
}

static unsigned int __initdata max_gsi_irqs;
integer_param("max_gsi_irqs", max_gsi_irqs);

static __init bool bad_ioapic_register(unsigned int idx)
{
    union IO_APIC_reg_00 reg_00 = { .raw = io_apic_read(idx, 0) };
    union IO_APIC_reg_01 reg_01 = { .raw = io_apic_read(idx, 1) };
    union IO_APIC_reg_02 reg_02 = { .raw = io_apic_read(idx, 2) };

    if ( reg_00.raw == -1 && reg_01.raw == -1 && reg_02.raw == -1 )
    {
        printk(KERN_WARNING "I/O APIC %#x registers return all ones, skipping!\n",
               mp_ioapics[idx].mpc_apicaddr);
        return 1;
    }

    return 0;
}

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
                smp_found_config = false;
                skip_ioapic_setup = true;
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
        apic_printk(APIC_VERBOSE, "mapped IOAPIC to %08Lx (%08lx)\n",
                    __fix_to_virt(idx), ioapic_phys);
        idx++;

        if ( bad_ioapic_register(i) )
        {
            clear_fixmap(idx);
            continue;
        }

        if ( smp_found_config )
        {
            /* The number of IO-APIC IRQ registers (== #pins): */
            reg_01.raw = io_apic_read(i, 1);
            nr_ioapic_entries[i] = reg_01.bits.entries + 1;
            nr_irqs_gsi += nr_ioapic_entries[i];

            if ( rangeset_add_singleton(mmio_ro_ranges,
                                        ioapic_phys >> PAGE_SHIFT) )
                printk(KERN_ERR "Failed to mark IO-APIC page %lx read-only\n",
                       ioapic_phys);
        }
    }

    nr_irqs_gsi = max(nr_irqs_gsi, highest_gsi() + 1);

    if ( max_gsi_irqs == 0 )
        max_gsi_irqs = nr_irqs ? nr_irqs / 8 : PAGE_SIZE;
    else if ( nr_irqs != 0 && max_gsi_irqs > nr_irqs )
    {
        printk(XENLOG_WARNING "\"max_gsi_irqs=\" cannot be specified larger"
                              " than \"nr_irqs=\"\n");
        max_gsi_irqs = nr_irqs;
    }
    if ( max_gsi_irqs < 16 )
        max_gsi_irqs = 16;

    /* for PHYSDEVOP_pirq_eoi_gmfn guest assumptions */
    if ( max_gsi_irqs > PAGE_SIZE * 8 )
        max_gsi_irqs = PAGE_SIZE * 8;

    if ( !smp_found_config || skip_ioapic_setup || nr_irqs_gsi < 16 )
        nr_irqs_gsi = 16;
    else if ( nr_irqs_gsi > max_gsi_irqs )
    {
        printk(XENLOG_WARNING "Limiting to %u GSI IRQs (found %u)\n",
               max_gsi_irqs, nr_irqs_gsi);
        nr_irqs_gsi = max_gsi_irqs;
    }

    if ( nr_irqs == 0 )
        nr_irqs = cpu_has_apic ?
                  max(16U + num_present_cpus() * NR_DYNAMIC_VECTORS,
                      8 * nr_irqs_gsi) :
                  nr_irqs_gsi;
    else if ( nr_irqs < 16 )
        nr_irqs = 16;
    printk(XENLOG_INFO "IRQ limits: %u GSI, %u MSI/MSI-X\n",
           nr_irqs_gsi, nr_irqs - nr_irqs_gsi);
}

unsigned int arch_hwdom_irqs(domid_t domid)
{
    unsigned int n = fls(num_present_cpus());

    if ( !domid )
        n = min(n, dom0_max_vcpus());
    n = min(nr_irqs_gsi + n * NR_DYNAMIC_VECTORS, nr_irqs);

    /* Bounded by the domain pirq eoi bitmap gfn. */
    n = min_t(unsigned int, n, PAGE_SIZE * BITS_PER_BYTE);

    printk("Dom%d has maximum %u PIRQs\n", domid, n);

    return n;
}
