/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#if defined(CONFIG_X86)
#include <xen/arch-x86/xen.h>
#include <xen/hvm/hvm_info_table.h>
#elif defined(CONFIG_ARM_64)
#include <xen/arch-arm.h>
#endif

static unsigned int indent_level;
static bool debug = false;

typedef enum dm_version {
    QEMU_NONE,
    QEMU_XEN_TRADITIONAL,
    QEMU_XEN,
} dm_version;

static void indent(void)
{
    unsigned int i;
    for ( i = 0; i < indent_level; i++ )
        printf("    ");
}

static __attribute__((format(printf, 2, 3)))
void _stmt(const char *name, const char *fmt, ...)
{
    va_list args;

    indent();
    printf("%s", name);

    if ( !fmt )
        return;

    printf(" ( ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf(" )");
}

#define stmt(n, f, a...)                        \
    do {                                        \
        _stmt(n, f , ## a );                    \
        printf("\n");                           \
    } while (0)

#define push_block(n, f, a...)                  \
    do {                                        \
        _stmt(n, f , ## a );                    \
        printf(" {\n");                         \
        indent_level++;                         \
    } while (0)

static void pop_block(void)
{
    indent_level--;
    indent();
    printf("}\n");
}

#ifdef CONFIG_X86
static void pci_hotplug_notify(unsigned int slt)
{
    stmt("Notify", "\\_SB.PCI0.S%02X, EVT", slt);
}

static void decision_tree(
    unsigned int s, unsigned int e, char *var, void (*leaf)(unsigned int))
{
    if ( s == (e-1) )
    {
        (*leaf)(s);
        return;
    }

    push_block("If", "And(%s, 0x%02x)", var, (e-s)/2);
    decision_tree((s+e)/2, e, var, leaf);
    pop_block();
    push_block("Else", NULL);
    decision_tree(s, (s+e)/2, var, leaf);
    pop_block();
}
#endif

static struct option options[] = {
    { "maxcpu", 1, 0, 'c' },
#ifdef CONFIG_X86
    { "dm-version", 1, 0, 'q' },
#endif
    { "debug", 1, 0, 'd' },
    { 0, 0, 0, 0 }
};

int main(int argc, char **argv)
{
    unsigned int cpu, max_cpus;
#if defined(CONFIG_X86)
    dm_version dm_version = QEMU_XEN_TRADITIONAL;
    unsigned int slot, dev, intx, link;

    max_cpus = HVM_MAX_VCPUS;
#elif defined(CONFIG_ARM_64)
    max_cpus = GUEST_MAX_VCPUS;
#endif

    for ( ; ; )
    {
        int opt = getopt_long(argc, argv, "", options, NULL);
        if ( opt == -1 )
            break;

        switch ( opt )
        {
        case 'c': {
            long i = 0;
            char *endptr;

            i = strtol(optarg, &endptr, 10);
            if ( (*optarg != '\0') && (*endptr == '\0') && (i >= 0) )
            {
                max_cpus = i;
            }
            else if ( !(strcmp(optarg, "any") == 0) )
            {
                fprintf(stderr, "`%s' is not a number or is < 0.\n", optarg);
                return -1;
            }
            break;
        }
#ifdef CONFIG_X86
        case 'q':
            if (strcmp(optarg, "qemu-xen") == 0) {
                dm_version = QEMU_XEN;
            } else if (strcmp(optarg, "qemu-xen-traditional") == 0) {
                dm_version = QEMU_XEN_TRADITIONAL;
            } else if (strcmp(optarg, "none") == 0) {
                dm_version = QEMU_NONE;
            } else {
                fprintf(stderr, "Unknown device model version `%s'.\n", optarg);
                return -1;
            }
            break;
#endif
        case 'd':
            if (*optarg == 'y')
                debug = true;
            break;
        default:
            return -1;
        }
    }

    /**** DSDT DefinitionBlock start ****/
    /* (we append to existing DSDT definition block) */
    indent_level++;

    /**** Processor start ****/
    push_block("Scope", "\\_SB");

#ifdef CONFIG_X86
    /* MADT checksum */
    stmt("OperationRegion", "MSUM, SystemMemory, \\_SB.MSUA, 1");
    push_block("Field", "MSUM, ByteAcc, NoLock, Preserve");
    indent(); printf("MSU, 8\n");
    pop_block();

    /* Processor object helpers. */
    push_block("Method", "PMAT, 2");
    push_block("If", "LLess(Arg0, NCPU)");
    stmt("Return", "ToBuffer(Arg1)");
    pop_block();
    stmt("Return", "Buffer() {0, 8, 0xff, 0xff, 0, 0, 0, 0}");
    pop_block();
#endif

    /* Define processor objects and control methods. */
    for ( cpu = 0; cpu < max_cpus; cpu++)
    {
        push_block("Processor", "PR%02X, %d, 0x0000b010, 0x06", cpu, cpu);

        stmt("Name", "_HID, \"ACPI0007\"");

        stmt("Name", "_UID, %d", cpu);
#ifdef CONFIG_ARM_64
        pop_block();
        continue;
#endif
        /* Name this processor's MADT LAPIC descriptor. */
        stmt("OperationRegion", 
             "MATR, SystemMemory, Add(\\_SB.MAPA, %d), 8", cpu*8);

        push_block("Field", "MATR, ByteAcc, NoLock, Preserve");
        indent(); printf("MAT, 64\n");
        pop_block();

        push_block("Field", "MATR, ByteAcc, NoLock, Preserve");
        indent(); printf("Offset(4),\n");
        indent(); printf("FLG, 1\n");
        pop_block();

        push_block("Method", "_MAT, 0");
        if ( cpu )
            stmt("Return", "PMAT (%d, MAT)", cpu);
        else
            stmt("Return", "ToBuffer(MAT)");
        pop_block();

        push_block("Method", "_STA");
        if ( cpu )
            push_block("If", "LLess(%d, \\_SB.NCPU)", cpu);
        push_block("If", "FLG");
        stmt("Return", "0xF");
        pop_block();
        if ( cpu )
            pop_block();
        stmt("Return", "0x0");
        pop_block();

        push_block("Method", "_EJ0, 1, NotSerialized");
        stmt("Sleep", "0xC8");
        pop_block();

        pop_block();
    }

#ifdef CONFIG_ARM_64
    pop_block();
    /**** Processor end ****/
#else

    /* Operation Region 'PRST': bitmask of online CPUs. */
    stmt("OperationRegion", "PRST, SystemIO, %#x, %d",
        XEN_ACPI_CPU_MAP, XEN_ACPI_CPU_MAP_LEN);
    push_block("Field", "PRST, ByteAcc, NoLock, Preserve");
    indent(); printf("PRS, %u\n", max_cpus);
    pop_block();

    /* Control method 'PRSC': CPU hotplug GPE handler. */
    push_block("Method", "PRSC, 0");
    stmt("Store", "ToBuffer(PRS), Local0");
    for ( cpu = 0; cpu < max_cpus; cpu++ )
    {
        /* Read a byte at a time from the PRST online-CPU bitmask. */
        if ( (cpu & 7) == 0 )
            stmt("Store", "DerefOf(Index(Local0, %u)), Local1", cpu/8);
        else
            stmt("ShiftRight", "Local1, 1, Local1");
        /* Extract current CPU's status: 0=offline; 1=online. */
        stmt("And", "Local1, 1, Local2");
        /* Check if status is up-to-date in the relevant MADT LAPIC entry... */
        push_block("If", "LNotEqual(Local2, \\_SB.PR%02X.FLG)", cpu);
        /* ...If not, update it and the MADT checksum, and notify OSPM. */
        stmt("Store", "Local2, \\_SB.PR%02X.FLG", cpu);
        push_block("If", "LEqual(Local2, 1)");
        stmt("Notify", "PR%02X, 1", cpu); /* Notify: Device Check */
        stmt("Subtract", "\\_SB.MSU, 1, \\_SB.MSU"); /* Adjust MADT csum */
        pop_block();
        push_block("Else", NULL);
        stmt("Notify", "PR%02X, 3", cpu); /* Notify: Eject Request */
        stmt("Add", "\\_SB.MSU, 1, \\_SB.MSU"); /* Adjust MADT csum */
        pop_block();
        pop_block();
    }
    stmt("Return", "One");
    pop_block();

    pop_block();

    /* Define GPE control method. */
    push_block("Scope", "\\_GPE");
    push_block("Method",
               dm_version == QEMU_XEN_TRADITIONAL ? "_L%02d" : "_E%02d",
               XEN_ACPI_GPE0_CPUHP_BIT);
    stmt("\\_SB.PRSC ()", NULL);
    pop_block();
    pop_block();

    if (dm_version == QEMU_NONE) {
        pop_block();
        return 0;
    }
    /**** Processor end ****/


    /**** PCI0 start ****/
    push_block("Scope", "\\_SB.PCI0");

    /*
     * Reserve the IO port ranges [0x10c0, 0x1101] and [0xb044, 0xb047].
     * Or else, for a hotplugged-in device, the port IO BAR assigned
     * by guest OS may conflict with the ranges here.
     */
    push_block("Device", "HP0"); {
        stmt("Name", "_HID, EISAID(\"PNP0C02\")");
        if (dm_version == QEMU_XEN_TRADITIONAL) {
            stmt("Name", "_CRS, ResourceTemplate() {"
                 "  IO (Decode16, 0x10c0, 0x10c0, 0x00, 0x82)"
                 "  IO (Decode16, 0xb044, 0xb044, 0x00, 0x04)"
                 "}");
        } else {
            stmt("Name", "_CRS, ResourceTemplate() {"
                 "  IO (Decode16, 0xae00, 0xae00, 0x00, 0x10)"
                 "  IO (Decode16, 0xb044, 0xb044, 0x00, 0x04)"
                 "}");
        }
    } pop_block();

    /*** PCI-ISA link definitions ***/
    /* BUFA: List of ISA IRQs available for linking to PCI INTx. */
    stmt("Name", "BUFA, ResourceTemplate() { "
         "IRQ(Level, ActiveLow, Shared) { 5, 10, 11 } }");
    /* BUFB: IRQ descriptor for returning from link-device _CRS methods. */
    stmt("Name", "BUFB, Buffer() { "
         "0x23, 0x00, 0x00, 0x18, " /* IRQ descriptor */
         "0x79, 0 }");              /* End tag, null checksum */
    stmt("CreateWordField", "BUFB, 0x01, IRQV");
    /* Create four PCI-ISA link devices: LNKA, LNKB, LNKC, LNKD. */
    for ( link = 0; link < 4; link++ )
    {
        push_block("Device", "LNK%c", 'A'+link);
        stmt("Name", "_HID,  EISAID(\"PNP0C0F\")");  /* PCI interrupt link */
        stmt("Name", "_UID, %u", link+1);
        push_block("Method", "_STA, 0");
        push_block("If", "And(PIR%c, 0x80)", 'A'+link);
        stmt("Return", "0x09");
        pop_block();
        push_block("Else", NULL);
        stmt("Return", "0x0B");
        pop_block();
        pop_block();
        push_block("Method", "_PRS");
        stmt("Return", "BUFA");
        pop_block();
        push_block("Method", "_DIS");
        stmt("Or", "PIR%c, 0x80, PIR%c", 'A'+link, 'A'+link);
        pop_block();
        push_block("Method", "_CRS");
        stmt("And", "PIR%c, 0x0f, Local0", 'A'+link);
        stmt("ShiftLeft", "0x1, Local0, IRQV");
        stmt("Return", "BUFB");
        pop_block();
        push_block("Method", "_SRS, 1");
        stmt("CreateWordField", "ARG0, 0x01, IRQ1");
        stmt("FindSetRightBit", "IRQ1, Local0");
        stmt("Decrement", "Local0");
        stmt("Store", "Local0, PIR%c", 'A'+link);
        pop_block();
        pop_block();
    }

    /*** PCI interrupt routing definitions***/
    /* _PRT: Method to return routing table. */
    push_block("Method", "_PRT, 0");
    push_block("If", "PICD");
    stmt("Return", "PRTA");
    pop_block();
    stmt("Return", "PRTP");
    pop_block();
    /* PRTP: PIC routing table (via ISA links). */
    printf("Name(PRTP, Package() {\n");
    for ( dev = 1; dev < 32; dev++ )
        for ( intx = 0; intx < 4; intx++ ) /* INTA-D */
            printf("Package(){0x%04xffff, %u, \\_SB.PCI0.LNK%c, 0},\n",
                   dev, intx, 'A'+((dev+intx)&3));
    printf("})\n");
    /* PRTA: APIC routing table (via non-legacy IOAPIC GSIs). */
    printf("Name(PRTA, Package() {\n");
    for ( dev = 1; dev < 32; dev++ )
        for ( intx = 0; intx < 4; intx++ ) /* INTA-D */
            printf("Package(){0x%04xffff, %u, 0, %u},\n",
                   dev, intx, ((dev*4+dev/8+intx)&31)+16);
    printf("})\n");

    /*
     * Each PCI hotplug slot needs at least two methods to handle
     * the ACPI event:
     *  _EJ0: eject a device
     *  _STA: return a device's status, e.g. enabled or removed
     * 
     * Eject button would generate a general-purpose event, then the
     * control method for this event uses Notify() to inform OSPM which
     * action happened and on which device.
     *
     * Pls. refer "6.3 Device Insertion, Removal, and Status Objects"
     * in ACPI spec 3.0b for details.
     *
     * QEMU provides a simple hotplug controller with some I/O to handle
     * the hotplug action and status, which is beyond the ACPI scope.
     */
    if (dm_version == QEMU_XEN_TRADITIONAL) {
        for ( slot = 0; slot < 0x100; slot++ )
        {
            push_block("Device", "S%02X", slot);
            /* _ADR == dev:fn (16:16) */
            stmt("Name", "_ADR, 0x%08x", ((slot & ~7) << 13) | (slot & 7));
            /* _SUN == dev */
            stmt("Name", "_SUN, 0x%08x", slot >> 3);
            push_block("Method", "_EJ0, 1");
            if (debug)
            {
                stmt("Store", "0x%02x, \\_GPE.DPT1", slot);
                stmt("Store", "0x88, \\_GPE.DPT2");
            }
            stmt("Store", "0x%02x, \\_GPE.PH%02X", /* eject */
                 (slot & 1) ? 0x10 : 0x01, slot & ~1);
            pop_block();
            push_block("Method", "_STA, 0");
            if (debug)
            {
                stmt("Store", "0x%02x, \\_GPE.DPT1", slot);
                stmt("Store", "0x89, \\_GPE.DPT2");
            }
            if ( slot & 1 )
                stmt("ShiftRight", "0x4, \\_GPE.PH%02X, Local1", slot & ~1);
            else
                stmt("And", "\\_GPE.PH%02X, 0x0f, Local1", slot & ~1);
            stmt("Return", "Local1"); /* IN status as the _STA */
            pop_block();
            pop_block();
        }
    } else {
        stmt("OperationRegion", "SEJ, SystemIO, 0xae08, 0x08");
        push_block("Field", "SEJ, DWordAcc, NoLock, WriteAsZeros");
        indent(); printf("B0EJ, 32,\n");
        indent(); printf("B0RM, 32,\n");
        pop_block();

        /* hotplug_slot */
        for (slot = 1; slot <= 31; slot++) {
            push_block("Device", "S%i", slot); {
                stmt("Name", "_ADR, %#06x0000", slot);
                push_block("Method", "_EJ0,1"); {
                    stmt("Store", "%#010x, B0EJ", 1 << slot);
                } pop_block();
                stmt("Name", "_SUN, %i", slot);
                push_block("Method", "_STA, 0"); {
                    push_block("If", "And(B0RM, ShiftLeft(1, %i))", slot);
                    stmt("Return", "0xF");
                    pop_block();
                    stmt("Return", "0x0");
                } pop_block();
            } pop_block();
        }
    }

    pop_block();
    /**** PCI0 end ****/


    /**** GPE start ****/
    push_block("Scope", "\\_GPE");

    if (dm_version == QEMU_XEN_TRADITIONAL) {
        stmt("OperationRegion", "PHP, SystemIO, 0x10c0, 0x82");

        push_block("Field", "PHP, ByteAcc, NoLock, Preserve");
        indent(); printf("PSTA, 8,\n"); /* hotplug controller event reg */
        indent(); printf("PSTB, 8,\n"); /* hotplug controller slot reg */
        for ( slot = 0; slot < 0x100; slot += 2 )
        {
            indent();
            /* Each hotplug control register manages a pair of pci functions. */
            printf("PH%02X, 8,\n", slot);
        }
        pop_block();
    } else {
        stmt("OperationRegion", "PCST, SystemIO, 0xae00, 0x08");
        push_block("Field", "PCST, DWordAcc, NoLock, WriteAsZeros");
        indent(); printf("PCIU, 32,\n");
        indent(); printf("PCID, 32,\n");
        pop_block();
    }

    stmt("OperationRegion", "DG1, SystemIO, 0xb044, 0x04");

    push_block("Field", "DG1, ByteAcc, NoLock, Preserve");
    indent(); printf("DPT1, 8, DPT2, 8\n");
    pop_block();

    if (dm_version == QEMU_XEN_TRADITIONAL) {
        push_block("Method", "_L03, 0, Serialized");
        /* Detect slot and event (remove/add). */
        stmt("Name", "SLT, 0x0");
        stmt("Name", "EVT, 0x0");
        stmt("Store", "PSTA, Local1");
        stmt("And", "Local1, 0xf, EVT");
        stmt("Store", "PSTB, Local1"); /* XXX: Store (PSTB, SLT) ? */
        stmt("And", "Local1, 0xff, SLT");
        if (debug)
        {
            stmt("Store", "SLT, DPT1");
            stmt("Store", "EVT, DPT2");
        }
        /* Decision tree */
        decision_tree(0x00, 0x100, "SLT", pci_hotplug_notify);
        pop_block();
    } else {
        push_block("Method", "_E01");
        for (slot = 1; slot <= 31; slot++) {
            push_block("If", "And(PCIU, ShiftLeft(1, %i))", slot);
            stmt("Notify", "\\_SB.PCI0.S%i, 1", slot);
            pop_block();
            push_block("If", "And(PCID, ShiftLeft(1, %i))", slot);
            stmt("Notify", "\\_SB.PCI0.S%i, 3", slot);
            pop_block();
        }
        pop_block();
    }

    pop_block();
    /**** GPE end ****/
#endif

    pop_block();
    /**** DSDT DefinitionBlock end ****/

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
