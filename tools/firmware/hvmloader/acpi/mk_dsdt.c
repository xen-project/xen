#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <xen/hvm/hvm_info_table.h>

static unsigned int indent_level;

static void indent(void)
{
    unsigned int i;
    for ( i = 0; i < indent_level; i++ )
        printf("    ");
}

static void _stmt(const char *name, const char *fmt, ...)
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

int main(void)
{
    unsigned int slot, dev, intx, link, cpu;

    /**** DSDT DefinitionBlock start ****/
    /* (we append to existing DSDT definition block) */
    indent_level++;

    /**** Processor start ****/
    push_block("Scope", "\\_PR");

    /* MADT checksum */
    stmt("OperationRegion", "MSUM, SystemMemory, \\_SB.MSUA, 1");
    push_block("Field", "MSUM, ByteAcc, NoLock, Preserve");
    indent(); printf("MSU, 8\n");
    pop_block();

    /* Define processor objects and control methods. */
    for ( cpu = 0; cpu < HVM_MAX_VCPUS; cpu++)
    {
        push_block("Processor", "PR%02X, %d, 0x0000b010, 0x06", cpu, cpu);

        stmt("Name", "_HID, \"ACPI0007\"");

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
        stmt("Return", "ToBuffer(MAT)");
        pop_block();

        push_block("Method", "_STA");
        push_block("If", "FLG");
        stmt("Return", "0xF");
        pop_block();
        push_block("Else", NULL);
        stmt("Return", "0x9");
        pop_block();
        pop_block();

        push_block("Method", "_EJ0, 1, NotSerialized");
        stmt("Sleep", "0xC8");
        pop_block();

        pop_block();
    }

    /* Operation Region 'PRST': bitmask of online CPUs. */
    stmt("OperationRegion", "PRST, SystemIO, 0xaf00, 32");
    push_block("Field", "PRST, ByteAcc, NoLock, Preserve");
    indent(); printf("PRS, %u\n", HVM_MAX_VCPUS);
    pop_block();

    /* Control method 'PRSC': CPU hotplug GPE handler. */
    push_block("Method", "PRSC, 0");
    stmt("Store", "PRS, Local0");
    for ( cpu = 0; cpu < HVM_MAX_VCPUS; cpu++ )
    {
        /* Read a byte at a time from the PRST online-CPU bitmask. */
        if ( (cpu & 7) == 0 )
            stmt("Store", "DerefOf(Index(Local0, %u)), Local1", cpu/8);
        else
            stmt("ShiftRight", "Local1, 1, Local1");
        /* Extract current CPU's status: 0=offline; 1=online. */
        stmt("And", "Local1, 1, Local2");
        /* Check if status is up-to-date in the relevant MADT LAPIC entry... */
        push_block("If", "LNotEqual(Local2, \\_PR.PR%02X.FLG)", cpu);
        /* ...If not, update it and the MADT checksum, and notify OSPM. */
        stmt("Store", "Local2, \\_PR.PR%02X.FLG", cpu);
        push_block("If", "LEqual(Local2, 1)");
        stmt("Notify", "PR%02X, 1", cpu); /* Notify: Device Check */
        stmt("Subtract", "\\_PR.MSU, 1, \\_PR.MSU"); /* Adjust MADT csum */
        pop_block();
        push_block("Else", NULL);
        stmt("Notify", "PR%02X, 3", cpu); /* Notify: Eject Request */
        stmt("Add", "\\_PR.MSU, 1, \\_PR.MSU"); /* Adjust MADT csum */
        pop_block();
        pop_block();
    }
    stmt("Return", "One");
    pop_block();

    pop_block();

    /* Define GPE control method '_L02'. */
    push_block("Scope", "\\_GPE");
    push_block("Method", "_L02");
    stmt("Return", "\\_PR.PRSC()");
    pop_block();
    pop_block();
    /**** Processor end ****/


    /**** PCI0 start ****/
    push_block("Scope", "\\_SB.PCI0");

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
     * Other methods are optional: 
     *  _PS0/3: put them here for debug purpose
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
    for ( slot = 0; slot < 0x100; slot++ )
    {
        push_block("Device", "S%02X", slot);
        /* _ADR == dev:fn (16:16) */
        stmt("Name", "_ADR, 0x%08x", ((slot & ~7) << 13) | (slot & 7));
        /* _SUN == dev */
        stmt("Name", "_SUN, 0x%08x", slot >> 3);
        push_block("Method", "_PS0, 0");
        stmt("Store", "0x%02x, \\_GPE.DPT1", slot);
        stmt("Store", "0x80, \\_GPE.DPT2");
        pop_block();
        push_block("Method", "_PS3, 0");
        stmt("Store", "0x%02x, \\_GPE.DPT1", slot);
        stmt("Store", "0x83, \\_GPE.DPT2");
        pop_block();
        push_block("Method", "_EJ0, 1");
        stmt("Store", "0x%02x, \\_GPE.DPT1", slot);
        stmt("Store", "0x88, \\_GPE.DPT2");
        stmt("Store", "0x%02x, \\_GPE.PH%02X", /* eject */
             (slot & 1) ? 0x10 : 0x01, slot & ~1);
        pop_block();
        push_block("Method", "_STA, 0");
        stmt("Store", "0x%02x, \\_GPE.DPT1", slot);
        stmt("Store", "0x89, \\_GPE.DPT2");
        if ( slot & 1 )
            stmt("ShiftRight", "0x4, \\_GPE.PH%02X, Local1", slot & ~1);
        else
            stmt("And", "\\_GPE.PH%02X, 0x0f, Local1", slot & ~1);
        stmt("Return", "Local1"); /* IN status as the _STA */
        pop_block();
        pop_block();
    }

    pop_block();
    /**** PCI0 end ****/


    /**** GPE start ****/
    push_block("Scope", "\\_GPE");

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

    stmt("OperationRegion", "DG1, SystemIO, 0xb044, 0x04");

    push_block("Field", "DG1, ByteAcc, NoLock, Preserve");
    indent(); printf("DPT1, 8, DPT2, 8\n");
    pop_block();

    push_block("Method", "_L03, 0, Serialized");
    /* Detect slot and event (remove/add). */
    stmt("Name", "SLT, 0x0");
    stmt("Name", "EVT, 0x0");
    stmt("Store", "PSTA, Local1");
    stmt("And", "Local1, 0xf, EVT");
    stmt("Store", "PSTB, Local1"); /* XXX: Store (PSTB, SLT) ? */
    stmt("And", "Local1, 0xff, SLT");
    /* Debug */
    stmt("Store", "SLT, DPT1");
    stmt("Store", "EVT, DPT2");
    /* Decision tree */
    decision_tree(0x00, 0x100, "SLT", pci_hotplug_notify);
    pop_block();

    pop_block();
    /**** GPE end ****/


    pop_block();
    /**** DSDT DefinitionBlock end ****/

    return 0;
}
