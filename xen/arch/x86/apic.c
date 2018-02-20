/*
 *      based on linux-2.6.17.13/arch/i386/kernel/apic.c
 *
 *  Local APIC handling, local APIC timers
 *
 *  (c) 1999, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *  Fixes
 *  Maciej W. Rozycki   :   Bits for genuine 82489DX APICs;
 *                  thanks to Eric Gilmore
 *                  and Rolf G. Tews
 *                  for testing these extensively.
 *    Maciej W. Rozycki :   Various updates and fixes.
 *    Mikael Pettersson :   Power Management for UP-APIC.
 *    Pavel Machek and
 *    Mikael Pettersson    :    PM converted to driver model.
 */

#include <xen/perfc.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <asm/mc146818rtc.h>
#include <asm/msr.h>
#include <asm/atomic.h>
#include <asm/mpspec.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <mach_apic.h>
#include <io_ports.h>
#include <xen/kexec.h>
#include <asm/guest.h>
#include <asm/time.h>

static bool __read_mostly tdt_enabled;
static bool __initdata tdt_enable = true;
boolean_param("tdt", tdt_enable);

static struct {
    int active;
    /* r/w apic fields */
    unsigned int apic_id;
    unsigned int apic_taskpri;
    unsigned int apic_ldr;
    unsigned int apic_dfr;
    unsigned int apic_spiv;
    unsigned int apic_lvtt;
    unsigned int apic_lvtpc;
    unsigned int apic_lvtcmci;
    unsigned int apic_lvt0;
    unsigned int apic_lvt1;
    unsigned int apic_lvterr;
    unsigned int apic_tmict;
    unsigned int apic_tdcr;
    unsigned int apic_thmr;
} apic_pm_state;

/*
 * Knob to control our willingness to enable the local APIC.
 */
static s8 __initdata enable_local_apic; /* -1=force-disable, +1=force-enable */

/*
 * Debug level
 */
u8 __read_mostly apic_verbosity;

static bool __initdata opt_x2apic = true;
boolean_param("x2apic", opt_x2apic);

/*
 * Bootstrap processor local APIC boot mode - so we can undo our changes
 * to the APIC state.
 */
static enum apic_mode apic_boot_mode = APIC_MODE_INVALID;

bool __read_mostly x2apic_enabled;
bool __read_mostly directed_eoi_enabled;

static int modern_apic(void)
{
    unsigned int lvr, version;
    /* AMD systems use old APIC versions, so check the CPU */
    if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
        boot_cpu_data.x86 >= 0xf)
        return 1;
    lvr = apic_read(APIC_LVR);
    version = GET_APIC_VERSION(lvr);
    return version >= 0x14;
}

/*
 * 'what should we do if we get a hw irq event on an illegal vector'.
 * each architecture has to answer this themselves.
 */
void ack_bad_irq(unsigned int irq)
{
    printk("unexpected IRQ trap at irq %02x\n", irq);
    /*
     * Currently unexpected vectors happen only on SMP and APIC.
     * We _must_ ack these because every local APIC has only N
     * irq slots per priority level, and a 'hanging, unacked' IRQ
     * holds up an irq slot - in excessive cases (when multiple
     * unexpected vectors occur) that might lock up the APIC
     * completely.
     * But only ack when the APIC is enabled -AK
     */
    if (cpu_has_apic)
        ack_APIC_irq();
}

void __init apic_intr_init(void)
{
    smp_intr_init();

    /* self generated IPI for local APIC timer */
    set_direct_apic_vector(LOCAL_TIMER_VECTOR, apic_timer_interrupt);

    /* IPI vectors for APIC spurious and error interrupts */
    set_direct_apic_vector(SPURIOUS_APIC_VECTOR, spurious_interrupt);
    set_direct_apic_vector(ERROR_APIC_VECTOR, error_interrupt);

    /* Performance Counters Interrupt */
    set_direct_apic_vector(PMU_APIC_VECTOR, pmu_apic_interrupt);
}

/* Using APIC to generate smp_local_timer_interrupt? */
static bool __read_mostly using_apic_timer;

static bool __read_mostly enabled_via_apicbase;

int get_physical_broadcast(void)
{
    if (modern_apic())
        return 0xff;
    else
        return 0xf;
}

int get_maxlvt(void)
{
    unsigned int v = apic_read(APIC_LVR);

    return GET_APIC_MAXLVT(v);
}

void clear_local_APIC(void)
{
    int maxlvt;
    unsigned long v;

    maxlvt = get_maxlvt();

    /* Work around AMD Erratum 411. This is a nice thing to do anyway. */
    apic_write(APIC_TMICT, 0);

    /*
     * Masking an LVT entry on a P6 can trigger a local APIC error
     * if the vector is zero. Mask LVTERR first to prevent this.
     */
    if (maxlvt >= 3) {
        v = ERROR_APIC_VECTOR; /* any non-zero vector will do */
        apic_write(APIC_LVTERR, v | APIC_LVT_MASKED);
    }
    /*
     * Careful: we have to set masks only first to deassert
     * any level-triggered sources.
     */
    v = apic_read(APIC_LVTT);
    apic_write(APIC_LVTT, v | APIC_LVT_MASKED);
    v = apic_read(APIC_LVT0);
    apic_write(APIC_LVT0, v | APIC_LVT_MASKED);
    v = apic_read(APIC_LVT1);
    apic_write(APIC_LVT1, v | APIC_LVT_MASKED);
    if (maxlvt >= 4) {
        v = apic_read(APIC_LVTPC);
        apic_write(APIC_LVTPC, v | APIC_LVT_MASKED);
    }

/* lets not touch this if we didn't frob it */
#ifdef CONFIG_X86_MCE_THERMAL
    if (maxlvt >= 5) {
        v = apic_read(APIC_LVTTHMR);
        apic_write(APIC_LVTTHMR, v | APIC_LVT_MASKED);
    }
#endif

    if (maxlvt >= 6) {
        v = apic_read(APIC_CMCI);
        apic_write(APIC_CMCI, v | APIC_LVT_MASKED);
    }
    /*
     * Clean APIC state for other OSs:
     */
    apic_write(APIC_LVTT, APIC_LVT_MASKED);
    apic_write(APIC_LVT0, APIC_LVT_MASKED);
    apic_write(APIC_LVT1, APIC_LVT_MASKED);
    if (maxlvt >= 3)
        apic_write(APIC_LVTERR, APIC_LVT_MASKED);
    if (maxlvt >= 4)
        apic_write(APIC_LVTPC, APIC_LVT_MASKED);

#ifdef CONFIG_X86_MCE_THERMAL
    if (maxlvt >= 5)
        apic_write(APIC_LVTTHMR, APIC_LVT_MASKED);
#endif
    if (maxlvt >= 6)
        apic_write(APIC_CMCI, APIC_LVT_MASKED);

    if (maxlvt > 3)        /* Due to Pentium errata 3AP and 11AP. */
        apic_write(APIC_ESR, 0);
    apic_read(APIC_ESR);
}

void __init connect_bsp_APIC(void)
{
    if (pic_mode) {
        /*
         * Do not trust the local APIC being empty at bootup.
         */
        clear_local_APIC();
        /*
         * PIC mode, enable APIC mode in the IMCR, i.e.
         * connect BSP's local APIC to INT and NMI lines.
         */
        apic_printk(APIC_VERBOSE, "leaving PIC mode, "
                    "enabling APIC mode.\n");
        outb(0x70, 0x22);
        outb(0x01, 0x23);
    }
    enable_apic_mode();
}

void disconnect_bsp_APIC(int virt_wire_setup)
{
    if (pic_mode) {
        /*
         * Put the board back into PIC mode (has an effect
         * only on certain older boards).  Note that APIC
         * interrupts, including IPIs, won't work beyond
         * this point!  The only exception are INIT IPIs.
         */
        apic_printk(APIC_VERBOSE, "disabling APIC mode, "
                    "entering PIC mode.\n");
        outb(0x70, 0x22);
        outb(0x00, 0x23);
    }
    else {
        /* Go back to Virtual Wire compatibility mode */
        unsigned long value;

        /* For the spurious interrupt use vector F, and enable it */
        value = apic_read(APIC_SPIV);
        value &= ~APIC_VECTOR_MASK;
        value |= APIC_SPIV_APIC_ENABLED;
        value |= 0xf;
        apic_write(APIC_SPIV, value);

        if (!virt_wire_setup) {
            /* For LVT0 make it edge triggered, active high, external and enabled */
            value = apic_read(APIC_LVT0);
            value &= ~(APIC_MODE_MASK | APIC_SEND_PENDING |
                       APIC_INPUT_POLARITY | APIC_LVT_REMOTE_IRR |
                       APIC_LVT_LEVEL_TRIGGER | APIC_LVT_MASKED );
            value |= APIC_LVT_REMOTE_IRR | APIC_SEND_PENDING;
            value = SET_APIC_DELIVERY_MODE(value, APIC_MODE_EXTINT);
            apic_write(APIC_LVT0, value);
        }
        else {
            /* Disable LVT0 */
            apic_write(APIC_LVT0, APIC_LVT_MASKED);
        }

        /* For LVT1 make it edge triggered, active high, nmi and enabled */
        value = apic_read(APIC_LVT1);
        value &= ~(
            APIC_MODE_MASK | APIC_SEND_PENDING |
            APIC_INPUT_POLARITY | APIC_LVT_REMOTE_IRR |
            APIC_LVT_LEVEL_TRIGGER | APIC_LVT_MASKED);
        value |= APIC_LVT_REMOTE_IRR | APIC_SEND_PENDING;
        value = SET_APIC_DELIVERY_MODE(value, APIC_MODE_NMI);
        apic_write(APIC_LVT1, value);
    }
}

void disable_local_APIC(void)
{
    clear_local_APIC();

    /*
     * Disable APIC (implies clearing of registers
     * for 82489DX!).
     */
    apic_write(APIC_SPIV, apic_read(APIC_SPIV) & ~APIC_SPIV_APIC_ENABLED);

    if (enabled_via_apicbase) {
        uint64_t msr_content;
        rdmsrl(MSR_IA32_APICBASE, msr_content);
        wrmsrl(MSR_IA32_APICBASE, msr_content &
               ~(MSR_IA32_APICBASE_ENABLE|MSR_IA32_APICBASE_EXTD));
    }

    if ( kexecing && (current_local_apic_mode() != apic_boot_mode) )
    {
        uint64_t msr_content;
        rdmsrl(MSR_IA32_APICBASE, msr_content);
        msr_content &= ~(MSR_IA32_APICBASE_ENABLE|MSR_IA32_APICBASE_EXTD);
        wrmsrl(MSR_IA32_APICBASE, msr_content);

        switch ( apic_boot_mode )
        {
        case APIC_MODE_DISABLED:
            break; /* Nothing to do - we did this above */
        case APIC_MODE_XAPIC:
            msr_content |= MSR_IA32_APICBASE_ENABLE;
            wrmsrl(MSR_IA32_APICBASE, msr_content);
            break;
        case APIC_MODE_X2APIC:
            msr_content |= MSR_IA32_APICBASE_ENABLE;
            wrmsrl(MSR_IA32_APICBASE, msr_content);
            msr_content |= MSR_IA32_APICBASE_EXTD;
            wrmsrl(MSR_IA32_APICBASE, msr_content);
            break;
        default:
            printk("Default case when reverting #%d lapic to boot state\n",
                   smp_processor_id());
            break;
        }
    }

}

/*
 * This is to verify that we're looking at a real local APIC.
 * Check these against your board if the CPUs aren't getting
 * started for no apparent reason.
 */
int __init verify_local_APIC(void)
{
    unsigned int reg0, reg1;

    /*
     * The version register is read-only in a real APIC.
     */
    reg0 = apic_read(APIC_LVR);
    apic_printk(APIC_DEBUG, "Getting VERSION: %x\n", reg0);

    /* We don't try writing LVR in x2APIC mode since that incurs #GP. */
    if ( !x2apic_enabled )
        apic_write(APIC_LVR, reg0 ^ APIC_LVR_MASK);
    reg1 = apic_read(APIC_LVR);
    apic_printk(APIC_DEBUG, "Getting VERSION: %x\n", reg1);

    /*
     * The two version reads above should print the same
     * numbers.  If the second one is different, then we
     * poke at a non-APIC.
     */
    if (reg1 != reg0)
        return 0;

    /*
     * Check if the version looks reasonably.
     */
    reg1 = GET_APIC_VERSION(reg0);
    if (reg1 == 0x00 || reg1 == 0xff)
        return 0;
    reg1 = get_maxlvt();
    if (reg1 < 0x02 || reg1 == 0xff)
        return 0;

    /*
     * Detecting directed EOI on BSP:
     * If having directed EOI support in lapic, force to use ioapic_ack_old,
     * and enable the directed EOI for intr handling.
     */
    if ( reg0 & APIC_LVR_DIRECTED_EOI )
    {
        if ( ioapic_ack_new && ioapic_ack_forced )
            printk("Not enabling directed EOI because ioapic_ack_new has been "
                   "forced on the command line\n");
        else
        {
            ioapic_ack_new = false;
            directed_eoi_enabled = true;
            printk("Enabled directed EOI with ioapic_ack_old on!\n");
        }
    }

    /*
     * The ID register is read/write in a real APIC.
     */
    reg0 = apic_read(APIC_ID);
    apic_printk(APIC_DEBUG, "Getting ID: %x\n", reg0);

    /*
     * The next two are just to see if we have sane values.
     * They're only really relevant if we're in Virtual Wire
     * compatibility mode, but most boxes are anymore.
     */
    reg0 = apic_read(APIC_LVT0);
    apic_printk(APIC_DEBUG, "Getting LVT0: %x\n", reg0);
    reg1 = apic_read(APIC_LVT1);
    apic_printk(APIC_DEBUG, "Getting LVT1: %x\n", reg1);

    return 1;
}

void __init sync_Arb_IDs(void)
{
    /* Unsupported on P4 - see Intel Dev. Manual Vol. 3, Ch. 8.6.1
       And not needed on AMD */
    if (modern_apic())
        return;
    /*
     * Wait for idle.
     */
    apic_wait_icr_idle();

    apic_printk(APIC_DEBUG, "Synchronizing Arb IDs.\n");
    apic_write(APIC_ICR, APIC_DEST_ALLINC | APIC_INT_LEVELTRIG | APIC_DM_INIT);
}

/*
 * An initial setup of the virtual wire mode.
 */
void __init init_bsp_APIC(void)
{
    unsigned long value;

    /*
     * Don't do the setup now if we have a SMP BIOS as the
     * through-I/O-APIC virtual wire mode might be active.
     */
    if (smp_found_config || !cpu_has_apic)
        return;

    /*
     * Do not trust the local APIC being empty at bootup.
     */
    clear_local_APIC();
    
    /*
     * Enable APIC.
     */
    value = apic_read(APIC_SPIV);
    value &= ~APIC_VECTOR_MASK;
    value |= APIC_SPIV_APIC_ENABLED;
    
    /* This bit is reserved on P4/Xeon and should be cleared */
    if ((boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) && (boot_cpu_data.x86 == 15))
        value &= ~APIC_SPIV_FOCUS_DISABLED;
    else
        value |= APIC_SPIV_FOCUS_DISABLED;
    value |= SPURIOUS_APIC_VECTOR;
    apic_write(APIC_SPIV, value);

    /*
     * Set up the virtual wire mode.
     */
    apic_write(APIC_LVT0, APIC_DM_EXTINT);
    apic_write(APIC_LVT1, APIC_DM_NMI);
}

static void apic_pm_activate(void)
{
    apic_pm_state.active = 1;
}

static void __enable_x2apic(void)
{
    uint64_t msr_content;

    rdmsrl(MSR_IA32_APICBASE, msr_content);
    if ( !(msr_content & MSR_IA32_APICBASE_EXTD) )
    {
        msr_content |= MSR_IA32_APICBASE_ENABLE | MSR_IA32_APICBASE_EXTD;
        msr_content = (uint32_t)msr_content;
        wrmsrl(MSR_IA32_APICBASE, msr_content);
    }
}

static void resume_x2apic(void)
{
    struct IO_APIC_route_entry **ioapic_entries = NULL;

    ASSERT(x2apic_enabled);

    ioapic_entries = alloc_ioapic_entries();
    if ( !ioapic_entries )
    {
        printk("Allocate ioapic_entries failed\n");
        goto out;
    }

    if ( save_IO_APIC_setup(ioapic_entries) )
    {
        printk("Saving IO-APIC state failed\n");
        goto out;
    }

    mask_8259A();
    mask_IO_APIC_setup(ioapic_entries);

    iommu_enable_x2apic_IR();
    __enable_x2apic();

    restore_IO_APIC_setup(ioapic_entries);
    unmask_8259A();

out:
    if ( ioapic_entries )
        free_ioapic_entries(ioapic_entries);
}

void setup_local_APIC(void)
{
    unsigned long oldvalue, value, maxlvt;
    int i, j;

    /* Pound the ESR really hard over the head with a big hammer - mbligh */
    if (esr_disable) {
        apic_write(APIC_ESR, 0);
        apic_write(APIC_ESR, 0);
        apic_write(APIC_ESR, 0);
        apic_write(APIC_ESR, 0);
    }

    BUILD_BUG_ON((SPURIOUS_APIC_VECTOR & 0x0f) != 0x0f);

    /*
     * Double-check whether this APIC is really registered.
     */
    if (!apic_id_registered())
        BUG();

    /*
     * Intel recommends to set DFR, LDR and TPR before enabling
     * an APIC.  See e.g. "AP-388 82489DX User's Manual" (Intel
     * document number 292116).  So here it goes...
     */
    init_apic_ldr();

    /*
     * Set Task Priority to reject any interrupts below FIRST_DYNAMIC_VECTOR.
     */
    apic_write(APIC_TASKPRI, (FIRST_DYNAMIC_VECTOR & 0xF0) - 0x10);

    /*
     * After a crash, we no longer service the interrupts and a pending
     * interrupt from previous kernel might still have ISR bit set.
     *
     * Most probably by now CPU has serviced that pending interrupt and
     * it might not have done the ack_APIC_irq() because it thought,
     * interrupt came from i8259 as ExtInt. LAPIC did not get EOI so it
     * does not clear the ISR bit and cpu thinks it has already serivced
     * the interrupt. Hence a vector might get locked. It was noticed
     * for timer irq (vector 0x31). Issue an extra EOI to clear ISR.
     */
    for (i = APIC_ISR_NR - 1; i >= 0; i--) {
        value = apic_read(APIC_ISR + i*0x10);
        for (j = 31; j >= 0; j--) {
            if (value & (1u << j))
                ack_APIC_irq();
        }
    }

    /*
     * Now that we are all set up, enable the APIC
     */
    value = apic_read(APIC_SPIV);
    value &= ~APIC_VECTOR_MASK;
    /*
     * Enable APIC
     */
    value |= APIC_SPIV_APIC_ENABLED;

    /*
     * Some unknown Intel IO/APIC (or APIC) errata is biting us with
     * certain networking cards. If high frequency interrupts are
     * happening on a particular IOAPIC pin, plus the IOAPIC routing
     * entry is masked/unmasked at a high rate as well then sooner or
     * later IOAPIC line gets 'stuck', no more interrupts are received
     * from the device. If focus CPU is disabled then the hang goes
     * away, oh well :-(
     *
     * [ This bug can be reproduced easily with a level-triggered
     *   PCI Ne2000 networking cards and PII/PIII processors, dual
     *   BX chipset. ]
     */
    /*
     * Actually disabling the focus CPU check just makes the hang less
     * frequent as it makes the interrupt distributon model be more
     * like LRU than MRU (the short-term load is more even across CPUs).
     * See also the comment in end_level_ioapic_irq().  --macro
     */
#if 1
    /* Enable focus processor (bit==0) */
    value &= ~APIC_SPIV_FOCUS_DISABLED;
#else
    /* Disable focus processor (bit==1) */
    value |= APIC_SPIV_FOCUS_DISABLED;
#endif
    /*
     * Set spurious IRQ vector
     */
    value |= SPURIOUS_APIC_VECTOR;

    /*
     * Enable directed EOI
     */
    if ( directed_eoi_enabled )
    {
        value |= APIC_SPIV_DIRECTED_EOI;
        apic_printk(APIC_VERBOSE, "Suppress EOI broadcast on CPU#%d\n",
                    smp_processor_id());
    }

    apic_write(APIC_SPIV, value);

    /*
     * Set up LVT0, LVT1:
     *
     * set up through-local-APIC on the BP's LINT0. This is not
     * strictly necessery in pure symmetric-IO mode, but sometimes
     * we delegate interrupts to the 8259A.
     */
    /*
     * TODO: set up through-local-APIC from through-I/O-APIC? --macro
     */
    value = apic_read(APIC_LVT0) & APIC_LVT_MASKED;
    if (!smp_processor_id() && (pic_mode || !value)) {
        value = APIC_DM_EXTINT;
        apic_printk(APIC_VERBOSE, "enabled ExtINT on CPU#%d\n",
                    smp_processor_id());
    } else {
        value = APIC_DM_EXTINT | APIC_LVT_MASKED;
        apic_printk(APIC_VERBOSE, "masked ExtINT on CPU#%d\n",
                    smp_processor_id());
    }
    apic_write(APIC_LVT0, value);

    /*
     * only the BP should see the LINT1 NMI signal, obviously.
     */
    if (!smp_processor_id())
        value = APIC_DM_NMI;
    else
        value = APIC_DM_NMI | APIC_LVT_MASKED;
    apic_write(APIC_LVT1, value);

    if (!esr_disable) {
        maxlvt = get_maxlvt();
        if (maxlvt > 3)     /* Due to the Pentium erratum 3AP. */
            apic_write(APIC_ESR, 0);
        oldvalue = apic_read(APIC_ESR);

        value = ERROR_APIC_VECTOR;      // enables sending errors
        apic_write(APIC_LVTERR, value);
        /*
         * spec says clear errors after enabling vector.
         */
        if (maxlvt > 3)
            apic_write(APIC_ESR, 0);
        value = apic_read(APIC_ESR);
        if (value != oldvalue)
            apic_printk(APIC_VERBOSE, "ESR value before enabling "
                        "vector: %#lx  after: %#lx\n",
                        oldvalue, value);
    } else {
        /*
         * Something untraceble is creating bad interrupts on
         * secondary quads ... for the moment, just leave the
         * ESR disabled - we can't do anything useful with the
         * errors anyway - mbligh
         */
        printk("Leaving ESR disabled.\n");
    }

    if (nmi_watchdog == NMI_LOCAL_APIC && smp_processor_id())
        setup_apic_nmi_watchdog();
    apic_pm_activate();
}

int lapic_suspend(void)
{
    unsigned long flags;
    int maxlvt = get_maxlvt();
    if (!apic_pm_state.active)
        return 0;

    apic_pm_state.apic_id = apic_read(APIC_ID);
    apic_pm_state.apic_taskpri = apic_read(APIC_TASKPRI);
    apic_pm_state.apic_ldr = apic_read(APIC_LDR);
    apic_pm_state.apic_dfr = apic_read(APIC_DFR);
    apic_pm_state.apic_spiv = apic_read(APIC_SPIV);
    apic_pm_state.apic_lvtt = apic_read(APIC_LVTT);
    if (maxlvt >= 4)
        apic_pm_state.apic_lvtpc = apic_read(APIC_LVTPC);

    if (maxlvt >= 6) {
        apic_pm_state.apic_lvtcmci = apic_read(APIC_CMCI);
    }

    apic_pm_state.apic_lvt0 = apic_read(APIC_LVT0);
    apic_pm_state.apic_lvt1 = apic_read(APIC_LVT1);
    apic_pm_state.apic_lvterr = apic_read(APIC_LVTERR);
    apic_pm_state.apic_tmict = apic_read(APIC_TMICT);
    apic_pm_state.apic_tdcr = apic_read(APIC_TDCR);
    if (maxlvt >= 5)
        apic_pm_state.apic_thmr = apic_read(APIC_LVTTHMR);

    local_irq_save(flags);
    disable_local_APIC();
    iommu_disable_x2apic_IR();
    local_irq_restore(flags);
    return 0;
}

int lapic_resume(void)
{
    uint64_t msr_content;
    unsigned long flags;
    int maxlvt;

    if (!apic_pm_state.active)
        return 0;

    local_irq_save(flags);

    /*
     * Make sure the APICBASE points to the right address
     *
     * FIXME! This will be wrong if we ever support suspend on
     * SMP! We'll need to do this as part of the CPU restore!
     */
    if ( !x2apic_enabled )
    {
        rdmsrl(MSR_IA32_APICBASE, msr_content);
        msr_content &= ~MSR_IA32_APICBASE_BASE;
        wrmsrl(MSR_IA32_APICBASE,
            msr_content | MSR_IA32_APICBASE_ENABLE | mp_lapic_addr);
    }
    else
        resume_x2apic();

    maxlvt = get_maxlvt();
    apic_write(APIC_LVTERR, ERROR_APIC_VECTOR | APIC_LVT_MASKED);
    apic_write(APIC_ID, apic_pm_state.apic_id);
    apic_write(APIC_DFR, apic_pm_state.apic_dfr);
    apic_write(APIC_LDR, apic_pm_state.apic_ldr);
    apic_write(APIC_TASKPRI, apic_pm_state.apic_taskpri);
    apic_write(APIC_SPIV, apic_pm_state.apic_spiv);
    apic_write(APIC_LVT0, apic_pm_state.apic_lvt0);
    apic_write(APIC_LVT1, apic_pm_state.apic_lvt1);
    if (maxlvt >= 5)
        apic_write(APIC_LVTTHMR, apic_pm_state.apic_thmr);

    if (maxlvt >= 6) {
        apic_write(APIC_CMCI, apic_pm_state.apic_lvtcmci);
    }

    if (maxlvt >= 4)
        apic_write(APIC_LVTPC, apic_pm_state.apic_lvtpc);
    apic_write(APIC_LVTT, apic_pm_state.apic_lvtt);
    apic_write(APIC_TDCR, apic_pm_state.apic_tdcr);
    apic_write(APIC_TMICT, apic_pm_state.apic_tmict);
    apic_write(APIC_ESR, 0);
    apic_read(APIC_ESR);
    apic_write(APIC_LVTERR, apic_pm_state.apic_lvterr);
    apic_write(APIC_ESR, 0);
    apic_read(APIC_ESR);
    local_irq_restore(flags);
    return 0;
}


/*
 * Detect and enable local APICs on non-SMP boards.
 * Original code written by Keir Fraser.
 */

static int __init lapic_disable(const char *str)
{
    enable_local_apic = -1;
    setup_clear_cpu_cap(X86_FEATURE_APIC);
    return 0;
}
custom_param("nolapic", lapic_disable);
boolean_param("lapic", enable_local_apic);

static int __init apic_set_verbosity(const char *str)
{
    if (strcmp("debug", str) == 0)
        apic_verbosity = APIC_DEBUG;
    else if (strcmp("verbose", str) == 0)
        apic_verbosity = APIC_VERBOSE;
    else
        return -EINVAL;

    return 0;
}
custom_param("apic_verbosity", apic_set_verbosity);

static int __init detect_init_APIC (void)
{
    uint64_t msr_content;

    /* Disabled by kernel option? */
    if (enable_local_apic < 0)
        return -1;

    if (rdmsr_safe(MSR_IA32_APICBASE, msr_content)) {
        printk("No local APIC present\n");
        return -1;
    }

    if (!cpu_has_apic) {
        /*
         * Over-ride BIOS and try to enable the local
         * APIC only if "lapic" specified.
         */
        if (enable_local_apic <= 0) {
            printk("Local APIC disabled by BIOS -- "
                   "you can enable it with \"lapic\"\n");
            return -1;
        }
        /*
         * Some BIOSes disable the local APIC in the
         * APIC_BASE MSR. This can only be done in
         * software for Intel P6 or later and AMD K7
         * (Model > 1) or later.
         */
        if (!(msr_content & MSR_IA32_APICBASE_ENABLE)) {
            printk("Local APIC disabled by BIOS -- reenabling.\n");
            msr_content &= ~MSR_IA32_APICBASE_BASE;
            msr_content |= MSR_IA32_APICBASE_ENABLE | APIC_DEFAULT_PHYS_BASE;
            wrmsrl(MSR_IA32_APICBASE, msr_content);
            enabled_via_apicbase = true;
        }
    }
    /*
     * The APIC feature bit should now be enabled
     * in `cpuid'
     */
    if (!(cpuid_edx(1) & cpufeat_mask(X86_FEATURE_APIC))) {
        printk("Could not enable APIC!\n");
        return -1;
    }

    setup_force_cpu_cap(X86_FEATURE_APIC);
    mp_lapic_addr = APIC_DEFAULT_PHYS_BASE;

    /* The BIOS may have set up the APIC at some other address */
    if (msr_content & MSR_IA32_APICBASE_ENABLE)
        mp_lapic_addr = msr_content & MSR_IA32_APICBASE_BASE;

    if (nmi_watchdog != NMI_NONE)
        nmi_watchdog = NMI_LOCAL_APIC;

    printk("Found and enabled local APIC!\n");

    apic_pm_activate();

    return 0;
}

void x2apic_ap_setup(void)
{
    if ( x2apic_enabled )
        __enable_x2apic();
}

void __init x2apic_bsp_setup(void)
{
    struct IO_APIC_route_entry **ioapic_entries = NULL;

    if ( !cpu_has_x2apic )
        return;

    if ( !opt_x2apic )
    {
        if ( !x2apic_enabled )
        {
            printk("Not enabling x2APIC: disabled by cmdline.\n");
            return;
        }        
        printk("x2APIC: Already enabled by BIOS: Ignoring cmdline disable.\n");
    }

    if ( !iommu_supports_eim() )
    {
        if ( !x2apic_enabled )
        {
            printk("Not enabling x2APIC: depends on iommu_supports_eim.\n");
            return;
        }
        panic("x2APIC: already enabled by BIOS, but "
              "iommu_supports_eim failed");
    }

    if ( (ioapic_entries = alloc_ioapic_entries()) == NULL )
    {
        printk("Allocate ioapic_entries failed\n");
        goto out;
    }

    if ( save_IO_APIC_setup(ioapic_entries) )
    {
        printk("Saving IO-APIC state failed\n");
        goto out;
    }

    mask_8259A();
    mask_IO_APIC_setup(ioapic_entries);

    switch ( iommu_enable_x2apic_IR() )
    {
    case 0:
        break;
    case -ENXIO: /* ACPI_DMAR_X2APIC_OPT_OUT set */
        if ( !x2apic_enabled )
        {
            printk("Not enabling x2APIC (upon firmware request)\n");
            goto restore_out;
        }
        /* fall through */
    default:
        if ( x2apic_enabled )
            panic("Interrupt remapping could not be enabled while "
                  "x2APIC is already enabled by BIOS");

        printk(XENLOG_ERR
               "Failed to enable Interrupt Remapping: Will not enable x2APIC.\n");
        goto restore_out;
    }

    force_iommu = 1;

    genapic = apic_x2apic_probe();
    printk("Switched to APIC driver %s.\n", genapic->name);

    if ( !x2apic_enabled )
    {
        x2apic_enabled = true;
        __enable_x2apic();
    }

restore_out:
    restore_IO_APIC_setup(ioapic_entries);
    unmask_8259A();

out:
    if ( ioapic_entries )
        free_ioapic_entries(ioapic_entries);
}

void __init init_apic_mappings(void)
{
    unsigned long apic_phys;

    if ( x2apic_enabled )
        goto __next;
    /*
     * If no local APIC can be found then set up a fake all
     * zeroes page to simulate the local APIC and another
     * one for the IO-APIC.
     */
    if (!smp_found_config && detect_init_APIC()) {
        apic_phys = __pa(alloc_xenheap_page());
        clear_page(__va(apic_phys));
    } else
        apic_phys = mp_lapic_addr;

    set_fixmap_nocache(FIX_APIC_BASE, apic_phys);
    apic_printk(APIC_VERBOSE, "mapped APIC to %08Lx (%08lx)\n", APIC_BASE,
                apic_phys);

__next:
    /*
     * Fetch the APIC ID of the BSP in case we have a
     * default configuration (or the MP table is broken).
     */
    if (boot_cpu_physical_apicid == -1U)
        boot_cpu_physical_apicid = get_apic_id();
    x86_cpu_to_apicid[0] = get_apic_id();

    init_ioapic_mappings();
}

/*****************************************************************************
 * APIC calibration
 * 
 * The APIC is programmed in bus cycles.
 * Timeout values should specified in real time units.
 * The "cheapest" time source is the cyclecounter.
 * 
 * Thus, we need a mappings from: bus cycles <- cycle counter <- system time
 * 
 * The calibration is currently a bit shoddy since it requires the external
 * timer chip to generate periodic timer interupts. 
 *****************************************************************************/

/* used for system time scaling */
static u32 __read_mostly bus_scale; /* scaling factor: ns -> bus cycles */

/*
 * The timer chip is already set up at HZ interrupts per second here,
 * but we do not accept timer interrupts yet. We only allow the BP
 * to calibrate.
 */
static unsigned int __init get_8254_timer_count(void)
{
    /*extern spinlock_t i8253_lock;*/
    /*unsigned long flags;*/

    unsigned int count;

    /*spin_lock_irqsave(&i8253_lock, flags);*/

    outb_p(0x00, PIT_MODE);
    count = inb_p(PIT_CH0);
    count |= inb_p(PIT_CH0) << 8;

    /*spin_unlock_irqrestore(&i8253_lock, flags);*/

    return count;
}

/* next tick in 8254 can be caught by catching timer wraparound */
static void __init wait_8254_wraparound(void)
{
    unsigned int curr_count, prev_count;
    
    curr_count = get_8254_timer_count();
    do {
        prev_count = curr_count;
        curr_count = get_8254_timer_count();

        /* workaround for broken Mercury/Neptune */
        if (prev_count >= curr_count + 0x100)
            curr_count = get_8254_timer_count();
        
    } while (prev_count >= curr_count);
}

/*
 * This function sets up the local APIC timer, with a timeout of
 * 'clocks' APIC bus clock. During calibration we actually call
 * this function twice on the boot CPU, once with a bogus timeout
 * value, second time for real. The other (noncalibrating) CPUs
 * call this function only once, with the real, calibrated value.
 *
 * We do reads before writes even if unnecessary, to get around the
 * P5 APIC double write bug.
 */

#define APIC_DIVISOR 1

static void __setup_APIC_LVTT(unsigned int clocks)
{
    unsigned int lvtt_value, tmp_value;

    /* NB. Xen uses local APIC timer in one-shot mode. */
    lvtt_value = /*APIC_TIMER_MODE_PERIODIC |*/ LOCAL_TIMER_VECTOR;

    if ( tdt_enabled )
    {
        lvtt_value &= (~APIC_TIMER_MODE_MASK);
        lvtt_value |= APIC_TIMER_MODE_TSC_DEADLINE;
    }

    apic_write(APIC_LVTT, lvtt_value);

    tmp_value = apic_read(APIC_TDCR);
    apic_write(APIC_TDCR, tmp_value | APIC_TDR_DIV_1);

    apic_write(APIC_TMICT, clocks / APIC_DIVISOR);
}

static void setup_APIC_timer(void)
{
    unsigned long flags;
    local_irq_save(flags);
    __setup_APIC_LVTT(0);
    local_irq_restore(flags);
}

static void wait_tick_pvh(void)
{
    u64 lapse_ns = 1000000000ULL / HZ;
    s_time_t start, curr_time;

    start = NOW();

    /* Won't wrap around */
    do {
        cpu_relax();
        curr_time = NOW();
    } while ( curr_time - start < lapse_ns );
}

/*
 * In this function we calibrate APIC bus clocks to the external
 * timer. Unfortunately we cannot use jiffies and the timer irq
 * to calibrate, since some later bootup code depends on getting
 * the first irq? Ugh.
 *
 * We want to do the calibration only once since we
 * want to have local timer irqs syncron. CPUs connected
 * by the same APIC bus have the very same bus frequency.
 * And we want to have irqs off anyways, no accidental
 * APIC irq that way.
 */

static int __init calibrate_APIC_clock(void)
{
    unsigned long long t1, t2;
    long tt1, tt2;
    long result;
    int i;
    unsigned long bus_freq; /* KAF: pointer-size avoids compile warns. */
    u32 bus_cycle;          /* length of one bus cycle in pico-seconds */
    const int LOOPS = HZ/10;

    apic_printk(APIC_VERBOSE, "calibrating APIC timer ...\n");

    /*
     * Put whatever arbitrary (but long enough) timeout
     * value into the APIC clock, we just want to get the
     * counter running for calibration.
     */
    __setup_APIC_LVTT(1000000000);

    if ( !xen_guest )
        /*
         * The timer chip counts down to zero. Let's wait
         * for a wraparound to start exact measurement:
         * (the current tick might have been already half done)
         */
        wait_8254_wraparound();
    else
        wait_tick_pvh();

    /*
     * We wrapped around just now. Let's start:
     */
    t1 = rdtsc_ordered();
    tt1 = apic_read(APIC_TMCCT);

    /*
     * Let's wait LOOPS ticks:
     */
    for (i = 0; i < LOOPS; i++)
        if ( !xen_guest )
            wait_8254_wraparound();
        else
            wait_tick_pvh();

    tt2 = apic_read(APIC_TMCCT);
    t2 = rdtsc_ordered();

    /*
     * The APIC bus clock counter is 32 bits only, it
     * might have overflown, but note that we use signed
     * longs, thus no extra care needed.
     *
     * underflown to be exact, as the timer counts down ;)
     */

    result = (tt1-tt2)*APIC_DIVISOR/LOOPS;

    apic_printk(APIC_VERBOSE, "..... CPU clock speed is %ld.%04ld MHz.\n",
                ((long)(t2 - t1) / LOOPS) / (1000000 / HZ),
                ((long)(t2 - t1) / LOOPS) % (1000000 / HZ));

    apic_printk(APIC_VERBOSE, "..... host bus clock speed is %ld.%04ld MHz.\n",
                result / (1000000 / HZ), result % (1000000 / HZ));

    /* set up multipliers for accurate timer code */
    bus_freq   = result*HZ;
    bus_cycle  = (u32) (1000000000000LL/bus_freq); /* in pico seconds */
    bus_scale  = (1000*262144)/bus_cycle;

    apic_printk(APIC_VERBOSE, "..... bus_scale = %#x\n", bus_scale);
    /* reset APIC to zero timeout value */
    __setup_APIC_LVTT(0);

    return result;
}

void __init setup_boot_APIC_clock(void)
{
    unsigned long flags;
    apic_printk(APIC_VERBOSE, "Using local APIC timer interrupts.\n");
    using_apic_timer = true;

    local_irq_save(flags);

    calibrate_APIC_clock();

    if ( tdt_enable && boot_cpu_has(X86_FEATURE_TSC_DEADLINE) )
    {
        printk(KERN_DEBUG "TSC deadline timer enabled\n");
        tdt_enabled = true;
    }

    setup_APIC_timer();
    
    local_irq_restore(flags);
}

void setup_secondary_APIC_clock(void)
{
    setup_APIC_timer();
}

void disable_APIC_timer(void)
{
    if (using_apic_timer) {
        unsigned long v;

        /* Work around AMD Erratum 411. This is a nice thing to do anyway. */
        apic_write(APIC_TMICT, 0);

        v = apic_read(APIC_LVTT);
        apic_write(APIC_LVTT, v | APIC_LVT_MASKED);
    }
}

void enable_APIC_timer(void)
{
    if (using_apic_timer) {
        unsigned long v;
        
        v = apic_read(APIC_LVTT);
        apic_write(APIC_LVTT, v & ~APIC_LVT_MASKED);
    }
}

#undef APIC_DIVISOR

/*
 * reprogram_timer: Reprogram the APIC timer.
 * Timeout is a Xen system time (nanoseconds since boot); 0 disables the timer.
 * Returns 1 on success; 0 if the timeout is too soon or is in the past.
 */
int reprogram_timer(s_time_t timeout)
{
    s_time_t expire;
    u32 apic_tmict = 0;

    /* No local APIC: timer list is polled via the PIT interrupt. */
    if ( !cpu_has_apic )
        return 1;

    if ( tdt_enabled )
    {
        wrmsrl(MSR_IA32_TSC_DEADLINE, timeout ? stime2tsc(timeout) : 0);
        return 1;
    }

    if ( timeout && ((expire = timeout - NOW()) > 0) )
        apic_tmict = min_t(u64, (bus_scale * expire) >> 18, UINT_MAX);

    apic_write(APIC_TMICT, (unsigned long)apic_tmict);

    return apic_tmict || !timeout;
}

void apic_timer_interrupt(struct cpu_user_regs * regs)
{
    ack_APIC_irq();
    perfc_incr(apic_timer);
    raise_softirq(TIMER_SOFTIRQ);
}

static DEFINE_PER_CPU(bool, state_dump_pending);

void smp_send_state_dump(unsigned int cpu)
{
    /* We overload the spurious interrupt handler to handle the dump. */
    per_cpu(state_dump_pending, cpu) = true;
    send_IPI_mask(cpumask_of(cpu), SPURIOUS_APIC_VECTOR);
}

/*
 * Spurious interrupts should _never_ happen with our APIC/SMP architecture.
 */
void spurious_interrupt(struct cpu_user_regs *regs)
{
    /*
     * Check if this is a vectored interrupt (most likely, as this is probably
     * a request to dump local CPU state). Vectored interrupts are ACKed;
     * spurious interrupts are not.
     */
    if (apic_isr_read(SPURIOUS_APIC_VECTOR)) {
        ack_APIC_irq();
        if (this_cpu(state_dump_pending)) {
            this_cpu(state_dump_pending) = false;
            dump_execstate(regs);
            goto out;
        }
    }

    /* see sw-dev-man vol 3, chapter 7.4.13.5 */
    printk(KERN_INFO "spurious APIC interrupt on CPU#%d, should "
           "never happen.\n", smp_processor_id());

out: ;
}

/*
 * This interrupt should never happen with our APIC/SMP architecture
 */

void error_interrupt(struct cpu_user_regs *regs)
{
    static const char *const esr_fields[] = {
        "Send CS error",
        "Receive CS error",
        "Send accept error",
        "Receive accept error",
        "Redirectable IPI",
        "Send illegal vector",
        "Received illegal vector",
        "Illegal register address",
    };
    unsigned int v, v1;
    int i;

    /* First tickle the hardware, only then report what went on. -- REW */
    v = apic_read(APIC_ESR);
    apic_write(APIC_ESR, 0);
    v1 = apic_read(APIC_ESR);
    ack_APIC_irq();

    printk(XENLOG_DEBUG "APIC error on CPU%u: %02x(%02x)",
            smp_processor_id(), v , v1);
    for ( i = 7; i >= 0; --i )
        if ( v1 & (1 << i) )
            printk(", %s", esr_fields[i]);
    printk("\n");
}

/*
 * This interrupt handles performance counters interrupt
 */

void pmu_apic_interrupt(struct cpu_user_regs *regs)
{
    ack_APIC_irq();
    vpmu_do_interrupt(regs);
}

/*
 * This initializes the IO-APIC and APIC hardware if this is
 * a UP kernel.
 */
int __init APIC_init_uniprocessor (void)
{
    if (enable_local_apic < 0)
        setup_clear_cpu_cap(X86_FEATURE_APIC);

    if (!smp_found_config && !cpu_has_apic) {
        skip_ioapic_setup = true;
        return -1;
    }

    /*
     * Complain if the BIOS pretends there is one.
     */
    if (!cpu_has_apic) {
        printk(KERN_ERR "BIOS bug, local APIC #%d not detected!...\n",
               boot_cpu_physical_apicid);
        skip_ioapic_setup = true;
        return -1;
    }

    verify_local_APIC();

    connect_bsp_APIC();

    /*
     * Hack: In case of kdump, after a crash, kernel might be booting
     * on a cpu with non-zero lapic id. But boot_cpu_physical_apicid
     * might be zero if read from MP tables. Get it from LAPIC.
     */
#ifdef CONFIG_CRASH_DUMP
    boot_cpu_physical_apicid = get_apic_id();
#endif
    physids_clear(phys_cpu_present_map);
    physid_set(boot_cpu_physical_apicid, phys_cpu_present_map);

    setup_local_APIC();

    if (nmi_watchdog == NMI_LOCAL_APIC)
        check_nmi_watchdog();

    if (smp_found_config)
        if (!skip_ioapic_setup && nr_ioapics)
            setup_IO_APIC();

    setup_boot_APIC_clock();

    return 0;
}

static const char * __init apic_mode_to_str(const enum apic_mode mode)
{
    switch ( mode )
    {
        case APIC_MODE_INVALID:
            return "invalid";
        case APIC_MODE_DISABLED:
            return "disabled";
        case APIC_MODE_XAPIC:
            return "xapic";
        case APIC_MODE_X2APIC:
            return "x2apic";
        default:
            return "unrecognised";
    }
}

/* Needs to be called during startup.  It records the state the BIOS
 * leaves the local APIC so we can undo upon kexec.
 */
void __init record_boot_APIC_mode(void)
{
    /* Sanity check - we should only ever run once, but could possibly
     * be called several times */
    if ( APIC_MODE_INVALID != apic_boot_mode )
        return;

    apic_boot_mode = current_local_apic_mode();

    apic_printk(APIC_DEBUG, "APIC boot state is '%s'\n",
                apic_mode_to_str(apic_boot_mode));
}

/* Look at the bits in MSR_IA32_APICBASE and work out which
 * APIC mode we are in */
enum apic_mode current_local_apic_mode(void)
{
    u64 msr_contents;

    rdmsrl(MSR_IA32_APICBASE, msr_contents);

    /* Reading EXTD bit from the MSR is only valid if CPUID
     * says so, else reserved */
    if ( boot_cpu_has(X86_FEATURE_X2APIC)
         && (msr_contents & MSR_IA32_APICBASE_EXTD) )
        return APIC_MODE_X2APIC;

    /* EN bit should always be valid as long as we can read the MSR
     */
    if ( msr_contents & MSR_IA32_APICBASE_ENABLE )
        return APIC_MODE_XAPIC;

    return APIC_MODE_DISABLED;
}


void check_for_unexpected_msi(unsigned int vector)
{
    BUG_ON(apic_isr_read(vector));
}
