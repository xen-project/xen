/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: apic.c
 *      Author: 
 *     Changes: 
 *              
 *        Date: Nov 2002
 * 
 * Environment: Xen Hypervisor
 * Description: programmable APIC timer interface for accurate timers
 *              modified version of Linux' apic.c
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 */

/*
 *  Local APIC handling, local APIC timers
 *
 *  (c) 1999, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *  Fixes
 *  Maciej W. Rozycki   :   Bits for genuine 82489DX APICs;
 *                  thanks to Eric Gilmore
 *                  and Rolf G. Tews
 *                  for testing these extensively.
 */


#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/sched.h>
#include <xeno/irq.h>
#include <xeno/delay.h>
#include <asm/mc146818rtc.h>
#include <asm/msr.h>
#include <xeno/errno.h>
#include <asm/atomic.h>
#include <xeno/smp.h>
#include <xeno/interrupt.h>
#include <asm/mpspec.h>
#include <asm/pgalloc.h>
#include <asm/hardirq.h>
#include <asm/apic.h>
#include <xeno/mm.h>

#include <asm/timex.h>
#include <xeno/ac_timer.h>
#include <xeno/perfc.h>

#undef APIC_TIME_TRACE
#ifdef APIC_TIME_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif


/* Using APIC to generate smp_local_timer_interrupt? */
int using_apic_timer = 0;

int get_maxlvt(void)
{
    unsigned int v, ver, maxlvt;

    v = apic_read(APIC_LVR);
    ver = GET_APIC_VERSION(v);
    /* 82489DXs do not report # of LVT entries. */
    maxlvt = APIC_INTEGRATED(ver) ? GET_APIC_MAXLVT(v) : 2;
    return maxlvt;
}

static void clear_local_APIC(void)
{
    int maxlvt;
    unsigned long v;

    maxlvt = get_maxlvt();

    /*
     * Careful: we have to set masks only first to deassert
     * any level-triggered sources.
     */
    v = apic_read(APIC_LVTT);
    apic_write_around(APIC_LVTT, v | APIC_LVT_MASKED);
    v = apic_read(APIC_LVT0);
    apic_write_around(APIC_LVT0, v | APIC_LVT_MASKED);
    v = apic_read(APIC_LVT1);
    apic_write_around(APIC_LVT1, v | APIC_LVT_MASKED);
    if (maxlvt >= 3) {
        v = apic_read(APIC_LVTERR);
        apic_write_around(APIC_LVTERR, v | APIC_LVT_MASKED);
    }
    if (maxlvt >= 4) {
        v = apic_read(APIC_LVTPC);
        apic_write_around(APIC_LVTPC, v | APIC_LVT_MASKED);
    }

    /*
     * Clean APIC state for other OSs:
     */
    apic_write_around(APIC_LVTT, APIC_LVT_MASKED);
    apic_write_around(APIC_LVT0, APIC_LVT_MASKED);
    apic_write_around(APIC_LVT1, APIC_LVT_MASKED);
    if (maxlvt >= 3)
        apic_write_around(APIC_LVTERR, APIC_LVT_MASKED);
    if (maxlvt >= 4)
        apic_write_around(APIC_LVTPC, APIC_LVT_MASKED);
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
        printk("leaving PIC mode, enabling APIC mode.\n");
        outb(0x70, 0x22);
        outb(0x01, 0x23);
    }
}

void disconnect_bsp_APIC(void)
{
    if (pic_mode) {
        /*
         * Put the board back into PIC mode (has an effect
         * only on certain older boards).  Note that APIC
         * interrupts, including IPIs, won't work beyond
         * this point!  The only exception are INIT IPIs.
         */
        printk("disabling APIC mode, entering PIC mode.\n");
        outb(0x70, 0x22);
        outb(0x00, 0x23);
    }
}

void disable_local_APIC(void)
{
    unsigned long value;

    clear_local_APIC();

    /*
     * Disable APIC (implies clearing of registers
     * for 82489DX!).
     */
    value = apic_read(APIC_SPIV);
    value &= ~APIC_SPIV_APIC_ENABLED;
    apic_write_around(APIC_SPIV, value);
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
    Dprintk("Getting VERSION: %x\n", reg0);
    apic_write(APIC_LVR, reg0 ^ APIC_LVR_MASK);
    reg1 = apic_read(APIC_LVR);
    Dprintk("Getting VERSION: %x\n", reg1);

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
     * The ID register is read/write in a real APIC.
     */
    reg0 = apic_read(APIC_ID);
    Dprintk("Getting ID: %x\n", reg0);
    apic_write(APIC_ID, reg0 ^ APIC_ID_MASK);
    reg1 = apic_read(APIC_ID);
    Dprintk("Getting ID: %x\n", reg1);
    apic_write(APIC_ID, reg0);
    if (reg1 != (reg0 ^ APIC_ID_MASK))
        return 0;

    /*
     * The next two are just to see if we have sane values.
     * They're only really relevant if we're in Virtual Wire
     * compatibility mode, but most boxes are anymore.
     */
    reg0 = apic_read(APIC_LVT0);
    Dprintk("Getting LVT0: %x\n", reg0);
    reg1 = apic_read(APIC_LVT1);
    Dprintk("Getting LVT1: %x\n", reg1);

    return 1;
}

void __init sync_Arb_IDs(void)
{
    /* Wait for idle. */
    apic_wait_icr_idle();

    Dprintk("Synchronizing Arb IDs.\n");
    apic_write_around(APIC_ICR, APIC_DEST_ALLINC | APIC_INT_LEVELTRIG
                      | APIC_DM_INIT);
}

extern void __error_in_apic_c (void);

/*
 * WAS: An initial setup of the virtual wire mode.
 * NOW: We don't bother doing anything. All we need at this point
 * is to receive timer ticks, so that 'jiffies' is incremented.
 * If we're SMP, then we can assume BIOS did setup for us.
 * If we're UP, then the APIC should be disabled (it is at reset).
 * If we're UP and APIC is enabled, then BIOS is clever and has 
 * probably done initial interrupt routing for us.
 */
void __init init_bsp_APIC(void)
{
}

void __init setup_local_APIC (void)
{
    unsigned long value, ver, maxlvt;

    value = apic_read(APIC_LVR);
    ver = GET_APIC_VERSION(value);

    if ((SPURIOUS_APIC_VECTOR & 0x0f) != 0x0f)
        __error_in_apic_c();

    /* Double-check wether this APIC is really registered. */
    if (!test_bit(GET_APIC_ID(apic_read(APIC_ID)), &phys_cpu_present_map))
        BUG();

    /*
     * Intel recommends to set DFR, LDR and TPR before enabling
     * an APIC.  See e.g. "AP-388 82489DX User's Manual" (Intel
     * document number 292116).  So here it goes...
     */

    /*
     * In clustered apic mode, the firmware does this for us 
     * Put the APIC into flat delivery mode.
     * Must be "all ones" explicitly for 82489DX.
     */
    apic_write_around(APIC_DFR, 0xffffffff);

    /*
     * Set up the logical destination ID.
     */
    value = apic_read(APIC_LDR);
    value &= ~APIC_LDR_MASK;
    value |= (1<<(smp_processor_id()+24));
    apic_write_around(APIC_LDR, value);

    /*
     * Set Task Priority to 'accept all'. We never change this
     * later on.
     */
    value = apic_read(APIC_TASKPRI);
    value &= ~APIC_TPRI_MASK;
    apic_write_around(APIC_TASKPRI, value);

    /*
     * Now that we are all set up, enable the APIC
     */
    value = apic_read(APIC_SPIV);
    value &= ~APIC_VECTOR_MASK;
    /*
     * Enable APIC
     */
    value |= APIC_SPIV_APIC_ENABLED;

    /* Enable focus processor (bit==0) */
    value &= ~APIC_SPIV_FOCUS_DISABLED;

    /* Set spurious IRQ vector */
    value |= SPURIOUS_APIC_VECTOR;
    apic_write_around(APIC_SPIV, value);

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
    if (!smp_processor_id()) { 
        value = APIC_DM_EXTINT;
        printk("enabled ExtINT on CPU#%d\n", smp_processor_id());
    } else {
        value = APIC_DM_EXTINT | APIC_LVT_MASKED;
        printk("masked ExtINT on CPU#%d\n", smp_processor_id());
    }
    apic_write_around(APIC_LVT0, value);

    /*
     * only the BP should see the LINT1 NMI signal, obviously.
     */
    if (!smp_processor_id())
        value = APIC_DM_NMI;
    else
        value = APIC_DM_NMI | APIC_LVT_MASKED;
    if (!APIC_INTEGRATED(ver))      /* 82489DX */
        value |= APIC_LVT_LEVEL_TRIGGER;
    apic_write_around(APIC_LVT1, value);

    if (APIC_INTEGRATED(ver)) {     /* !82489DX */
        maxlvt = get_maxlvt();
        if (maxlvt > 3)     /* Due to the Pentium erratum 3AP. */
            apic_write(APIC_ESR, 0);
        value = apic_read(APIC_ESR);
        printk("ESR value before enabling vector: %08lx\n", value);

        value = ERROR_APIC_VECTOR;      /* enables sending errors */
        apic_write_around(APIC_LVTERR, value);
        /* spec says clear errors after enabling vector. */
        if (maxlvt > 3)
            apic_write(APIC_ESR, 0);
        value = apic_read(APIC_ESR);
        printk("ESR value after enabling vector: %08lx\n", value);
    } else {
        printk("No ESR for 82489DX.\n");
    }

	if (nmi_watchdog == NMI_LOCAL_APIC)
		setup_apic_nmi_watchdog();
}


static inline void apic_pm_init1(void) { }
static inline void apic_pm_init2(void) { }


/*
 * Detect and enable local APICs on non-SMP boards.
 * Original code written by Keir Fraser.
 */

static int __init detect_init_APIC (void)
{
    u32 h, l, features;
    extern void get_cpu_vendor(struct cpuinfo_x86*);

    /* Workaround for us being called before identify_cpu(). */
    get_cpu_vendor(&boot_cpu_data);

    switch (boot_cpu_data.x86_vendor) {
    case X86_VENDOR_AMD:
        if (boot_cpu_data.x86 == 6 && boot_cpu_data.x86_model > 1)
            break;
        goto no_apic;
    case X86_VENDOR_INTEL:
        if (boot_cpu_data.x86 == 6 ||
            (boot_cpu_data.x86 == 15 && cpu_has_apic) ||
            (boot_cpu_data.x86 == 5 && cpu_has_apic))
            break;
        goto no_apic;
    default:
        goto no_apic;
    }

    if (!cpu_has_apic) {
        /*
         * Some BIOSes disable the local APIC in the
         * APIC_BASE MSR. This can only be done in
         * software for Intel P6 and AMD K7 (Model > 1).
         */
        rdmsr(MSR_IA32_APICBASE, l, h);
        if (!(l & MSR_IA32_APICBASE_ENABLE)) {
            printk("Local APIC disabled by BIOS -- reenabling.\n");
            l &= ~MSR_IA32_APICBASE_BASE;
            l |= MSR_IA32_APICBASE_ENABLE | APIC_DEFAULT_PHYS_BASE;
            wrmsr(MSR_IA32_APICBASE, l, h);
        }
    }

    /* The APIC feature bit should now be enabled in `cpuid' */
    features = cpuid_edx(1);
    if (!(features & (1 << X86_FEATURE_APIC))) {
        printk("Could not enable APIC!\n");
        return -1;
    }

    set_bit(X86_FEATURE_APIC, &boot_cpu_data.x86_capability);
    mp_lapic_addr = APIC_DEFAULT_PHYS_BASE;
    boot_cpu_physical_apicid = 0;
	if (nmi_watchdog != NMI_NONE)
		nmi_watchdog = NMI_LOCAL_APIC;

    printk("Found and enabled local APIC!\n");
    apic_pm_init1();
    return 0;

 no_apic:
    printk("No local APIC present or hardware disabled\n");
    return -1;
}

void __init init_apic_mappings(void)
{
    unsigned long apic_phys = 0;

    /*
     * If no local APIC can be found then set up a fake all zeroes page to 
     * simulate the local APIC and another one for the IO-APIC.
     */
    if (!smp_found_config && detect_init_APIC()) {
        apic_phys = get_free_page(GFP_KERNEL);
        apic_phys = __pa(apic_phys);
    } else
        apic_phys = mp_lapic_addr;

    set_fixmap_nocache(FIX_APIC_BASE, apic_phys);
    Dprintk("mapped APIC to %08lx (%08lx)\n", APIC_BASE, apic_phys);

    /*
     * Fetch the APIC ID of the BSP in case we have a
     * default configuration (or the MP table is broken).
     */
    if (boot_cpu_physical_apicid == -1U)
        boot_cpu_physical_apicid = GET_APIC_ID(apic_read(APIC_ID));

#ifdef CONFIG_X86_IO_APIC
    {
        unsigned long ioapic_phys = 0, idx = FIX_IO_APIC_BASE_0;
        int i;

        for (i = 0; i < nr_ioapics; i++) {
            if (smp_found_config)
                ioapic_phys = mp_ioapics[i].mpc_apicaddr;
            set_fixmap_nocache(idx, ioapic_phys);
            Dprintk("mapped IOAPIC to %08lx (%08lx)\n",
                    __fix_to_virt(idx), ioapic_phys);
            idx++;
        }
    }
#endif
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
static unsigned int bus_freq;
static u32          bus_cycle;   /* length of one bus cycle in pico-seconds */
static u32          bus_scale;   /* scaling factor convert ns to bus cycles */
u64 cpu_freq;

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
    outb_p(0x00, 0x43);
    count = inb_p(0x40);
    count |= inb_p(0x40) << 8;
    /*spin_unlock_irqrestore(&i8253_lock, flags);*/
    return count;
}

void __init wait_8254_wraparound(void)
{
    unsigned int curr_count, prev_count=~0;
    int delta;
    curr_count = get_8254_timer_count();
    do {
        prev_count = curr_count;
        curr_count = get_8254_timer_count();
        delta = curr_count-prev_count;
        /*
         * This limit for delta seems arbitrary, but it isn't, it's slightly 
         * above the level of error a buggy Mercury/Neptune chipset timer can 
         * cause.
         */
    } while (delta < 300);
}

/*
 * This function sets up the local APIC timer, with a timeout of
 * 'clocks' APIC bus clock. During calibration we actually call
 * this function with a very large value and read the current time after
 * a well defined period of time as expired.
 *
 * Calibration is only performed once, for CPU0!
 *
 * We do reads before writes even if unnecessary, to get around the
 * P5 APIC double write bug.
 */
#define APIC_DIVISOR 1
static void __setup_APIC_LVTT(unsigned int clocks)
{
    unsigned int lvtt1_value, tmp_value;
    lvtt1_value = SET_APIC_TIMER_BASE(APIC_TIMER_BASE_DIV)|LOCAL_TIMER_VECTOR;
    apic_write_around(APIC_LVTT, lvtt1_value);
    tmp_value = apic_read(APIC_TDCR);
    apic_write_around(APIC_TDCR, (tmp_value | APIC_TDR_DIV_1));
    apic_write_around(APIC_TMICT, clocks/APIC_DIVISOR);
}

/*
 * this is done for every CPU from setup_APIC_clocks() below.
 * We setup each local APIC with a zero timeout value for now.
 * Unlike Linux, we don't have to wait for slices etc.
 */
void setup_APIC_timer(void * data)
{
    unsigned long flags;
    __save_flags(flags);
    __sti();
    printk("cpu: %d: setup timer.", smp_processor_id());
    __setup_APIC_LVTT(0);
    printk("done\n");
    __restore_flags(flags);
}

/*
 * In this function we calibrate APIC bus clocks to the external timer.
 *
 * As a result we have the Bys Speed and CPU speed in Hz.
 * 
 * We want to do the calibration only once (for CPU0).  CPUs connected by the
 * same APIC bus have the very same bus frequency.
 *
 * This bit is a bit shoddy since we use the very same periodic timer interrupt
 * we try to eliminate to calibrate the APIC. 
 */

int __init calibrate_APIC_clock(void)
{
    unsigned long long t1 = 0, t2 = 0;
    long tt1, tt2;
    long result;
    int i;
    const int LOOPS = HZ/10;

    printk("calibrating APIC timer for CPU%d...\n",  smp_processor_id());

    /* Put whatever arbitrary (but long enough) timeout
     * value into the APIC clock, we just want to get the
     * counter running for calibration. */
    __setup_APIC_LVTT(1000000000);

    /* The timer chip counts down to zero. Let's wait
     * for a wraparound to start exact measurement:
     * (the current tick might have been already half done) */
    wait_8254_wraparound();

    /* We wrapped around just now. Let's start: */
    rdtscll(t1);
    tt1 = apic_read(APIC_TMCCT);

    /* Let's wait LOOPS wraprounds: */
    for (i = 0; i < LOOPS; i++)
        wait_8254_wraparound();

    tt2 = apic_read(APIC_TMCCT);
    rdtscll(t2);

    /* The APIC bus clock counter is 32 bits only, it
     * might have overflown, but note that we use signed
     * longs, thus no extra care needed.
     * underflown to be exact, as the timer counts down ;) */
    result = (tt1-tt2)*APIC_DIVISOR/LOOPS;

    printk("..... CPU speed is %ld.%04ld MHz.\n",
           ((long)(t2-t1)/LOOPS)/(1000000/HZ),
           ((long)(t2-t1)/LOOPS)%(1000000/HZ));

    printk("..... Bus speed is %ld.%04ld MHz.\n",
           result/(1000000/HZ),
           result%(1000000/HZ));

    cpu_freq = (u64)(((t2-t1)/LOOPS)*HZ);

    /* set up multipliers for accurate timer code */
    bus_freq   = result*HZ;
    bus_cycle  = (u32) (1000000000000LL/bus_freq); /* in pico seconds */
    bus_scale  = (1000*262144)/bus_cycle;

    /* print results */
    printk("..... bus_freq  = %u Hz\n",  bus_freq);
    printk("..... bus_cycle = %u ps\n",  bus_cycle);
    printk("..... bus_scale = %u \n",    bus_scale);
    /* reset APIC to zero timeout value */
    __setup_APIC_LVTT(0);
    return result;
}

/*
 * initialise the APIC timers for all CPUs
 * we start with the first and find out processor frequency and bus speed
 */
void __init setup_APIC_clocks (void)
{
    printk("Using local APIC timer interrupts.\n");
    using_apic_timer = 1;
    __cli();
    /* calibrate CPU0 for CPU speed and BUS speed */
    bus_freq = calibrate_APIC_clock();
    /* Now set up the timer for real. */
    setup_APIC_timer((void *)bus_freq);
    __sti();
    /* and update all other cpus */
    smp_call_function(setup_APIC_timer, (void *)bus_freq, 1, 1);
}

#undef APIC_DIVISOR

/*
 * reprogram the APIC timer. Timeoutvalue is in ns from start of boot
 * returns 1 on success
 * returns 0 if the timeout value is too small or in the past.
 */
int reprogram_ac_timer(s_time_t timeout)
{
    int         cpu = smp_processor_id();
    s_time_t    now;
    s_time_t    expire;
    u64         apic_tmict;

    /*
     * We use this value because we don't trust zero (we think it may just
     * cause an immediate interrupt). At least this is guaranteed to hold it
     * off for ages (esp. since the clock ticks on bus clock, not cpu clock!).
     */
    if (timeout == 0) {
        apic_tmict = 0xffffffff;
        goto reprogram;
    }

    now = NOW();
    expire = timeout - now; /* value from now */

    if (expire <= 0) {
        printk("APICT[%02d] Timeout in the past 0x%08X%08X > 0x%08X%08X\n", 
               cpu, (u32)(now>>32), (u32)now, (u32)(timeout>>32),(u32)timeout);
        return 0;       /* timeout value in the past */
    }

    /* conversion to bus units */
    apic_tmict = (((u64)bus_scale) * expire)>>18;

    if (apic_tmict >= 0xffffffff) {
        printk("APICT[%02d] Timeout value too large\n", cpu);
        apic_tmict = 0xffffffff;
    }
    if (apic_tmict == 0) {
        printk("APICT[%02d] timeout value too small\n", cpu);
        return 0;
    }

 reprogram:
    /* Program the timer. */
    apic_write(APIC_TMICT, (unsigned long)apic_tmict);

    TRC(printk("APICT[%02d] reprog(): expire=%lld %u\n",
               cpu, expire, apic_tmict));
    return 1;
}

/*
 * Local timer interrupt handler.
 * here the programmable, accurate timers are executed.
 * If we are on CPU0 and we should have updated jiffies, we do this 
 * as well and and deal with traditional linux timers. Note, that of 
 * the timer APIC on CPU does not go off every 10ms or so the linux 
 * timers loose accuracy, but that shouldn't be a problem.
 */
static s_time_t last_cpu0_tirq = 0;
inline void smp_local_timer_interrupt(struct pt_regs * regs)
{
    int cpu = smp_processor_id();
    s_time_t diff, now;

    /* if CPU 0 do old timer stuff  */
    if (cpu == 0)
    {
        now = NOW();
        diff = now - last_cpu0_tirq;

        if (diff <= 0) {
            printk ("System Time went backwards: %lld\n", diff);
            return;
        }

        while (diff >= MILLISECS(10)) {
            do_timer(regs);
            diff           -= MILLISECS(10);
            last_cpu0_tirq += MILLISECS(10);
        }
    }
    /* call accurate timer function */
    do_ac_timer();
}

/*
 * Local APIC timer interrupt. This is the most natural way for doing
 * local interrupts, but local timer interrupts can be emulated by
 * broadcast interrupts too. [in case the hw doesnt support APIC timers]
 *
 * [ if a single-CPU system runs an SMP kernel then we call the local
 *   interrupt as well. Thus we cannot inline the local irq ... ]
 */
unsigned int apic_timer_irqs [NR_CPUS];

void smp_apic_timer_interrupt(struct pt_regs * regs)
{
    int cpu = smp_processor_id();
#ifndef NDEBUG
    u32 cc_start, cc_end;
    rdtscl(cc_start);
#endif

    /*
     * the NMI deadlock-detector uses this.
     */
    apic_timer_irqs[cpu]++;

    /*
     * NOTE! We'd better ACK the irq immediately, because timer handling can 
     * be slow. XXX is this save?
     */
    ack_APIC_irq();

    /* call the local handler */
    irq_enter(cpu, 0);
    perfc_incrc(apic_timer);
    smp_local_timer_interrupt(regs);
    irq_exit(cpu, 0);

    if (softirq_pending(cpu))
        do_softirq();

#ifndef NDEBUG
    rdtscl(cc_end);
    if ( (cc_end - cc_start) > (cpu_khz * 100) )
        printk("APIC Long ISR on CPU=%02d %08X -> %08X\n",cpu,cc_start,cc_end);
#endif
}

/*
 * This interrupt should _never_ happen with our APIC/SMP architecture
 */
asmlinkage void smp_spurious_interrupt(void)
{
    unsigned long v;

    /*
     * Check if this really is a spurious interrupt and ACK it
     * if it is a vectored one.  Just in case...
     * Spurious interrupts should not be ACKed.
     */
    v = apic_read(APIC_ISR + ((SPURIOUS_APIC_VECTOR & ~0x1f) >> 1));
    if (v & (1 << (SPURIOUS_APIC_VECTOR & 0x1f)))
        ack_APIC_irq();

    /* see sw-dev-man vol 3, chapter 7.4.13.5 */
    printk("spurious APIC interrupt on CPU#%d, should never happen.\n",
           smp_processor_id());
}

/*
 * This interrupt should never happen with our APIC/SMP architecture
 */

asmlinkage void smp_error_interrupt(void)
{
    unsigned long v, v1;

    /* First tickle the hardware, only then report what went on. -- REW */
    v = apic_read(APIC_ESR);
    apic_write(APIC_ESR, 0);
    v1 = apic_read(APIC_ESR);
    ack_APIC_irq();
    atomic_inc(&irq_err_count);

    /* Here is what the APIC error bits mean:
       0: Send CS error
       1: Receive CS error
       2: Send accept error
       3: Receive accept error
       4: Reserved
       5: Send illegal vector
       6: Received illegal vector
       7: Illegal register address
    */
    printk ("APIC error on CPU%d: %02lx(%02lx)\n",
            smp_processor_id(), v , v1);
}

/*
 * This initializes the IO-APIC and APIC hardware if this is
 * a UP kernel.
 */
int __init APIC_init_uniprocessor (void)
{
    if (!smp_found_config && !cpu_has_apic)
        return -1;

    /*
     * Complain if the BIOS pretends there is one.
     */
    if (!cpu_has_apic&&APIC_INTEGRATED(apic_version[boot_cpu_physical_apicid]))
    {
        printk("BIOS bug, local APIC #%d not detected!...\n",
               boot_cpu_physical_apicid);
        return -1;
    }

    verify_local_APIC();

    connect_bsp_APIC();

#ifdef CONFIG_SMP
    cpu_online_map = 1;
#endif
    phys_cpu_present_map = 1;
    apic_write_around(APIC_ID, boot_cpu_physical_apicid);

    apic_pm_init2();

    setup_local_APIC();

#ifdef CONFIG_X86_IO_APIC
    if (smp_found_config && nr_ioapics)
        setup_IO_APIC();
#endif
    setup_APIC_clocks();

    return 0;
}
