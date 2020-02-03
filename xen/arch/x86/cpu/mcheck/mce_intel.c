#include <xen/init.h>
#include <xen/types.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/delay.h>
#include <xen/param.h>
#include <xen/smp.h>
#include <xen/mm.h>
#include <xen/cpu.h>
#include <asm/processor.h>
#include <public/sysctl.h>
#include <asm/system.h>
#include <asm/msr.h>
#include <asm/p2m.h>
#include <asm/mce.h>
#include <asm/apic.h>
#include "mce.h"
#include "x86_mca.h"
#include "barrier.h"
#include "util.h"
#include "vmce.h"
#include "mcaction.h"

static DEFINE_PER_CPU_READ_MOSTLY(struct mca_banks *, mce_banks_owned);
bool __read_mostly cmci_support;
static bool __read_mostly ser_support;
static bool __read_mostly mce_force_broadcast;
boolean_param("mce_fb", mce_force_broadcast);

static int __read_mostly nr_intel_ext_msrs;

/* If mce_force_broadcast == 1, lmce_support will be disabled forcibly. */
bool __read_mostly lmce_support;

/* Intel SDM define bit15~bit0 of IA32_MCi_STATUS as the MC error code */
#define INTEL_MCCOD_MASK 0xFFFF

/*
 * Currently Intel SDM define 2 kinds of srao errors:
 * 1). Memory scrubbing error, error code = 0xC0 ~ 0xCF
 * 2). L3 explicit writeback error, error code = 0x17A
 */
#define INTEL_SRAO_MEM_SCRUB 0xC0 ... 0xCF
#define INTEL_SRAO_L3_EWB    0x17A

/*
 * Currently Intel SDM define 2 kinds of srar errors:
 * 1). Data Load error, error code = 0x134
 * 2). Instruction Fetch error, error code = 0x150
 */
#define INTEL_SRAR_DATA_LOAD	0x134
#define INTEL_SRAR_INSTR_FETCH	0x150

#define MCE_RING                0x1
static DEFINE_PER_CPU(int, last_state);

static void intel_thermal_interrupt(struct cpu_user_regs *regs)
{
    uint64_t msr_content;
    unsigned int cpu = smp_processor_id();
    static DEFINE_PER_CPU(s_time_t, next);
    int *this_last_state;

    ack_APIC_irq();

    if ( NOW() < per_cpu(next, cpu) )
        return;

    per_cpu(next, cpu) = NOW() + MILLISECS(5000);
    rdmsrl(MSR_IA32_THERM_STATUS, msr_content);
    this_last_state = &per_cpu(last_state, cpu);
    if ( *this_last_state == (msr_content & MCE_RING) )
        return;
    *this_last_state = msr_content & MCE_RING;
    if ( msr_content & MCE_RING )
    {
        printk(KERN_EMERG "CPU%u: Temperature above threshold\n", cpu);
        printk(KERN_EMERG "CPU%u: Running in modulated clock mode\n", cpu);
        add_taint(TAINT_MACHINE_CHECK);
    } else
        printk(KERN_INFO "CPU%u: Temperature/speed normal\n", cpu);
}

/* Thermal monitoring depends on APIC, ACPI and clock modulation */
static bool intel_thermal_supported(struct cpuinfo_x86 *c)
{
    if ( !cpu_has_apic )
        return false;
    if ( !cpu_has(c, X86_FEATURE_ACPI) || !cpu_has(c, X86_FEATURE_TM1) )
        return false;
    return true;
}

static u32 __read_mostly lvtthmr_init;

static void __init mcheck_intel_therm_init(void)
{
    /*
     * This function is only called on boot CPU. Save the init thermal
     * LVT value on BSP and use that value to restore APs' thermal LVT
     * entry BIOS programmed later
     */
    if ( intel_thermal_supported(&boot_cpu_data) )
        lvtthmr_init = apic_read(APIC_LVTTHMR);
}

/* P4/Xeon Thermal regulation detect and init */
static void intel_init_thermal(struct cpuinfo_x86 *c)
{
    uint64_t msr_content;
    uint32_t val;
    int tm2 = 0;
    unsigned int cpu = smp_processor_id();
    static uint8_t thermal_apic_vector;

    if ( !intel_thermal_supported(c) )
        return; /* -ENODEV */

    /* first check if its enabled already, in which case there might
     * be some SMM goo which handles it, so we can't even put a handler
     * since it might be delivered via SMI already -zwanem.
     */
    rdmsrl(MSR_IA32_MISC_ENABLE, msr_content);
    val = lvtthmr_init;
    /*
     * The initial value of thermal LVT entries on all APs always reads
     * 0x10000 because APs are woken up by BSP issuing INIT-SIPI-SIPI
     * sequence to them and LVT registers are reset to 0s except for
     * the mask bits which are set to 1s when APs receive INIT IPI.
     * If BIOS takes over the thermal interrupt and sets its interrupt
     * delivery mode to SMI (not fixed), it restores the value that the
     * BIOS has programmed on AP based on BSP's info we saved (since BIOS
     * is required to set the same value for all threads/cores).
     */
    if ( (val & APIC_MODE_MASK) != APIC_DM_FIXED
         || (val & APIC_VECTOR_MASK) > 0xf )
        apic_write(APIC_LVTTHMR, val);

    if ( (msr_content & (1ULL<<3))
         && (val & APIC_MODE_MASK) == APIC_DM_SMI )
    {
        if ( c == &boot_cpu_data )
            printk(KERN_DEBUG "Thermal monitoring handled by SMI\n");
        return; /* -EBUSY */
    }

    if ( cpu_has(c, X86_FEATURE_TM2) && (msr_content & (1ULL << 13)) )
        tm2 = 1;

    /* check whether a vector already exists, temporarily masked? */
    if ( val & APIC_VECTOR_MASK )
    {
        if ( c == &boot_cpu_data )
            printk(KERN_DEBUG "Thermal LVT vector (%#x) already installed\n",
                   val & APIC_VECTOR_MASK);
        return; /* -EBUSY */
    }

    alloc_direct_apic_vector(&thermal_apic_vector, intel_thermal_interrupt);

    /* The temperature transition interrupt handler setup */
    val = thermal_apic_vector;    /* our delivery vector */
    val |= (APIC_DM_FIXED | APIC_LVT_MASKED);  /* we'll mask till we're ready */
    apic_write(APIC_LVTTHMR, val);

    rdmsrl(MSR_IA32_THERM_INTERRUPT, msr_content);
    wrmsrl(MSR_IA32_THERM_INTERRUPT, msr_content | 0x03);

    rdmsrl(MSR_IA32_MISC_ENABLE, msr_content);
    wrmsrl(MSR_IA32_MISC_ENABLE, msr_content | (1ULL<<3));

    apic_write(APIC_LVTTHMR, val & ~APIC_LVT_MASKED);
    if ( opt_cpu_info )
        printk(KERN_INFO "CPU%u: Thermal monitoring enabled (%s)\n",
               cpu, tm2 ? "TM2" : "TM1");
}

/* Intel MCE handler */
static inline void intel_get_extended_msr(struct mcinfo_extended *ext, u32 msr)
{
    if ( ext->mc_msrs < ARRAY_SIZE(ext->mc_msr)
         && msr < MSR_IA32_MCG_EAX + nr_intel_ext_msrs )
    {
        ext->mc_msr[ext->mc_msrs].reg = msr;
        rdmsrl(msr, ext->mc_msr[ext->mc_msrs].value);
        ++ext->mc_msrs;
    }
}


struct mcinfo_extended *
intel_get_extended_msrs(struct mcinfo_global *mig, struct mc_info *mi)
{
    struct mcinfo_extended *mc_ext;
    int i;

    /*
     * According to spec, processor _support_ 64 bit will always
     * have MSR beyond IA32_MCG_MISC
     */
    if ( !mi|| !mig || nr_intel_ext_msrs == 0 ||
         !(mig->mc_gstatus & MCG_STATUS_EIPV) )
        return NULL;

    mc_ext = x86_mcinfo_reserve(mi, sizeof(*mc_ext), MC_TYPE_EXTENDED);
    if ( !mc_ext )
    {
        mi->flags |= MCINFO_FLAGS_UNCOMPLETE;
        return NULL;
    }

    for ( i = MSR_IA32_MCG_EAX; i <= MSR_IA32_MCG_MISC; i++ )
        intel_get_extended_msr(mc_ext, i);

    for ( i = MSR_IA32_MCG_R8; i <= MSR_IA32_MCG_R15; i++ )
        intel_get_extended_msr(mc_ext, i);

    return mc_ext;
}

enum intel_mce_type
{
    intel_mce_invalid,
    intel_mce_fatal,
    intel_mce_corrected,
    intel_mce_ucr_ucna,
    intel_mce_ucr_srao,
    intel_mce_ucr_srar,
};

static enum intel_mce_type intel_check_mce_type(uint64_t status)
{
    if ( !(status & MCi_STATUS_VAL) )
        return intel_mce_invalid;

    if ( status & MCi_STATUS_PCC )
        return intel_mce_fatal;

    /* Corrected error? */
    if ( !(status & MCi_STATUS_UC) )
        return intel_mce_corrected;

    if ( !ser_support )
        return intel_mce_fatal;

    if ( status & MCi_STATUS_S )
    {
        if ( status & MCi_STATUS_AR )
        {
            if ( status & MCi_STATUS_OVER )
                return intel_mce_fatal;
            else
                return intel_mce_ucr_srar;
        } else
            return intel_mce_ucr_srao;
    }
    else
        return intel_mce_ucr_ucna;

    /* Any type not included abovoe ? */
    return intel_mce_fatal;
}

static void intel_memerr_dhandler(
             struct mca_binfo *binfo,
             enum mce_result *result,
             const struct cpu_user_regs *regs)
{
    mce_printk(MCE_VERBOSE, "MCE: Enter UCR recovery action\n");
    mc_memerr_dhandler(binfo, result, regs);
}

static bool intel_srar_check(uint64_t status)
{
    return (intel_check_mce_type(status) == intel_mce_ucr_srar);
}

static bool intel_checkaddr(uint64_t status, uint64_t misc, int addrtype)
{
    if ( !(status & MCi_STATUS_ADDRV) ||
         !(status & MCi_STATUS_MISCV) ||
         ((misc & MCi_MISC_ADDRMOD_MASK) != MCi_MISC_PHYSMOD) )
        /* addr is virtual */
        return (addrtype == MC_ADDR_VIRTUAL);

    return (addrtype == MC_ADDR_PHYSICAL);
}

static void intel_srar_dhandler(
             struct mca_binfo *binfo,
             enum mce_result *result,
             const struct cpu_user_regs *regs)
{
    uint64_t status = binfo->mib->mc_status;

    /* For unknown srar error code, reset system */
    *result = MCER_RESET;

    switch ( status & INTEL_MCCOD_MASK )
    {
    case INTEL_SRAR_DATA_LOAD:
    case INTEL_SRAR_INSTR_FETCH:
        intel_memerr_dhandler(binfo, result, regs);
        break;
    }
}

static bool intel_srao_check(uint64_t status)
{
    return (intel_check_mce_type(status) == intel_mce_ucr_srao);
}

static void intel_srao_dhandler(
             struct mca_binfo *binfo,
             enum mce_result *result,
             const struct cpu_user_regs *regs)
{
    uint64_t status = binfo->mib->mc_status;

    /* For unknown srao error code, no action required */
    *result = MCER_CONTINUE;

    if ( status & MCi_STATUS_VAL )
    {
        switch ( status & INTEL_MCCOD_MASK )
        {
        case INTEL_SRAO_MEM_SCRUB:
        case INTEL_SRAO_L3_EWB:
            intel_memerr_dhandler(binfo, result, regs);
            break;
        }
    }
}

static bool intel_default_check(uint64_t status)
{
    return true;
}

static void intel_default_mce_dhandler(
             struct mca_binfo *binfo,
             enum mce_result *result,
             const struct cpu_user_regs * regs)
{
    uint64_t status = binfo->mib->mc_status;
    enum intel_mce_type type;

    type = intel_check_mce_type(status);

    if ( type == intel_mce_fatal )
        *result = MCER_RESET;
    else
        *result = MCER_CONTINUE;
}

static const struct mca_error_handler intel_mce_dhandlers[] = {
    {intel_srao_check, intel_srao_dhandler},
    {intel_srar_check, intel_srar_dhandler},
    {intel_default_check, intel_default_mce_dhandler}
};

static void intel_default_mce_uhandler(
             struct mca_binfo *binfo,
             enum mce_result *result,
             const struct cpu_user_regs *regs)
{
    uint64_t status = binfo->mib->mc_status;
    enum intel_mce_type type;

    type = intel_check_mce_type(status);

    switch ( type )
    {
    case intel_mce_fatal:
        *result = MCER_RESET;
        break;

    default:
        *result = MCER_CONTINUE;
        break;
    }
}

static const struct mca_error_handler intel_mce_uhandlers[] = {
    {intel_default_check, intel_default_mce_uhandler}
};

/* According to MCA OS writer guide, CMCI handler need to clear bank when
 * 1) CE (UC = 0)
 * 2) ser_support = 1, Superious error, OVER = 0, EN = 0, [UC = 1]
 * 3) ser_support = 1, UCNA, OVER = 0, S = 1, AR = 0, PCC = 0, [UC = 1, EN = 1]
 * MCA handler need to clear bank when
 * 1) ser_support = 1, Superious error, OVER = 0, EN = 0, UC = 1
 * 2) ser_support = 1, SRAR, UC = 1, OVER = 0, S = 1, AR = 1, [EN = 1]
 * 3) ser_support = 1, SRAO, UC = 1, S = 1, AR = 0, [EN = 1]
 */

static bool intel_need_clearbank_scan(enum mca_source who, u64 status)
{
    if ( who == MCA_CMCI_HANDLER )
    {
        /* CMCI need clear bank */
        if ( !(status & MCi_STATUS_UC) )
            return true;
        /* Spurious need clear bank */
        else if ( ser_support && !(status & MCi_STATUS_OVER)
                  && !(status & MCi_STATUS_EN) )
            return true;
        /* UCNA OVER = 0 need clear bank */
        else if ( ser_support && !(status & MCi_STATUS_OVER)
                  && !(status & MCi_STATUS_PCC) && !(status & MCi_STATUS_S)
                  && !(status & MCi_STATUS_AR) )
            return true;
        /* Only Log, no clear */
        else return false;
    }
    else if ( who == MCA_MCE_SCAN )
    {
        if ( !ser_support )
            return false;
        /*
         * For fatal error, it shouldn't be cleared so that sticky bank
         * have chance to be handled after reboot by polling
         */
        if ( (status & MCi_STATUS_UC) && (status & MCi_STATUS_PCC) )
            return false;
        /* Spurious need clear bank */
        else if ( !(status & MCi_STATUS_OVER)
                  && (status & MCi_STATUS_UC) && !(status & MCi_STATUS_EN) )
            return true;
        /* SRAR OVER=0 clear bank. OVER = 1 have caused reset */
        else if ( (status & MCi_STATUS_UC)
                  && (status & MCi_STATUS_S) && (status & MCi_STATUS_AR)
                  && !(status & MCi_STATUS_OVER) )
            return true;
        /* SRAO need clear bank */
        else if ( !(status & MCi_STATUS_AR)
                  && (status & MCi_STATUS_S) && (status & MCi_STATUS_UC) )
            return true;
        else
            return false;
    }

    return true;
}

/*
 * MCE continues/is recoverable when
 * 1) CE UC = 0
 * 2) Supious ser_support = 1, OVER = 0, En = 0 [UC = 1]
 * 3) SRAR ser_support = 1, OVER = 0, PCC = 0, S = 1, AR = 1 [UC =1, EN = 1]
 * 4) SRAO ser_support = 1, PCC = 0, S = 1, AR = 0, EN = 1 [UC = 1]
 * 5) UCNA ser_support = 1, OVER = 0, EN = 1, PCC = 0, S = 0, AR = 0, [UC = 1]
 */
static bool intel_recoverable_scan(uint64_t status)
{

    if ( !(status & MCi_STATUS_UC ) )
        return true;
    else if ( ser_support && !(status & MCi_STATUS_EN)
              && !(status & MCi_STATUS_OVER) )
        return true;
    /* SRAR error */
    else if ( ser_support && !(status & MCi_STATUS_OVER)
              && !(status & MCi_STATUS_PCC) && (status & MCi_STATUS_S)
              && (status & MCi_STATUS_AR) && (status & MCi_STATUS_EN) )
        return true;
    /* SRAO error */
    else if ( ser_support && !(status & MCi_STATUS_PCC)
              && (status & MCi_STATUS_S) && !(status & MCi_STATUS_AR)
              && (status & MCi_STATUS_EN) )
        return true;
    /* UCNA error */
    else if ( ser_support && !(status & MCi_STATUS_OVER)
              && (status & MCi_STATUS_EN) && !(status & MCi_STATUS_PCC)
              && !(status & MCi_STATUS_S) && !(status & MCi_STATUS_AR) )
        return true;
    return false;
}

/* CMCI */
static DEFINE_SPINLOCK(cmci_discover_lock);

/*
 * Discover bank sharing using the algorithm recommended in the SDM.
 */
static int do_cmci_discover(int i)
{
    unsigned msr = MSR_IA32_MCx_CTL2(i);
    u64 val;
    unsigned int threshold, max_threshold;
    unsigned int cpu = smp_processor_id();
    static unsigned int cmci_threshold = 2;
    integer_param("cmci-threshold", cmci_threshold);

    rdmsrl(msr, val);
    /* Some other CPU already owns this bank. */
    if ( val & CMCI_EN )
    {
        mcabanks_clear(i, per_cpu(mce_banks_owned, cpu));
        goto out;
    }

    if ( cmci_threshold )
    {
        wrmsrl(msr, val | CMCI_EN | CMCI_THRESHOLD_MASK);
        rdmsrl(msr, val);
    }

    if ( !(val & CMCI_EN) )
    {
        /* This bank does not support CMCI. Polling timer has to handle it. */
        mcabanks_set(i, per_cpu(no_cmci_banks, cpu));
        wrmsrl(msr, val & ~CMCI_THRESHOLD_MASK);
        return 0;
    }
    max_threshold = MASK_EXTR(val, CMCI_THRESHOLD_MASK);
    threshold = cmci_threshold;
    if ( threshold > max_threshold )
    {
        mce_printk(MCE_QUIET,
                   "CMCI: threshold %#x too large for CPU%u bank %u, using %#x\n",
                   threshold, cpu, i, max_threshold);
        threshold = max_threshold;
    }
    wrmsrl(msr, (val & ~CMCI_THRESHOLD_MASK) | CMCI_EN | threshold);
    mcabanks_set(i, per_cpu(mce_banks_owned, cpu));
out:
    mcabanks_clear(i, per_cpu(no_cmci_banks, cpu));
    return 1;
}

static void cmci_discover(void)
{
    unsigned long flags;
    unsigned int i, cpu = smp_processor_id();
    mctelem_cookie_t mctc;
    struct mca_summary bs;

    mce_printk(MCE_VERBOSE, "CMCI: find owner on CPU%u\n", cpu);

    spin_lock_irqsave(&cmci_discover_lock, flags);

    for ( i = 0; i < per_cpu(nr_mce_banks, cpu); i++ )
        if ( !mcabanks_test(i, per_cpu(mce_banks_owned, cpu)) )
            do_cmci_discover(i);

    spin_unlock_irqrestore(&cmci_discover_lock, flags);

    /*
     * In case CMCI happended when do owner change.
     * If CMCI happened yet not processed immediately,
     * MCi_status (error_count bit 38~52) is not cleared,
     * the CMCI interrupt will never be triggered again.
     */

    mctc = mcheck_mca_logout(
        MCA_CMCI_HANDLER, per_cpu(mce_banks_owned, cpu), &bs, NULL);

    if ( bs.errcnt && mctc != NULL )
    {
        if ( dom0_vmce_enabled() )
        {
            mctelem_commit(mctc);
            send_global_virq(VIRQ_MCA);
        }
        else
        {
            x86_mcinfo_dump(mctelem_dataptr(mctc));
            mctelem_dismiss(mctc);
        }
    }
    else if ( mctc != NULL )
        mctelem_dismiss(mctc);

    mce_printk(MCE_VERBOSE, "CMCI: CPU%d owner_map[%lx], no_cmci_map[%lx]\n",
               cpu,
               per_cpu(mce_banks_owned, cpu)->bank_map[0],
               per_cpu(no_cmci_banks, cpu)->bank_map[0]);
}

/*
 * Define an owner for each bank. Banks can be shared between CPUs
 * and to avoid reporting events multiple times always set up one
 * CPU as owner.
 *
 * The assignment has to be redone when CPUs go offline and
 * any of the owners goes away. Also pollers run in parallel so we
 * have to be careful to update the banks in a way that doesn't
 * lose or duplicate events.
 */

static void mce_set_owner(void)
{
    if ( !cmci_support || !opt_mce )
        return;

    cmci_discover();
}

static void __cpu_mcheck_distribute_cmci(void *unused)
{
    cmci_discover();
}

static void cpu_mcheck_distribute_cmci(void)
{
    if ( cmci_support && opt_mce )
        on_each_cpu(__cpu_mcheck_distribute_cmci, NULL, 0);
}

static void clear_cmci(void)
{
    unsigned int i, cpu = smp_processor_id();

    if ( !cmci_support || !opt_mce )
        return;

    mce_printk(MCE_VERBOSE, "CMCI: clear_cmci support on CPU%u\n", cpu);

    for ( i = 0; i < per_cpu(nr_mce_banks, cpu); i++ )
    {
        unsigned msr = MSR_IA32_MCx_CTL2(i);
        u64 val;

        if ( !mcabanks_test(i, per_cpu(mce_banks_owned, cpu)) )
            continue;
        rdmsrl(msr, val);
        if ( val & (CMCI_EN|CMCI_THRESHOLD_MASK) )
            wrmsrl(msr, val & ~(CMCI_EN|CMCI_THRESHOLD_MASK));
        mcabanks_clear(i, per_cpu(mce_banks_owned, cpu));
    }
}

static void cpu_mcheck_disable(void)
{
    if ( cmci_support && opt_mce )
        clear_cmci();
}

static void cmci_interrupt(struct cpu_user_regs *regs)
{
    mctelem_cookie_t mctc;
    struct mca_summary bs;

    ack_APIC_irq();

    mctc = mcheck_mca_logout(
        MCA_CMCI_HANDLER, this_cpu(mce_banks_owned), &bs, NULL);

    if ( bs.errcnt && mctc != NULL )
    {
        if ( dom0_vmce_enabled() )
        {
            mctelem_commit(mctc);
            mce_printk(MCE_VERBOSE, "CMCI: send CMCI to DOM0 through virq\n");
            send_global_virq(VIRQ_MCA);
        }
        else
        {
            x86_mcinfo_dump(mctelem_dataptr(mctc));
            mctelem_dismiss(mctc);
        }
    }
    else if ( mctc != NULL )
        mctelem_dismiss(mctc);
}

static void intel_init_cmci(struct cpuinfo_x86 *c)
{
    u32 l, apic;
    int cpu = smp_processor_id();

    if ( !mce_available(c) || !cmci_support )
    {
        if ( opt_cpu_info )
            mce_printk(MCE_QUIET, "CMCI: CPU%d has no CMCI support\n", cpu);
        return;
    }

    apic = apic_read(APIC_CMCI);
    if ( apic & APIC_VECTOR_MASK )
    {
        mce_printk(MCE_QUIET, "CPU%d CMCI LVT vector (%#x) already installed\n",
                   cpu, ( apic & APIC_VECTOR_MASK ));
        return;
    }

    alloc_direct_apic_vector(&cmci_apic_vector, cmci_interrupt);

    apic = cmci_apic_vector;
    apic |= (APIC_DM_FIXED | APIC_LVT_MASKED);
    apic_write(APIC_CMCI, apic);

    l = apic_read(APIC_CMCI);
    apic_write(APIC_CMCI, l & ~APIC_LVT_MASKED);

    mce_set_owner();
}

/* MCA */

static bool mce_is_broadcast(struct cpuinfo_x86 *c)
{
    if ( mce_force_broadcast )
        return true;

    /*
     * According to Intel SDM Dec, 2009, 15.10.4.1, For processors with
     * DisplayFamily_DisplayModel encoding of 06H_EH and above,
     * a MCA signal is broadcast to all logical processors in the system
     */
    if ( c->x86_vendor == X86_VENDOR_INTEL && c->x86 == 6 &&
         c->x86_model >= 0xe )
        return true;
    return false;
}

static bool intel_enable_lmce(void)
{
    uint64_t msr_content;

    /*
     * Section "Enabling Local Machine Check" in Intel SDM Vol 3
     * requires software must ensure the LOCK bit and LMCE_ON bit
     * of MSR_IA32_FEATURE_CONTROL are set before setting
     * MSR_IA32_MCG_EXT_CTL.LMCE_EN.
     */

    if ( rdmsr_safe(MSR_IA32_FEATURE_CONTROL, msr_content) )
        return false;

    if ( (msr_content & IA32_FEATURE_CONTROL_LOCK) &&
         (msr_content & IA32_FEATURE_CONTROL_LMCE_ON) )
    {
        wrmsrl(MSR_IA32_MCG_EXT_CTL, MCG_EXT_CTL_LMCE_EN);
        return true;
    }

    return false;
}

/* Check and init MCA */
static void intel_init_mca(struct cpuinfo_x86 *c)
{
    bool broadcast, cmci = false, ser = false, lmce = false;
    int ext_num = 0, first;
    uint64_t msr_content;

    broadcast = mce_is_broadcast(c);

    rdmsrl(MSR_IA32_MCG_CAP, msr_content);

    if ( (msr_content & MCG_CMCI_P) && cpu_has_apic )
        cmci = true;

    /* Support Software Error Recovery */
    if ( msr_content & MCG_SER_P )
        ser = true;

    if ( msr_content & MCG_EXT_P )
        ext_num = (msr_content >> MCG_EXT_CNT) & 0xff;

    first = mce_firstbank(c);

    if ( !mce_force_broadcast && (msr_content & MCG_LMCE_P) )
        lmce = intel_enable_lmce();

#define CAP(enabled, name) ((enabled) ? ", " name : "")
    if ( smp_processor_id() == 0 )
    {
        dprintk(XENLOG_INFO,
                "MCA Capability: firstbank %d, extended MCE MSR %d%s%s%s%s\n",
                first, ext_num,
                CAP(broadcast, "BCAST"),
                CAP(ser, "SER"),
                CAP(cmci, "CMCI"),
                CAP(lmce, "LMCE"));

        mce_broadcast = broadcast;
        cmci_support = cmci;
        ser_support = ser;
        lmce_support = lmce;
        nr_intel_ext_msrs = ext_num;
        firstbank = first;
    }
    else if ( cmci != cmci_support || ser != ser_support ||
              broadcast != mce_broadcast ||
              first != firstbank || ext_num != nr_intel_ext_msrs ||
              lmce != lmce_support )
        dprintk(XENLOG_WARNING,
                "CPU%u has different MCA capability "
                "(firstbank %d, extended MCE MSR %d%s%s%s%s)"
                " than BSP, may cause undetermined result!!!\n",
                smp_processor_id(), first, ext_num,
                CAP(broadcast, "BCAST"),
                CAP(ser, "SER"),
                CAP(cmci, "CMCI"),
                CAP(lmce, "LMCE"));
#undef CAP
}

static void intel_mce_post_reset(void)
{
    mctelem_cookie_t mctc;
    struct mca_summary bs;

    mctc = mcheck_mca_logout(MCA_RESET, mca_allbanks, &bs, NULL);

    /* in the boot up stage, print out and also log in DOM0 boot process */
    if ( bs.errcnt && mctc != NULL )
    {
        x86_mcinfo_dump(mctelem_dataptr(mctc));
        mctelem_commit(mctc);
    }
    return;
}

static void intel_init_mce(void)
{
    uint64_t msr_content;
    int i;

    intel_mce_post_reset();

    /* clear all banks */
    for ( i = firstbank; i < this_cpu(nr_mce_banks); i++ )
    {
        /*
         * Some banks are shared across cores, use MCi_CTRL to judge whether
         * this bank has been initialized by other cores already.
         */
        rdmsrl(MSR_IA32_MCx_CTL(i), msr_content);
        if ( !msr_content )
        {
            /* if ctl is 0, this bank is never initialized */
            mce_printk(MCE_VERBOSE, "mce_init: init bank%d\n", i);
            wrmsrl(MSR_IA32_MCx_CTL(i), 0xffffffffffffffffULL);
            wrmsrl(MSR_IA32_MCx_STATUS(i), 0x0ULL);
        }
    }
    if ( firstbank ) /* if cmci enabled, firstbank = 0 */
        wrmsrl(MSR_IA32_MC0_STATUS, 0x0ULL);

    x86_mce_vector_register(mcheck_cmn_handler);
    mce_recoverable_register(intel_recoverable_scan);
    mce_need_clearbank_register(intel_need_clearbank_scan);
    mce_register_addrcheck(intel_checkaddr);

    mce_dhandlers = intel_mce_dhandlers;
    mce_dhandler_num = ARRAY_SIZE(intel_mce_dhandlers);
    mce_uhandlers = intel_mce_uhandlers;
    mce_uhandler_num = ARRAY_SIZE(intel_mce_uhandlers);
}

static void intel_init_ppin(const struct cpuinfo_x86 *c)
{
    /*
     * Even if testing the presence of the MSR would be enough, we don't
     * want to risk the situation where other models reuse this MSR for
     * other purposes.
     */
    switch ( c->x86_model )
    {
        uint64_t val;

    case 0x3e: /* IvyBridge X */
    case 0x3f: /* Haswell X */
    case 0x4f: /* Broadwell X */
    case 0x55: /* Skylake X */
    case 0x56: /* Broadwell Xeon D */
    case 0x57: /* Knights Landing */
    case 0x85: /* Knights Mill */

        if ( (c != &boot_cpu_data && !ppin_msr) ||
             rdmsr_safe(MSR_PPIN_CTL, val) )
            return;

        /* If PPIN is disabled, but not locked, try to enable. */
        if ( !(val & (PPIN_ENABLE | PPIN_LOCKOUT)) )
        {
            wrmsr_safe(MSR_PPIN_CTL, val | PPIN_ENABLE);
            rdmsr_safe(MSR_PPIN_CTL, val);
        }

        if ( (val & (PPIN_ENABLE | PPIN_LOCKOUT)) != PPIN_ENABLE )
            ppin_msr = 0;
        else if ( c == &boot_cpu_data )
            ppin_msr = MSR_PPIN;
    }
}

static void cpu_mcabank_free(unsigned int cpu)
{
    struct mca_banks *cmci = per_cpu(no_cmci_banks, cpu);
    struct mca_banks *owned = per_cpu(mce_banks_owned, cpu);

    mcabanks_free(cmci);
    mcabanks_free(owned);
}

static int cpu_mcabank_alloc(unsigned int cpu)
{
    unsigned int nr = per_cpu(nr_mce_banks, cpu);
    struct mca_banks *cmci = mcabanks_alloc(nr);
    struct mca_banks *owned = mcabanks_alloc(nr);

    if ( !cmci || !owned )
        goto out;

    per_cpu(no_cmci_banks, cpu) = cmci;
    per_cpu(mce_banks_owned, cpu) = owned;
    per_cpu(last_state, cpu) = -1;

    return 0;
 out:
    mcabanks_free(cmci);
    mcabanks_free(owned);
    return -ENOMEM;
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = cpu_mcabank_alloc(cpu);
        break;

    case CPU_DYING:
        cpu_mcheck_disable();
        break;

    case CPU_UP_CANCELED:
    case CPU_DEAD:
        cpu_mcheck_distribute_cmci();
        cpu_mcabank_free(cpu);
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

/* p4/p6 family have similar MCA initialization process */
enum mcheck_type intel_mcheck_init(struct cpuinfo_x86 *c, bool bsp)
{
    if ( bsp )
    {
        /* Early MCE initialisation for BSP. */
        if ( cpu_mcabank_alloc(0) )
            BUG();
        register_cpu_notifier(&cpu_nfb);
        mcheck_intel_therm_init();
    }
    else
    {
        unsigned int cpu = smp_processor_id();

        per_cpu(no_cmci_banks, cpu)->num = per_cpu(nr_mce_banks, cpu);
        per_cpu(mce_banks_owned, cpu)->num = per_cpu(nr_mce_banks, cpu);
    }

    intel_init_mca(c);

    mce_handler_init();

    intel_init_mce();

    intel_init_cmci(c);

    intel_init_thermal(c);

    intel_init_ppin(c);

    return mcheck_intel;
}

/* intel specific MCA MSR */
int vmce_intel_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val)
{
    unsigned int bank = msr - MSR_IA32_MC0_CTL2;

    if ( bank < GUEST_MC_BANK_NUM )
    {
        v->arch.vmce.bank[bank].mci_ctl2 = val;
        mce_printk(MCE_VERBOSE, "MCE: wr MC%u_CTL2 %#"PRIx64"\n", bank, val);
    }

    return 1;
}

int vmce_intel_rdmsr(const struct vcpu *v, uint32_t msr, uint64_t *val)
{
    unsigned int bank = msr - MSR_IA32_MC0_CTL2;

    if ( bank < GUEST_MC_BANK_NUM )
    {
        *val = v->arch.vmce.bank[bank].mci_ctl2;
        mce_printk(MCE_VERBOSE, "MCE: rd MC%u_CTL2 %#"PRIx64"\n", bank, *val);
    }

    return 1;
}

bool vmce_has_lmce(const struct vcpu *v)
{
    return v->arch.vmce.mcg_cap & MCG_LMCE_P;
}
