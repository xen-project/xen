/* drivers/acpi/sleep/power.c - PM core functionality for Xen
 *
 * Copyrights from Linux side:
 * Copyright (c) 2000-2003 Patrick Mochel
 * Copyright (C) 2001-2003 Pavel Machek <pavel@suse.cz>
 * Copyright (c) 2003 Open Source Development Lab
 * Copyright (c) 2004 David Shaohua Li <shaohua.li@intel.com>
 * Copyright (c) 2005 Alexey Starikovskiy <alexey.y.starikovskiy@intel.com>
 *
 * Slimmed with Xen specific support.
 */

#include <asm/io.h>
#include <xen/acpi.h>
#include <xen/errno.h>
#include <xen/iocap.h>
#include <xen/sched.h>
#include <asm/acpi.h>
#include <asm/irq.h>
#include <asm/init.h>
#include <xen/spinlock.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/console.h>
#include <xen/iommu.h>
#include <xen/watchdog.h>
#include <xen/cpu.h>
#include <public/platform.h>
#include <asm/tboot.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/spec_ctrl.h>
#include <acpi/cpufreq/cpufreq.h>

uint32_t system_reset_counter = 1;

static int __init parse_acpi_sleep(const char *s)
{
    const char *ss;
    unsigned int flag = 0;
    int rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( !cmdline_strcmp(s, "s3_bios") )
            flag |= 1;
        else if ( !cmdline_strcmp(s, "s3_mode") )
            flag |= 2;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    acpi_video_flags |= flag;

    return rc;
}
custom_param("acpi_sleep", parse_acpi_sleep);

static DEFINE_SPINLOCK(pm_lock);

struct acpi_sleep_info acpi_sinfo;

void do_suspend_lowlevel(void);

enum dev_power_saved
{
    SAVED_NONE,
    SAVED_CONSOLE,
    SAVED_TIME,
    SAVED_I8259A,
    SAVED_IOAPIC,
    SAVED_IOMMU,
    SAVED_LAPIC,
    SAVED_ALL,
};

static int device_power_down(void)
{
    if ( console_suspend() )
        return SAVED_NONE;

    if ( time_suspend() )
        return SAVED_CONSOLE;

    if ( i8259A_suspend() )
        return SAVED_TIME;

    /* ioapic_suspend cannot fail */
    ioapic_suspend();

    if ( iommu_suspend() )
        return SAVED_IOAPIC;

    if ( lapic_suspend() )
        return SAVED_IOMMU;

    return SAVED_ALL;
}

static void device_power_up(enum dev_power_saved saved)
{
    switch ( saved )
    {
    case SAVED_ALL:
    case SAVED_LAPIC:
        lapic_resume();
        /* fall through */
    case SAVED_IOMMU:
        iommu_resume();
        /* fall through */
    case SAVED_IOAPIC:
        ioapic_resume();
        /* fall through */
    case SAVED_I8259A:
        i8259A_resume();
        /* fall through */
    case SAVED_TIME:
        time_resume();
        /* fall through */
    case SAVED_CONSOLE:
        console_resume();
        /* fall through */
    case SAVED_NONE:
        break;
    default:
        BUG();
        break;
    }
}

static void freeze_domains(void)
{
    struct domain *d;

    rcu_read_lock(&domlist_read_lock);
    /*
     * Note that we iterate in order of domain-id. Hence we will pause dom0
     * first which is required for correctness (as only dom0 can add domains to
     * the domain list). Otherwise we could miss concurrently-created domains.
     */
    for_each_domain ( d )
        domain_pause(d);
    rcu_read_unlock(&domlist_read_lock);

    scheduler_disable();
}

static void thaw_domains(void)
{
    struct domain *d;

    scheduler_enable();

    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d )
    {
        restore_vcpu_affinity(d);
        domain_unpause(d);
    }
    rcu_read_unlock(&domlist_read_lock);
}

static void acpi_sleep_prepare(u32 state)
{
    void *wakeup_vector_va;

    if ( state != ACPI_STATE_S3 )
        return;

    wakeup_vector_va = __acpi_map_table(
        acpi_sinfo.wakeup_vector, sizeof(uint64_t));

    /* TBoot will set resume vector itself (when it is safe to do so). */
    if ( tboot_in_measured_env() )
        return;

    if ( acpi_sinfo.vector_width == 32 )
        *(uint32_t *)wakeup_vector_va = bootsym_phys(wakeup_start);
    else
        *(uint64_t *)wakeup_vector_va = bootsym_phys(wakeup_start);
}

static void acpi_sleep_post(u32 state) {}

/* Main interface to do xen specific suspend/resume */
static int enter_state(u32 state)
{
    unsigned long flags;
    int error;
    struct cpu_info *ci;
    unsigned long cr4;

    if ( (state <= ACPI_STATE_S0) || (state > ACPI_S_STATES_MAX) )
        return -EINVAL;

    if ( !spin_trylock(&pm_lock) )
        return -EBUSY;

    BUG_ON(system_state != SYS_STATE_active);
    BUG_ON(!is_idle_vcpu(current));
    BUG_ON(smp_processor_id() != 0);
    system_state = SYS_STATE_suspend;

    printk(XENLOG_INFO "Preparing system for ACPI S%d state.\n", state);

    freeze_domains();

    acpi_dmar_reinstate();

    if ( (error = disable_nonboot_cpus()) )
    {
        system_state = SYS_STATE_resume;
        goto enable_cpu;
    }

    cpufreq_del_cpu(0);

    hvm_cpu_down();

    acpi_sleep_prepare(state);

    watchdog_disable();
    console_start_sync();
    printk("Entering ACPI S%d state.\n", state);

    local_irq_save(flags);
    spin_debug_disable();

    if ( (error = device_power_down()) != SAVED_ALL )
    {
        printk(XENLOG_ERR "Some devices failed to power down.");
        system_state = SYS_STATE_resume;
        device_power_up(error);
        console_end_sync();
        watchdog_enable();
        error = -EIO;
        goto done;
    }
    else
        error = 0;

    ci = get_cpu_info();
    spec_ctrl_enter_idle(ci);
    /* Avoid NMI/#MC using MSR_SPEC_CTRL until we've reloaded microcode. */
    ci->spec_ctrl_flags &= ~SCF_ist_wrmsr;

    ACPI_FLUSH_CPU_CACHE();

    switch ( state )
    {
    case ACPI_STATE_S3:
        do_suspend_lowlevel();
        system_reset_counter++;
        error = tboot_s3_resume();
        break;
    case ACPI_STATE_S5:
        acpi_enter_sleep_state(ACPI_STATE_S5);
        break;
    default:
        error = -EINVAL;
        break;
    }

    system_state = SYS_STATE_resume;

    /* Restore CR4 and EFER from cached values. */
    cr4 = read_cr4();
    write_cr4(cr4 & ~X86_CR4_MCE);
    write_efer(read_efer());

    device_power_up(SAVED_ALL);

    mcheck_init(&boot_cpu_data, false);
    write_cr4(cr4);

    printk(XENLOG_INFO "Finishing wakeup from ACPI S%d state.\n", state);

    if ( (state == ACPI_STATE_S3) && error )
        tboot_s3_error(error);

    console_end_sync();
    watchdog_enable();

    microcode_update_one(true);

    if ( !recheck_cpu_features(0) )
        panic("Missing previously available feature(s)\n");

    /* Re-enabled default NMI/#MC use of MSR_SPEC_CTRL. */
    ci->spec_ctrl_flags |= (default_spec_ctrl_flags & SCF_ist_wrmsr);
    spec_ctrl_exit_idle(ci);

 done:
    spin_debug_enable();
    local_irq_restore(flags);
    acpi_sleep_post(state);
    if ( hvm_cpu_up() )
        BUG();
    cpufreq_add_cpu(0);

 enable_cpu:
    rcu_barrier();
    mtrr_aps_sync_begin();
    enable_nonboot_cpus();
    mtrr_aps_sync_end();
    iommu_adjust_irq_affinities();
    acpi_dmar_zap();
    thaw_domains();
    system_state = SYS_STATE_active;
    spin_unlock(&pm_lock);
    return error;
}

static long enter_state_helper(void *data)
{
    struct acpi_sleep_info *sinfo = (struct acpi_sleep_info *)data;
    return enter_state(sinfo->sleep_state);
}

/*
 * Dom0 issues this hypercall in place of writing pm1a_cnt. Xen then
 * takes over the control and put the system into sleep state really.
 */
int acpi_enter_sleep(struct xenpf_enter_acpi_sleep *sleep)
{
    if ( sleep->flags & XENPF_ACPI_SLEEP_EXTENDED )
    {
        if ( !acpi_sinfo.sleep_control.address ||
             !acpi_sinfo.sleep_status.address )
            return -EPERM;

        if ( sleep->flags & ~XENPF_ACPI_SLEEP_EXTENDED )
            return -EINVAL;

        if ( sleep->val_a > ACPI_SLEEP_TYPE_MAX ||
             (sleep->val_b != ACPI_SLEEP_TYPE_INVALID &&
              sleep->val_b > ACPI_SLEEP_TYPE_MAX) )
            return -ERANGE;

        acpi_sinfo.sleep_type_a = sleep->val_a;
        acpi_sinfo.sleep_type_b = sleep->val_b;

        acpi_sinfo.sleep_extended = 1;
    }

    else if ( !acpi_sinfo.pm1a_cnt_blk.address )
        return -EPERM;

    /* Sanity check */
    else if ( sleep->val_b &&
              ((sleep->val_a ^ sleep->val_b) & ACPI_BITMASK_SLEEP_ENABLE) )
    {
        gdprintk(XENLOG_ERR, "Mismatched pm1a/pm1b setting\n");
        return -EINVAL;
    }

    else if ( sleep->flags )
        return -EINVAL;

    else
    {
        acpi_sinfo.pm1a_cnt_val = sleep->val_a;
        acpi_sinfo.pm1b_cnt_val = sleep->val_b;
        acpi_sinfo.sleep_extended = 0;
    }

    acpi_sinfo.sleep_state = sleep->sleep_state;

    return continue_hypercall_on_cpu(0, enter_state_helper, &acpi_sinfo);
}

static int acpi_get_wake_status(void)
{
    uint32_t val;
    acpi_status status;

    if ( acpi_sinfo.sleep_extended )
    {
        status = acpi_hw_register_read(ACPI_REGISTER_SLEEP_STATUS, &val);

        return ACPI_FAILURE(status) ? 0 : val & ACPI_X_WAKE_STATUS;
    }

    /* Wake status is the 15th bit of PM1 status register. (ACPI spec 3.0) */
    status = acpi_hw_register_read(ACPI_REGISTER_PM1_STATUS, &val);
    if ( ACPI_FAILURE(status) )
        return 0;

    val &= ACPI_BITMASK_WAKE_STATUS;
    val >>= ACPI_BITPOSITION_WAKE_STATUS;
    return val;
}

static void tboot_sleep(u8 sleep_state)
{
    uint32_t shutdown_type;

#define TB_COPY_GAS(tbg, g)             \
    tbg.space_id = g.space_id;          \
    tbg.bit_width = g.bit_width;        \
    tbg.bit_offset = g.bit_offset;      \
    tbg.access_width = g.access_width;  \
    tbg.address = g.address;

    /* sizes are not same (due to packing) so copy each one */
    TB_COPY_GAS(g_tboot_shared->acpi_sinfo.pm1a_cnt_blk,
                acpi_sinfo.pm1a_cnt_blk);
    TB_COPY_GAS(g_tboot_shared->acpi_sinfo.pm1b_cnt_blk,
                acpi_sinfo.pm1b_cnt_blk);
    TB_COPY_GAS(g_tboot_shared->acpi_sinfo.pm1a_evt_blk,
                acpi_sinfo.pm1a_evt_blk);
    TB_COPY_GAS(g_tboot_shared->acpi_sinfo.pm1b_evt_blk,
                acpi_sinfo.pm1b_evt_blk);
    g_tboot_shared->acpi_sinfo.pm1a_cnt_val = acpi_sinfo.pm1a_cnt_val;
    g_tboot_shared->acpi_sinfo.pm1b_cnt_val = acpi_sinfo.pm1b_cnt_val;
    g_tboot_shared->acpi_sinfo.wakeup_vector = acpi_sinfo.wakeup_vector;
    g_tboot_shared->acpi_sinfo.vector_width = acpi_sinfo.vector_width;
    g_tboot_shared->acpi_sinfo.kernel_s3_resume_vector =
                                              bootsym_phys(wakeup_start);

    switch ( sleep_state )
    {
        case ACPI_STATE_S3:
            shutdown_type = TB_SHUTDOWN_S3;
            break;
        case ACPI_STATE_S4:
            shutdown_type = TB_SHUTDOWN_S4;
            break;
        case ACPI_STATE_S5:
            shutdown_type = TB_SHUTDOWN_S5;
            break;
        default:
            return;
    }

    tboot_shutdown(shutdown_type);
}

/* System is really put into sleep state by this stub */
acpi_status acpi_enter_sleep_state(u8 sleep_state)
{
    acpi_status status;

    if ( tboot_in_measured_env() )
    {
        tboot_sleep(sleep_state);
        printk(XENLOG_ERR "TBOOT failed entering s3 state\n");
        return_ACPI_STATUS(AE_ERROR);
    }

    ACPI_FLUSH_CPU_CACHE();

    if ( acpi_sinfo.sleep_extended )
    {
        /*
         * Set the SLP_TYP and SLP_EN bits.
         *
         * Note: We only use the first value returned by the \_Sx method
         * (acpi_sinfo.sleep_type_a) - As per ACPI specification.
         */
        u8 sleep_type_value =
            ((acpi_sinfo.sleep_type_a << ACPI_X_SLEEP_TYPE_POSITION) &
             ACPI_X_SLEEP_TYPE_MASK) | ACPI_X_SLEEP_ENABLE;

        status = acpi_hw_register_write(ACPI_REGISTER_SLEEP_CONTROL,
                                        sleep_type_value);
    }
    else
    {
        status = acpi_hw_register_write(ACPI_REGISTER_PM1A_CONTROL,
                                        acpi_sinfo.pm1a_cnt_val);
        if ( !ACPI_FAILURE(status) && acpi_sinfo.pm1b_cnt_blk.address )
            status = acpi_hw_register_write(ACPI_REGISTER_PM1B_CONTROL,
                                            acpi_sinfo.pm1b_cnt_val);
    }

    if ( ACPI_FAILURE(status) )
        return_ACPI_STATUS(AE_ERROR);

    /* Wait until we enter sleep state, and spin until we wake */
    while ( !acpi_get_wake_status() )
        continue;

    return_ACPI_STATUS(AE_OK);
}
