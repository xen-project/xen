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

#include <xen/acpi.h>
#include <xen/console.h>
#include <xen/cpu.h>
#include <xen/domain.h>
#include <xen/errno.h>
#include <xen/iocap.h>
#include <xen/iommu.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/watchdog.h>

#include <asm/acpi.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/irq.h>
#include <asm/microcode.h>
#include <asm/prot-key.h>
#include <asm/spec_ctrl.h>
#include <asm/tboot.h>
#include <asm/trampoline.h>
#include <asm/traps.h>

#include <public/platform.h>

#include <acpi/cpufreq/cpufreq.h>

uint32_t system_reset_counter = 1;

static int __init cf_check parse_acpi_sleep(const char *s)
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

    bootsym(video_flags) |= flag;

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

static void acpi_sleep_prepare(u32 state)
{
    void *wakeup_vector_va;
    paddr_t entry_pa;

    if ( state != ACPI_STATE_S3 )
        return;

    /* TBoot will set resume vector itself (when it is safe to do so). */
    if ( tboot_in_measured_env() )
        return;

    set_fixmap(FIX_ACPI_END, acpi_sinfo.wakeup_vector);
    wakeup_vector_va = fix_to_virt(FIX_ACPI_END) +
                       PAGE_OFFSET(acpi_sinfo.wakeup_vector);

    entry_pa = bootsym_phys(entry_S3);

    if ( acpi_sinfo.vector_width == 32 )
        *(uint32_t *)wakeup_vector_va = entry_pa;
    else
        *(uint64_t *)wakeup_vector_va = entry_pa;

    clear_fixmap(FIX_ACPI_END);
}

static void acpi_sleep_post(u32 state) {}

/* Main interface to do xen specific suspend/resume */
static int enter_state(u32 state)
{
    unsigned long flags;
    int error;
    struct cpu_info *ci;

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
    scheduler_disable();

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
    /* Avoid NMI/#MC using unsafe MSRs until we've reloaded microcode. */
    ci->scf &= ~SCF_IST_MASK;

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

    /* Restore EFER from cached value. */
    write_efer(read_efer());

    device_power_up(SAVED_ALL);

    mcheck_init(&boot_cpu_data, false);

    printk(XENLOG_INFO "Finishing wakeup from ACPI S%d state.\n", state);

    if ( (state == ACPI_STATE_S3) && error )
        tboot_s3_error(error);

    console_end_sync();
    watchdog_enable();

    microcode_update_one();

    tsx_init(); /* Needs microcode.  May change HLE/RTM feature bits. */

    if ( !recheck_cpu_features(0) )
        panic("Missing previously available feature(s)\n");

    /* Re-enabled default NMI/#MC use of MSRs now microcode is loaded. */
    ci->scf |= (default_scf & SCF_IST_MASK);

    if ( boot_cpu_has(X86_FEATURE_IBRSB) || boot_cpu_has(X86_FEATURE_IBRS) )
    {
        wrmsrl(MSR_SPEC_CTRL, default_xen_spec_ctrl);
        ci->last_spec_ctrl = default_xen_spec_ctrl;
    }

    update_mcu_opt_ctrl();
    update_pb_opt_ctrl();

    /*
     * This should be before restoring CR4, but that is earlier in asm and
     * awkward.  Instead, we rely on MSR_PKRS being something sane out of S3
     * (0, or Xen's previous value) until this point, where we need to become
     * certain that Xen's cache matches reality.
     */
    if ( cpu_has_pks )
        wrpkrs_and_cache(0);

    /* (re)initialise SYSCALL/SYSENTER state, amongst other things. */
    percpu_traps_init();

 done:
    spin_debug_enable();
    local_irq_restore(flags);
    acpi_sleep_post(state);
    if ( hvm_cpu_up() )
        BUG();
    cpufreq_add_cpu(0);

 enable_cpu:
    mtrr_aps_sync_begin();
    enable_nonboot_cpus();
    mtrr_aps_sync_end();
    iommu_adjust_irq_affinities();
    acpi_dmar_zap();
    scheduler_enable();
    thaw_domains();
    system_state = SYS_STATE_active;
    spin_unlock(&pm_lock);
    return error;
}

static long cf_check enter_state_helper(void *data)
{
    struct acpi_sleep_info *sinfo = (struct acpi_sleep_info *)data;
    return enter_state(sinfo->sleep_state);
}

/*
 * Dom0 issues this hypercall in place of writing pm1a_cnt. Xen then
 * takes over the control and put the system into sleep state really.
 */
int acpi_enter_sleep(const struct xenpf_enter_acpi_sleep *sleep)
{
    if ( sleep->sleep_state == ACPI_STATE_S3 &&
         (!acpi_sinfo.wakeup_vector || !acpi_sinfo.vector_width ||
          (PAGE_OFFSET(acpi_sinfo.wakeup_vector) >
           PAGE_SIZE - acpi_sinfo.vector_width / 8)) )
        return -EOPNOTSUPP;

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

#define TB_COPY_GAS(tbg, g)                 \
    (tbg).space_id = (g).space_id;          \
    (tbg).bit_width = (g).bit_width;        \
    (tbg).bit_offset = (g).bit_offset;      \
    (tbg).access_width = (g).access_width;  \
    (tbg).address = (g).address;

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
                                              bootsym_phys(entry_S3);

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
