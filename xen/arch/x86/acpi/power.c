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

#include <xen/config.h>
#include <asm/io.h>
#include <asm/acpi.h>
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
#include <public/platform.h>
#include <asm/tboot.h>

#include <acpi/cpufreq/cpufreq.h>

uint32_t system_reset_counter = 1;

static char __initdata opt_acpi_sleep[20];
string_param("acpi_sleep", opt_acpi_sleep);

static u8 sleep_states[ACPI_S_STATE_COUNT];
static DEFINE_SPINLOCK(pm_lock);

struct acpi_sleep_info acpi_sinfo;

void do_suspend_lowlevel(void);

static int device_power_down(void)
{
    console_suspend();

    time_suspend();

    i8259A_suspend();

    ioapic_suspend();

    iommu_suspend();

    lapic_suspend();

    return 0;
}

static void device_power_up(void)
{
    lapic_resume();

    iommu_resume();

    ioapic_resume();

    i8259A_resume();

    time_resume();

    console_resume();
}

static void freeze_domains(void)
{
    struct domain *d;
    struct vcpu *v;

    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d )
    {
        for_each_vcpu ( d, v )
        {
            if ( v != current )
                vcpu_pause(v);
            else
                vcpu_pause_nosync(v);
        }
    }
    rcu_read_unlock(&domlist_read_lock);
}

static void thaw_domains(void)
{
    struct domain *d;
    struct vcpu *v;

    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d )
    {
        for_each_vcpu ( d, v )
            vcpu_unpause(v);
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
    unsigned long cr4;

    BUG_ON(!spin_is_locked(&pm_lock));

    disable_nonboot_cpus();
    if ( num_online_cpus() != 1 )
    {
        error = -EBUSY;
        goto enable_cpu;
    }

    cpufreq_del_cpu(0);

    hvm_cpu_down();

    acpi_sleep_prepare(state);

    console_start_sync();
    printk("Entering ACPI S%d state.\n", state);

    local_irq_save(flags);
    spin_debug_disable();

    if ( (error = device_power_down()) )
    {
        printk(XENLOG_ERR "Some devices failed to power down.");
        goto done;
    }

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

    /* Restore CR4 and EFER from cached values. */
    cr4 = read_cr4();
    write_cr4(cr4 & ~X86_CR4_MCE);
    if ( cpu_has_efer )
        write_efer(read_efer());

    device_power_up();

    mcheck_init(&boot_cpu_data);
    write_cr4(cr4);

    printk(XENLOG_INFO "Finishing wakeup from ACPI S%d state.\n", state);

    if ( (state == ACPI_STATE_S3) && error )
        panic("Memory integrity was lost on resume (%d)\n", error);

 done:
    spin_debug_enable();
    local_irq_restore(flags);
    console_end_sync();
    acpi_sleep_post(state);
    if ( !hvm_cpu_up() )
        BUG();

 enable_cpu:
    cpufreq_add_cpu(0);
    microcode_resume_cpu(0);
    enable_nonboot_cpus();
    thaw_domains();
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
    int rc;
    u32 state;

    if ( !IS_PRIV(current->domain) || !acpi_sinfo.pm1a_cnt_blk.address )
        return -EPERM;

    /* Sanity check */
    if ( acpi_sinfo.pm1b_cnt_val &&
         ((sleep->pm1a_cnt_val ^ sleep->pm1b_cnt_val) &
          ACPI_BITMASK_SLEEP_ENABLE) )
    {
        gdprintk(XENLOG_ERR, "Mismatched pm1a/pm1b setting.");
        return -EINVAL;
    }

    state = sleep->sleep_state;
    if ( sleep->flags ||
         (state <= ACPI_STATE_S0) || (state > ACPI_S_STATES_MAX) )
        return -EINVAL;

    if ( !spin_trylock(&pm_lock) )
        return -EBUSY;

    acpi_sinfo.pm1a_cnt_val = sleep->pm1a_cnt_val;
    acpi_sinfo.pm1b_cnt_val = sleep->pm1b_cnt_val;
    acpi_sinfo.sleep_state = state;

    printk(XENLOG_INFO "Preparing system for ACPI S%d state.", state);

    freeze_domains();

    rc = continue_hypercall_on_cpu(0, enter_state_helper, &acpi_sinfo);
    if ( rc )
    {
        /* Continuation will not execute: undo our own work so far. */
        thaw_domains();
        spin_unlock(&pm_lock);
    }

    return rc;
}

static int acpi_get_wake_status(void)
{
    uint32_t val;
    acpi_status status;

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
acpi_status asmlinkage acpi_enter_sleep_state(u8 sleep_state)
{
    acpi_status status;

    if ( tboot_in_measured_env() )
    {
        tboot_sleep(sleep_state);
        printk(XENLOG_ERR "TBOOT failed entering s3 state\n");
        return_ACPI_STATUS(AE_ERROR);
    }

    ACPI_FLUSH_CPU_CACHE();

    status = acpi_hw_register_write(ACPI_REGISTER_PM1A_CONTROL, 
                                    acpi_sinfo.pm1a_cnt_val);
    if ( ACPI_FAILURE(status) )
        return_ACPI_STATUS(AE_ERROR);

    if ( acpi_sinfo.pm1b_cnt_blk.address )
    {
        status = acpi_hw_register_write(ACPI_REGISTER_PM1B_CONTROL, 
                                        acpi_sinfo.pm1b_cnt_val);
        if ( ACPI_FAILURE(status) )
            return_ACPI_STATUS(AE_ERROR);
    }

    /* Wait until we enter sleep state, and spin until we wake */
    while ( !acpi_get_wake_status() )
        continue;

    return_ACPI_STATUS(AE_OK);
}

static int __init acpi_sleep_init(void)
{
    int i;
    char *p = opt_acpi_sleep;

    while ( (p != NULL) && (*p != '\0') )
    {
        if ( !strncmp(p, "s3_bios", 7) )
            acpi_video_flags |= 1;
        if ( !strncmp(p, "s3_mode", 7) )
            acpi_video_flags |= 2;
        p = strchr(p, ',');
        if ( p != NULL )
            p += strspn(p, ", \t");
    }

    printk(XENLOG_INFO "ACPI sleep modes:");
    for ( i = 0; i < ACPI_S_STATE_COUNT; i++ )
    {
        if ( i == ACPI_STATE_S3 )
        {
            sleep_states[i] = 1;
            printk(" S%d", i);
        }
        else
            sleep_states[i] = 0;
    }
    printk("\n");

    return 0;
}
__initcall(acpi_sleep_init);
