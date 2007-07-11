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
#include <public/platform.h>

#define pmprintk(_l, _f, _a...) printk(_l "<PM>" _f, ## _a )

u8 sleep_states[ACPI_S_STATE_COUNT];
DEFINE_SPINLOCK(pm_lock);

struct acpi_sleep_info {
    uint16_t pm1a_cnt;
    uint16_t pm1b_cnt;
    uint16_t pm1a_evt;
    uint16_t pm1b_evt;
    uint16_t pm1a_cnt_val;
    uint16_t pm1b_cnt_val;
    uint32_t sleep_state;
} acpi_sinfo;

extern void do_suspend_lowlevel(void);

static char *acpi_states[ACPI_S_STATE_COUNT] =
{
    [ACPI_STATE_S1] = "standby",
    [ACPI_STATE_S3] = "mem",
    [ACPI_STATE_S4] = "disk",
};

unsigned long acpi_video_flags;
unsigned long saved_videomode;

/* XXX: Add suspend failure recover later */
static int device_power_down(void)
{
    console_suspend();

    time_suspend();

    i8259A_suspend();
    
    ioapic_suspend();
    
    lapic_suspend();

    return 0;
}

static void device_power_up(void)
{
    lapic_resume();
    
    ioapic_resume();

    i8259A_resume();
    
    time_resume();

    console_resume();
}

static void freeze_domains(void)
{
    struct domain *d;

    for_each_domain(d)
        if (d->domain_id != 0)
            domain_pause(d);
}

static void thaw_domains(void)
{
    struct domain *d;

    for_each_domain(d)
        if (d->domain_id != 0)
            domain_unpause(d);
}

/* Main interface to do xen specific suspend/resume */
int enter_state(u32 state)
{
    unsigned long flags;
    int error;

    if (state <= ACPI_STATE_S0 || state > ACPI_S_STATES_MAX)
        return -EINVAL;

    /* Sync lazy state on ths cpu */
    __sync_lazy_execstate();
    pmprintk(XENLOG_INFO, "Flush lazy state\n");

    if (!spin_trylock(&pm_lock))
        return -EBUSY;
    
    freeze_domains();

    hvm_suspend_cpu();

    pmprintk(XENLOG_INFO, "PM: Preparing system for %s sleep\n",
        acpi_states[state]);

    local_irq_save(flags);

    if ((error = device_power_down()))
    {
        printk(XENLOG_ERR "Some devices failed to power down\n");
        goto Done;
    }

    ACPI_FLUSH_CPU_CACHE();

    switch (state)
    {
        case ACPI_STATE_S3:
            do_suspend_lowlevel();
            break;
        default:
            error = -EINVAL;
            break;
    }

    pmprintk(XENLOG_INFO, "Back to C!\n");

    device_power_up();

    pmprintk(XENLOG_INFO, "PM: Finishing wakeup.\n");

 Done:
    local_irq_restore(flags);

    hvm_resume_cpu();

    thaw_domains();
    spin_unlock(&pm_lock);
    return error;
}

/*
 * Xen just requires address of pm1x_cnt, and ACPI interpreter
 * is still kept in dom0. Address of xen wakeup stub will be
 * returned, and then dom0 writes that address to FACS.
 */
int set_acpi_sleep_info(struct xenpf_set_acpi_sleep *info)
{
    if (acpi_sinfo.pm1a_cnt)
        pmprintk(XENLOG_WARNING, "Multiple setting on acpi sleep info\n");

    acpi_sinfo.pm1a_cnt = info->pm1a_cnt_port;
    acpi_sinfo.pm1b_cnt = info->pm1b_cnt_port;
    acpi_sinfo.pm1a_evt = info->pm1a_evt_port;
    acpi_sinfo.pm1b_evt = info->pm1b_evt_port;
    info->xen_waking_vec = (uint64_t)bootsym_phys(wakeup_start);

    pmprintk(XENLOG_INFO, "pm1a[%x],pm1b[%x],pm1a_e[%x],pm1b_e[%x]"
                       "wake[%"PRIx64"]",
                       acpi_sinfo.pm1a_cnt, acpi_sinfo.pm1b_cnt,
                       acpi_sinfo.pm1a_evt, acpi_sinfo.pm1b_evt,
                       info->xen_waking_vec);
    return 0;
}

/*
 * Dom0 issues this hypercall in place of writing pm1a_cnt. Xen then
 * takes over the control and put the system into sleep state really.
 * Also video flags and mode are passed here, in case user may use
 * "acpi_sleep=***" for video resume.
 *
 * Guest may issue a two-phases write to PM1x_CNT, to work
 * around poorly implemented hardware. It's better to keep
 * this logic here. Two writes can be differentiated by 
 * enable bit setting.
 */
int acpi_enter_sleep(struct xenpf_enter_acpi_sleep *sleep)
{
    if (!IS_PRIV(current->domain) || !acpi_sinfo.pm1a_cnt)
        return -EPERM;

    /* Sanity check */
    if (acpi_sinfo.pm1b_cnt_val &&
        ((sleep->pm1a_cnt_val ^ sleep->pm1b_cnt_val) &
        ACPI_BITMASK_SLEEP_ENABLE))
    {
        pmprintk(XENLOG_ERR, "Mismatched pm1a/pm1b setting\n");
        return -EINVAL;
    }

    /* Write #1 */
    if (!(sleep->pm1a_cnt_val & ACPI_BITMASK_SLEEP_ENABLE))
    {
        outw((u16)sleep->pm1a_cnt_val, acpi_sinfo.pm1a_cnt);
        if (acpi_sinfo.pm1b_cnt)
            outw((u16)sleep->pm1b_cnt_val, acpi_sinfo.pm1b_cnt);
        return 0;
    }

    /* Write #2 */
    acpi_sinfo.pm1a_cnt_val = sleep->pm1a_cnt_val;
    acpi_sinfo.pm1b_cnt_val = sleep->pm1b_cnt_val;
    acpi_sinfo.sleep_state = sleep->sleep_state;
    acpi_video_flags = sleep->video_flags;
    saved_videomode = sleep->video_mode;

    return enter_state(acpi_sinfo.sleep_state);
}

static int acpi_get_wake_status(void)
{
    uint16_t val;

    /* Wake status is the 15th bit of PM1 status register. (ACPI spec 3.0) */
    val = inw(acpi_sinfo.pm1a_evt) | inw(acpi_sinfo.pm1b_evt);
    val &= ACPI_BITMASK_WAKE_STATUS;
    val >>= ACPI_BITPOSITION_WAKE_STATUS;
    return val;
}

/* System is really put into sleep state by this stub */
acpi_status asmlinkage acpi_enter_sleep_state(u8 sleep_state)
{
    ACPI_FLUSH_CPU_CACHE();

    outw((u16)acpi_sinfo.pm1a_cnt_val, acpi_sinfo.pm1a_cnt);
    if (acpi_sinfo.pm1b_cnt)
        outw((u16)acpi_sinfo.pm1b_cnt_val, acpi_sinfo.pm1b_cnt);
    
    /* Wait until we enter sleep state, and spin until we wake */
    while (!acpi_get_wake_status());
    return_ACPI_STATUS(AE_OK);
}

static int __init acpi_sleep_init(void)
{
    int i = 0; 

    pmprintk(XENLOG_INFO, "ACPI (supports");
    for (i = 0; i < ACPI_S_STATE_COUNT; i++)
    {
        if (i == ACPI_STATE_S3)
        {
            sleep_states[i] = 1;
            printk(" S%d", i);
        }
        else
            sleep_states[i] = 0;
    }
    printk(")\n");
    return 0;
}
__initcall(acpi_sleep_init);
