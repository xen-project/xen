#include <xen/config.h>
#include <xen/console.h>
#include <xen/cpu.h>
#include <xen/delay.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <asm/platform.h>
#include <asm/psci.h>

static void noreturn halt_this_cpu(void *arg)
{
    stop_cpu();
}

void machine_halt(void)
{
    int timeout = 10;

    watchdog_disable();
    console_start_sync();
    local_irq_enable();
    smp_call_function(halt_this_cpu, NULL, 0);
    local_irq_disable();

    /* Wait at most another 10ms for all other CPUs to go offline. */
    while ( (num_online_cpus() > 1) && (timeout-- > 0) )
        mdelay(1);

    /* This is mainly for PSCI-0.2, which does not return if success. */
    call_psci_system_off();

    /* Alternative halt procedure */
    platform_poweroff();
    halt_this_cpu(NULL);
}

void machine_restart(unsigned int delay_millisecs)
{
    int timeout = 10;

    local_irq_enable();
    smp_call_function(halt_this_cpu, NULL, 0);
    local_irq_disable();

    mdelay(delay_millisecs);

    /* Wait at most another 10ms for all other CPUs to go offline. */
    while ( (num_online_cpus() > 1) && (timeout-- > 0) )
        mdelay(1);

    /* This is mainly for PSCI-0.2, which does not return if success. */
    call_psci_system_reset();

    /* Alternative reset procedure */
    while ( 1 )
    {
        platform_reset();
        mdelay(100);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
