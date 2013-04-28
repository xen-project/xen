#include <xen/config.h>
#include <xen/console.h>
#include <xen/cpu.h>
#include <xen/delay.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <asm/platform.h>

static void raw_machine_reset(void)
{
    platform_reset();
}

static void halt_this_cpu(void *arg)
{
    stop_cpu();
}

void machine_halt(void)
{
    watchdog_disable();
    console_start_sync();
    local_irq_enable();
    smp_call_function(halt_this_cpu, NULL, 0);
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

    while ( 1 )
    {
        raw_machine_reset();
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
