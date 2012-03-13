#include <xen/config.h>
#include <xen/console.h>
#include <xen/cpu.h>
#include <xen/delay.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/smp.h>

static void raw_machine_reset(void)
{
    /* XXX get this from device tree */
#ifdef SP810_ADDRESS
    /* Use the SP810 system controller to force a reset */
    volatile uint32_t *sp810;
    set_fixmap(FIXMAP_MISC, SP810_ADDRESS >> PAGE_SHIFT, DEV_SHARED);
    sp810 = ((uint32_t *)
             (FIXMAP_ADDR(FIXMAP_MISC) + (SP810_ADDRESS & ~PAGE_MASK)));
    sp810[0] = 0x3; /* switch to slow mode */
    dsb(); isb();
    sp810[1] = 0x1; /* writing any value to SCSYSSTAT reg will reset system */
    dsb(); isb();
    clear_fixmap(FIXMAP_MISC);
#endif
}

static void halt_this_cpu(void *arg)
{
    __cpu_disable();
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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
