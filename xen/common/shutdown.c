#include <xen/init.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/sections.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/watchdog.h>
#include <xen/shutdown.h>
#include <xen/console.h>
#include <xen/kexec.h>
#include <public/sched.h>

/* opt_noreboot: If true, machine will need manual reset on error. */
bool __ro_after_init opt_noreboot;
boolean_param("noreboot", opt_noreboot);

static void noreturn reboot_or_halt(void)
{
    if ( opt_noreboot )
    {
        printk("'noreboot' set - not rebooting.\n");
        machine_halt();
    }
    else
    {
        printk("rebooting machine in 5 seconds.\n");
        watchdog_disable();
        machine_restart(5000);
    }
}

void hwdom_shutdown(unsigned char reason)
{
    switch ( reason )
    {
    case SHUTDOWN_poweroff:
        printk("Hardware Dom%u halted: halting machine\n",
               hardware_domain->domain_id);
        machine_halt();

    case SHUTDOWN_crash:
        printk("Hardware Dom%u crashed: ", hardware_domain->domain_id);
        kexec_crash(CRASHREASON_HWDOM);
        reboot_or_halt();

    case SHUTDOWN_reboot:
        printk("Hardware Dom%u shutdown: rebooting machine\n",
               hardware_domain->domain_id);
        machine_restart(0);

    case SHUTDOWN_watchdog:
        printk("Hardware Dom%u shutdown: watchdog rebooting machine\n",
               hardware_domain->domain_id);
        kexec_crash(CRASHREASON_WATCHDOG);
        machine_restart(0);

    case SHUTDOWN_soft_reset:
        printk("Hardware domain %d did unsupported soft reset, rebooting.\n",
               hardware_domain->domain_id);
        machine_restart(0);

    default:
        printk("Hardware Dom%u shutdown (unknown reason %u): ",
               hardware_domain->domain_id, reason);
        reboot_or_halt();
    }
}
