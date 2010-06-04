#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/shutdown.h>
#include <xen/console.h>
#include <asm/debugger.h>
#include <public/sched.h>

/* opt_noreboot: If true, machine will need manual reset on error. */
int opt_noreboot;
boolean_param("noreboot", opt_noreboot);

static void maybe_reboot(void)
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

void dom0_shutdown(u8 reason)
{
    switch ( reason )
    {
    case SHUTDOWN_poweroff:
    {
        printk("Domain 0 halted: halting machine.\n");
        machine_halt();
        break; /* not reached */
    }

    case SHUTDOWN_crash:
    {
        debugger_trap_immediate();
        printk("Domain 0 crashed: ");
        maybe_reboot();
        break; /* not reached */
    }

    case SHUTDOWN_reboot:
    {
        printk("Domain 0 shutdown: rebooting machine.\n");
        machine_restart(0);
        break; /* not reached */
    }

    case SHUTDOWN_watchdog:
    {
        printk("Domain 0 shutdown: watchdog rebooting machine.\n");
        kexec_crash();
        machine_restart(0);
        break; /* not reached */
    }

    default:
    {
        printk("Domain 0 shutdown (unknown reason %u): ", reason);
        maybe_reboot();
        break; /* not reached */
    }
    }
}  

