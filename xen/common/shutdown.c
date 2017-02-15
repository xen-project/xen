#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/watchdog.h>
#include <xen/shutdown.h>
#include <xen/console.h>
#ifdef CONFIG_KEXEC
#include <xen/kexec.h>
#endif
#include <asm/debugger.h>
#include <public/sched.h>

/* opt_noreboot: If true, machine will need manual reset on error. */
bool_t __read_mostly opt_noreboot;
boolean_param("noreboot", opt_noreboot);

static void noreturn maybe_reboot(void)
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

void hwdom_shutdown(u8 reason)
{
    switch ( reason )
    {
    case SHUTDOWN_poweroff:
        printk("Hardware Dom%u halted: halting machine\n",
               hardware_domain->domain_id);
        machine_halt();
        break; /* not reached */

    case SHUTDOWN_crash:
        debugger_trap_immediate();
        printk("Hardware Dom%u crashed: ", hardware_domain->domain_id);
#ifdef CONFIG_KEXEC
        kexec_crash();
#endif
        maybe_reboot();
        break; /* not reached */

    case SHUTDOWN_reboot:
        printk("Hardware Dom%u shutdown: rebooting machine\n",
               hardware_domain->domain_id);
        machine_restart(0);
        break; /* not reached */

    case SHUTDOWN_watchdog:
        printk("Hardware Dom%u shutdown: watchdog rebooting machine\n",
               hardware_domain->domain_id);
#ifdef CONFIG_KEXEC
        kexec_crash();
#endif
        machine_restart(0);
        break; /* not reached */

    case SHUTDOWN_soft_reset:
        printk("Hardware domain %d did unsupported soft reset, rebooting.\n",
               hardware_domain->domain_id);
        machine_restart(0);
        break; /* not reached */

    default:
        printk("Hardware Dom%u shutdown (unknown reason %u): ",
               hardware_domain->domain_id, reason);
        maybe_reboot();
        break; /* not reached */
    }
}  

