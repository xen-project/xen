#include <mini-os/os.h>
#include <mini-os/events.h>
#include <mini-os/hypervisor.h>
#include <mini-os/console.h>

static void virq_debug(evtchn_port_t port, struct pt_regs *regs, void *params)
{
    printk("Received a virq_debug event\n");
}

evtchn_port_t debug_port = -1;
void arch_init_events(void)
{
    debug_port = bind_virq(VIRQ_DEBUG, (evtchn_handler_t)virq_debug, 0);
    if(debug_port == -1)
        BUG();
    unmask_evtchn(debug_port);
}

void arch_unbind_ports(void)
{
    if(debug_port != -1)
    {
        mask_evtchn(debug_port);
        unbind_evtchn(debug_port);
    }
}

void arch_fini_events(void)
{
}
