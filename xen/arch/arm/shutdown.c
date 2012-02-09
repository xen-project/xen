#include <xen/config.h>
#include <xen/lib.h>

void machine_halt(void)
{
        /* TODO: halt */
        while(1) ;
}

void machine_restart(unsigned int delay_millisecs)
{
        /* TODO: restart */
        printk("Cannot restart yet\n");
        while(1);
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
