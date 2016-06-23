#include <xen/delay.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/softirq.h>
#include <xen/warning.h>

#define WARNING_ARRAY_SIZE 20
static unsigned int __initdata nr_warnings;
static const char *__initdata warnings[WARNING_ARRAY_SIZE];

void __init warning_add(const char *warning)
{
    if ( nr_warnings >= WARNING_ARRAY_SIZE )
        panic("Too many pieces of warning text.");

    warnings[nr_warnings] = warning;
    nr_warnings++;
}

void __init warning_print(void)
{
    unsigned int i, j;

    if ( !nr_warnings )
        return;

    printk("***************************************************\n");

    for ( i = 0; i < nr_warnings; i++ )
    {
        printk("%s", warnings[i]);
        printk("***************************************************\n");
    }

    for ( i = 0; i < 3; i++ )
    {
        printk("%u... ", 3 - i);
        for ( j = 0; j < 100; j++ )
        {
            process_pending_softirqs();
            mdelay(10);
        }
    }
    printk("\n");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
