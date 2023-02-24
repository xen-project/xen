#include <xen/compile.h>
#include <xen/init.h>

#include <asm/early_printk.h>

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
    __aligned(STACK_SIZE);

void __init noreturn start_xen(void)
{
    early_printk("Hello from C env\n");

    early_printk("All set up\n");
    for ( ;; )
        asm volatile ("wfi");

    unreachable();
}
