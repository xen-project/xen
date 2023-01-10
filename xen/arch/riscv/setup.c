#include <xen/compile.h>
#include <xen/init.h>

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
    __aligned(STACK_SIZE);

void __init noreturn start_xen(void)
{
    for ( ;; )
        asm volatile ("wfi");

    unreachable();
}
