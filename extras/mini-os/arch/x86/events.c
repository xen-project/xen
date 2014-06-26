#include <mini-os/os.h>
#include <mini-os/mm.h>
#include <mini-os/events.h>

#if defined(__x86_64__)
char irqstack[2 * STACK_SIZE];

static struct pda
{
    int irqcount;       /* offset 0 (used in x86_64.S) */
    char *irqstackptr;  /*        8 */
} cpu0_pda;
#endif

void arch_init_events(void)
{
#if defined(__x86_64__)
    asm volatile("movl %0,%%fs ; movl %0,%%gs" :: "r" (0));
    wrmsrl(0xc0000101, &cpu0_pda); /* 0xc0000101 is MSR_GS_BASE */
    cpu0_pda.irqcount = -1;
    cpu0_pda.irqstackptr = (void*) (((unsigned long)irqstack + 2 * STACK_SIZE)
                                    & ~(STACK_SIZE - 1));
#endif
}

void arch_unbind_ports(void)
{
}

void arch_fini_events(void)
{
#if defined(__x86_64__)
    wrmsrl(0xc0000101, NULL); /* 0xc0000101 is MSR_GS_BASE */
#endif
}
