#ifndef __XEN_STACK_PROTECTOR_H__
#define __XEN_STACK_PROTECTOR_H__

extern unsigned long __stack_chk_guard;

/*
 * This function should be called from a C function that escapes stack
 * canary tracking (by calling reset_stack_and_jump() for example).
 */
static always_inline void boot_stack_chk_guard_setup(void)
{
#ifdef CONFIG_STACK_PROTECTOR

    /*
     * Linear congruent generator (X_n+1 = X_n * a + c).
     *
     * Constant is taken from "Tables Of Linear Congruential
     * Generators Of Different Sizes And Good Lattice Structure" by
     * Pierre L’Ecuyer.
     */
#if BITS_PER_LONG == 32
    const unsigned long a = 2891336453UL;
#else
    const unsigned long a = 2862933555777941757UL;
#endif
    const unsigned long c = 1;

    unsigned long cycles = get_cycles();

    /* Use the initial value if we can't generate random one */
    if ( !cycles )
        return;

    __stack_chk_guard = cycles * a + c;

#endif	/* CONFIG_STACK_PROTECTOR */
}

#endif	/* __XEN_STACK_PROTECTOR_H__ */
