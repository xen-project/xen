/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/random.h>
#include <xen/time.h>

/*
 * Initial value is chosen by a fair dice roll.
 * It will be updated during boot process.
 */
#if BITS_PER_LONG == 32
unsigned long __ro_after_init __stack_chk_guard = 0xdd2cc927UL;
#else
unsigned long __ro_after_init __stack_chk_guard = 0x2d853605a4d9a09cUL;
#endif

/* SAF-13-safe compiler-called function */
void noreturn __stack_chk_fail(void)
{
    dump_execution_state();
    panic("Stack Protector integrity violation identified\n");
}
