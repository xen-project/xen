/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * RISC-V early printk using SBI
 *
 * Copyright (C) 2021 Bobby Eshleman <bobbyeshleman@gmail.com>
 */
#include <asm/early_printk.h>
#include <asm/sbi.h>

/*
 * When the MMU is off during early boot, any C function called has to
 * use PC-relative rather than absolute address because the physical address
 * may not match the virtual address.
 *
 * To guarantee PC-relative address cmodel=medany should be used
 */
#ifndef __riscv_cmodel_medany
#error "early_*() can be called from head.S with MMU-off"
#endif

/*
 * TODO:
 *   sbi_console_putchar is already planned for deprecation
 *   so it should be reworked to use UART directly.
*/
void early_puts(const char *s, size_t nr)
{
    while ( nr-- > 0 )
    {
        sbi_console_putchar(*s);
        s++;
    }
}

void early_printk(const char *str)
{
    while ( *str )
    {
        early_puts(str, 1);
        str++;
    }
}
