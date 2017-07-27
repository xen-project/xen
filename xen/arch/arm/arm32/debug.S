/*
 * xen/arch/arm/arm32/debug.S
 *
 * Wrapper for early printk
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (c) 2013 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/early_printk.h>

#ifdef EARLY_PRINTK_INC
#include EARLY_PRINTK_INC
#endif

/*
 * Print a character on the UART - this function is called by C
 * r0: character to print
 */
GLOBAL(early_putch)
        ldr   r1, =EARLY_UART_VIRTUAL_ADDRESS  /* r1 := VA UART base address */
        early_uart_ready r1, r2
        early_uart_transmit r1, r0
        mov   pc, lr

/* Flush the UART - this function is called by C */
GLOBAL(early_flush)
        ldr   r1, =EARLY_UART_VIRTUAL_ADDRESS  /* r1 := VA UART base address */
        early_uart_ready r1, r2
        mov   pc, lr

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
