/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/******************************************************************************
 * asm-x86/serial.h
 * 
 * Architecture-specific private serial definitions.
 */

#ifndef __ASM_X86_SERIAL_H__
#define __ASM_X86_SERIAL_H__

#define OPT_COM1_STR ""
#define OPT_COM2_STR ""

static inline int arch_serial_putc(uart_t *uart, unsigned char c)
{
    int space;
    if ( (space = (inb(uart->io_base + LSR) & LSR_THRE)) )
        outb(c, uart->io_base + THR);
    return space;
}

#endif /* __ASM_X86_SERIAL_H__ */
