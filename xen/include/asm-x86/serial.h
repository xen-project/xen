
#ifndef __ASM_X86_SERIAL_H__
#define __ASM_X86_SERIAL_H__

#define OPT_COM1_STR ""
#define OPT_COM2_STR ""

#define arch_serial_putc(_uart, _c)                 \
    ( (inb((_uart)->io_base + LSR) & LSR_THRE) ?    \
      (outb((_c), (_uart)->io_base + THR), 1) : 0 )

#endif /* __ASM_X86_SERIAL_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 */
