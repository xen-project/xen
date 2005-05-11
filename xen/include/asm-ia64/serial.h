#ifndef __ASM_SERIAL_H__
#define __ASM_SERIAL_H__

#include <asm/regs.h>
#include <asm/irq.h>
#include <xen/serial.h>
#include <asm/hpsim_ssc.h>

#if 1
#define arch_serial_putc(_uart, _c)					\
	( platform_is_hp_ski() ? (ia64_ssc(c,0,0,0,SSC_PUTCHAR), 1) :	\
	( longs_peak_putc(c), 1 ))
#else
#define arch_serial_putc(_uart, _c)					\
	( platform_is_hp_ski() ? (ia64_ssc(c,0,0,0,SSC_PUTCHAR), 1) :	\
	( (inb((_uart)->io_base + LSR) & LSR_THRE) ?    		\
	(outb((_c), (_uart)->io_base + THR), 1) : 0 ))
#endif


#define OPT_COM1_STR "115200"
#define OPT_COM2_STR ""

unsigned char irq_serial_getc(int handle);

void serial_force_unlock(int handle);

#endif /* __ASM_SERIAL_H__ */
