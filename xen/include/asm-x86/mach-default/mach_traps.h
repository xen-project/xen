/*
 *  include/asm-i386/mach-default/mach_traps.h
 *
 *  Machine specific NMI handling for generic.
 *  Split out from traps.c by Osamu Tomita <tomita@cinet.co.jp>
 */
#ifndef _MACH_TRAPS_H
#define _MACH_TRAPS_H

static inline void clear_mem_error(unsigned char reason)
{
	reason = (reason & 0xf) | 4;
	outb(reason, 0x61);
}

static inline unsigned char get_nmi_reason(void)
{
	return inb(0x61);
}

static inline void reassert_nmi(void)
{
	outb(0x8f, 0x70);
	inb(0x71);		/* dummy */
	outb(0x0f, 0x70);
	inb(0x71);		/* dummy */
}

#endif /* !_MACH_TRAPS_H */
