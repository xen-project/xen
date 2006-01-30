/*
 *  include/asm-xen/asm-i386/mach-xen/mach_traps.h
 *
 *  Machine specific NMI handling for Xen
 */
#ifndef _MACH_TRAPS_H
#define _MACH_TRAPS_H

#include <linux/bitops.h>
#include <xen/interface/nmi.h>

static inline void clear_mem_error(unsigned char reason) {}
static inline void clear_io_check_error(unsigned char reason) {}

static inline unsigned char get_nmi_reason(void)
{
	shared_info_t *s = HYPERVISOR_shared_info;
	unsigned char reason = 0;

	/* construct a value which looks like it came from
	 * port 0x61.
	 */
	if (test_bit(_XEN_NMIREASON_io_error, &s->arch.nmi_reason))
		reason |= 0x40;
	if (test_bit(_XEN_NMIREASON_parity_error, &s->arch.nmi_reason))
		reason |= 0x80;

        return reason;
}

static inline void reassert_nmi(void) {}

#endif /* !_MACH_TRAPS_H */
