// this file is now obsolete and can be removed
#include <asm/hpsim_ssc.h>

static inline int arch_serial_putc(unsigned char c)
{
	if (platform_is_hp_ski()) {
		ia64_ssc(c, 0, 0, 0, SSC_PUTCHAR);
	}
	else {
// this is tested on HP Longs Peak platform... it
// will probably work on other Itanium platforms as
// well, but undoubtedly needs work
		longs_peak_putc(c);
	}
	return 1;
}

