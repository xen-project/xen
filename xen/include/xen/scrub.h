#ifndef __XEN_SCRUB_H__
#define __XEN_SCRUB_H__

#include <xen/const.h>

/* SCRUB_PATTERN needs to be a repeating series of bytes. */
#ifdef CONFIG_DEBUG
# define SCRUB_PATTERN       _AC(0xc2c2c2c2c2c2c2c2,ULL)
#else
# define SCRUB_PATTERN       _AC(0,ULL)
#endif
#define SCRUB_BYTE_PATTERN   (SCRUB_PATTERN & 0xff)

#endif /* __XEN_SCRUB_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
