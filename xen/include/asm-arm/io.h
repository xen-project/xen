#ifndef _ASM_IO_H
#define _ASM_IO_H

#if defined(CONFIG_ARM_32)
# include <asm/arm32/io.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/io.h>
#else
# error "unknown ARM variant"
#endif

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
