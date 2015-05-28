#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <xen/config.h>
#include <xen/lib.h>

#if defined(CONFIG_ARM_32)
# include <asm/arm32/spinlock.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/spinlock.h>
#else
# error "unknown ARM variant"
#endif

#endif /* __ASM_SPINLOCK_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
