#ifndef __ARM_ASM_DEFNS_H__
#define __ARM_ASM_DEFNS_H__

#ifndef COMPILE_OFFSETS
/* NB. Auto-generated from arch/.../asm-offsets.c */
#include <asm/asm-offsets.h>
#endif
#include <asm/processor.h>

/* For generic assembly code: use macros to define operand sizes. */
#if defined(CONFIG_ARM_32)
# define __OP32
#elif defined(CONFIG_ARM_64)
# define __OP32 "w"
#else
# error "unknown ARM variant"
#endif

#endif /* __ARM_ASM_DEFNS_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
