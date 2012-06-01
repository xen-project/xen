#ifndef __ARM_VFP_H_
#define __ARM_VFP_H_

#include <xen/types.h>

#define FPEXC_EN (1u << 30)

/* Save and restore FP state.
 * Ought to be using the new vmrs/vmsr names, but older binutils has a
 * bug where it only allows them to target fpscr (and not, say, fpexc). */
#define READ_FP(reg) ({                                 \
    uint32_t val;                                       \
    asm volatile ("fmrx %0, fp" #reg : "=r" (val));     \
    val; })

#define WRITE_FP(reg, val) do {                         \
    asm volatile ("fmxr fp" #reg ", %0" : : "r" (val)); \
} while (0)


/* Start-of-day: Turn on VFP */
static inline void enable_vfp(void)
{
    WRITE_FP(exc, READ_FP(exc) | FPEXC_EN);
}

#endif
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
