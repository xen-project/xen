#ifndef __ASM_X86_MWAIT_H__
#define __ASM_X86_MWAIT_H__

#include <xen/types.h>

#define MWAIT_SUBSTATE_MASK		0xf
#define MWAIT_CSTATE_MASK		0xfU
#define MWAIT_SUBSTATE_SIZE		4

#define CPUID_MWAIT_LEAF		5
#define CPUID5_ECX_EXTENSIONS_SUPPORTED 0x1
#define CPUID5_ECX_INTERRUPT_BREAK	0x2

#define MWAIT_ECX_INTERRUPT_BREAK	0x1

void mwait_idle_with_hints(unsigned int eax, unsigned int ecx);
#ifdef CONFIG_INTEL
bool mwait_pc10_supported(void);
#else
static inline bool mwait_pc10_supported(void)
{
    return false;
}
#endif

#endif /* __ASM_X86_MWAIT_H__ */
