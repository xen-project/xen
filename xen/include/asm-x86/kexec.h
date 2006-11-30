#ifndef __X86_KEXEC_H__
#define __X86_KEXEC_H__

#ifdef __x86_64__
#include <asm/x86_64/kexec.h>
#else
#include <asm/x86_32/kexec.h>
#endif

#endif /* __X86_KEXEC_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
