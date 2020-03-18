#ifndef ASM_X86__MICROCODE_H
#define ASM_X86__MICROCODE_H

#include <xen/percpu.h>

struct cpu_signature {
    unsigned int sig;
    unsigned int pf;
    unsigned int rev;
};

DECLARE_PER_CPU(struct cpu_signature, cpu_sig);

#endif /* ASM_X86__MICROCODE_H */
