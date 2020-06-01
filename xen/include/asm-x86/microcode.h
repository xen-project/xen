#ifndef ASM_X86__MICROCODE_H
#define ASM_X86__MICROCODE_H

#include <xen/types.h>
#include <xen/percpu.h>

#include <public/xen.h>

struct cpu_signature {
    /* CPU signature (CPUID.1.EAX). */
    unsigned int sig;

    /* Platform Flags.  Only applicable to Intel. */
    unsigned int pf;

    /* Microcode Revision. */
    unsigned int rev;
};

DECLARE_PER_CPU(struct cpu_signature, cpu_sig);

void microcode_set_module(unsigned int idx);
int microcode_update(XEN_GUEST_HANDLE(const_void), unsigned long len);
int early_microcode_init(void);
int microcode_update_one(void);

#endif /* ASM_X86__MICROCODE_H */
