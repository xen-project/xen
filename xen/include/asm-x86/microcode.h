#ifndef ASM_X86__MICROCODE_H
#define ASM_X86__MICROCODE_H

#include <xen/types.h>
#include <xen/percpu.h>

#include <public/xen.h>

struct cpu_signature {
    unsigned int sig;
    unsigned int pf;
    unsigned int rev;
};

DECLARE_PER_CPU(struct cpu_signature, cpu_sig);

void microcode_set_module(unsigned int idx);
int microcode_update(XEN_GUEST_HANDLE_PARAM(const_void), unsigned long len);
int early_microcode_init(void);
int microcode_update_one(bool start_update);

#endif /* ASM_X86__MICROCODE_H */
