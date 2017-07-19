#ifndef __PV_EMULATE_H__
#define __PV_EMULATE_H__

#include <asm/x86_emulate.h>

int pv_emul_read_descriptor(unsigned int sel, const struct vcpu *v,
                            unsigned long *base, unsigned long *limit,
                            unsigned int *ar, bool insn_fetch);

void pv_emul_instruction_done(struct cpu_user_regs *regs, unsigned long rip);

static inline int pv_emul_is_mem_write(const struct x86_emulate_state *state,
                                       struct x86_emulate_ctxt *ctxt)
{
    return x86_insn_is_mem_write(state, ctxt) ? X86EMUL_OKAY
                                              : X86EMUL_UNHANDLEABLE;
}

#endif /* __PV_EMULATE_H__ */
