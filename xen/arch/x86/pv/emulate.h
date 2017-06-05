#ifndef __PV_EMULATE_H__
#define __PV_EMULATE_H__

int pv_emul_read_descriptor(unsigned int sel, const struct vcpu *v,
                            unsigned long *base, unsigned long *limit,
                            unsigned int *ar, bool insn_fetch);

void pv_emul_instruction_done(struct cpu_user_regs *regs, unsigned long rip);

#endif /* __PV_EMULATE_H__ */
