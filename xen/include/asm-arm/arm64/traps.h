#ifndef __ASM_ARM64_TRAPS__
#define __ASM_ARM64_TRAPS__

void inject_undef64_exception(struct cpu_user_regs *regs, int instr_len);

void do_sysreg(struct cpu_user_regs *regs,
               const union hsr hsr);

#endif /* __ASM_ARM64_TRAPS__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

