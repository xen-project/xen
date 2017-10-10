#ifndef __ASM_ARM_TRAPS__
#define __ASM_ARM_TRAPS__

#include <asm/processor.h>

#if defined(CONFIG_ARM_32)
# include <asm/arm32/traps.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/traps.h>
#endif

int check_conditional_instr(struct cpu_user_regs *regs, const union hsr hsr);

void advance_pc(struct cpu_user_regs *regs, const union hsr hsr);

void inject_undef_exception(struct cpu_user_regs *regs, const union hsr hsr);

/* read as zero and write ignore */
void handle_raz_wi(struct cpu_user_regs *regs, int regidx, bool read,
                   const union hsr hsr, int min_el);

/* write only as write ignore */
void handle_wo_wi(struct cpu_user_regs *regs, int regidx, bool read,
                  const union hsr hsr, int min_el);

/* read only as read as zero */
void handle_ro_raz(struct cpu_user_regs *regs, int regidx, bool read,
                   const union hsr hsr, int min_el);

/* Co-processor registers emulation (see arch/arm/vcpreg.c). */
void do_cp15_32(struct cpu_user_regs *regs, const union hsr hsr);
void do_cp15_64(struct cpu_user_regs *regs, const union hsr hsr);
void do_cp14_32(struct cpu_user_regs *regs, const union hsr hsr);
void do_cp14_64(struct cpu_user_regs *regs, const union hsr hsr);
void do_cp14_dbg(struct cpu_user_regs *regs, const union hsr hsr);
void do_cp(struct cpu_user_regs *regs, const union hsr hsr);

/* SMCCC handling */
void do_trap_smc(struct cpu_user_regs *regs, const union hsr hsr);
void do_trap_hvc_smccc(struct cpu_user_regs *regs);

#endif /* __ASM_ARM_TRAPS__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

