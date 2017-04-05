/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */
#define COMPILE_OFFSETS

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/bitops.h>
#include <public/xen.h>
#include <asm/current.h>

#define DEFINE(_sym, _val)                                                 \
    asm volatile ("\n.ascii\"==>#define " #_sym " %0 /* " #_val " */<==\"" \
                  : : "i" (_val) )
#define BLANK()                                                            \
    asm volatile ( "\n.ascii\"==><==\"" : : )
#define OFFSET(_sym, _str, _mem)                                           \
    DEFINE(_sym, offsetof(_str, _mem));

void __dummy__(void)
{
   OFFSET(UREGS_X0, struct cpu_user_regs, x0);
   OFFSET(UREGS_LR, struct cpu_user_regs, lr);

   OFFSET(UREGS_SP, struct cpu_user_regs, sp);
   OFFSET(UREGS_PC, struct cpu_user_regs, pc);
   OFFSET(UREGS_CPSR, struct cpu_user_regs, cpsr);
   OFFSET(UREGS_ESR_el2, struct cpu_user_regs, hsr);

   OFFSET(UREGS_SPSR_el1, struct cpu_user_regs, spsr_el1);

   OFFSET(UREGS_SPSR_fiq, struct cpu_user_regs, spsr_fiq);
   OFFSET(UREGS_SPSR_irq, struct cpu_user_regs, spsr_irq);
   OFFSET(UREGS_SPSR_und, struct cpu_user_regs, spsr_und);
   OFFSET(UREGS_SPSR_abt, struct cpu_user_regs, spsr_abt);

   OFFSET(UREGS_SP_el0, struct cpu_user_regs, sp_el0);
   OFFSET(UREGS_SP_el1, struct cpu_user_regs, sp_el1);
   OFFSET(UREGS_ELR_el1, struct cpu_user_regs, elr_el1);

   OFFSET(UREGS_kernel_sizeof, struct cpu_user_regs, spsr_el1);
   DEFINE(UREGS_user_sizeof, sizeof(struct cpu_user_regs));
   BLANK();

   DEFINE(CPUINFO_sizeof, sizeof(struct cpu_info));

   OFFSET(VCPU_arch_saved_context, struct vcpu, arch.saved_context);

   BLANK();
   OFFSET(INITINFO_stack, struct init_info, stack);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
