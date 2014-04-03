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
#include <asm/procinfo.h>

#define DEFINE(_sym, _val)                                                 \
    asm volatile ("\n.ascii\"==>#define " #_sym " %0 /* " #_val " */<==\"" \
                  : : "i" (_val) )
#define BLANK()                                                            \
    asm volatile ( "\n.ascii\"==><==\"" : : )
#define OFFSET(_sym, _str, _mem)                                           \
    DEFINE(_sym, offsetof(_str, _mem));

void __dummy__(void)
{
   OFFSET(UREGS_sp, struct cpu_user_regs, sp);
   OFFSET(UREGS_lr, struct cpu_user_regs, lr);
   OFFSET(UREGS_pc, struct cpu_user_regs, pc);
   OFFSET(UREGS_cpsr, struct cpu_user_regs, cpsr);

   OFFSET(UREGS_LR_usr, struct cpu_user_regs, lr_usr);
   OFFSET(UREGS_SP_usr, struct cpu_user_regs, sp_usr);

   OFFSET(UREGS_SP_svc, struct cpu_user_regs, sp_svc);
   OFFSET(UREGS_LR_svc, struct cpu_user_regs, lr_svc);
   OFFSET(UREGS_SPSR_svc, struct cpu_user_regs, spsr_svc);

   OFFSET(UREGS_SP_abt, struct cpu_user_regs, sp_abt);
   OFFSET(UREGS_LR_abt, struct cpu_user_regs, lr_abt);
   OFFSET(UREGS_SPSR_abt, struct cpu_user_regs, spsr_abt);

   OFFSET(UREGS_SP_und, struct cpu_user_regs, sp_und);
   OFFSET(UREGS_LR_und, struct cpu_user_regs, lr_und);
   OFFSET(UREGS_SPSR_und, struct cpu_user_regs, spsr_und);

   OFFSET(UREGS_SP_irq, struct cpu_user_regs, sp_irq);
   OFFSET(UREGS_LR_irq, struct cpu_user_regs, lr_irq);
   OFFSET(UREGS_SPSR_irq, struct cpu_user_regs, spsr_irq);

   OFFSET(UREGS_SP_fiq, struct cpu_user_regs, sp_fiq);
   OFFSET(UREGS_LR_fiq, struct cpu_user_regs, lr_fiq);
   OFFSET(UREGS_SPSR_fiq, struct cpu_user_regs, spsr_fiq);

   OFFSET(UREGS_R8_fiq, struct cpu_user_regs, r8_fiq);
   OFFSET(UREGS_R9_fiq, struct cpu_user_regs, r9_fiq);
   OFFSET(UREGS_R10_fiq, struct cpu_user_regs, r10_fiq);
   OFFSET(UREGS_R11_fiq, struct cpu_user_regs, r11_fiq);
   OFFSET(UREGS_R12_fiq, struct cpu_user_regs, r12_fiq);

   OFFSET(UREGS_kernel_sizeof, struct cpu_user_regs, cpsr);
   DEFINE(UREGS_user_sizeof, sizeof(struct cpu_user_regs));
   BLANK();

   DEFINE(CPUINFO_sizeof, sizeof(struct cpu_info));

   OFFSET(VCPU_arch_saved_context, struct vcpu, arch.saved_context);

   BLANK();
   DEFINE(PROCINFO_sizeof, sizeof(struct proc_info_list));
   OFFSET(PROCINFO_cpu_val, struct proc_info_list, cpu_val);
   OFFSET(PROCINFO_cpu_mask, struct proc_info_list, cpu_mask);
   OFFSET(PROCINFO_cpu_init, struct proc_info_list, cpu_init);

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
