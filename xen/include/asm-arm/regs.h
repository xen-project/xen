#ifndef __ARM_REGS_H__
#define __ARM_REGS_H__

#define PSR_MODE_MASK 0x1f

#ifndef __ASSEMBLY__

#include <xen/types.h>
#include <public/xen.h>
#include <asm/processor.h>

#define psr_mode(psr,m) (((psr) & PSR_MODE_MASK) == m)

#define psr_mode_is_32bit(psr) !!((psr) & PSR_MODE_BIT)

#define usr_mode(r)     psr_mode((r)->cpsr,PSR_MODE_USR)
#define fiq_mode(r)     psr_mode((r)->cpsr,PSR_MODE_FIQ)
#define irq_mode(r)     psr_mode((r)->cpsr,PSR_MODE_IRQ)
#define svc_mode(r)     psr_mode((r)->cpsr,PSR_MODE_SVC)
#define mon_mode(r)     psr_mode((r)->cpsr,PSR_MODE_MON)
#define abt_mode(r)     psr_mode((r)->cpsr,PSR_MODE_ABT)
#define und_mode(r)     psr_mode((r)->cpsr,PSR_MODE_UND)
#define sys_mode(r)     psr_mode((r)->cpsr,PSR_MODE_SYS)

#ifdef CONFIG_ARM_32
#define hyp_mode(r)     psr_mode((r)->cpsr,PSR_MODE_HYP)
#define psr_mode_is_user(r) usr_mode(r)
#else
#define hyp_mode(r)     (psr_mode((r)->cpsr,PSR_MODE_EL2h) || \
                         psr_mode((r)->cpsr,PSR_MODE_EL2t))

/*
 * Trap may have been taken from EL0, which might be in AArch32 usr
 * mode, or in AArch64 mode (PSR_MODE_EL0t).
 */
#define psr_mode_is_user(r) \
    (psr_mode((r)->cpsr,PSR_MODE_EL0t) || usr_mode(r))
#endif

#define guest_mode(r)                                                         \
({                                                                            \
    unsigned long diff = (char *)guest_cpu_user_regs() - (char *)(r);         \
    /* Frame pointer must point into current CPU stack. */                    \
    ASSERT(diff < STACK_SIZE);                                                \
    /* If not a guest frame, it must be a hypervisor frame. */                \
    ASSERT((diff == 0) || hyp_mode(r));                                       \
    /* Return TRUE if it's a guest frame. */                                  \
    (diff == 0);                                                              \
})

#define return_reg(v) ((v)->arch.cpu_info->guest_cpu_user_regs.r0)

/*
 * Returns a pointer to the given register value in regs, taking the
 * processor mode (CPSR) into account.
 */
extern register_t *select_user_reg(struct cpu_user_regs *regs, int reg);

#endif

#endif /* __ARM_REGS_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
