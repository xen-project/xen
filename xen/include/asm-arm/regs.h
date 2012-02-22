#ifndef __ARM_REGS_H__
#define __ARM_REGS_H__

#include <xen/types.h>
#include <public/xen.h>
#include <asm/processor.h>

#define psr_mode(psr,m) (((psr) & PSR_MODE_MASK) == m)

#define usr_mode(r)     psr_mode((r)->cpsr,PSR_MODE_USR)
#define fiq_mode(r)     psr_mode((r)->cpsr,PSR_MODE_FIQ)
#define irq_mode(r)     psr_mode((r)->cpsr,PSR_MODE_IRQ)
#define svc_mode(r)     psr_mode((r)->cpsr,PSR_MODE_SVC)
#define mon_mode(r)     psr_mode((r)->cpsr,PSR_MODE_MON)
#define abt_mode(r)     psr_mode((r)->cpsr,PSR_MODE_ABT)
#define hyp_mode(r)     psr_mode((r)->cpsr,PSR_MODE_HYP)
#define und_mode(r)     psr_mode((r)->cpsr,PSR_MODE_UND)
#define sys_mode(r)     psr_mode((r)->cpsr,PSR_MODE_SYS)

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

#endif /* __ARM_REGS_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
