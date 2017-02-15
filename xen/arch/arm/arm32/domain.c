#include <xen/sched.h>

#include <asm/domain.h>
#include <asm/processor.h>

#include <public/xen.h>

/* C(hyp,user), hyp is Xen internal name, user is user API name. */

#define ALLREGS \
    C(r0,r0_usr);   C(r1,r1_usr);   C(r2,r2_usr);   C(r3,r3_usr);   \
    C(r4,r4_usr);   C(r5,r5_usr);   C(r6,r6_usr);   C(r7,r7_usr);   \
    C(r8,r8_usr);   C(r9,r9_usr);   C(r10,r10_usr); C(r11,r11_usr); \
    C(r12,r12_usr); \
    C(sp_usr,sp_usr); \
    C(lr,lr_usr); \
    C(spsr_irq,spsr_irq); C(lr_irq,lr_irq); C(sp_irq,sp_irq); \
    C(spsr_svc,spsr_svc); C(lr_svc,lr_svc); C(sp_svc,sp_svc); \
    C(spsr_abt,spsr_abt); C(lr_abt,lr_abt); C(sp_abt,sp_abt); \
    C(spsr_und,spsr_und); C(lr_und,lr_und); C(sp_und,sp_und); \
    C(spsr_fiq,spsr_fiq); C(sp_fiq,sp_fiq); C(sp_fiq,sp_fiq); \
    C(r8_fiq,r8_fiq); C(r9_fiq,r9_fiq); \
    C(r10_fiq,r10_fiq); C(r11_fiq,r11_fiq); C(r12_fiq,r12_fiq); \
    C(pc,pc32); \
    C(cpsr,cpsr)

void vcpu_regs_hyp_to_user(const struct vcpu *vcpu,
                           struct vcpu_guest_core_regs *regs)
{
#define C(hyp,user) regs->user = vcpu->arch.cpu_info->guest_cpu_user_regs.hyp
    ALLREGS;
#undef C
}

void vcpu_regs_user_to_hyp(struct vcpu *vcpu,
                           const struct vcpu_guest_core_regs *regs)
{
#define C(hyp,user) vcpu->arch.cpu_info->guest_cpu_user_regs.hyp = regs->user
    ALLREGS;
#undef C
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
