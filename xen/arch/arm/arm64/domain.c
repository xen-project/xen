#include <xen/config.h>
#include <xen/sched.h>

#include <asm/domain.h>
#include <asm/processor.h>

#include <public/xen.h>

/* C(hyp,user), hyp is Xen internal name, user is user API name. */

#define ALLREGS \
    C(x0,x0);   C(x1,x1);   C(x2,x2);   C(x3,x3);   \
    C(x4,x4);   C(x5,x5);   C(x6,x6);   C(x7,x7);   \
    C(x8,x8);   C(x9,x9);   C(x10,x10); C(x11,x11); \
    C(x12,x12); C(x13,x13); C(x14,x14); C(x15,x15); \
    C(x16,x16); C(x17,x17); C(x18,x18); C(x19,x19); \
    C(x20,x20); C(x21,x21); C(x22,x22); C(x23,x23); \
    C(x24,x24); C(x25,x25); C(x26,x26); C(x27,x27); \
    C(x28,x28); C(fp,x29);  C(lr,x30);  C(pc,pc64); \
    C(cpsr, cpsr); C(spsr_el1, spsr_el1)

#define ALLREGS32 C(spsr_fiq, spsr_fiq); C(spsr_irq,spsr_irq); \
                  C(spsr_und,spsr_und); C(spsr_abt,spsr_abt)

#define ALLREGS64 C(sp_el0,sp_el0); C(sp_el1,sp_el1); C(elr_el1,elr_el1)

void vcpu_regs_hyp_to_user(const struct vcpu *vcpu,
                           struct vcpu_guest_core_regs *regs)
{
#define C(hyp,user) regs->user = vcpu->arch.cpu_info->guest_cpu_user_regs.hyp
    ALLREGS;
    if ( is_32bit_domain(vcpu->domain) )
    {
        ALLREGS32;
    }
    else
    {
        ALLREGS64;
    }
#undef C
}

void vcpu_regs_user_to_hyp(struct vcpu *vcpu,
                           const struct vcpu_guest_core_regs *regs)
{
#define C(hyp,user) vcpu->arch.cpu_info->guest_cpu_user_regs.hyp = regs->user
    ALLREGS;
    if ( is_32bit_domain(vcpu->domain) )
    {
        ALLREGS32;
    }
    else
    {
        ALLREGS64;
    }
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
