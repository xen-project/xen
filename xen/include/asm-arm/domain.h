#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <xen/config.h>
#include <xen/cache.h>
#include <asm/page.h>
#include <asm/p2m.h>

struct pending_irq
{
    int irq;
    struct irq_desc *desc; /* only set it the irq corresponds to a physical irq */
    uint8_t priority;
    struct list_head link;
};

struct arch_domain
{
}  __cacheline_aligned;

struct arch_vcpu
{
    struct cpu_user_regs user_regs;

    uint32_t sctlr;
    uint32_t ttbr0, ttbr1, ttbcr;

}  __cacheline_aligned;

void vcpu_show_execution_state(struct vcpu *);
void vcpu_show_registers(const struct vcpu *);

#endif /* __ASM_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
