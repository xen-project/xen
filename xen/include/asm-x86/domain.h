
#ifndef __ASM_X86_DOMAIN_H__
#define __ASM_X86_DOMAIN_H__

extern void arch_do_createdomain(struct domain *d);

extern void arch_final_setup_guestos(
    struct domain *d, full_execution_context_t *c);

static inline void free_perdomain_pt(struct domain *d)
{
    free_page((unsigned long)d->mm.perdomain_pt);
}

extern void domain_relinquish_memory(struct domain *d);

#endif /* __ASM_X86_DOMAIN_H__ */
