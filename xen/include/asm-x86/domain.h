
#ifndef __ASM_X86_DOMAIN_H__
#define __ASM_X86_DOMAIN_H__

extern void arch_do_createdomain(struct exec_domain *d);

extern int  arch_final_setup_guestos(
    struct exec_domain *d, full_execution_context_t *c);

extern void free_perdomain_pt(struct exec_domain *d);

extern void domain_relinquish_memory(struct domain *d);

#endif /* __ASM_X86_DOMAIN_H__ */
