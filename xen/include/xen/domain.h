
#ifndef __XEN_DOMAIN_H__
#define __XEN_DOMAIN_H__



/*
 * Arch-specifics.
 */

extern void arch_do_createdomain(struct domain *d);

extern int  arch_final_setup_guestos(
    struct domain *d, full_execution_context_t *c);

extern void free_perdomain_pt(struct domain *d);

extern void domain_relinquish_memory(struct domain *d);

#endif /* __XEN_DOMAIN_H__ */
