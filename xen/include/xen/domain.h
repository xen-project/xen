
#ifndef __XEN_DOMAIN_H__
#define __XEN_DOMAIN_H__

/*
 * Arch-specifics.
 */

extern void domain_startofday(void);

extern struct domain *arch_alloc_domain_struct(void);

extern void arch_free_domain_struct(struct domain *d);

struct exec_domain *arch_alloc_exec_domain_struct(void);

extern void arch_free_exec_domain_struct(struct exec_domain *ed);

extern void arch_do_createdomain(struct exec_domain *ed);

extern int  arch_final_setup_guestos(
    struct exec_domain *d, full_execution_context_t *c);

extern void free_perdomain_pt(struct domain *d);

extern void domain_relinquish_memory(struct domain *d);

extern void dump_pageframe_info(struct domain *d);

#endif /* __XEN_DOMAIN_H__ */
