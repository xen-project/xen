
#ifndef __XEN_DOMAIN_H__
#define __XEN_DOMAIN_H__

/*
 * Arch-specifics.
 */

extern struct domain *arch_alloc_domain_struct(void);

extern void arch_free_domain_struct(struct domain *d);

struct exec_domain *arch_alloc_exec_domain_struct(void);

extern void arch_free_exec_domain_struct(struct exec_domain *ed);

extern void arch_do_createdomain(struct exec_domain *ed);

extern void arch_do_boot_vcpu(struct exec_domain *ed);

extern int  arch_set_info_guest(
    struct exec_domain *d, full_execution_context_t *c);

extern void free_perdomain_pt(struct domain *d);

extern void domain_relinquish_resources(struct domain *d);

extern void dump_pageframe_info(struct domain *d);

extern unsigned long alloc_monitor_pagetable(struct exec_domain *ed);

#endif /* __XEN_DOMAIN_H__ */
