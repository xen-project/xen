
#ifndef __XEN_DOMAIN_H__
#define __XEN_DOMAIN_H__

/*
 * Arch-specifics.
 */

struct vcpu *arch_alloc_vcpu_struct(void);

extern void arch_free_vcpu_struct(struct vcpu *v);

extern void arch_do_createdomain(struct vcpu *v);

extern void arch_do_boot_vcpu(struct vcpu *v);

extern int  arch_set_info_guest(
    struct vcpu *v, struct vcpu_guest_context *c);

extern void vcpu_migrate_cpu(struct vcpu *v, int newcpu);

extern void free_perdomain_pt(struct domain *d);

extern void domain_relinquish_resources(struct domain *d);

extern void dump_pageframe_info(struct domain *d);

#endif /* __XEN_DOMAIN_H__ */
