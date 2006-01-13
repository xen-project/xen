
#ifndef __XEN_DOMAIN_H__
#define __XEN_DOMAIN_H__

extern int boot_vcpu(
    struct domain *d, int vcpuid, struct vcpu_guest_context *ctxt);

/*
 * Arch-specifics.
 */

struct vcpu *alloc_vcpu_struct(struct domain *d, unsigned int vcpu_id);

extern void free_vcpu_struct(struct vcpu *v);

extern int arch_do_createdomain(struct vcpu *v);

extern int arch_set_info_guest(
    struct vcpu *v, struct vcpu_guest_context *c);

extern void free_perdomain_pt(struct domain *d);

extern void domain_relinquish_resources(struct domain *d);

extern void dump_pageframe_info(struct domain *d);

#endif /* __XEN_DOMAIN_H__ */
