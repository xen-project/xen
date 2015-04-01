
#ifndef __XEN_DOMAIN_H__
#define __XEN_DOMAIN_H__

#include <public/xen.h>
#include <asm/domain.h>
#include <asm/numa.h>

typedef union {
    struct vcpu_guest_context *nat;
    struct compat_vcpu_guest_context *cmp;
} vcpu_guest_context_u __attribute__((__transparent_union__));

struct vcpu *alloc_vcpu(
    struct domain *d, unsigned int vcpu_id, unsigned int cpu_id);
struct vcpu *alloc_dom0_vcpu0(struct domain *dom0);
int vcpu_reset(struct vcpu *);

struct xen_domctl_getdomaininfo;
void getdomaininfo(struct domain *d, struct xen_domctl_getdomaininfo *info);

/*
 * Arch-specifics.
 */

/* Allocate/free a domain structure. */
struct domain *alloc_domain_struct(void);
void free_domain_struct(struct domain *d);

/* Allocate/free a VCPU structure. */
struct vcpu *alloc_vcpu_struct(void);
void free_vcpu_struct(struct vcpu *v);

/* Allocate/free a vcpu_guest_context structure. */
#ifndef alloc_vcpu_guest_context
struct vcpu_guest_context *alloc_vcpu_guest_context(void);
void free_vcpu_guest_context(struct vcpu_guest_context *);
#endif

/* Allocate/free a PIRQ structure. */
#ifndef alloc_pirq_struct
struct pirq *alloc_pirq_struct(struct domain *);
#endif
void free_pirq_struct(void *);

/*
 * Initialise/destroy arch-specific details of a VCPU.
 *  - vcpu_initialise() is called after the basic generic fields of the
 *    VCPU structure are initialised. Many operations can be applied to the
 *    VCPU at this point (e.g., vcpu_pause()).
 *  - vcpu_destroy() is called only if vcpu_initialise() previously succeeded.
 */
int  vcpu_initialise(struct vcpu *v);
void vcpu_destroy(struct vcpu *v);

int map_vcpu_info(struct vcpu *v, unsigned long gfn, unsigned offset);
void unmap_vcpu_info(struct vcpu *v);

int arch_domain_create(struct domain *d, unsigned int domcr_flags,
                       struct xen_arch_domainconfig *config);

void arch_domain_destroy(struct domain *d);

void arch_domain_shutdown(struct domain *d);
void arch_domain_pause(struct domain *d);
void arch_domain_unpause(struct domain *d);

int arch_set_info_guest(struct vcpu *, vcpu_guest_context_u);
void arch_get_info_guest(struct vcpu *, vcpu_guest_context_u);

int domain_relinquish_resources(struct domain *d);

void dump_pageframe_info(struct domain *d);

void arch_dump_vcpu_info(struct vcpu *v);

void arch_dump_domain_info(struct domain *d);

int arch_vcpu_reset(struct vcpu *);

extern spinlock_t vcpu_alloc_lock;
bool_t domctl_lock_acquire(void);
void domctl_lock_release(void);

/*
 * Continue the current hypercall via func(data) on specified cpu.
 * If this function returns 0 then the function is guaranteed to run at some
 * point in the future. If this function returns an error code then the
 * function has not been and will not be executed.
 */
int continue_hypercall_on_cpu(
    unsigned int cpu, long (*func)(void *data), void *data);

extern unsigned int xen_processor_pmbits;

extern bool_t opt_dom0_vcpus_pin;

/* vnuma topology per domain. */
struct vnuma_info {
    unsigned int nr_vnodes;
    unsigned int nr_vmemranges;
    unsigned int *vdistance;
    unsigned int *vcpu_to_vnode;
    nodeid_t *vnode_to_pnode;
    struct xen_vmemrange *vmemrange;
};

void vnuma_destroy(struct vnuma_info *vnuma);

#endif /* __XEN_DOMAIN_H__ */
