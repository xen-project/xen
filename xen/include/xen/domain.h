
#ifndef __XEN_DOMAIN_H__
#define __XEN_DOMAIN_H__

#include <xen/types.h>

#include <public/xen.h>
#include <asm/domain.h>
#include <asm/numa.h>

typedef union {
    struct vcpu_guest_context *nat;
    struct compat_vcpu_guest_context *cmp;
} vcpu_guest_context_u __attribute__((__transparent_union__));

struct vcpu *vcpu_create(struct domain *d, unsigned int vcpu_id);

unsigned int dom0_max_vcpus(void);
struct vcpu *alloc_dom0_vcpu0(struct domain *dom0);

int vcpu_reset(struct vcpu *);
int vcpu_up(struct vcpu *v);

void setup_system_domains(void);

struct xen_domctl_getdomaininfo;
void getdomaininfo(struct domain *d, struct xen_domctl_getdomaininfo *info);
void arch_get_domain_info(const struct domain *d,
                          struct xen_domctl_getdomaininfo *info);

/*
 * Arch-specifics.
 */

/* Allocate/free a domain structure. */
struct domain *alloc_domain_struct(void);
void free_domain_struct(struct domain *d);

/* Allocate/free a VCPU structure. */
struct vcpu *alloc_vcpu_struct(const struct domain *d);
void free_vcpu_struct(struct vcpu *v);

/* Allocate/free a PIRQ structure. */
#ifndef alloc_pirq_struct
struct pirq *alloc_pirq_struct(struct domain *);
#endif
void free_pirq_struct(void *);

/*
 * Initialise/destroy arch-specific details of a VCPU.
 *  - arch_vcpu_create() is called after the basic generic fields of the
 *    VCPU structure are initialised. Many operations can be applied to the
 *    VCPU at this point (e.g., vcpu_pause()).
 *  - arch_vcpu_destroy() is called only if arch_vcpu_create() previously
 *    succeeded.
 */
int  arch_vcpu_create(struct vcpu *v);
void arch_vcpu_destroy(struct vcpu *v);

int map_vcpu_info(struct vcpu *v, unsigned long gfn, unsigned offset);
void unmap_vcpu_info(struct vcpu *v);

int arch_domain_create(struct domain *d,
                       struct xen_domctl_createdomain *config);

void arch_domain_destroy(struct domain *d);

void arch_domain_shutdown(struct domain *d);
void arch_domain_pause(struct domain *d);
void arch_domain_unpause(struct domain *d);

int arch_domain_soft_reset(struct domain *d);

void arch_domain_creation_finished(struct domain *d);

void arch_p2m_set_access_required(struct domain *d, bool access_required);

int arch_set_info_guest(struct vcpu *, vcpu_guest_context_u);
void arch_get_info_guest(struct vcpu *, vcpu_guest_context_u);

int arch_initialise_vcpu(struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg);
int default_initialise_vcpu(struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg);

int domain_relinquish_resources(struct domain *d);

void dump_pageframe_info(struct domain *d);

void arch_dump_vcpu_info(struct vcpu *v);

void arch_dump_domain_info(struct domain *d);

int arch_vcpu_reset(struct vcpu *);

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

/*
 * Companion to continue_hypercall_on_cpu(), to feed func()'s result back into
 * vcpu regsiter state.
 */
void arch_hypercall_tasklet_result(struct vcpu *v, long res);

extern unsigned int xen_processor_pmbits;

extern bool_t opt_dom0_vcpus_pin;
extern cpumask_t dom0_cpus;
extern bool dom0_affinity_relaxed;

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
