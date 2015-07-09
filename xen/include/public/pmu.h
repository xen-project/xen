#ifndef __XEN_PUBLIC_PMU_H__
#define __XEN_PUBLIC_PMU_H__

#include "xen.h"
#if defined(__i386__) || defined(__x86_64__)
#include "arch-x86/pmu.h"
#elif defined (__arm__) || defined (__aarch64__)
#include "arch-arm.h"
#else
#error "Unsupported architecture"
#endif

#define XENPMU_VER_MAJ    0
#define XENPMU_VER_MIN    1

/*
 * Shared PMU data between hypervisor and PV(H) domains.
 *
 * The hypervisor fills out this structure during PMU interrupt and sends an
 * interrupt to appropriate VCPU.
 * Architecture-independent fields of xen_pmu_data are WO for the hypervisor
 * and RO for the guest but some fields in xen_pmu_arch can be writable
 * by both the hypervisor and the guest (see arch-$arch/pmu.h).
 */
struct xen_pmu_data {
    /* Interrupted VCPU */
    uint32_t vcpu_id;

    /*
     * Physical processor on which the interrupt occurred. On non-privileged
     * guests set to vcpu_id;
     */
    uint32_t pcpu_id;

    /*
     * Domain that was interrupted. On non-privileged guests set to DOMID_SELF.
     * On privileged guests can be DOMID_SELF, DOMID_XEN, or, when in
     * XENPMU_MODE_ALL mode, domain ID of another domain.
     */
    domid_t  domain_id;

    uint8_t pad[6];

    /* Architecture-specific information */
    struct xen_pmu_arch pmu;
};

#endif /* __XEN_PUBLIC_PMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
