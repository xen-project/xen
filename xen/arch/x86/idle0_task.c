
#include <xen/config.h>
#include <xen/sched.h>
#include <asm/desc.h>

struct domain idle0_domain = {
    domain_id:   IDLE_DOMAIN_ID,
    domain_flags:DOMF_idle_domain,
    refcnt:      ATOMIC_INIT(1)
};

struct vcpu idle0_vcpu = {
    processor:   0,
    cpu_affinity:CPU_MASK_CPU0,
    domain:      &idle0_domain
};

struct tss_struct init_tss[NR_CPUS];

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
