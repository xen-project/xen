#include <xen/types.h>
#include <public/arch-x86/xen-mca.h>
#ifndef _XEN_X86_MCE_H
#define _XEN_X86_MCE_H

/* This entry is for recording bank nodes for the impacted domain,
 * put into impact_header list. */
struct bank_entry {
    struct list_head list;
    uint16_t bank;
    uint64_t mci_status;
    uint64_t mci_addr;
    uint64_t mci_misc;
};

struct domain_mca_msrs
{
    /* Guest should not change below values after DOM boot up */
    uint64_t mcg_status;
    uint16_t nr_injection;
    struct list_head impact_header;
    spinlock_t lock;
};

/* Guest vMCE MSRs virtualization */
extern int vmce_init_msr(struct domain *d);
extern void vmce_destroy_msr(struct domain *d);
extern void vmce_init_vcpu(struct vcpu *);
extern int vmce_restore_vcpu(struct vcpu *, uint64_t caps);
extern int vmce_wrmsr(uint32_t msr, uint64_t val);
extern int vmce_rdmsr(uint32_t msr, uint64_t *val);

extern unsigned int nr_mce_banks;

#endif
