#include <xen/types.h>
#include <public/arch-x86/xen-mca.h>
#ifndef _XEN_X86_MCE_H
#define _XEN_X86_MCE_H
/* Define for GUEST MCA handling */
#define MAX_NR_BANKS 30

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
    uint64_t mcg_cap;
    uint64_t mcg_ctl;
    uint64_t mcg_status;
    uint64_t *mci_ctl;
    uint16_t nr_injection;
    struct list_head impact_header;
    spinlock_t lock;
};

#define dom_vmce(x)   ((x)->arch.vmca_msrs)

/* Guest vMCE MSRs virtualization */
extern int vmce_init_msr(struct domain *d);
extern int vmce_wrmsr(uint32_t msr, uint64_t val);
extern int vmce_rdmsr(uint32_t msr, uint64_t *val);
#endif
