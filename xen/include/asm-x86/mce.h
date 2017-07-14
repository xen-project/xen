#include <xen/types.h>
#include <public/arch-x86/xen-mca.h>
#ifndef _XEN_X86_MCE_H
#define _XEN_X86_MCE_H

/*
 * Emulate 2 banks for guest
 * Bank0: reserved for 'bank0 quirk' occur at some very old processors:
 *   1). Intel cpu whose family-model value < 06-1A;
 *   2). AMD K7
 * Bank1: used to transfer error info to guest
 */
#define GUEST_MC_BANK_NUM 2

/* Filter MSCOD model specific error code to guest */
#define MCi_STATUS_MSCOD_MASK (~(0xffffULL << 16))

/* No mci_ctl since it stick all 1's */
struct vmce_bank {
    uint64_t mci_status;
    uint64_t mci_addr;
    uint64_t mci_misc;
    uint64_t mci_ctl2;
};

/* No mcg_ctl since it not expose to guest */
struct vmce {
    uint64_t mcg_cap;
    uint64_t mcg_status;
    uint64_t mcg_ext_ctl;
    spinlock_t lock;
    struct vmce_bank bank[GUEST_MC_BANK_NUM];
};

/* Guest vMCE MSRs virtualization */
extern void vmce_init_vcpu(struct vcpu *);
extern int vmce_restore_vcpu(struct vcpu *, const struct hvm_vmce_vcpu *);
extern int vmce_wrmsr(uint32_t msr, uint64_t val);
extern int vmce_rdmsr(uint32_t msr, uint64_t *val);
extern bool vmce_has_lmce(const struct vcpu *v);
extern int vmce_enable_mca_cap(struct domain *d, uint64_t cap);

extern unsigned int nr_mce_banks;

#endif
