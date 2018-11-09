/*****************************************************************************
 *
 * include/xen/viridian.h
 *
 * Copyright (c) 2008 Citrix Corp.
 *
 */

#ifndef __ASM_X86_HVM_VIRIDIAN_H__
#define __ASM_X86_HVM_VIRIDIAN_H__

union viridian_page_msr
{
    uint64_t raw;
    struct
    {
        uint64_t enabled:1;
        uint64_t reserved_preserved:11;
        uint64_t pfn:48;
    } fields;
};

struct viridian_page
{
    union viridian_page_msr msr;
    void *ptr;
};

struct viridian_vcpu
{
    struct viridian_page vp_assist;
    bool apic_assist_pending;
    uint64_t crash_param[5];
};

union viridian_guest_os_id_msr
{
    uint64_t raw;
    struct
    {
        uint64_t build_number:16;
        uint64_t service_pack:8;
        uint64_t minor:8;
        uint64_t major:8;
        uint64_t os:8;
        uint64_t vendor:16;
    } fields;
};

struct viridian_time_ref_count
{
    unsigned long flags;

#define _TRC_accessed 0
#define TRC_accessed (1 << _TRC_accessed)
#define _TRC_running 1
#define TRC_running (1 << _TRC_running)

    uint64_t val;
    int64_t off;
};

struct viridian_domain
{
    union viridian_guest_os_id_msr guest_os_id;
    union viridian_page_msr hypercall_gpa;
    struct viridian_time_ref_count time_ref_count;
    union viridian_page_msr reference_tsc;
};

void cpuid_viridian_leaves(const struct vcpu *v, uint32_t leaf,
                           uint32_t subleaf, struct cpuid_leaf *res);

int guest_wrmsr_viridian(struct vcpu *v, uint32_t idx, uint64_t val);
int guest_rdmsr_viridian(const struct vcpu *v, uint32_t idx, uint64_t *val);

int
viridian_hypercall(struct cpu_user_regs *regs);

void viridian_time_ref_count_freeze(struct domain *d);
void viridian_time_ref_count_thaw(struct domain *d);

void viridian_vcpu_deinit(struct vcpu *v);
void viridian_domain_deinit(struct domain *d);

void viridian_apic_assist_set(struct vcpu *v);
bool viridian_apic_assist_completed(struct vcpu *v);
void viridian_apic_assist_clear(struct vcpu *v);

#endif /* __ASM_X86_HVM_VIRIDIAN_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
