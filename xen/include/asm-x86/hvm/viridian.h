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
    };
};

struct viridian_page
{
    union viridian_page_msr msr;
    void *ptr;
};

union viridian_sint_msr
{
    uint64_t raw;
    struct
    {
        uint64_t vector:8;
        uint64_t reserved_preserved1:8;
        uint64_t mask:1;
        uint64_t auto_eoi:1;
        uint64_t polling:1;
        uint64_t reserved_preserved2:45;
    };
};

union viridian_stimer_config_msr
{
    uint64_t raw;
    struct
    {
        uint64_t enabled:1;
        uint64_t periodic:1;
        uint64_t lazy:1;
        uint64_t auto_enable:1;
        uint64_t vector:8;
        uint64_t direct_mode:1;
        uint64_t reserved_zero1:3;
        uint64_t sintx:4;
        uint64_t reserved_zero2:44;
    };
};

struct viridian_stimer {
    struct vcpu *v;
    struct timer timer;
    union viridian_stimer_config_msr config;
    uint64_t count;
    uint64_t expiration;
    bool started;
};

struct viridian_vcpu
{
    struct viridian_page vp_assist;
    bool apic_assist_pending;
    bool polled;
    unsigned int msg_pending;
    uint64_t scontrol;
    uint64_t siefp;
    struct viridian_page simp;
    union viridian_sint_msr sint[16];
    uint8_t vector_to_sintx[256];
    struct viridian_stimer stimer[4];
    unsigned int stimer_enabled;
    unsigned int stimer_pending;
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
    };
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
    struct viridian_page reference_tsc;
};

void cpuid_viridian_leaves(const struct vcpu *v, uint32_t leaf,
                           uint32_t subleaf, struct cpuid_leaf *res);

int guest_wrmsr_viridian(struct vcpu *v, uint32_t idx, uint64_t val);
int guest_rdmsr_viridian(const struct vcpu *v, uint32_t idx, uint64_t *val);

int
viridian_hypercall(struct cpu_user_regs *regs);

void viridian_time_domain_freeze(const struct domain *d);
void viridian_time_domain_thaw(const struct domain *d);

int viridian_vcpu_init(struct vcpu *v);
int viridian_domain_init(struct domain *d);

void viridian_vcpu_deinit(struct vcpu *v);
void viridian_domain_deinit(struct domain *d);

void viridian_apic_assist_set(const struct vcpu *v);
bool viridian_apic_assist_completed(const struct vcpu *v);
void viridian_apic_assist_clear(const struct vcpu *v);

void viridian_synic_poll(struct vcpu *v);
bool viridian_synic_is_auto_eoi_sint(const struct vcpu *v,
                                     unsigned int vector);
void viridian_synic_ack_sint(const struct vcpu *v, unsigned int vector);

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
