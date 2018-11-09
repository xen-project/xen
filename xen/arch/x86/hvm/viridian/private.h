/* Copyright (c) 2018 Citrix Systems Inc. */

#ifndef X86_HVM_VIRIDIAN_PRIVATE_H
#define X86_HVM_VIRIDIAN_PRIVATE_H

#include <asm/hvm/save.h>

/* Viridian MSR numbers. */
#define HV_X64_MSR_GUEST_OS_ID                   0x40000000
#define HV_X64_MSR_HYPERCALL                     0x40000001
#define HV_X64_MSR_VP_INDEX                      0x40000002
#define HV_X64_MSR_RESET                         0x40000003
#define HV_X64_MSR_VP_RUNTIME                    0x40000010
#define HV_X64_MSR_TIME_REF_COUNT                0x40000020
#define HV_X64_MSR_REFERENCE_TSC                 0x40000021
#define HV_X64_MSR_TSC_FREQUENCY                 0x40000022
#define HV_X64_MSR_APIC_FREQUENCY                0x40000023
#define HV_X64_MSR_EOI                           0x40000070
#define HV_X64_MSR_ICR                           0x40000071
#define HV_X64_MSR_TPR                           0x40000072
#define HV_X64_MSR_VP_ASSIST_PAGE                0x40000073
#define HV_X64_MSR_SCONTROL                      0x40000080
#define HV_X64_MSR_SVERSION                      0x40000081
#define HV_X64_MSR_SIEFP                         0x40000082
#define HV_X64_MSR_SIMP                          0x40000083
#define HV_X64_MSR_EOM                           0x40000084
#define HV_X64_MSR_SINT0                         0x40000090
#define HV_X64_MSR_SINT1                         0x40000091
#define HV_X64_MSR_SINT2                         0x40000092
#define HV_X64_MSR_SINT3                         0x40000093
#define HV_X64_MSR_SINT4                         0x40000094
#define HV_X64_MSR_SINT5                         0x40000095
#define HV_X64_MSR_SINT6                         0x40000096
#define HV_X64_MSR_SINT7                         0x40000097
#define HV_X64_MSR_SINT8                         0x40000098
#define HV_X64_MSR_SINT9                         0x40000099
#define HV_X64_MSR_SINT10                        0x4000009A
#define HV_X64_MSR_SINT11                        0x4000009B
#define HV_X64_MSR_SINT12                        0x4000009C
#define HV_X64_MSR_SINT13                        0x4000009D
#define HV_X64_MSR_SINT14                        0x4000009E
#define HV_X64_MSR_SINT15                        0x4000009F
#define HV_X64_MSR_STIMER0_CONFIG                0x400000B0
#define HV_X64_MSR_STIMER0_COUNT                 0x400000B1
#define HV_X64_MSR_STIMER1_CONFIG                0x400000B2
#define HV_X64_MSR_STIMER1_COUNT                 0x400000B3
#define HV_X64_MSR_STIMER2_CONFIG                0x400000B4
#define HV_X64_MSR_STIMER2_COUNT                 0x400000B5
#define HV_X64_MSR_STIMER3_CONFIG                0x400000B6
#define HV_X64_MSR_STIMER3_COUNT                 0x400000B7
#define HV_X64_MSR_POWER_STATE_TRIGGER_C1        0x400000C1
#define HV_X64_MSR_POWER_STATE_TRIGGER_C2        0x400000C2
#define HV_X64_MSR_POWER_STATE_TRIGGER_C3        0x400000C3
#define HV_X64_MSR_POWER_STATE_CONFIG_C1         0x400000D1
#define HV_X64_MSR_POWER_STATE_CONFIG_C2         0x400000D2
#define HV_X64_MSR_POWER_STATE_CONFIG_C3         0x400000D3
#define HV_X64_MSR_STATS_PARTITION_RETAIL_PAGE   0x400000E0
#define HV_X64_MSR_STATS_PARTITION_INTERNAL_PAGE 0x400000E1
#define HV_X64_MSR_STATS_VP_RETAIL_PAGE          0x400000E2
#define HV_X64_MSR_STATS_VP_INTERNAL_PAGE        0x400000E3
#define HV_X64_MSR_GUEST_IDLE                    0x400000F0
#define HV_X64_MSR_SYNTH_DEBUG_CONTROL           0x400000F1
#define HV_X64_MSR_SYNTH_DEBUG_STATUS            0x400000F2
#define HV_X64_MSR_SYNTH_DEBUG_SEND_BUFFER       0x400000F3
#define HV_X64_MSR_SYNTH_DEBUG_RECEIVE_BUFFER    0x400000F4
#define HV_X64_MSR_SYNTH_DEBUG_PENDING_BUFFER    0x400000F5
#define HV_X64_MSR_CRASH_P0                      0x40000100
#define HV_X64_MSR_CRASH_P1                      0x40000101
#define HV_X64_MSR_CRASH_P2                      0x40000102
#define HV_X64_MSR_CRASH_P3                      0x40000103
#define HV_X64_MSR_CRASH_P4                      0x40000104
#define HV_X64_MSR_CRASH_CTL                     0x40000105

int viridian_synic_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val);
int viridian_synic_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val);

void viridian_synic_save_vcpu_ctxt(const struct vcpu *v,
                                   struct hvm_viridian_vcpu_context *ctxt);
void viridian_synic_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt);

int viridian_time_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val);
int viridian_time_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val);

void viridian_time_save_domain_ctxt(
    const struct domain *d, struct hvm_viridian_domain_context *ctxt);
void viridian_time_load_domain_ctxt(
    struct domain *d, const struct hvm_viridian_domain_context *ctxt);

void viridian_dump_guest_page(const struct vcpu *v, const char *name,
                              const struct viridian_page *vp);
void viridian_map_guest_page(struct vcpu *v, struct viridian_page *vp);
void viridian_unmap_guest_page(struct viridian_page *vp);

#endif /* X86_HVM_VIRIDIAN_PRIVATE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
