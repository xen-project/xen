#ifndef __ASM_X86_HVM_TRACE_H__
#define __ASM_X86_HVM_TRACE_H__

#include <xen/trace.h>

#define DO_TRC_HVM_VMENTRY     1
#define DO_TRC_HVM_VMEXIT      1
#define DO_TRC_HVM_PF_XEN      1
#define DO_TRC_HVM_PF_INJECT   1
#define DO_TRC_HVM_INJ_EXC     1
#define DO_TRC_HVM_INJ_VIRQ    1
#define DO_TRC_HVM_REINJ_VIRQ  1
#define DO_TRC_HVM_IO_READ     1
#define DO_TRC_HVM_IO_WRITE    1
#define DO_TRC_HVM_CR_READ     1
#define DO_TRC_HVM_CR_WRITE    1
#define DO_TRC_HVM_DR_READ     1
#define DO_TRC_HVM_DR_WRITE    1
#define DO_TRC_HVM_MSR_READ    1
#define DO_TRC_HVM_MSR_WRITE   1
#define DO_TRC_HVM_CPUID       1
#define DO_TRC_HVM_INTR        1
#define DO_TRC_HVM_NMI         1
#define DO_TRC_HVM_MCE         1
#define DO_TRC_HVM_SMI         1
#define DO_TRC_HVM_VMMCALL     1
#define DO_TRC_HVM_HLT         1
#define DO_TRC_HVM_INVLPG      1
#define DO_TRC_HVM_IO_ASSIST   1
#define DO_TRC_HVM_MMIO_ASSIST 1
#define DO_TRC_HVM_CLTS        1
#define DO_TRC_HVM_LMSW        1

static inline void hvmtrace_vmexit(struct vcpu *v,
                                   unsigned long rip,
                                   unsigned long exit_reason)
{
    if ( likely(!tb_init_done) )
        return;

#ifdef __x86_64__
    if ( hvm_long_mode_enabled(v) )
    {
        struct {
            unsigned did:16, vid:16;
            unsigned exit_reason:32;
            u64 rip;
        } d;

        d.did = v->domain->domain_id;
        d.vid = v->vcpu_id;
        d.exit_reason = exit_reason;
        d.rip = rip;
        __trace_var(TRC_HVM_VMEXIT64, 1/*cycles*/, sizeof(d),
                    (unsigned char *)&d);
    }
    else
#endif
    {
        struct {
            unsigned did:16, vid:16;
            unsigned exit_reason:32;
            u32 eip;
        } d;

        d.did = v->domain->domain_id;
        d.vid = v->vcpu_id;
        d.exit_reason = exit_reason;
        d.eip = rip;
        __trace_var(TRC_HVM_VMEXIT, 1/*cycles*/, sizeof(d),
                    (unsigned char *)&d);
    }
}


static inline void hvmtrace_vmentry(struct vcpu *v)
{
    struct {
        unsigned did:16, vid:16;
    } d;

    if ( likely(!tb_init_done) )
        return;

    d.did = v->domain->domain_id;
    d.vid = v->vcpu_id;
    __trace_var(TRC_HVM_VMENTRY, 1/*cycles*/, sizeof(d), (unsigned char *)&d);
}

static inline void hvmtrace_msr_read(struct vcpu *v, u32 ecx, u64 msr_content)
{
    struct {
        unsigned did:16, vid:16;
        u32 ecx;
        u64 msr_content;
    } d;

    if ( likely(!tb_init_done) )
        return;

    d.did = v->domain->domain_id;
    d.vid = v->vcpu_id;
    d.ecx = ecx;
    d.msr_content = msr_content;
    __trace_var(TRC_HVM_MSR_READ, 0/*!cycles*/, sizeof(d),
                (unsigned char *)&d);
}

static inline void hvmtrace_msr_write(struct vcpu *v, u32 ecx, u64 msr_content)
{
    struct {
        unsigned did:16, vid:16;
        u32 ecx;
        u64 msr_content;
    } d;

    if ( likely(!tb_init_done) )
        return;

    d.did = v->domain->domain_id;
    d.vid = v->vcpu_id;
    d.ecx = ecx;
    d.msr_content = msr_content;
    __trace_var(TRC_HVM_MSR_WRITE, 0/*!cycles*/,sizeof(d),
                (unsigned char *)&d);
}

static inline void hvmtrace_pf_xen(struct vcpu *v, unsigned long va,
                                   u32 error_code)
{
    if ( likely(!tb_init_done) )
        return;

#ifdef __x86_64__
    if( hvm_long_mode_enabled(v) )
    {
        struct {
            unsigned did:16, vid:16;
            u32 error_code;
            u64 va;
        } d;
        d.did = v->domain->domain_id;
        d.vid = v->vcpu_id;
        d.error_code = error_code;
        d.va = va;
        __trace_var(TRC_HVM_PF_XEN64, 0/*!cycles*/,sizeof(d),
                    (unsigned char *)&d);
    }
    else
#endif
    {
        struct {
            unsigned did:16, vid:16;
            u32 error_code;
            u32 va;
        } d;
        d.did = v->domain->domain_id;
        d.vid = v->vcpu_id;
        d.error_code = error_code;
        d.va = va;
        __trace_var(TRC_HVM_PF_XEN, 0/*!cycles*/,sizeof(d),
                    (unsigned char *)&d);
    }
}

#define HVMTRACE_ND(evt, vcpu, count, d1, d2, d3, d4)                   \
    do {                                                                \
        if ( unlikely(tb_init_done) && DO_TRC_HVM_ ## evt )             \
        {                                                               \
            struct {                                                    \
                unsigned did:16, vid:16;                                \
                u32 d[4];                                               \
            } _d;                                                       \
            _d.did=(vcpu)->domain->domain_id;                           \
            _d.vid=(vcpu)->vcpu_id;                                     \
            _d.d[0]=(d1);                                               \
            _d.d[1]=(d2);                                               \
            _d.d[2]=(d3);                                               \
            _d.d[3]=(d4);                                               \
            __trace_var(TRC_HVM_ ## evt, 0/*!cycles*/,                  \
                        sizeof(u32)*count+1, (unsigned char *)&_d);     \
        }                                                               \
    } while(0)

#define HVMTRACE_4D(evt, vcpu, d1, d2, d3, d4)   HVMTRACE_ND(evt, vcpu, 4, d1, d2, d3,  d4)
#define HVMTRACE_3D(evt, vcpu, d1, d2, d3)       HVMTRACE_ND(evt, vcpu, 3, d1, d2, d3,  0)
#define HVMTRACE_2D(evt, vcpu, d1, d2)           HVMTRACE_ND(evt, vcpu, 2, d1, d2,  0,  0)
#define HVMTRACE_1D(evt, vcpu, d1)               HVMTRACE_ND(evt, vcpu, 1, d1,  0,  0,  0)
#define HVMTRACE_0D(evt, vcpu)                   HVMTRACE_ND(evt, vcpu, 0, 0,  0,  0,  0)

#endif /* __ASM_X86_HVM_TRACE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
