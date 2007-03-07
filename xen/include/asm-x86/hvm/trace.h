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
#define DO_TRC_HVM_SMI         1
#define DO_TRC_HVM_VMMCALL     1
#define DO_TRC_HVM_HLT         1
#define DO_TRC_HVM_INVLPG      1

#define HVMTRACE_4D(evt, vcpu, d1, d2, d3, d4)                      \
    do {                                                            \
        if (DO_TRC_HVM_ ## evt)                                     \
            TRACE_5D(                                               \
                TRC_HVM_ ## evt,                                    \
                ((vcpu)->domain->domain_id<<16) + (vcpu)->vcpu_id,  \
                d1, d2, d3, d4                                      \
            );                                                      \
    } while(0)

#define HVMTRACE_3D(evt, vcpu, d1, d2, d3)       HVMTRACE_4D(evt, vcpu, d1, d2, d3,  0)
#define HVMTRACE_2D(evt, vcpu, d1, d2)           HVMTRACE_4D(evt, vcpu, d1, d2,  0,  0)
#define HVMTRACE_1D(evt, vcpu, d1)               HVMTRACE_4D(evt, vcpu, d1,  0,  0,  0)
#define HVMTRACE_0D(evt, vcpu)                   HVMTRACE_4D(evt, vcpu,  0,  0,  0,  0)

#endif //__ASM_X86_HVM_TRACE_H__
