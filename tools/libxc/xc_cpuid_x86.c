/******************************************************************************
 * xc_cpuid_x86.c 
 *
 * Compute cpuid of a domain.
 *
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include "xc_private.h"
#include "xc_cpufeature.h"
#include <xen/hvm/params.h>

#define bitmaskof(idx)      (1u << (idx))
#define clear_bit(idx, dst) ((dst) &= ~(1u << (idx)))
#define set_bit(idx, dst)   ((dst) |= (1u << (idx)))

#define DEF_MAX_BASE 0x0000000du
#define DEF_MAX_INTELEXT  0x80000008u
#define DEF_MAX_AMDEXT    0x8000001cu

static int hypervisor_is_64bit(xc_interface *xch)
{
    xen_capabilities_info_t xen_caps = "";
    return ((xc_version(xch, XENVER_capabilities, &xen_caps) == 0) &&
            (strstr(xen_caps, "x86_64") != NULL));
}

static void cpuid(const unsigned int *input, unsigned int *regs)
{
    unsigned int count = (input[1] == XEN_CPUID_INPUT_UNUSED) ? 0 : input[1];
#ifdef __i386__
    /* Use the stack to avoid reg constraint failures with some gcc flags */
    asm (
        "push %%ebx; push %%edx\n\t"
        "cpuid\n\t"
        "mov %%ebx,4(%4)\n\t"
        "mov %%edx,12(%4)\n\t"
        "pop %%edx; pop %%ebx\n\t"
        : "=a" (regs[0]), "=c" (regs[2])
        : "0" (input[0]), "1" (count), "S" (regs)
        : "memory" );
#else
    asm (
        "cpuid"
        : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
        : "0" (input[0]), "2" (count) );
#endif
}

/* Get the manufacturer brand name of the host processor. */
static void xc_cpuid_brand_get(char *str)
{
    unsigned int input[2] = { 0, 0 };
    unsigned int regs[4];

    cpuid(input, regs);

    *(uint32_t *)(str + 0) = regs[1];
    *(uint32_t *)(str + 4) = regs[3];
    *(uint32_t *)(str + 8) = regs[2];
    str[12] = '\0';
}

static void amd_xc_cpuid_policy(
    xc_interface *xch, domid_t domid,
    const unsigned int *input, unsigned int *regs,
    int is_pae, int is_nestedhvm)
{
    switch ( input[0] )
    {
    case 0x00000002:
    case 0x00000004:
        regs[0] = regs[1] = regs[2] = 0;
        break;

    case 0x80000000:
        if ( regs[0] > DEF_MAX_AMDEXT )
            regs[0] = DEF_MAX_AMDEXT;
        break;

    case 0x80000001: {
        int is_64bit = hypervisor_is_64bit(xch) && is_pae;

        if ( !is_pae )
            clear_bit(X86_FEATURE_PAE, regs[3]);

        /* Filter all other features according to a whitelist. */
        regs[2] &= ((is_64bit ? bitmaskof(X86_FEATURE_LAHF_LM) : 0) |
                    bitmaskof(X86_FEATURE_CMP_LEGACY) |
                    (is_nestedhvm ? bitmaskof(X86_FEATURE_SVM) : 0) |
                    bitmaskof(X86_FEATURE_CR8_LEGACY) |
                    bitmaskof(X86_FEATURE_ABM) |
                    bitmaskof(X86_FEATURE_SSE4A) |
                    bitmaskof(X86_FEATURE_MISALIGNSSE) |
                    bitmaskof(X86_FEATURE_3DNOWPREFETCH) |
                    bitmaskof(X86_FEATURE_OSVW) |
                    bitmaskof(X86_FEATURE_XOP) |
                    bitmaskof(X86_FEATURE_FMA4) |
                    bitmaskof(X86_FEATURE_TBM) |
                    bitmaskof(X86_FEATURE_LWP));
        regs[3] &= (0x0183f3ff | /* features shared with 0x00000001:EDX */
                    (is_pae ? bitmaskof(X86_FEATURE_NX) : 0) |
                    (is_64bit ? bitmaskof(X86_FEATURE_LM) : 0) |
                    bitmaskof(X86_FEATURE_SYSCALL) |
                    bitmaskof(X86_FEATURE_MP) |
                    bitmaskof(X86_FEATURE_MMXEXT) |
                    bitmaskof(X86_FEATURE_FFXSR) |
                    bitmaskof(X86_FEATURE_3DNOW) |
                    bitmaskof(X86_FEATURE_3DNOWEXT));
        break;
    }

    case 0x80000008:
        /*
         * ECX[15:12] is ApicIdCoreSize: ECX[7:0] is NumberOfCores (minus one).
         * Update to reflect vLAPIC_ID = vCPU_ID * 2.
         */
        regs[2] = ((regs[2] & 0xf000u) + 1) | ((regs[2] & 0xffu) << 1) | 1u;
        break;

    case 0x8000000a: {
        if (!is_nestedhvm) {
            regs[0] = regs[1] = regs[2] = regs[3] = 0;
            break;
        }

#define SVM_FEATURE_NPT            0x00000001 /* Nested page table support */
#define SVM_FEATURE_LBRV           0x00000002 /* LBR virtualization support */
#define SVM_FEATURE_SVML           0x00000004 /* SVM locking MSR support */
#define SVM_FEATURE_NRIPS          0x00000008 /* Next RIP save on VMEXIT */
#define SVM_FEATURE_TSCRATEMSR     0x00000010 /* TSC ratio MSR support */
#define SVM_FEATURE_VMCBCLEAN      0x00000020 /* VMCB clean bits support */
#define SVM_FEATURE_FLUSHBYASID    0x00000040 /* TLB flush by ASID support */
#define SVM_FEATURE_DECODEASSISTS  0x00000080 /* Decode assists support */
#define SVM_FEATURE_PAUSEFILTER    0x00000400 /* Pause intercept filter */

        /* Pass 1: Only passthrough SVM features which are
         * available in hw and which are implemented
         */
        regs[3] &= (SVM_FEATURE_NPT | SVM_FEATURE_LBRV | \
            SVM_FEATURE_NRIPS | SVM_FEATURE_PAUSEFILTER | \
            SVM_FEATURE_DECODEASSISTS);

        /* Pass 2: Always enable SVM features which are emulated */
        regs[3] |= SVM_FEATURE_VMCBCLEAN | SVM_FEATURE_TSCRATEMSR;
        break;
    }

    }
}

static void intel_xc_cpuid_policy(
    xc_interface *xch, domid_t domid,
    const unsigned int *input, unsigned int *regs,
    int is_pae, int is_nestedhvm)
{
    switch ( input[0] )
    {
    case 0x00000001:
        /* ECX[5] is availability of VMX */
        if (is_nestedhvm)
            set_bit(X86_FEATURE_VMXE, regs[2]);
        break;

    case 0x00000004:
        /*
         * EAX[31:26] is Maximum Cores Per Package (minus one).
         * Update to reflect vLAPIC_ID = vCPU_ID * 2.
         */
        regs[0] = (((regs[0] & 0x7c000000u) << 1) | 0x04000000u |
                   (regs[0] & 0x3ffu));
        regs[3] &= 0x3ffu;
        break;

    case 0x80000000:
        if ( regs[0] > DEF_MAX_INTELEXT )
            regs[0] = DEF_MAX_INTELEXT;
        break;

    case 0x80000001: {
        int is_64bit = hypervisor_is_64bit(xch) && is_pae;

        /* Only a few features are advertised in Intel's 0x80000001. */
        regs[2] &= (is_64bit ? bitmaskof(X86_FEATURE_LAHF_LM) : 0) |
                               bitmaskof(X86_FEATURE_3DNOWPREFETCH) |
                               bitmaskof(X86_FEATURE_ABM);
        regs[3] &= ((is_pae ? bitmaskof(X86_FEATURE_NX) : 0) |
                    (is_64bit ? bitmaskof(X86_FEATURE_LM) : 0) |
                    (is_64bit ? bitmaskof(X86_FEATURE_SYSCALL) : 0) |
                    (is_64bit ? bitmaskof(X86_FEATURE_RDTSCP) : 0));
        break;
    }

    case 0x80000005:
        regs[0] = regs[1] = regs[2] = 0;
        break;

    case 0x80000008:
        /* Mask AMD Number of Cores information. */
        regs[2] = 0;
        break;
    }
}

#define XSAVEOPT        (1 << 0)
/* Configure extended state enumeration leaves (0x0000000D for xsave) */
static void xc_cpuid_config_xsave(
    xc_interface *xch, domid_t domid, uint64_t xfeature_mask,
    const unsigned int *input, unsigned int *regs)
{
    if ( xfeature_mask == 0 )
    {
        regs[0] = regs[1] = regs[2] = regs[3] = 0;
        return;
    }

    switch ( input[1] )
    {
    case 0: 
        /* EAX: low 32bits of xfeature_enabled_mask */
        regs[0] = xfeature_mask & 0xFFFFFFFF;
        /* EDX: high 32bits of xfeature_enabled_mask */
        regs[3] = (xfeature_mask >> 32) & 0xFFFFFFFF;
        /* ECX: max size required by all HW features */
        {
            unsigned int _input[2] = {0xd, 0x0}, _regs[4];
            regs[2] = 0;
            for ( _input[1] = 2; _input[1] < 64; _input[1]++ )
            {
                cpuid(_input, _regs);
                if ( (_regs[0] + _regs[1]) > regs[2] )
                    regs[2] = _regs[0] + _regs[1];
            }
        }
        /* EBX: max size required by enabled features. 
         * This register contains a dynamic value, which varies when a guest 
         * enables or disables XSTATE features (via xsetbv). The default size 
         * after reset is 576. */ 
        regs[1] = 512 + 64; /* FP/SSE + XSAVE.HEADER */
        break;
    case 1: /* leaf 1 */
        regs[0] &= XSAVEOPT;
        regs[1] = regs[2] = regs[3] = 0;
        break;
    case 2 ... 63: /* sub-leaves */
        if ( !(xfeature_mask & (1ULL << input[1])) )
        {
            regs[0] = regs[1] = regs[2] = regs[3] = 0;
            break;
        }
        /* Don't touch EAX, EBX. Also cleanup ECX and EDX */
        regs[2] = regs[3] = 0;
        break;
    }
}

static void xc_cpuid_hvm_policy(
    xc_interface *xch, domid_t domid,
    const unsigned int *input, unsigned int *regs)
{
    DECLARE_DOMCTL;
    char brand[13];
    unsigned long nestedhvm;
    unsigned long pae;
    int is_pae, is_nestedhvm;
    uint64_t xfeature_mask;

    xc_get_hvm_param(xch, domid, HVM_PARAM_PAE_ENABLED, &pae);
    is_pae = !!pae;

    /* Detecting Xen's atitude towards XSAVE */
    memset(&domctl, 0, sizeof(domctl));
    domctl.cmd = XEN_DOMCTL_getvcpuextstate;
    domctl.domain = domid;
    do_domctl(xch, &domctl);
    xfeature_mask = domctl.u.vcpuextstate.xfeature_mask;

    xc_get_hvm_param(xch, domid, HVM_PARAM_NESTEDHVM, &nestedhvm);
    is_nestedhvm = !!nestedhvm;

    switch ( input[0] )
    {
    case 0x00000000:
        if ( regs[0] > DEF_MAX_BASE )
            regs[0] = DEF_MAX_BASE;
        break;

    case 0x00000001:
        /*
         * EBX[23:16] is Maximum Logical Processors Per Package.
         * Update to reflect vLAPIC_ID = vCPU_ID * 2.
         */
        regs[1] = (regs[1] & 0x0000ffffu) | ((regs[1] & 0x007f0000u) << 1);

        regs[2] &= (bitmaskof(X86_FEATURE_XMM3) |
                    bitmaskof(X86_FEATURE_PCLMULQDQ) |
                    bitmaskof(X86_FEATURE_SSSE3) |
                    bitmaskof(X86_FEATURE_FMA) |
                    bitmaskof(X86_FEATURE_CX16) |
                    bitmaskof(X86_FEATURE_PCID) |
                    bitmaskof(X86_FEATURE_SSE4_1) |
                    bitmaskof(X86_FEATURE_SSE4_2) |
                    bitmaskof(X86_FEATURE_MOVBE)  |
                    bitmaskof(X86_FEATURE_POPCNT) |
                    bitmaskof(X86_FEATURE_AES) |
                    bitmaskof(X86_FEATURE_F16C) |
                    bitmaskof(X86_FEATURE_RDRAND) |
                    ((xfeature_mask != 0) ?
                     (bitmaskof(X86_FEATURE_AVX) |
                      bitmaskof(X86_FEATURE_XSAVE)) : 0));

        regs[2] |= (bitmaskof(X86_FEATURE_HYPERVISOR) |
                    bitmaskof(X86_FEATURE_TSC_DEADLINE) |
                    bitmaskof(X86_FEATURE_X2APIC));

        regs[3] &= (bitmaskof(X86_FEATURE_FPU) |
                    bitmaskof(X86_FEATURE_VME) |
                    bitmaskof(X86_FEATURE_DE) |
                    bitmaskof(X86_FEATURE_PSE) |
                    bitmaskof(X86_FEATURE_TSC) |
                    bitmaskof(X86_FEATURE_MSR) |
                    bitmaskof(X86_FEATURE_PAE) |
                    bitmaskof(X86_FEATURE_MCE) |
                    bitmaskof(X86_FEATURE_CX8) |
                    bitmaskof(X86_FEATURE_APIC) |
                    bitmaskof(X86_FEATURE_SEP) |
                    bitmaskof(X86_FEATURE_MTRR) |
                    bitmaskof(X86_FEATURE_PGE) |
                    bitmaskof(X86_FEATURE_MCA) |
                    bitmaskof(X86_FEATURE_CMOV) |
                    bitmaskof(X86_FEATURE_PAT) |
                    bitmaskof(X86_FEATURE_CLFLSH) |
                    bitmaskof(X86_FEATURE_PSE36) |
                    bitmaskof(X86_FEATURE_MMX) |
                    bitmaskof(X86_FEATURE_FXSR) |
                    bitmaskof(X86_FEATURE_XMM) |
                    bitmaskof(X86_FEATURE_XMM2) |
                    bitmaskof(X86_FEATURE_HT));
            
        /* We always support MTRR MSRs. */
        regs[3] |= bitmaskof(X86_FEATURE_MTRR);

        if ( !is_pae ) {
            clear_bit(X86_FEATURE_PAE, regs[3]);
            clear_bit(X86_FEATURE_PSE36, regs[3]);
        }
        break;

    case 0x00000007: /* Intel-defined CPU features */
        if ( input[1] == 0 ) {
            regs[1] &= (bitmaskof(X86_FEATURE_TSC_ADJUST) |
                        bitmaskof(X86_FEATURE_BMI1) |
                        bitmaskof(X86_FEATURE_HLE)  |
                        bitmaskof(X86_FEATURE_AVX2) |
                        bitmaskof(X86_FEATURE_SMEP) |
                        bitmaskof(X86_FEATURE_BMI2) |
                        bitmaskof(X86_FEATURE_ERMS) |
                        bitmaskof(X86_FEATURE_INVPCID) |
                        bitmaskof(X86_FEATURE_RTM)  |
                        bitmaskof(X86_FEATURE_RDSEED)  |
                        bitmaskof(X86_FEATURE_ADX)  |
                        bitmaskof(X86_FEATURE_FSGSBASE));
        } else
            regs[1] = 0;
        regs[0] = regs[2] = regs[3] = 0;
        break;

    case 0x0000000d:
        xc_cpuid_config_xsave(xch, domid, xfeature_mask, input, regs);
        break;

    case 0x80000000:
        /* Passthrough to cpu vendor specific functions */
        break;

    case 0x80000001:
        if ( !is_pae ) {
            clear_bit(X86_FEATURE_NX, regs[3]);
            clear_bit(X86_FEATURE_PSE36, regs[3]);
        }
        break;

    case 0x80000007:
        /*
         * Keep only TSCInvariant. This may be cleared by the hypervisor
         * depending on guest TSC and migration settings.
         */
        regs[0] = regs[1] = regs[2] = 0;
        regs[3] &= 1u<<8;
        break;

    case 0x80000008:
        regs[0] &= 0x0000ffffu;
        regs[1] = regs[3] = 0;
        break;

    case 0x00000002: /* Intel cache info (dumped by AMD policy) */
    case 0x00000004: /* Intel cache info (dumped by AMD policy) */
    case 0x0000000a: /* Architectural Performance Monitor Features */
    case 0x80000002: /* Processor name string */
    case 0x80000003: /* ... continued         */
    case 0x80000004: /* ... continued         */
    case 0x80000005: /* AMD L1 cache/TLB info (dumped by Intel policy) */
    case 0x80000006: /* AMD L2/3 cache/TLB info ; Intel L2 cache features */
    case 0x8000000a: /* AMD SVM feature bits */
    case 0x8000001c: /* AMD lightweight profiling */
        break;

    default:
        regs[0] = regs[1] = regs[2] = regs[3] = 0;
        break;
    }

    xc_cpuid_brand_get(brand);
    if ( strstr(brand, "AMD") )
        amd_xc_cpuid_policy(xch, domid, input, regs, is_pae, is_nestedhvm);
    else
        intel_xc_cpuid_policy(xch, domid, input, regs, is_pae, is_nestedhvm);

}

static void xc_cpuid_pv_policy(
    xc_interface *xch, domid_t domid,
    const unsigned int *input, unsigned int *regs)
{
    DECLARE_DOMCTL;
    unsigned int guest_width;
    int guest_64bit, xen_64bit = hypervisor_is_64bit(xch);
    char brand[13];
    uint64_t xfeature_mask;

    xc_cpuid_brand_get(brand);

    xc_domain_get_guest_width(xch, domid, &guest_width);
    guest_64bit = (guest_width == 8);

    /* Detecting Xen's atitude towards XSAVE */
    memset(&domctl, 0, sizeof(domctl));
    domctl.cmd = XEN_DOMCTL_getvcpuextstate;
    domctl.domain = domid;
    do_domctl(xch, &domctl);
    xfeature_mask = domctl.u.vcpuextstate.xfeature_mask;

    if ( (input[0] & 0x7fffffff) == 0x00000001 )
    {
        clear_bit(X86_FEATURE_VME, regs[3]);
        clear_bit(X86_FEATURE_PSE, regs[3]);
        clear_bit(X86_FEATURE_PGE, regs[3]);
        clear_bit(X86_FEATURE_MCE, regs[3]);
        clear_bit(X86_FEATURE_MCA, regs[3]);
        clear_bit(X86_FEATURE_MTRR, regs[3]);
        clear_bit(X86_FEATURE_PSE36, regs[3]);
    }

    switch ( input[0] )
    {
    case 0x00000001:
        if ( !xen_64bit || strstr(brand, "AMD") )
            clear_bit(X86_FEATURE_SEP, regs[3]);
        clear_bit(X86_FEATURE_DS, regs[3]);
        clear_bit(X86_FEATURE_ACC, regs[3]);
        clear_bit(X86_FEATURE_PBE, regs[3]);

        clear_bit(X86_FEATURE_DTES64, regs[2]);
        clear_bit(X86_FEATURE_MWAIT, regs[2]);
        clear_bit(X86_FEATURE_DSCPL, regs[2]);
        clear_bit(X86_FEATURE_VMXE, regs[2]);
        clear_bit(X86_FEATURE_SMXE, regs[2]);
        clear_bit(X86_FEATURE_EST, regs[2]);
        clear_bit(X86_FEATURE_TM2, regs[2]);
        if ( !guest_64bit )
            clear_bit(X86_FEATURE_CX16, regs[2]);
        if ( xfeature_mask == 0 )
        {
            clear_bit(X86_FEATURE_XSAVE, regs[2]);
            clear_bit(X86_FEATURE_AVX, regs[2]);
        }
        clear_bit(X86_FEATURE_XTPR, regs[2]);
        clear_bit(X86_FEATURE_PDCM, regs[2]);
        clear_bit(X86_FEATURE_PCID, regs[2]);
        clear_bit(X86_FEATURE_DCA, regs[2]);
        set_bit(X86_FEATURE_HYPERVISOR, regs[2]);
        break;

    case 0x00000007:
        if ( input[1] == 0 )
            regs[1] &= (bitmaskof(X86_FEATURE_BMI1) |
                        bitmaskof(X86_FEATURE_HLE)  |
                        bitmaskof(X86_FEATURE_AVX2) |
                        bitmaskof(X86_FEATURE_BMI2) |
                        bitmaskof(X86_FEATURE_ERMS) |
                        bitmaskof(X86_FEATURE_RTM)  |
                        bitmaskof(X86_FEATURE_RDSEED)  |
                        bitmaskof(X86_FEATURE_ADX)  |
                        bitmaskof(X86_FEATURE_FSGSBASE));
        else
            regs[1] = 0;
        regs[0] = regs[2] = regs[3] = 0;
        break;

    case 0x0000000d:
        xc_cpuid_config_xsave(xch, domid, xfeature_mask, input, regs);
        break;

    case 0x80000001:
        if ( !guest_64bit )
        {
            clear_bit(X86_FEATURE_LM, regs[3]);
            clear_bit(X86_FEATURE_LAHF_LM, regs[2]);
            if ( !strstr(brand, "AMD") )
                clear_bit(X86_FEATURE_SYSCALL, regs[3]);
        }
        else
        {
            set_bit(X86_FEATURE_SYSCALL, regs[3]);
        }
        clear_bit(X86_FEATURE_PAGE1GB, regs[3]);
        clear_bit(X86_FEATURE_RDTSCP, regs[3]);

        clear_bit(X86_FEATURE_SVM, regs[2]);
        clear_bit(X86_FEATURE_OSVW, regs[2]);
        clear_bit(X86_FEATURE_IBS, regs[2]);
        clear_bit(X86_FEATURE_SKINIT, regs[2]);
        clear_bit(X86_FEATURE_WDT, regs[2]);
        clear_bit(X86_FEATURE_LWP, regs[2]);
        clear_bit(X86_FEATURE_NODEID_MSR, regs[2]);
        clear_bit(X86_FEATURE_TOPOEXT, regs[2]);
        break;

    case 0x00000005: /* MONITOR/MWAIT */
    case 0x0000000a: /* Architectural Performance Monitor Features */
    case 0x0000000b: /* Extended Topology Enumeration */
    case 0x8000000a: /* SVM revision and features */
    case 0x8000001b: /* Instruction Based Sampling */
    case 0x8000001c: /* Light Weight Profiling */
    case 0x8000001e: /* Extended topology reporting */
        regs[0] = regs[1] = regs[2] = regs[3] = 0;
        break;
    }
}

static int xc_cpuid_policy(
    xc_interface *xch, domid_t domid,
    const unsigned int *input, unsigned int *regs)
{
    xc_dominfo_t        info;

    if ( xc_domain_getinfo(xch, domid, 1, &info) == 0 )
        return -EINVAL;

    if ( info.hvm )
        xc_cpuid_hvm_policy(xch, domid, input, regs);
    else
        xc_cpuid_pv_policy(xch, domid, input, regs);

    return 0;
}

static int xc_cpuid_do_domctl(
    xc_interface *xch, domid_t domid,
    const unsigned int *input, const unsigned int *regs)
{
    DECLARE_DOMCTL;

    memset(&domctl, 0, sizeof (domctl));
    domctl.domain = domid;
    domctl.cmd = XEN_DOMCTL_set_cpuid;
    domctl.u.cpuid.input[0] = input[0];
    domctl.u.cpuid.input[1] = input[1];
    domctl.u.cpuid.eax = regs[0];
    domctl.u.cpuid.ebx = regs[1];
    domctl.u.cpuid.ecx = regs[2];
    domctl.u.cpuid.edx = regs[3];

    return do_domctl(xch, &domctl);
}

static char *alloc_str(void)
{
    char *s = malloc(33);
    if ( s == NULL )
        return s;
    memset(s, 0, 33);
    return s;
}

void xc_cpuid_to_str(const unsigned int *regs, char **strs)
{
    int i, j;

    for ( i = 0; i < 4; i++ )
    {
        strs[i] = alloc_str();
        if ( strs[i] == NULL )
            continue;
        for ( j = 0; j < 32; j++ )
            strs[i][j] = !!((regs[i] & (1U << (31 - j)))) ? '1' : '0';
    }
}

int xc_cpuid_apply_policy(xc_interface *xch, domid_t domid)
{
    unsigned int input[2] = { 0, 0 }, regs[4];
    unsigned int base_max, ext_max;
    char brand[13];
    int rc;


    cpuid(input, regs);
    base_max = (regs[0] <= DEF_MAX_BASE) ? regs[0] : DEF_MAX_BASE;
    input[0] = 0x80000000;
    cpuid(input, regs);

    xc_cpuid_brand_get(brand);
    if ( strstr(brand, "AMD") )
        ext_max = (regs[0] <= DEF_MAX_AMDEXT) ? regs[0] : DEF_MAX_AMDEXT;
    else
        ext_max = (regs[0] <= DEF_MAX_INTELEXT) ? regs[0] : DEF_MAX_INTELEXT;

    input[0] = 0;
    input[1] = XEN_CPUID_INPUT_UNUSED;
    for ( ; ; )
    {
        cpuid(input, regs);
        xc_cpuid_policy(xch, domid, input, regs);

        if ( regs[0] || regs[1] || regs[2] || regs[3] )
        {
            rc = xc_cpuid_do_domctl(xch, domid, input, regs);
            if ( rc )
                return rc;
        }

        /* Intel cache descriptor leaves. */
        if ( input[0] == 4 )
        {
            input[1]++;
            /* More to do? Then loop keeping %%eax==0x00000004. */
            if ( (regs[0] & 0x1f) != 0 )
                continue;
        }

        /* XSAVE information, subleaves 0-63. */
        if ( (input[0] == 0xd) && (input[1]++ < 63) )
            continue;

        input[0]++;
        if ( !(input[0] & 0x80000000u) && (input[0] > base_max ) )
            input[0] = 0x80000000u;

        input[1] = XEN_CPUID_INPUT_UNUSED;
        if ( (input[0] == 4) || (input[0] == 7) || (input[0] == 0xd) )
            input[1] = 0;

        if ( (input[0] & 0x80000000u) && (input[0] > ext_max) )
            break;
    }

    return 0;
}

/*
 * Check whether a VM is allowed to launch on this host's processor type.
 *
 * @config format is similar to that of xc_cpuid_set():
 *  '1' -> the bit must be set to 1
 *  '0' -> must be 0
 *  'x' -> we don't care
 *  's' -> (same) must be the same
 */
int xc_cpuid_check(
    xc_interface *xch, const unsigned int *input,
    const char **config,
    char **config_transformed)
{
    int i, j, rc;
    unsigned int regs[4];

    memset(config_transformed, 0, 4 * sizeof(*config_transformed));

    cpuid(input, regs);

    for ( i = 0; i < 4; i++ )
    {
        if ( config[i] == NULL )
            continue;
        config_transformed[i] = alloc_str();
        if ( config_transformed[i] == NULL )
        {
            rc = -ENOMEM;
            goto fail_rc;
        }
        for ( j = 0; j < 32; j++ )
        {
            unsigned char val = !!((regs[i] & (1U << (31 - j))));
            if ( !strchr("10xs", config[i][j]) ||
                 ((config[i][j] == '1') && !val) ||
                 ((config[i][j] == '0') && val) )
                goto fail;
            config_transformed[i][j] = config[i][j];
            if ( config[i][j] == 's' )
                config_transformed[i][j] = '0' + val;
        }
    }

    return 0;

 fail:
    rc = -EPERM;
 fail_rc:
    for ( i = 0; i < 4; i++ )
    {
        free(config_transformed[i]);
        config_transformed[i] = NULL;
    }
    return rc;
}

/*
 * Configure a single input with the informatiom from config.
 *
 * Config is an array of strings:
 *   config[0] = eax
 *   config[1] = ebx
 *   config[2] = ecx
 *   config[3] = edx
 *
 * The format of the string is the following:
 *   '1' -> force to 1
 *   '0' -> force to 0
 *   'x' -> we don't care (use default)
 *   'k' -> pass through host value
 *   's' -> pass through the first time and then keep the same value
 *          across save/restore and migration.
 * 
 * For 's' and 'x' the configuration is overwritten with the value applied.
 */
int xc_cpuid_set(
    xc_interface *xch, domid_t domid, const unsigned int *input,
    const char **config, char **config_transformed)
{
    int rc;
    unsigned int i, j, regs[4], polregs[4];

    memset(config_transformed, 0, 4 * sizeof(*config_transformed));

    cpuid(input, regs);

    memcpy(polregs, regs, sizeof(regs));
    xc_cpuid_policy(xch, domid, input, polregs);

    for ( i = 0; i < 4; i++ )
    {
        if ( config[i] == NULL )
        {
            regs[i] = polregs[i];
            continue;
        }
        
        config_transformed[i] = alloc_str();
        if ( config_transformed[i] == NULL )
        {
            rc = -ENOMEM;
            goto fail;
        }

        for ( j = 0; j < 32; j++ )
        {
            unsigned char val = !!((regs[i] & (1U << (31 - j))));
            unsigned char polval = !!((polregs[i] & (1U << (31 - j))));

            rc = -EINVAL;
            if ( !strchr("10xks", config[i][j]) )
                goto fail;

            if ( config[i][j] == '1' )
                val = 1;
            else if ( config[i][j] == '0' )
                val = 0;
            else if ( config[i][j] == 'x' )
                val = polval;

            if ( val )
                set_bit(31 - j, regs[i]);
            else
                clear_bit(31 - j, regs[i]);

            config_transformed[i][j] = config[i][j];
            if ( config[i][j] == 's' )
                config_transformed[i][j] = '0' + val;
        }
    }

    rc = xc_cpuid_do_domctl(xch, domid, input, regs);
    if ( rc == 0 )
        return 0;

 fail:
    for ( i = 0; i < 4; i++ )
    {
        free(config_transformed[i]);
        config_transformed[i] = NULL;
    }
    return rc;
}
