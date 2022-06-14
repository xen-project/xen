/******************************************************************************
 * arch/x86/spec_ctrl.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017-2018 Citrix Systems Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/warning.h>

#include <asm/hvm/svm/svm.h>
#include <asm/microcode.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/pv/domain.h>
#include <asm/pv/shim.h>
#include <asm/setup.h>
#include <asm/spec_ctrl.h>
#include <asm/spec_ctrl_asm.h>

/* Cmdline controls for Xen's alternative blocks. */
static bool __initdata opt_msr_sc_pv = true;
static bool __initdata opt_msr_sc_hvm = true;
static bool __initdata opt_rsb_pv = true;
static bool __initdata opt_rsb_hvm = true;
static int8_t __read_mostly opt_md_clear_pv = -1;
static int8_t __read_mostly opt_md_clear_hvm = -1;

static int8_t __read_mostly opt_ibpb_entry_pv = -1;
static int8_t __read_mostly opt_ibpb_entry_hvm = -1;
static bool __read_mostly opt_ibpb_entry_dom0;

/* Cmdline controls for Xen's speculative settings. */
static enum ind_thunk {
    THUNK_DEFAULT, /* Decide which thunk to use at boot time. */
    THUNK_NONE,    /* Missing compiler support for thunks. */

    THUNK_RETPOLINE,
    THUNK_LFENCE,
    THUNK_JMP,
} opt_thunk __initdata = THUNK_DEFAULT;

static int8_t __initdata opt_ibrs = -1;
int8_t __initdata opt_stibp = -1;
bool __read_mostly opt_ssbd;
int8_t __initdata opt_psfd = -1;

int8_t __read_mostly opt_ibpb_ctxt_switch = -1;
int8_t __read_mostly opt_eager_fpu = -1;
int8_t __read_mostly opt_l1d_flush = -1;
bool __read_mostly opt_branch_harden = true;

bool __initdata bsp_delay_spec_ctrl;
uint8_t __read_mostly default_xen_spec_ctrl;
uint8_t __read_mostly default_spec_ctrl_flags;

paddr_t __read_mostly l1tf_addr_mask, __read_mostly l1tf_safe_maddr;
static bool __initdata cpu_has_bug_l1tf;
static unsigned int __initdata l1d_maxphysaddr;

static bool __initdata cpu_has_bug_msbds_only; /* => minimal HT impact. */
static bool __initdata cpu_has_bug_mds; /* Any other M{LP,SB,FB}DS combination. */

static int8_t __initdata opt_srb_lock = -1;
uint64_t __read_mostly default_xen_mcu_opt_ctrl;
static bool __initdata opt_unpriv_mmio;
static bool __read_mostly opt_fb_clear_mmio;

static int __init parse_spec_ctrl(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        /* Global and Xen-wide disable. */
        val = parse_bool(s, ss);
        if ( !val )
        {
            opt_msr_sc_pv = false;
            opt_msr_sc_hvm = false;

            opt_eager_fpu = 0;

            if ( opt_xpti_hwdom < 0 )
                opt_xpti_hwdom = 0;
            if ( opt_xpti_domu < 0 )
                opt_xpti_domu = 0;

            if ( opt_smt < 0 )
                opt_smt = 1;

            if ( opt_pv_l1tf_hwdom < 0 )
                opt_pv_l1tf_hwdom = 0;
            if ( opt_pv_l1tf_domu < 0 )
                opt_pv_l1tf_domu = 0;

            if ( opt_tsx == -1 )
                opt_tsx = -3;

        disable_common:
            opt_rsb_pv = false;
            opt_rsb_hvm = false;
            opt_md_clear_pv = 0;
            opt_md_clear_hvm = 0;
            opt_ibpb_entry_pv = 0;
            opt_ibpb_entry_hvm = 0;
            opt_ibpb_entry_dom0 = false;

            opt_thunk = THUNK_JMP;
            opt_ibrs = 0;
            opt_ibpb_ctxt_switch = false;
            opt_ssbd = false;
            opt_l1d_flush = 0;
            opt_branch_harden = false;
            opt_srb_lock = 0;
            opt_unpriv_mmio = false;
        }
        else if ( val > 0 )
            rc = -EINVAL;
        else if ( (val = parse_boolean("xen", s, ss)) >= 0 )
        {
            if ( !val )
                goto disable_common;

            rc = -EINVAL;
        }

        /* Xen's alternative blocks. */
        else if ( (val = parse_boolean("pv", s, ss)) >= 0 )
        {
            opt_msr_sc_pv = val;
            opt_rsb_pv = val;
            opt_md_clear_pv = val;
            opt_ibpb_entry_pv = val;
        }
        else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
        {
            opt_msr_sc_hvm = val;
            opt_rsb_hvm = val;
            opt_md_clear_hvm = val;
            opt_ibpb_entry_hvm = val;
        }
        else if ( (val = parse_boolean("msr-sc", s, ss)) != -1 )
        {
            switch ( val )
            {
            case 0:
            case 1:
                opt_msr_sc_pv = opt_msr_sc_hvm = val;
                break;

            case -2:
                s += strlen("msr-sc=");
                if ( (val = parse_boolean("pv", s, ss)) >= 0 )
                    opt_msr_sc_pv = val;
                else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
                    opt_msr_sc_hvm = val;
                else
            default:
                    rc = -EINVAL;
                break;
            }
        }
        else if ( (val = parse_boolean("rsb", s, ss)) != -1 )
        {
            switch ( val )
            {
            case 0:
            case 1:
                opt_rsb_pv = opt_rsb_hvm = val;
                break;

            case -2:
                s += strlen("rsb=");
                if ( (val = parse_boolean("pv", s, ss)) >= 0 )
                    opt_rsb_pv = val;
                else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
                    opt_rsb_hvm = val;
                else
            default:
                    rc = -EINVAL;
                break;
            }
        }
        else if ( (val = parse_boolean("md-clear", s, ss)) != -1 )
        {
            switch ( val )
            {
            case 0:
            case 1:
                opt_md_clear_pv = opt_md_clear_hvm = val;
                break;

            case -2:
                s += strlen("md-clear=");
                if ( (val = parse_boolean("pv", s, ss)) >= 0 )
                    opt_md_clear_pv = val;
                else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
                    opt_md_clear_hvm = val;
                else
            default:
                    rc = -EINVAL;
                break;
            }
        }
        else if ( (val = parse_boolean("ibpb-entry", s, ss)) != -1 )
        {
            switch ( val )
            {
            case 0:
            case 1:
                opt_ibpb_entry_pv = opt_ibpb_entry_hvm =
                    opt_ibpb_entry_dom0 = val;
                break;

            case -2:
                s += strlen("ibpb-entry=");
                if ( (val = parse_boolean("pv", s, ss)) >= 0 )
                    opt_ibpb_entry_pv = val;
                else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
                    opt_ibpb_entry_hvm = val;
                else
            default:
                    rc = -EINVAL;
                break;
            }
        }

        /* Xen's speculative sidechannel mitigation settings. */
        else if ( !strncmp(s, "bti-thunk=", 10) )
        {
            s += 10;

            if ( !cmdline_strcmp(s, "retpoline") )
                opt_thunk = THUNK_RETPOLINE;
            else if ( !cmdline_strcmp(s, "lfence") )
                opt_thunk = THUNK_LFENCE;
            else if ( !cmdline_strcmp(s, "jmp") )
                opt_thunk = THUNK_JMP;
            else
                rc = -EINVAL;
        }

        /* Bits in MSR_SPEC_CTRL. */
        else if ( (val = parse_boolean("ibrs", s, ss)) >= 0 )
            opt_ibrs = val;
        else if ( (val = parse_boolean("stibp", s, ss)) >= 0 )
            opt_stibp = val;
        else if ( (val = parse_boolean("ssbd", s, ss)) >= 0 )
            opt_ssbd = val;
        else if ( (val = parse_boolean("psfd", s, ss)) >= 0 )
            opt_psfd = val;

        /* Misc settings. */
        else if ( (val = parse_boolean("ibpb", s, ss)) >= 0 )
            opt_ibpb_ctxt_switch = val;
        else if ( (val = parse_boolean("eager-fpu", s, ss)) >= 0 )
            opt_eager_fpu = val;
        else if ( (val = parse_boolean("l1d-flush", s, ss)) >= 0 )
            opt_l1d_flush = val;
        else if ( (val = parse_boolean("branch-harden", s, ss)) >= 0 )
            opt_branch_harden = val;
        else if ( (val = parse_boolean("srb-lock", s, ss)) >= 0 )
            opt_srb_lock = val;
        else if ( (val = parse_boolean("unpriv-mmio", s, ss)) >= 0 )
            opt_unpriv_mmio = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("spec-ctrl", parse_spec_ctrl);

int8_t __read_mostly opt_xpti_hwdom = -1;
int8_t __read_mostly opt_xpti_domu = -1;

static __init void xpti_init_default(uint64_t caps)
{
    if ( boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON) )
        caps = ARCH_CAPS_RDCL_NO;

    if ( caps & ARCH_CAPS_RDCL_NO )
    {
        if ( opt_xpti_hwdom < 0 )
            opt_xpti_hwdom = 0;
        if ( opt_xpti_domu < 0 )
            opt_xpti_domu = 0;
    }
    else
    {
        if ( opt_xpti_hwdom < 0 )
            opt_xpti_hwdom = 1;
        if ( opt_xpti_domu < 0 )
            opt_xpti_domu = 1;
    }
}

static __init int parse_xpti(const char *s)
{
    const char *ss;
    int val, rc = 0;

    /* Interpret 'xpti' alone in its positive boolean form. */
    if ( *s == '\0' )
        opt_xpti_hwdom = opt_xpti_domu = 1;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        switch ( parse_bool(s, ss) )
        {
        case 0:
            opt_xpti_hwdom = opt_xpti_domu = 0;
            break;

        case 1:
            opt_xpti_hwdom = opt_xpti_domu = 1;
            break;

        default:
            if ( !strcmp(s, "default") )
                opt_xpti_hwdom = opt_xpti_domu = -1;
            else if ( (val = parse_boolean("dom0", s, ss)) >= 0 )
                opt_xpti_hwdom = val;
            else if ( (val = parse_boolean("domu", s, ss)) >= 0 )
                opt_xpti_domu = val;
            else if ( *s )
                rc = -EINVAL;
            break;
        }

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("xpti", parse_xpti);

int8_t __read_mostly opt_pv_l1tf_hwdom = -1;
int8_t __read_mostly opt_pv_l1tf_domu = -1;

static __init int parse_pv_l1tf(const char *s)
{
    const char *ss;
    int val, rc = 0;

    /* Interpret 'pv-l1tf' alone in its positive boolean form. */
    if ( *s == '\0' )
        opt_pv_l1tf_hwdom = opt_pv_l1tf_domu = 1;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        switch ( parse_bool(s, ss) )
        {
        case 0:
            opt_pv_l1tf_hwdom = opt_pv_l1tf_domu = 0;
            break;

        case 1:
            opt_pv_l1tf_hwdom = opt_pv_l1tf_domu = 1;
            break;

        default:
            if ( (val = parse_boolean("dom0", s, ss)) >= 0 )
                opt_pv_l1tf_hwdom = val;
            else if ( (val = parse_boolean("domu", s, ss)) >= 0 )
                opt_pv_l1tf_domu = val;
            else if ( *s )
                rc = -EINVAL;
            break;
        }

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("pv-l1tf", parse_pv_l1tf);

static void __init print_details(enum ind_thunk thunk, uint64_t caps)
{
    unsigned int _7d0 = 0, e8b = 0, tmp;

    /* Collect diagnostics about available mitigations. */
    if ( boot_cpu_data.cpuid_level >= 7 )
        cpuid_count(7, 0, &tmp, &tmp, &tmp, &_7d0);
    if ( boot_cpu_data.extended_cpuid_level >= 0x80000008 )
        cpuid(0x80000008, &tmp, &e8b, &tmp, &tmp);

    printk("Speculative mitigation facilities:\n");

    /*
     * Hardware read-only information, stating immunity to certain issues, or
     * suggestions of which mitigation to use.
     */
    printk("  Hardware hints:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
           (caps & ARCH_CAPS_RDCL_NO)                        ? " RDCL_NO"        : "",
           (caps & ARCH_CAPS_IBRS_ALL)                       ? " IBRS_ALL"       : "",
           (caps & ARCH_CAPS_RSBA)                           ? " RSBA"           : "",
           (caps & ARCH_CAPS_SKIP_L1DFL)                     ? " SKIP_L1DFL"     : "",
           (e8b  & cpufeat_mask(X86_FEATURE_SSB_NO)) ||
           (caps & ARCH_CAPS_SSB_NO)                         ? " SSB_NO"         : "",
           (caps & ARCH_CAPS_MDS_NO)                         ? " MDS_NO"         : "",
           (caps & ARCH_CAPS_TAA_NO)                         ? " TAA_NO"         : "",
           (caps & ARCH_CAPS_SBDR_SSDP_NO)                   ? " SBDR_SSDP_NO"   : "",
           (caps & ARCH_CAPS_FBSDP_NO)                       ? " FBSDP_NO"       : "",
           (caps & ARCH_CAPS_PSDP_NO)                        ? " PSDP_NO"        : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBRS_ALWAYS))    ? " IBRS_ALWAYS"    : "",
           (e8b  & cpufeat_mask(X86_FEATURE_STIBP_ALWAYS))   ? " STIBP_ALWAYS"   : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBRS_FAST))      ? " IBRS_FAST"      : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBRS_SAME_MODE)) ? " IBRS_SAME_MODE" : "",
           (e8b  & cpufeat_mask(X86_FEATURE_BTC_NO))         ? " BTC_NO"         : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBPB_RET))       ? " IBPB_RET"       : "");

    /* Hardware features which need driving to mitigate issues. */
    printk("  Hardware features:%s%s%s%s%s%s%s%s%s%s%s%s\n",
           (e8b  & cpufeat_mask(X86_FEATURE_IBPB)) ||
           (_7d0 & cpufeat_mask(X86_FEATURE_IBRSB))          ? " IBPB"           : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBRS)) ||
           (_7d0 & cpufeat_mask(X86_FEATURE_IBRSB))          ? " IBRS"           : "",
           (e8b  & cpufeat_mask(X86_FEATURE_AMD_STIBP)) ||
           (_7d0 & cpufeat_mask(X86_FEATURE_STIBP))          ? " STIBP"          : "",
           (e8b  & cpufeat_mask(X86_FEATURE_AMD_SSBD)) ||
           (_7d0 & cpufeat_mask(X86_FEATURE_SSBD))           ? " SSBD"           : "",
           (e8b  & cpufeat_mask(X86_FEATURE_PSFD))           ? " PSFD"           : "",
           (_7d0 & cpufeat_mask(X86_FEATURE_L1D_FLUSH))      ? " L1D_FLUSH"      : "",
           (_7d0 & cpufeat_mask(X86_FEATURE_MD_CLEAR))       ? " MD_CLEAR"       : "",
           (_7d0 & cpufeat_mask(X86_FEATURE_SRBDS_CTRL))     ? " SRBDS_CTRL"     : "",
           (e8b  & cpufeat_mask(X86_FEATURE_VIRT_SSBD))      ? " VIRT_SSBD"      : "",
           (caps & ARCH_CAPS_TSX_CTRL)                       ? " TSX_CTRL"       : "",
           (caps & ARCH_CAPS_FB_CLEAR)                       ? " FB_CLEAR"       : "",
           (caps & ARCH_CAPS_FB_CLEAR_CTRL)                  ? " FB_CLEAR_CTRL"  : "");

    /* Compiled-in support which pertains to mitigations. */
    if ( IS_ENABLED(CONFIG_INDIRECT_THUNK) || IS_ENABLED(CONFIG_SHADOW_PAGING) )
        printk("  Compiled-in support:"
#ifdef CONFIG_INDIRECT_THUNK
               " INDIRECT_THUNK"
#endif
#ifdef CONFIG_SHADOW_PAGING
               " SHADOW_PAGING"
#endif
               "\n");

    /* Settings for Xen's protection, irrespective of guests. */
    printk("  Xen settings: BTI-Thunk %s, SPEC_CTRL: %s%s%s%s%s, Other:%s%s%s%s%s\n",
           thunk == THUNK_NONE      ? "N/A" :
           thunk == THUNK_RETPOLINE ? "RETPOLINE" :
           thunk == THUNK_LFENCE    ? "LFENCE" :
           thunk == THUNK_JMP       ? "JMP" : "?",
           (!boot_cpu_has(X86_FEATURE_IBRSB) &&
            !boot_cpu_has(X86_FEATURE_IBRS))         ? "No" :
           (default_xen_spec_ctrl & SPEC_CTRL_IBRS)  ? "IBRS+" :  "IBRS-",
           (!boot_cpu_has(X86_FEATURE_STIBP) &&
            !boot_cpu_has(X86_FEATURE_AMD_STIBP))    ? "" :
           (default_xen_spec_ctrl & SPEC_CTRL_STIBP) ? " STIBP+" : " STIBP-",
           (!boot_cpu_has(X86_FEATURE_SSBD) &&
            !boot_cpu_has(X86_FEATURE_AMD_SSBD))     ? "" :
           (default_xen_spec_ctrl & SPEC_CTRL_SSBD)  ? " SSBD+" : " SSBD-",
           !boot_cpu_has(X86_FEATURE_PSFD) &&
           (default_xen_spec_ctrl & SPEC_CTRL_PSFD)  ? " PSFD+" : " PSFD-",
           !(caps & ARCH_CAPS_TSX_CTRL)              ? "" :
           (opt_tsx & 1)                             ? " TSX+" : " TSX-",
           !boot_cpu_has(X86_FEATURE_SRBDS_CTRL)     ? "" :
           opt_srb_lock                              ? " SRB_LOCK+" : " SRB_LOCK-",
           opt_ibpb_ctxt_switch                      ? " IBPB-ctxt" : "",
           opt_l1d_flush                             ? " L1D_FLUSH" : "",
           opt_md_clear_pv || opt_md_clear_hvm ||
           opt_fb_clear_mmio                         ? " VERW"  : "",
           opt_branch_harden                         ? " BRANCH_HARDEN" : "");

    /* L1TF diagnostics, printed if vulnerable or PV shadowing is in use. */
    if ( cpu_has_bug_l1tf || opt_pv_l1tf_hwdom || opt_pv_l1tf_domu )
        printk("  L1TF: believed%s vulnerable, maxphysaddr L1D %u, CPUID %u"
               ", Safe address %"PRIx64"\n",
               cpu_has_bug_l1tf ? "" : " not",
               l1d_maxphysaddr, paddr_bits, l1tf_safe_maddr);

    /*
     * Alternatives blocks for protecting against and/or virtualising
     * mitigation support for guests.
     */
#ifdef CONFIG_HVM
    printk("  Support for HVM VMs:%s%s%s%s%s%s\n",
           (boot_cpu_has(X86_FEATURE_SC_MSR_HVM) ||
            boot_cpu_has(X86_FEATURE_SC_RSB_HVM) ||
            boot_cpu_has(X86_FEATURE_MD_CLEAR)   ||
            boot_cpu_has(X86_FEATURE_IBPB_ENTRY_HVM) ||
            opt_eager_fpu)                           ? ""               : " None",
           boot_cpu_has(X86_FEATURE_SC_MSR_HVM)      ? " MSR_SPEC_CTRL" : "",
           boot_cpu_has(X86_FEATURE_SC_RSB_HVM)      ? " RSB"           : "",
           opt_eager_fpu                             ? " EAGER_FPU"     : "",
           boot_cpu_has(X86_FEATURE_MD_CLEAR)        ? " MD_CLEAR"      : "",
           boot_cpu_has(X86_FEATURE_IBPB_ENTRY_HVM)  ? " IBPB-entry"    : "");

#endif
#ifdef CONFIG_PV
    printk("  Support for PV VMs:%s%s%s%s%s%s\n",
           (boot_cpu_has(X86_FEATURE_SC_MSR_PV) ||
            boot_cpu_has(X86_FEATURE_SC_RSB_PV) ||
            boot_cpu_has(X86_FEATURE_MD_CLEAR)  ||
            boot_cpu_has(X86_FEATURE_IBPB_ENTRY_PV) ||
            opt_eager_fpu)                           ? ""               : " None",
           boot_cpu_has(X86_FEATURE_SC_MSR_PV)       ? " MSR_SPEC_CTRL" : "",
           boot_cpu_has(X86_FEATURE_SC_RSB_PV)       ? " RSB"           : "",
           opt_eager_fpu                             ? " EAGER_FPU"     : "",
           boot_cpu_has(X86_FEATURE_MD_CLEAR)        ? " MD_CLEAR"      : "",
           boot_cpu_has(X86_FEATURE_IBPB_ENTRY_PV)   ? " IBPB-entry"    : "");

    printk("  XPTI (64-bit PV only): Dom0 %s, DomU %s (with%s PCID)\n",
           opt_xpti_hwdom ? "enabled" : "disabled",
           opt_xpti_domu  ? "enabled" : "disabled",
           xpti_pcid_enabled() ? "" : "out");

    printk("  PV L1TF shadowing: Dom0 %s, DomU %s\n",
           opt_pv_l1tf_hwdom ? "enabled"  : "disabled",
           opt_pv_l1tf_domu  ? "enabled"  : "disabled");
#endif
}

static bool __init check_smt_enabled(void)
{
    uint64_t val;
    unsigned int cpu;

    /*
     * x86_num_siblings defaults to 1 in the absence of other information, and
     * is adjusted based on other topology information found in CPUID leaves.
     *
     * On AMD hardware, it will be the current SMT configuration.  On Intel
     * hardware, it will represent the maximum capability, rather than the
     * current configuration.
     */
    if ( boot_cpu_data.x86_num_siblings < 2 )
        return false;

    /*
     * Intel Nehalem and later hardware does have an MSR which reports the
     * current count of cores/threads in the package.
     *
     * At the time of writing, it is almost completely undocumented, so isn't
     * virtualised reliably.
     */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL && !cpu_has_hypervisor &&
         !rdmsr_safe(MSR_INTEL_CORE_THREAD_COUNT, val) )
        return (MASK_EXTR(val, MSR_CTC_CORE_MASK) !=
                MASK_EXTR(val, MSR_CTC_THREAD_MASK));

    /*
     * Search over the CPUs reported in the ACPI tables.  Any whose APIC ID
     * has a non-zero thread id component indicates that SMT is active.
     */
    for_each_present_cpu ( cpu )
        if ( x86_cpu_to_apicid[cpu] & (boot_cpu_data.x86_num_siblings - 1) )
            return true;

    return false;
}

/* Calculate whether Retpoline is known-safe on this CPU. */
static bool __init retpoline_safe(uint64_t caps)
{
    unsigned int ucode_rev = this_cpu(cpu_sig).rev;

    if ( boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON) )
        return true;

    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return false;

    /*
     * RSBA may be set by a hypervisor to indicate that we may move to a
     * processor which isn't retpoline-safe.
     *
     * Processors offering Enhanced IBRS are not guarenteed to be
     * repoline-safe.
     */
    if ( caps & (ARCH_CAPS_RSBA | ARCH_CAPS_IBRS_ALL) )
        return false;

    switch ( boot_cpu_data.x86_model )
    {
    case 0x17: /* Penryn */
    case 0x1d: /* Dunnington */
    case 0x1e: /* Nehalem */
    case 0x1f: /* Auburndale / Havendale */
    case 0x1a: /* Nehalem EP */
    case 0x2e: /* Nehalem EX */
    case 0x25: /* Westmere */
    case 0x2c: /* Westmere EP */
    case 0x2f: /* Westmere EX */
    case 0x2a: /* SandyBridge */
    case 0x2d: /* SandyBridge EP/EX */
    case 0x3a: /* IvyBridge */
    case 0x3e: /* IvyBridge EP/EX */
    case 0x3c: /* Haswell */
    case 0x3f: /* Haswell EX/EP */
    case 0x45: /* Haswell D */
    case 0x46: /* Haswell H */
        return true;

        /*
         * Broadwell processors are retpoline-safe after specific microcode
         * versions.
         */
    case 0x3d: /* Broadwell */
        return ucode_rev >= 0x2a;
    case 0x47: /* Broadwell H */
        return ucode_rev >= 0x1d;
    case 0x4f: /* Broadwell EP/EX */
        return ucode_rev >= 0xb000021;
    case 0x56: /* Broadwell D */
        switch ( boot_cpu_data.x86_mask )
        {
        case 2:  return ucode_rev >= 0x15;
        case 3:  return ucode_rev >= 0x7000012;
        case 4:  return ucode_rev >= 0xf000011;
        case 5:  return ucode_rev >= 0xe000009;
        default:
            printk("Unrecognised CPU stepping %#x - assuming not reptpoline safe\n",
                   boot_cpu_data.x86_mask);
            return false;
        }
        break;

        /*
         * Skylake, Kabylake and Cannonlake processors are not retpoline-safe.
         */
    case 0x4e: /* Skylake M */
    case 0x55: /* Skylake X */
    case 0x5e: /* Skylake D */
    case 0x66: /* Cannonlake */
    case 0x67: /* Cannonlake? */
    case 0x8e: /* Kabylake M */
    case 0x9e: /* Kabylake D */
        return false;

        /*
         * Atom processors before Goldmont Plus/Gemini Lake are retpoline-safe.
         */
    case 0x1c: /* Pineview */
    case 0x26: /* Lincroft */
    case 0x27: /* Penwell */
    case 0x35: /* Cloverview */
    case 0x36: /* Cedarview */
    case 0x37: /* Baytrail / Valleyview (Silvermont) */
    case 0x4d: /* Avaton / Rangely (Silvermont) */
    case 0x4c: /* Cherrytrail / Brasswell */
    case 0x4a: /* Merrifield */
    case 0x57: /* Knights Landing */
    case 0x5a: /* Moorefield */
    case 0x5c: /* Goldmont */
    case 0x5f: /* Denverton */
    case 0x85: /* Knights Mill */
        return true;

    default:
        printk("Unrecognised CPU model %#x - assuming not reptpoline safe\n",
               boot_cpu_data.x86_model);
        return false;
    }
}

/* Calculate whether this CPU speculates past #NM */
static bool __init should_use_eager_fpu(void)
{
    /*
     * Assume all unrecognised processors are ok.  This is only known to
     * affect Intel Family 6 processors.
     */
    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return false;

    switch ( boot_cpu_data.x86_model )
    {
        /*
         * Core processors since at least Nehalem are vulnerable.
         */
    case 0x1e: /* Nehalem */
    case 0x1f: /* Auburndale / Havendale */
    case 0x1a: /* Nehalem EP */
    case 0x2e: /* Nehalem EX */
    case 0x25: /* Westmere */
    case 0x2c: /* Westmere EP */
    case 0x2f: /* Westmere EX */
    case 0x2a: /* SandyBridge */
    case 0x2d: /* SandyBridge EP/EX */
    case 0x3a: /* IvyBridge */
    case 0x3e: /* IvyBridge EP/EX */
    case 0x3c: /* Haswell */
    case 0x3f: /* Haswell EX/EP */
    case 0x45: /* Haswell D */
    case 0x46: /* Haswell H */
    case 0x3d: /* Broadwell */
    case 0x47: /* Broadwell H */
    case 0x4f: /* Broadwell EP/EX */
    case 0x56: /* Broadwell D */
    case 0x4e: /* Skylake M */
    case 0x55: /* Skylake X */
    case 0x5e: /* Skylake D */
    case 0x66: /* Cannonlake */
    case 0x67: /* Cannonlake? */
    case 0x8e: /* Kabylake M */
    case 0x9e: /* Kabylake D */
        return true;

        /*
         * Atom processors are not vulnerable.
         */
    case 0x1c: /* Pineview */
    case 0x26: /* Lincroft */
    case 0x27: /* Penwell */
    case 0x35: /* Cloverview */
    case 0x36: /* Cedarview */
    case 0x37: /* Baytrail / Valleyview (Silvermont) */
    case 0x4d: /* Avaton / Rangely (Silvermont) */
    case 0x4c: /* Cherrytrail / Brasswell */
    case 0x4a: /* Merrifield */
    case 0x5a: /* Moorefield */
    case 0x5c: /* Goldmont */
    case 0x5f: /* Denverton */
    case 0x7a: /* Gemini Lake */
        return false;

        /*
         * Knights processors are not vulnerable.
         */
    case 0x57: /* Knights Landing */
    case 0x85: /* Knights Mill */
        return false;

    default:
        printk("Unrecognised CPU model %#x - assuming vulnerable to LazyFPU\n",
               boot_cpu_data.x86_model);
        return true;
    }
}

static void __init ibpb_calculations(void)
{
    /* Check we have hardware IBPB support before using it... */
    if ( !boot_cpu_has(X86_FEATURE_IBRSB) && !boot_cpu_has(X86_FEATURE_IBPB) )
    {
        opt_ibpb_entry_hvm = opt_ibpb_entry_pv = opt_ibpb_ctxt_switch = 0;
        opt_ibpb_entry_dom0 = false;
        return;
    }

    /*
     * AMD/Hygon CPUs to date (June 2022) don't flush the the RAS.  Future
     * CPUs are expected to enumerate IBPB_RET when this has been fixed.
     * Until then, cover the difference with the software sequence.
     */
    if ( boot_cpu_has(X86_FEATURE_IBPB) && !boot_cpu_has(X86_FEATURE_IBPB_RET) )
        setup_force_cpu_cap(X86_BUG_IBPB_NO_RET);

    /*
     * IBPB-on-entry mitigations for Branch Type Confusion.
     *
     * IBPB && !BTC_NO selects all AMD/Hygon hardware, not known to be safe,
     * that we can provide some form of mitigation on.
     */
    if ( opt_ibpb_entry_pv == -1 )
        opt_ibpb_entry_pv = (IS_ENABLED(CONFIG_PV) &&
                             boot_cpu_has(X86_FEATURE_IBPB) &&
                             !boot_cpu_has(X86_FEATURE_BTC_NO));
    if ( opt_ibpb_entry_hvm == -1 )
        opt_ibpb_entry_hvm = (IS_ENABLED(CONFIG_HVM) &&
                              boot_cpu_has(X86_FEATURE_IBPB) &&
                              !boot_cpu_has(X86_FEATURE_BTC_NO));

    if ( opt_ibpb_entry_pv )
    {
        setup_force_cpu_cap(X86_FEATURE_IBPB_ENTRY_PV);

        /*
         * We only need to flush in IST context if we're protecting against PV
         * guests.  HVM IBPB-on-entry protections are both atomic with
         * NMI/#MC, so can't interrupt Xen ahead of having already flushed the
         * BTB.
         */
        default_spec_ctrl_flags |= SCF_ist_ibpb;
    }
    if ( opt_ibpb_entry_hvm )
        setup_force_cpu_cap(X86_FEATURE_IBPB_ENTRY_HVM);

    /*
     * If we're using IBPB-on-entry to protect against PV and HVM guests
     * (ignoring dom0 if trusted), then there's no need to also issue IBPB on
     * context switch too.
     */
    if ( opt_ibpb_ctxt_switch == -1 )
        opt_ibpb_ctxt_switch = !(opt_ibpb_entry_hvm && opt_ibpb_entry_pv);
}

/* Calculate whether this CPU is vulnerable to L1TF. */
static __init void l1tf_calculations(uint64_t caps)
{
    bool hit_default = false;

    l1d_maxphysaddr = paddr_bits;

    /* L1TF is only known to affect Intel Family 6 processors at this time. */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
         boot_cpu_data.x86 == 6 )
    {
        switch ( boot_cpu_data.x86_model )
        {
            /*
             * Core processors since at least Penryn are vulnerable.
             */
        case 0x17: /* Penryn */
        case 0x1d: /* Dunnington */
            cpu_has_bug_l1tf = true;
            break;

        case 0x1f: /* Auburndale / Havendale */
        case 0x1e: /* Nehalem */
        case 0x1a: /* Nehalem EP */
        case 0x2e: /* Nehalem EX */
        case 0x25: /* Westmere */
        case 0x2c: /* Westmere EP */
        case 0x2f: /* Westmere EX */
            cpu_has_bug_l1tf = true;
            l1d_maxphysaddr = 44;
            break;

        case 0x2a: /* SandyBridge */
        case 0x2d: /* SandyBridge EP/EX */
        case 0x3a: /* IvyBridge */
        case 0x3e: /* IvyBridge EP/EX */
        case 0x3c: /* Haswell */
        case 0x3f: /* Haswell EX/EP */
        case 0x45: /* Haswell D */
        case 0x46: /* Haswell H */
        case 0x3d: /* Broadwell */
        case 0x47: /* Broadwell H */
        case 0x4f: /* Broadwell EP/EX */
        case 0x56: /* Broadwell D */
        case 0x4e: /* Skylake M */
        case 0x55: /* Skylake X */
        case 0x5e: /* Skylake D */
        case 0x66: /* Cannonlake */
        case 0x67: /* Cannonlake? */
        case 0x8e: /* Kabylake M */
        case 0x9e: /* Kabylake D */
            cpu_has_bug_l1tf = true;
            l1d_maxphysaddr = 46;
            break;

            /*
             * Atom processors are not vulnerable.
             */
        case 0x1c: /* Pineview */
        case 0x26: /* Lincroft */
        case 0x27: /* Penwell */
        case 0x35: /* Cloverview */
        case 0x36: /* Cedarview */
        case 0x37: /* Baytrail / Valleyview (Silvermont) */
        case 0x4d: /* Avaton / Rangely (Silvermont) */
        case 0x4c: /* Cherrytrail / Brasswell */
        case 0x4a: /* Merrifield */
        case 0x5a: /* Moorefield */
        case 0x5c: /* Goldmont */
        case 0x5f: /* Denverton */
        case 0x7a: /* Gemini Lake */
            break;

            /*
             * Knights processors are not vulnerable.
             */
        case 0x57: /* Knights Landing */
        case 0x85: /* Knights Mill */
            break;

        default:
            /* Defer printk() until we've accounted for RDCL_NO. */
            hit_default = true;
            cpu_has_bug_l1tf = true;
            break;
        }
    }

    /* Any processor advertising RDCL_NO should be not vulnerable to L1TF. */
    if ( caps & ARCH_CAPS_RDCL_NO )
        cpu_has_bug_l1tf = false;

    if ( cpu_has_bug_l1tf && hit_default )
        printk("Unrecognised CPU model %#x - assuming vulnerable to L1TF\n",
               boot_cpu_data.x86_model);

    /*
     * L1TF safe address heuristics.  These apply to the real hardware we are
     * running on, and are best-effort-only if Xen is virtualised.
     *
     * The address mask which the L1D cache uses, which might be wider than
     * the CPUID-reported maxphysaddr.
     */
    l1tf_addr_mask = ((1ul << l1d_maxphysaddr) - 1) & PAGE_MASK;

    /*
     * To be safe, l1tf_safe_maddr must be above the highest cacheable entity
     * in system physical address space.  However, to preserve space for
     * paged-out metadata, it should be as low as possible above the highest
     * cacheable address, so as to require fewer high-order bits being set.
     *
     * These heuristics are based on some guesswork to improve the likelihood
     * of safety in the common case, including Linux's L1TF mitigation of
     * inverting all address bits in a non-present PTE.
     *
     * - If L1D is wider than CPUID (Nehalem and later mobile/desktop/low end
     *   server), setting any address bit beyond CPUID maxphysaddr guarantees
     *   to make the PTE safe.  This case doesn't require all the high-order
     *   bits being set, and doesn't require any other source of information
     *   for safety.
     *
     * - If L1D is the same as CPUID (Pre-Nehalem, or high end server), we
     *   must sacrifice high order bits from the real address space for
     *   safety.  Therefore, make a blind guess that there is nothing
     *   cacheable in the top quarter of physical address space.
     *
     *   It is exceedingly unlikely for machines to be populated with this
     *   much RAM (likely 512G on pre-Nehalem, 16T on Nehalem/Westmere, 64T on
     *   Sandybridge and later) due to the sheer volume of DIMMs this would
     *   actually take.
     *
     *   However, it is possible to find machines this large, so the "top
     *   quarter" guess is supplemented to push the limit higher if references
     *   to cacheable mappings (E820/SRAT/EFI/etc) are found above the top
     *   quarter boundary.
     *
     *   Finally, this top quarter guess gives us a good chance of being safe
     *   when running virtualised (and the CPUID maxphysaddr hasn't been
     *   levelled for heterogeneous migration safety), where the safety
     *   consideration is still in terms of host details, but all E820/etc
     *   information is in terms of guest physical layout.
     */
    l1tf_safe_maddr = max(l1tf_safe_maddr, ((l1d_maxphysaddr > paddr_bits)
                                            ? (1ul << paddr_bits)
                                            : (3ul << (paddr_bits - 2))));
}

/* Calculate whether this CPU is vulnerable to MDS. */
static __init void mds_calculations(uint64_t caps)
{
    /* MDS is only known to affect Intel Family 6 processors at this time. */
    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return;

    /* Any processor advertising MDS_NO should be not vulnerable to MDS. */
    if ( caps & ARCH_CAPS_MDS_NO )
        return;

    switch ( boot_cpu_data.x86_model )
    {
        /*
         * Core processors since at least Nehalem are vulnerable.
         */
    case 0x1f: /* Auburndale / Havendale */
    case 0x1e: /* Nehalem */
    case 0x1a: /* Nehalem EP */
    case 0x2e: /* Nehalem EX */
    case 0x25: /* Westmere */
    case 0x2c: /* Westmere EP */
    case 0x2f: /* Westmere EX */
    case 0x2a: /* SandyBridge */
    case 0x2d: /* SandyBridge EP/EX */
    case 0x3a: /* IvyBridge */
    case 0x3e: /* IvyBridge EP/EX */
    case 0x3c: /* Haswell */
    case 0x3f: /* Haswell EX/EP */
    case 0x45: /* Haswell D */
    case 0x46: /* Haswell H */
    case 0x3d: /* Broadwell */
    case 0x47: /* Broadwell H */
    case 0x4f: /* Broadwell EP/EX */
    case 0x56: /* Broadwell D */
    case 0x4e: /* Skylake M */
    case 0x5e: /* Skylake D */
        cpu_has_bug_mds = true;
        break;

        /*
         * Some Core processors have per-stepping vulnerability.
         */
    case 0x55: /* Skylake-X / Cascade Lake */
        if ( boot_cpu_data.x86_mask <= 5 )
            cpu_has_bug_mds = true;
        break;

    case 0x8e: /* Kaby / Coffee / Whiskey Lake M */
        if ( boot_cpu_data.x86_mask <= 0xb )
            cpu_has_bug_mds = true;
        break;

    case 0x9e: /* Kaby / Coffee / Whiskey Lake D */
        if ( boot_cpu_data.x86_mask <= 0xc )
            cpu_has_bug_mds = true;
        break;

        /*
         * Very old and very new Atom processors are not vulnerable.
         */
    case 0x1c: /* Pineview */
    case 0x26: /* Lincroft */
    case 0x27: /* Penwell */
    case 0x35: /* Cloverview */
    case 0x36: /* Cedarview */
    case 0x7a: /* Goldmont */
        break;

        /*
         * Middling Atom processors are vulnerable to just the Store Buffer
         * aspect.
         */
    case 0x37: /* Baytrail / Valleyview (Silvermont) */
    case 0x4a: /* Merrifield */
    case 0x4c: /* Cherrytrail / Brasswell */
    case 0x4d: /* Avaton / Rangely (Silvermont) */
    case 0x5a: /* Moorefield */
    case 0x5d: /* SoFIA 3G Granite/ES2.1 */
    case 0x65: /* SoFIA LTE AOSP */
    case 0x6e: /* Cougar Mountain */
    case 0x75: /* Lightning Mountain */
        /*
         * Knights processors (which are based on the Silvermont/Airmont
         * microarchitecture) are similarly only affected by the Store Buffer
         * aspect.
         */
    case 0x57: /* Knights Landing */
    case 0x85: /* Knights Mill */
        cpu_has_bug_msbds_only = true;
        break;

    default:
        printk("Unrecognised CPU model %#x - assuming vulnerable to MDS\n",
               boot_cpu_data.x86_model);
        cpu_has_bug_mds = true;
        break;
    }
}

void spec_ctrl_init_domain(struct domain *d)
{
    bool pv = is_pv_domain(d);

    bool verw = ((pv ? opt_md_clear_pv : opt_md_clear_hvm) ||
                 (opt_fb_clear_mmio && is_iommu_enabled(d)));

    bool ibpb = ((pv ? opt_ibpb_entry_pv : opt_ibpb_entry_hvm) &&
                 (d->domain_id != 0 || opt_ibpb_entry_dom0));

    d->arch.spec_ctrl_flags =
        (verw   ? SCF_verw         : 0) |
        (ibpb   ? SCF_entry_ibpb   : 0) |
        0;
}

void __init init_speculation_mitigations(void)
{
    enum ind_thunk thunk = THUNK_DEFAULT;
    bool has_spec_ctrl, ibrs = false, hw_smt_enabled;
    bool cpu_has_bug_taa;
    uint64_t caps = 0;

    if ( boot_cpu_has(X86_FEATURE_ARCH_CAPS) )
        rdmsrl(MSR_ARCH_CAPABILITIES, caps);

    hw_smt_enabled = check_smt_enabled();

    has_spec_ctrl = (boot_cpu_has(X86_FEATURE_IBRSB) ||
                     boot_cpu_has(X86_FEATURE_IBRS));

    /*
     * Has the user specified any custom BTI mitigations?  If so, follow their
     * instructions exactly and disable all heuristics.
     */
    if ( opt_thunk != THUNK_DEFAULT || opt_ibrs != -1 )
    {
        thunk = opt_thunk;
        ibrs  = !!opt_ibrs;
    }
    else
    {
        /*
         * Evaluate the safest Branch Target Injection mitigations to use.
         * First, begin with compiler-aided mitigations.
         */
        if ( IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        {
            /*
             * On all hardware, we'd like to use retpoline in preference to
             * IBRS, but only if it is safe on this hardware.
             */
            if ( retpoline_safe(caps) )
                thunk = THUNK_RETPOLINE;
            else if ( has_spec_ctrl )
                ibrs = true;
        }
        /* Without compiler thunk support, use IBRS if available. */
        else if ( has_spec_ctrl )
            ibrs = true;
    }

    /*
     * Supplimentary minor adjustments.  Without compiler support, there are
     * no thunks.
     */
    if ( !IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        thunk = THUNK_NONE;

    /*
     * If IBRS is in use and thunks are compiled in, there is no point
     * suffering extra overhead.  Switch to the least-overhead thunk.
     */
    if ( ibrs && thunk == THUNK_DEFAULT )
        thunk = THUNK_JMP;

    /*
     * If there are still no thunk preferences, the compiled default is
     * actually retpoline, and it is better than nothing.
     */
    if ( thunk == THUNK_DEFAULT )
        thunk = THUNK_RETPOLINE;

    /* Apply the chosen settings. */
    if ( thunk == THUNK_LFENCE )
        setup_force_cpu_cap(X86_FEATURE_IND_THUNK_LFENCE);
    else if ( thunk == THUNK_JMP )
        setup_force_cpu_cap(X86_FEATURE_IND_THUNK_JMP);

    /* Intel hardware: MSR_SPEC_CTRL alternatives setup. */
    if ( boot_cpu_has(X86_FEATURE_IBRSB) )
    {
        if ( opt_msr_sc_pv )
        {
            default_spec_ctrl_flags |= SCF_ist_sc_msr;
            setup_force_cpu_cap(X86_FEATURE_SC_MSR_PV);
        }

        if ( opt_msr_sc_hvm )
        {
            /*
             * While the guest MSR_SPEC_CTRL value is loaded/saved atomically,
             * Xen's value is not restored atomically.  An early NMI hitting
             * the VMExit path needs to restore Xen's value for safety.
             */
            default_spec_ctrl_flags |= SCF_ist_sc_msr;
            setup_force_cpu_cap(X86_FEATURE_SC_MSR_HVM);
        }
    }

    /* AMD hardware: MSR_SPEC_CTRL alternatives setup. */
    if ( boot_cpu_has(X86_FEATURE_IBRS) )
    {
        /*
         * Virtualising MSR_SPEC_CTRL for guests depends on SVM support, which
         * on real hardware matches the availability of MSR_SPEC_CTRL in the
         * first place.
         *
         * No need for SCF_ist_sc_msr because Xen's value is restored
         * atomically WRT NMIs in the VMExit path.
         *
         * TODO: Adjust cpu_has_svm_spec_ctrl to be usable earlier on boot.
         */
        if ( opt_msr_sc_hvm &&
             (boot_cpu_data.extended_cpuid_level >= 0x8000000a) &&
             (cpuid_edx(0x8000000a) & (1u << SVM_FEATURE_SPEC_CTRL)) )
            setup_force_cpu_cap(X86_FEATURE_SC_MSR_HVM);
    }

    /* Figure out default_xen_spec_ctrl. */
    if ( has_spec_ctrl && ibrs )
    {
        /* IBRS implies STIBP.  */
        if ( opt_stibp == -1 )
            opt_stibp = 1;

        default_xen_spec_ctrl |= SPEC_CTRL_IBRS;
    }

    /*
     * Use STIBP by default on all AMD systems.  Zen3 and later enumerate
     * STIBP_ALWAYS, but STIBP is needed on Zen2 as part of the mitigations
     * for Branch Type Confusion.
     *
     * Leave STIBP off by default on Intel.  Pre-eIBRS systems suffer a
     * substantial perf hit when it was implemented in microcode.
     */
    if ( opt_stibp == -1 )
        opt_stibp = !!boot_cpu_has(X86_FEATURE_AMD_STIBP);

    if ( opt_stibp && (boot_cpu_has(X86_FEATURE_STIBP) ||
                       boot_cpu_has(X86_FEATURE_AMD_STIBP)) )
        default_xen_spec_ctrl |= SPEC_CTRL_STIBP;

    if ( opt_ssbd && (boot_cpu_has(X86_FEATURE_SSBD) ||
                      boot_cpu_has(X86_FEATURE_AMD_SSBD)) )
    {
        /* SSBD implies PSFD */
        if ( opt_psfd == -1 )
            opt_psfd = 1;

        default_xen_spec_ctrl |= SPEC_CTRL_SSBD;
    }

    /*
     * Don't use PSFD by default.  AMD designed the predictor to
     * auto-clear on privilege change.  PSFD is implied by SSBD, which is
     * off by default.
     */
    if ( opt_psfd == -1 )
        opt_psfd = 0;

    if ( opt_psfd && boot_cpu_has(X86_FEATURE_PSFD) )
        default_xen_spec_ctrl |= SPEC_CTRL_PSFD;

    /*
     * PV guests can poison the RSB to any virtual address from which
     * they can execute a call instruction.  This is necessarily outside
     * of the Xen supervisor mappings.
     *
     * With SMEP enabled, the processor won't speculate into user mappings.
     * Therefore, in this case, we don't need to worry about poisoned entries
     * from 64bit PV guests.
     *
     * 32bit PV guest kernels run in ring 1, so use supervisor mappings.
     * If a processors speculates to 32bit PV guest kernel mappings, it is
     * speculating in 64bit supervisor mode, and can leak data.
     */
    if ( opt_rsb_pv )
    {
        setup_force_cpu_cap(X86_FEATURE_SC_RSB_PV);
        default_spec_ctrl_flags |= SCF_ist_rsb;
    }

    /*
     * HVM guests can always poison the RSB to point at Xen supervisor
     * mappings.
     */
    if ( opt_rsb_hvm )
        setup_force_cpu_cap(X86_FEATURE_SC_RSB_HVM);

    ibpb_calculations();

    /* Check whether Eager FPU should be enabled by default. */
    if ( opt_eager_fpu == -1 )
        opt_eager_fpu = should_use_eager_fpu();

    /* (Re)init BSP state now that default_spec_ctrl_flags has been calculated. */
    init_shadow_spec_ctrl_state();

    /*
     * For microcoded IBRS only (i.e. Intel, pre eIBRS), it is recommended to
     * clear MSR_SPEC_CTRL before going idle, to avoid impacting sibling
     * threads.  Activate this if SMT is enabled, and Xen is using a non-zero
     * MSR_SPEC_CTRL setting.
     */
    if ( boot_cpu_has(X86_FEATURE_IBRSB) && !(caps & ARCH_CAPS_IBRS_ALL) &&
         hw_smt_enabled && default_xen_spec_ctrl )
        setup_force_cpu_cap(X86_FEATURE_SC_MSR_IDLE);

    xpti_init_default(caps);

    l1tf_calculations(caps);

    /*
     * By default, enable PV domU L1TF mitigations on all L1TF-vulnerable
     * hardware, except when running in shim mode.
     *
     * In shim mode, SHADOW is expected to be compiled out, and a malicious
     * guest kernel can only attack the shim Xen, not the host Xen.
     */
    if ( opt_pv_l1tf_hwdom == -1 )
        opt_pv_l1tf_hwdom = 0;
    if ( opt_pv_l1tf_domu == -1 )
        opt_pv_l1tf_domu = !pv_shim && cpu_has_bug_l1tf;

    /*
     * By default, enable L1D_FLUSH on L1TF-vulnerable hardware, unless
     * instructed to skip the flush on vmentry by our outer hypervisor.
     */
    if ( !boot_cpu_has(X86_FEATURE_L1D_FLUSH) )
        opt_l1d_flush = 0;
    else if ( opt_l1d_flush == -1 )
        opt_l1d_flush = cpu_has_bug_l1tf && !(caps & ARCH_CAPS_SKIP_L1DFL);

    if ( opt_branch_harden )
        setup_force_cpu_cap(X86_FEATURE_SC_BRANCH_HARDEN);

    /*
     * We do not disable HT by default on affected hardware.
     *
     * Firstly, if the user intends to use exclusively PV, or HVM shadow
     * guests, HT isn't a concern and should remain fully enabled.  Secondly,
     * safety for HVM HAP guests can be arranged by the toolstack with core
     * parking, pinning or cpupool configurations, including mixed setups.
     *
     * However, if we are on affected hardware, with HT enabled, and the user
     * hasn't explicitly chosen whether to use HT or not, nag them to do so.
     */
    if ( opt_smt == -1 && cpu_has_bug_l1tf && !pv_shim && hw_smt_enabled )
        warning_add(
            "Booted on L1TF-vulnerable hardware with SMT/Hyperthreading\n"
            "enabled.  Please assess your configuration and choose an\n"
            "explicit 'smt=<bool>' setting.  See XSA-273.\n");

    mds_calculations(caps);

    /*
     * Parts which enumerate FB_CLEAR are those which are post-MDS_NO and have
     * reintroduced the VERW fill buffer flushing side effect because of a
     * susceptibility to FBSDP.
     *
     * If unprivileged guests have (or will have) MMIO mappings, we can
     * mitigate cross-domain leakage of fill buffer data by issuing VERW on
     * the return-to-guest path.
     */
    if ( opt_unpriv_mmio )
        opt_fb_clear_mmio = caps & ARCH_CAPS_FB_CLEAR;

    /*
     * By default, enable PV and HVM mitigations on MDS-vulnerable hardware.
     * This will only be a token effort for MLPDS/MFBDS when HT is enabled,
     * but it is somewhat better than nothing.
     */
    if ( opt_md_clear_pv == -1 )
        opt_md_clear_pv = ((cpu_has_bug_mds || cpu_has_bug_msbds_only) &&
                           boot_cpu_has(X86_FEATURE_MD_CLEAR));
    if ( opt_md_clear_hvm == -1 )
        opt_md_clear_hvm = ((cpu_has_bug_mds || cpu_has_bug_msbds_only) &&
                            boot_cpu_has(X86_FEATURE_MD_CLEAR));

    /*
     * Enable MDS/MMIO defences as applicable.  The Idle blocks need using if
     * either the PV or HVM MDS defences are used, or if we may give MMIO
     * access to untrusted guests.
     *
     * HVM is more complicated.  The MD_CLEAR microcode extends L1D_FLUSH with
     * equivalent semantics to avoid needing to perform both flushes on the
     * HVM path.  Therefore, we don't need VERW in addition to L1D_FLUSH (for
     * MDS mitigations.  L1D_FLUSH is not safe for MMIO mitigations.)
     *
     * After calculating the appropriate idle setting, simplify
     * opt_md_clear_hvm to mean just "should we VERW on the way into HVM
     * guests", so spec_ctrl_init_domain() can calculate suitable settings.
     */
    if ( opt_md_clear_pv || opt_md_clear_hvm || opt_fb_clear_mmio )
        setup_force_cpu_cap(X86_FEATURE_SC_VERW_IDLE);
    opt_md_clear_hvm &= !(caps & ARCH_CAPS_SKIP_L1DFL) && !opt_l1d_flush;

    /*
     * Warn the user if they are on MLPDS/MFBDS-vulnerable hardware with HT
     * active and no explicit SMT choice.
     */
    if ( opt_smt == -1 && cpu_has_bug_mds && hw_smt_enabled )
        warning_add(
            "Booted on MLPDS/MFBDS-vulnerable hardware with SMT/Hyperthreading\n"
            "enabled.  Mitigations will not be fully effective.  Please\n"
            "choose an explicit smt=<bool> setting.  See XSA-297.\n");

    /*
     * Vulnerability to TAA is a little complicated to quantify.
     *
     * In the pipeline, it is just another way to get speculative access to
     * stale load port, store buffer or fill buffer data, and therefore can be
     * considered a superset of MDS (on TSX-capable parts).  On parts which
     * predate MDS_NO, the existing VERW flushing will mitigate this
     * sidechannel as well.
     *
     * On parts which contain MDS_NO, the lack of VERW flushing means that an
     * attacker can still use TSX to target microarchitectural buffers to leak
     * secrets.  Therefore, we consider TAA to be the set of TSX-capable parts
     * which have MDS_NO but lack TAA_NO.
     *
     * Note: cpu_has_rtm (== hle) could already be hidden by `tsx=0` on the
     *       cmdline.  MSR_TSX_CTRL will only appear on TSX-capable parts, so
     *       we check both to spot TSX in a microcode/cmdline independent way.
     */
    cpu_has_bug_taa =
        (cpu_has_rtm || (caps & ARCH_CAPS_TSX_CTRL)) &&
        (caps & (ARCH_CAPS_MDS_NO | ARCH_CAPS_TAA_NO)) == ARCH_CAPS_MDS_NO;

    /*
     * On TAA-affected hardware, disabling TSX is the preferred mitigation, vs
     * the MDS mitigation of disabling HT and using VERW flushing.
     *
     * On CPUs which advertise MDS_NO, VERW has no flushing side effect until
     * the TSX_CTRL microcode is loaded, despite the MD_CLEAR CPUID bit being
     * advertised, and there isn't a MD_CLEAR_2 flag to use...
     *
     * If we're on affected hardware, able to do something about it (which
     * implies that VERW now works), no explicit TSX choice and traditional
     * MDS mitigations (no-SMT, VERW) not obviosuly in use (someone might
     * plausibly value TSX higher than Hyperthreading...), disable TSX to
     * mitigate TAA.
     */
    if ( opt_tsx == -1 && cpu_has_bug_taa && (caps & ARCH_CAPS_TSX_CTRL) &&
         ((hw_smt_enabled && opt_smt) ||
          !boot_cpu_has(X86_FEATURE_SC_VERW_IDLE)) )
    {
        opt_tsx = 0;
        tsx_init();
    }

    /* Calculate suitable defaults for MSR_MCU_OPT_CTRL */
    if ( boot_cpu_has(X86_FEATURE_SRBDS_CTRL) )
    {
        uint64_t val;

        rdmsrl(MSR_MCU_OPT_CTRL, val);

        /*
         * On some SRBDS-affected hardware, it may be safe to relax srb-lock
         * by default.
         *
         * All parts with SRBDS_CTRL suffer SSDP, the mechanism by which stale
         * RNG data becomes available to other contexts.  To recover the data,
         * an attacker needs to use:
         *  - SBDS (MDS or TAA to sample the cores fill buffer)
         *  - SBDR (Architecturally retrieve stale transaction buffer contents)
         *  - DRPW (Architecturally latch stale fill buffer data)
         *
         * On MDS_NO parts, and with TAA_NO or TSX unavailable/disabled, and
         * there is no unprivileged MMIO access, the RNG data doesn't need
         * protecting.
         */
        if ( opt_srb_lock == -1 && !opt_unpriv_mmio &&
             (caps & (ARCH_CAPS_MDS_NO|ARCH_CAPS_TAA_NO)) == ARCH_CAPS_MDS_NO &&
             (!cpu_has_hle || ((caps & ARCH_CAPS_TSX_CTRL) && opt_tsx == 0)) )
            opt_srb_lock = 0;

        val &= ~MCU_OPT_CTRL_RNGDS_MITG_DIS;
        if ( !opt_srb_lock )
            val |= MCU_OPT_CTRL_RNGDS_MITG_DIS;

        default_xen_mcu_opt_ctrl = val;
    }

    print_details(thunk, caps);

    /*
     * If MSR_SPEC_CTRL is available, apply Xen's default setting and discard
     * any firmware settings.  For performance reasons, when safe to do so, we
     * delay applying non-zero settings until after dom0 has been constructed.
     *
     * "when safe to do so" is based on whether we are virtualised.  A native
     * boot won't have any other code running in a position to mount an
     * attack.
     */
    if ( has_spec_ctrl )
    {
        bsp_delay_spec_ctrl = !cpu_has_hypervisor && default_xen_spec_ctrl;

        /*
         * If delaying MSR_SPEC_CTRL setup, use the same mechanism as
         * spec_ctrl_enter_idle(), by using a shadow value of zero.
         */
        if ( bsp_delay_spec_ctrl )
        {
            struct cpu_info *info = get_cpu_info();

            info->shadow_spec_ctrl = 0;
            barrier();
            info->spec_ctrl_flags |= SCF_use_shadow;
            barrier();
        }

        wrmsrl(MSR_SPEC_CTRL, bsp_delay_spec_ctrl ? 0 : default_xen_spec_ctrl);
    }

    if ( boot_cpu_has(X86_FEATURE_SRBDS_CTRL) )
        wrmsrl(MSR_MCU_OPT_CTRL, default_xen_mcu_opt_ctrl);
}

static void __init __maybe_unused build_assertions(void)
{
    /* The optimised assembly relies on this alias. */
    BUILD_BUG_ON(SCF_use_shadow != 1);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
