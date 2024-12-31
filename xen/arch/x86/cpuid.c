#include <xen/sched.h>
#include <xen/types.h>
#include <xen/version.h>

#include <public/arch-x86/cpuid.h>
#include <public/hvm/params.h>

#include <asm/cpu-policy.h>
#include <asm/cpuid.h>
#include <asm/hvm/viridian.h>
#include <asm/xstate.h>

#define EMPTY_LEAF ((struct cpuid_leaf){})

bool recheck_cpu_features(unsigned int cpu)
{
    bool okay = true;
    struct cpuinfo_x86 c = {0};
    const struct cpuinfo_x86 *bsp = &boot_cpu_data;
    unsigned int i;

    identify_cpu(&c);

    for ( i = 0; i < NCAPINTS; ++i )
    {
        if ( !(~c.x86_capability[i] & bsp->x86_capability[i]) )
            continue;

        printk(XENLOG_ERR "CPU%u: cap[%2u] is %08x (expected %08x)\n",
               cpu, i, c.x86_capability[i], bsp->x86_capability[i]);
        okay = false;
    }

    return okay;
}

static void cpuid_hypervisor_leaves(const struct vcpu *v, uint32_t leaf,
                                    uint32_t subleaf, struct cpuid_leaf *res)
{
    const struct domain *d = v->domain;
    const struct cpu_policy *p = d->arch.cpu_policy;
    uint32_t base = is_viridian_domain(d) ? 0x40000100 : 0x40000000;
    uint32_t idx  = leaf - base;
    unsigned int limit = is_viridian_domain(d) ? p->hv2_limit : p->hv_limit;

    if ( limit == 0 )
        /* Default number of leaves */
        limit = XEN_CPUID_MAX_NUM_LEAVES;
    else
        /* Clamp toolstack value between 2 and MAX_NUM_LEAVES. */
        limit = min(max(limit, 2u), XEN_CPUID_MAX_NUM_LEAVES + 0u);

    if ( idx > limit )
        return;

    switch ( idx )
    {
    case 0:
        res->a = base + limit; /* Largest leaf */
        res->b = XEN_CPUID_SIGNATURE_EBX;
        res->c = XEN_CPUID_SIGNATURE_ECX;
        res->d = XEN_CPUID_SIGNATURE_EDX;
        break;

    case 1:
        res->a = (xen_major_version() << 16) | xen_minor_version();
        break;

    case 2:
        res->a = 1;            /* Number of hypercall-transfer pages */
                               /* MSR base address */
        res->b = is_viridian_domain(d) ? 0x40000200 : 0x40000000;
        if ( is_pv_domain(d) ) /* Features */
            res->c |= XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD;
        break;

    case 3: /* Time leaf. */
        switch ( subleaf )
        {
        case 0: /* features */
            res->a = ((d->arch.vtsc << 0) |
                      (!!host_tsc_is_safe() << 1) |
                      (!!boot_cpu_has(X86_FEATURE_RDTSCP) << 2));
            res->b = d->arch.tsc_mode;
            res->c = d->arch.tsc_khz;
            res->d = d->arch.incarnation;
            break;

        case 1: /* scale and offset */
        {
            uint64_t offset;

            if ( !d->arch.vtsc )
                offset = d->arch.vtsc_offset;
            else
                /* offset already applied to value returned by virtual rdtscp */
                offset = 0;
            res->a = offset;
            res->b = offset >> 32;
            res->c = d->arch.vtsc_to_ns.mul_frac;
            res->d = d->arch.vtsc_to_ns.shift;
            break;
        }

        case 2: /* physical cpu_khz */
            res->a = cpu_khz;
            break;
        }
        break;

    case 4: /* HVM hypervisor leaf. */
        if ( !is_hvm_domain(d) || subleaf != 0 )
            break;

        if ( cpu_has_vmx_apic_reg_virt )
            res->a |= XEN_HVM_CPUID_APIC_ACCESS_VIRT;

        /*
         * We want to claim that x2APIC is virtualized if APIC MSR accesses
         * are not intercepted. When all three of these are true both rdmsr
         * and wrmsr in the guest will run without VMEXITs (see
         * vmx_vlapic_msr_changed()).
         */
        if ( cpu_has_vmx_virtualize_x2apic_mode &&
             cpu_has_vmx_apic_reg_virt &&
             cpu_has_vmx_virtual_intr_delivery )
            res->a |= XEN_HVM_CPUID_X2APIC_VIRT;

        /*
         * 1) Xen 4.10 and older was broken WRT grant maps requesting a DMA
         * mapping, and forgot to honour the guest's request.
         * 2) 4.11 (and presumably backports) fixed the bug, so the map
         * hypercall actually did what the guest asked.
         * 3) To work around the bug, guests must bounce buffer all DMA that
         * would otherwise use a grant map, because it doesn't know whether the
         * DMA is originating from an emulated or a real device.
         * 4) This flag tells guests it is safe not to bounce-buffer all DMA to
         * work around the bug.
         */
        res->a |= XEN_HVM_CPUID_IOMMU_MAPPINGS;

        /* Indicate presence of vcpu id and set it in ebx */
        res->a |= XEN_HVM_CPUID_VCPU_ID_PRESENT;
        res->b = v->vcpu_id;

        /* Indicate presence of domain id and set it in ecx */
        res->a |= XEN_HVM_CPUID_DOMID_PRESENT;
        res->c = d->domain_id;

        /*
         * Per-vCPU event channel upcalls are implemented and work
         * correctly with PIRQs routed over event channels.
         */
        res->a |= XEN_HVM_CPUID_UPCALL_VECTOR;

        break;

    case 5: /* PV-specific parameters */
        if ( is_hvm_domain(d) || subleaf != 0 )
            break;

        res->b = flsl(get_upper_mfn_bound()) + PAGE_SHIFT;
        break;

    default:
        ASSERT_UNREACHABLE();
        break;
    }
}

void guest_cpuid(const struct vcpu *v, uint32_t leaf,
                 uint32_t subleaf, struct cpuid_leaf *res)
{
    const struct domain *d = v->domain;
    const struct cpu_policy *p = d->arch.cpu_policy;

    *res = EMPTY_LEAF;

    /*
     * First pass:
     * - Perform max_leaf/subleaf calculations.  Out-of-range leaves return
     *   all zeros, following the AMD model.
     * - Fill in *res with static data.
     * - Dispatch the virtualised leaves to their respective handlers.
     */
    switch ( leaf )
    {
    case 0 ... CPUID_GUEST_NR_BASIC - 1:
        ASSERT(p->basic.max_leaf < ARRAY_SIZE(p->basic.raw));
        if ( leaf > min_t(uint32_t, p->basic.max_leaf,
                          ARRAY_SIZE(p->basic.raw) - 1) )
            return;

        switch ( leaf )
        {
        case 0x4:
            if ( subleaf >= ARRAY_SIZE(p->cache.raw) )
                return;

            *res = array_access_nospec(p->cache.raw, subleaf);
            break;

        case 0x7:
            ASSERT(p->feat.max_subleaf < ARRAY_SIZE(p->feat.raw));
            if ( subleaf > min_t(uint32_t, p->feat.max_subleaf,
                                 ARRAY_SIZE(p->feat.raw) - 1) )
                return;

            *res = array_access_nospec(p->feat.raw, subleaf);
            break;

        case 0xb:
            if ( subleaf >= ARRAY_SIZE(p->topo.raw) )
                return;

            *res = array_access_nospec(p->topo.raw, subleaf);
            break;

        case XSTATE_CPUID:
            if ( !p->basic.xsave || subleaf >= ARRAY_SIZE(p->xstate.raw) )
                return;

            *res = array_access_nospec(p->xstate.raw, subleaf);
            break;

        default:
            *res = array_access_nospec(p->basic.raw, leaf);
            break;
        }
        break;

    case 0x40000000U ... 0x400000ffU:
        if ( is_viridian_domain(d) )
            return cpuid_viridian_leaves(v, leaf, subleaf, res);

        fallthrough;
        /*
         * Intel reserve up until 0x4fffffff for hypervisor use.  AMD reserve
         * only until 0x400000ff, but we already use double that.
         */
    case 0x40000100U ... 0x400001ffU:
        return cpuid_hypervisor_leaves(v, leaf, subleaf, res);

    case 0x80000000U ... 0x80000000U + CPUID_GUEST_NR_EXTD - 1:
        ASSERT((p->extd.max_leaf & 0xffff) < ARRAY_SIZE(p->extd.raw));
        if ( (leaf & 0xffff) > min_t(uint32_t, p->extd.max_leaf & 0xffff,
                                     ARRAY_SIZE(p->extd.raw) - 1) )
            return;

        *res = array_access_nospec(p->extd.raw, leaf & 0xffff);
        break;

    default:
        return;
    }

    /*
     * Skip dynamic adjustments if we are in the wrong context.
     *
     * All dynamic adjustments depends on current register state, which will
     * be stale if the vcpu is running elsewhere.  It is simpler, quicker, and
     * more reliable for the caller to do nothing (consistently) than to hand
     * back stale data which it can't use safely.
     */
    if ( v != current )
        return;

    /*
     * Second pass:
     * - Dynamic adjustments
     */
    switch ( leaf )
    {
        const struct cpu_user_regs *regs;

    case 0x1:
        /* TODO: Rework topology logic. */
        res->b &= 0x00ffffffu;
        if ( is_hvm_domain(d) )
            res->b |= (v->vcpu_id * 2) << 24;

        /* TODO: Rework vPMU control in terms of toolstack choices. */
        if ( vpmu_available(v) &&
             vpmu_is_set(vcpu_vpmu(v), VPMU_CPU_HAS_DS) )
        {
            res->d |= cpufeat_mask(X86_FEATURE_DS);
            if ( cpu_has(&current_cpu_data, X86_FEATURE_DTES64) )
                res->c |= cpufeat_mask(X86_FEATURE_DTES64);
            if ( cpu_has(&current_cpu_data, X86_FEATURE_DSCPL) )
                res->c |= cpufeat_mask(X86_FEATURE_DSCPL);
        }

        if ( is_hvm_domain(d) )
        {
            /* OSXSAVE clear in policy.  Fast-forward CR4 back in. */
            if ( v->arch.hvm.guest_cr[4] & X86_CR4_OSXSAVE )
                res->c |= cpufeat_mask(X86_FEATURE_OSXSAVE);
        }
        else /* PV domain */
        {
            regs = guest_cpu_user_regs();

            /*
             * !!! OSXSAVE handling for PV guests is non-architectural !!!
             *
             * Architecturally, the correct code here is simply:
             *
             *   if ( v->arch.pv.ctrlreg[4] & X86_CR4_OSXSAVE )
             *       c |= cpufeat_mask(X86_FEATURE_OSXSAVE);
             *
             * However because of bugs in Xen (before c/s bd19080b, Nov 2010,
             * the XSAVE cpuid flag leaked into guests despite the feature not
             * being available for use), buggy workarounds where introduced to
             * Linux (c/s 947ccf9c, also Nov 2010) which relied on the fact
             * that Xen also incorrectly leaked OSXSAVE into the guest.
             *
             * Furthermore, providing architectural OSXSAVE behaviour to a
             * many Linux PV guests triggered a further kernel bug when the
             * fpu code observes that XSAVEOPT is available, assumes that
             * xsave state had been set up for the task, and follows a wild
             * pointer.
             *
             * Older Linux PVOPS kernels however do require architectural
             * behaviour.  They observe Xen's leaked OSXSAVE and assume they
             * can already use XSETBV, dying with a #UD because the shadowed
             * CR4.OSXSAVE is clear.  This behaviour has been adjusted in all
             * observed cases via stable backports of the above changeset.
             *
             * Therefore, the leaking of Xen's OSXSAVE setting has become a
             * defacto part of the PV ABI and can't reasonably be corrected.
             * It can however be restricted to only the enlightened CPUID
             * view, as seen by the guest kernel.
             *
             * The following situations and logic now applies:
             *
             * - Hardware without CPUID faulting support and native CPUID:
             *    There is nothing Xen can do here.  The hosts XSAVE flag will
             *    leak through and Xen's OSXSAVE choice will leak through.
             *
             *    In the case that the guest kernel has not set up OSXSAVE, only
             *    SSE will be set in xcr0, and guest userspace can't do too much
             *    damage itself.
             *
             * - Enlightened CPUID or CPUID faulting available:
             *    Xen can fully control what is seen here.  When the guest has
             *    been configured to have XSAVE available, guest kernels need
             *    to see the leaked OSXSAVE via the enlightened path, but
             *    guest userspace and the native is given architectural
             *    behaviour.
             *
             *    Emulated vs Faulted CPUID is distinguised based on whether a
             *    #UD or #GP is currently being serviced.
             */
            /* OSXSAVE clear in policy.  Fast-forward CR4 back in. */
            if ( (v->arch.pv.ctrlreg[4] & X86_CR4_OSXSAVE) ||
                 (p->basic.xsave &&
                  regs->entry_vector == X86_EXC_UD &&
                  guest_kernel_mode(v, regs) &&
                  (read_cr4() & X86_CR4_OSXSAVE)) )
                res->c |= cpufeat_mask(X86_FEATURE_OSXSAVE);

            /*
             * At the time of writing, a PV domain is the only viable option
             * for Dom0.  Several interactions between dom0 and Xen for real
             * hardware setup have unfortunately been implemented based on
             * state which incorrectly leaked into dom0.
             *
             * These leaks are retained for backwards compatibility, but
             * restricted to the hardware domains kernel only.
             */
            if ( is_hardware_domain(d) && guest_kernel_mode(v, regs) )
            {
                /*
                 * MONITOR never leaked into PV guests, as PV guests cannot
                 * use the MONITOR/MWAIT instructions.  As such, they require
                 * the feature to not being present in emulated CPUID.
                 *
                 * Modern PVOPS Linux try to be cunning and use native CPUID
                 * to see if the hardware actually supports MONITOR, and by
                 * extension, deep C states.
                 *
                 * If the feature is seen, deep-C state information is
                 * obtained from the DSDT and handed back to Xen via the
                 * XENPF_set_processor_pminfo hypercall.
                 *
                 * This mechanism is incompatible with an HVM-based hardware
                 * domain, and also with CPUID Faulting.
                 *
                 * Luckily, Xen can be just as 'cunning', and distinguish an
                 * emulated CPUID from a faulted CPUID by whether a #UD or #GP
                 * fault is currently being serviced.  Yuck...
                 */
                if ( cpu_has_monitor && regs->entry_vector == X86_EXC_GP )
                    res->c |= cpufeat_mask(X86_FEATURE_MONITOR);

                /*
                 * While MONITOR never leaked into PV guests, EIST always used
                 * to.
                 *
                 * Modern PVOPS Linux will only parse P state information from
                 * the DSDT and return it to Xen if EIST is seen in the
                 * emulated CPUID information.
                 */
                if ( cpu_has_eist )
                    res->c |= cpufeat_mask(X86_FEATURE_EIST);
            }
        }
        goto common_leaf1_adjustments;

    case 0x5:
        /*
         * Leak the hardware MONITOR leaf under the same conditions that the
         * MONITOR feature flag is leaked.  See above for details.
         */
        regs = guest_cpu_user_regs();
        if ( is_pv_domain(d) && is_hardware_domain(d) &&
             guest_kernel_mode(v, regs) && cpu_has_monitor &&
             regs->entry_vector == X86_EXC_GP )
            *res = raw_cpu_policy.basic.raw[5];
        break;

    case 0x7:
        switch ( subleaf )
        {
        case 0:
            /* OSPKE clear in policy.  Fast-forward CR4 back in. */
            if ( (is_pv_domain(d)
                  ? v->arch.pv.ctrlreg[4]
                  : v->arch.hvm.guest_cr[4]) & X86_CR4_PKE )
                res->c |= cpufeat_mask(X86_FEATURE_OSPKE);
            break;
        }
        break;

    case 0xa:
        /* TODO: Rework vPMU control in terms of toolstack choices. */
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
             !vpmu_available(v) )
            *res = EMPTY_LEAF;
        else
        {
            /* Report at most v3 since that's all we currently emulate. */
            if ( (res->a & 0xff) > 3 )
                res->a = (res->a & ~0xff) | 3;
        }
        break;

    case 0xb:
        /*
         * In principle, this leaf is Intel-only.  In practice, it is tightly
         * coupled with x2apic, and we offer an x2apic-capable APIC emulation
         * to guests on AMD hardware as well.
         *
         * TODO: Rework topology logic.
         */
        if ( p->basic.x2apic )
        {
            *(uint8_t *)&res->c = subleaf;

            /* Fix the x2APIC identifier. */
            res->d = v->vcpu_id * 2;
        }
        break;

    case XSTATE_CPUID:
        switch ( subleaf )
        {
        case 0:
            if ( p->basic.xsave )
                res->b = xstate_uncompressed_size(v->arch.xcr0);
            break;

        case 1:
            if ( p->xstate.xsavec )
                res->b = xstate_compressed_size(v->arch.xcr0 |
                                                v->arch.msrs->xss.raw);
            break;
        }
        break;

    case 0x80000001U:
        /* SYSCALL is hidden outside of long mode on Intel. */
        if ( p->x86_vendor == X86_VENDOR_INTEL &&
             is_hvm_domain(d) && !hvm_long_mode_active(v) )
            res->d &= ~cpufeat_mask(X86_FEATURE_SYSCALL);

    common_leaf1_adjustments:
        if ( is_hvm_domain(d) )
        {
            /* Fast-forward MSR_APIC_BASE.EN. */
            if ( vlapic_hw_disabled(vcpu_vlapic(v)) )
                res->d &= ~cpufeat_mask(X86_FEATURE_APIC);

            /*
             * PSE36 is not supported in shadow mode.  This bit should be
             * clear in hvm_shadow_max_featuremask[].
             *
             * However, an unspecified version of Hyper-V from 2011 refuses to
             * start as the "cpu does not provide required hw features" if it
             * can't see PSE36.
             *
             * As a workaround, leak the toolstack-provided PSE36 value into a
             * shadow guest if the guest is already using PAE paging (and
             * won't care about reverting back to PSE paging).  Otherwise,
             * knoble it, so a 32bit guest doesn't get the impression that it
             * could try to use PSE36 paging.
             */
            if ( !hap_enabled(d) && !hvm_pae_enabled(v) )
                res->d &= ~cpufeat_mask(X86_FEATURE_PSE36);
        }
        else /* PV domain */
        {
            /*
             * MTRR used to unconditionally leak into PV guests.  They cannot
             * MTRR infrastructure at all, and shouldn't be able to see the
             * feature.
             *
             * Modern PVOPS Linux self-clobbers the MTRR feature, to avoid
             * trying to use the associated MSRs.  Xenolinux-based PV dom0's
             * however use the MTRR feature as an indication of the presence
             * of the XENPF_{add,del,read}_memtype hypercalls.
             */
            if ( is_hardware_domain(d) && cpu_has_mtrr &&
                 guest_kernel_mode(v, guest_cpu_user_regs()) )
                res->d |= cpufeat_mask(X86_FEATURE_MTRR);
        }
        break;
    }
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
