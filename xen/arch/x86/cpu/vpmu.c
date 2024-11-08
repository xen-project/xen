/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vpmu.c: PMU virtualization for HVM domain.
 *
 * Copyright (c) 2007, Intel Corporation.
 *
 * Author: Haitao Shan <haitao.shan@intel.com>
 */
#include <xen/cpu.h>
#include <xen/err.h>
#include <xen/param.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/sched.h>

#include <asm/irq-vectors.h>
#include <asm/regs.h>
#include <asm/msr.h>
#include <asm/nmi.h>
#include <asm/p2m.h>
#include <asm/vpmu.h>
#include <asm/apic.h>

#include <public/pmu.h>
#include <xsm/xsm.h>

#ifdef CONFIG_COMPAT
#include <compat/pmu.h>
CHECK_pmu_cntr_pair;
CHECK_pmu_data;
CHECK_pmu_params;
#endif

static unsigned int __read_mostly opt_vpmu_enabled;
unsigned int __read_mostly vpmu_mode = XENPMU_MODE_OFF;
unsigned int __read_mostly vpmu_features = 0;
static struct arch_vpmu_ops __initdata vpmu_ops;

static DEFINE_SPINLOCK(vpmu_lock);
static unsigned vpmu_count;

static DEFINE_PER_CPU(struct vcpu *, last_vcpu);

static int __init cf_check parse_vpmu_params(const char *s)
{
    const char *ss;
    int rc = 0, val;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_bool(s, ss)) >= 0 )
        {
            opt_vpmu_enabled = val;
            if ( !val )
                vpmu_features = 0;
        }
        else if ( !cmdline_strcmp(s, "bts") )
            vpmu_features |= XENPMU_FEATURE_INTEL_BTS;
        else if ( !cmdline_strcmp(s, "ipc") )
            vpmu_features |= XENPMU_FEATURE_IPC_ONLY;
        else if ( !cmdline_strcmp(s, "arch") )
            vpmu_features |= XENPMU_FEATURE_ARCH_ONLY;
        else if ( (val = parse_boolean("rtm-abort", s, ss)) >= 0 )
            printk(XENLOG_WARNING
                   "'rtm-abort=<bool>' superseded.  Use 'tsx=<bool>' instead\n");
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    /* Selecting bts/ipc/arch implies vpmu=1. */
    if ( vpmu_features )
        opt_vpmu_enabled = true;

    if ( opt_vpmu_enabled )
        vpmu_mode = XENPMU_MODE_SELF;

    return rc;
}
custom_param("vpmu", parse_vpmu_params);

void vpmu_lvtpc_update(uint32_t val)
{
    struct vpmu_struct *vpmu;
    struct vcpu *curr = current;

    if ( likely(vpmu_mode == XENPMU_MODE_OFF) )
        return;

    vpmu = vcpu_vpmu(curr);

    vpmu->hw_lapic_lvtpc = PMU_APIC_VECTOR | (val & APIC_LVT_MASKED);

    /* Postpone APIC updates for PV(H) guests if PMU interrupt is pending */
    if ( has_vlapic(curr->domain) || !vpmu->xenpmu_data ||
         !vpmu_is_set(vpmu, VPMU_CACHED) )
        apic_write(APIC_LVTPC, vpmu->hw_lapic_lvtpc);
}

int vpmu_do_msr(unsigned int msr, uint64_t *msr_content, bool is_write)
{
    struct vcpu *curr = current;
    struct vpmu_struct *vpmu;
    int ret = 0;

    /*
     * Hide the PMU MSRs if vpmu is not configured, or the hardware domain is
     * profiling the whole system.
     */
    if ( likely(vpmu_mode == XENPMU_MODE_OFF) ||
         ((vpmu_mode & XENPMU_MODE_ALL) &&
          !is_hardware_domain(curr->domain)) )
         goto nop;

    vpmu = vcpu_vpmu(curr);
    if ( !vpmu_is_set(vpmu, VPMU_INITIALIZED) )
        goto nop;

    if ( is_write )
        ret = alternative_call(vpmu_ops.do_wrmsr, msr, *msr_content);
    else
        ret = alternative_call(vpmu_ops.do_rdmsr, msr, msr_content);

    /*
     * We may have received a PMU interrupt while handling MSR access
     * and since do_wr/rdmsr may load VPMU context we should save
     * (and unload) it again.
     */
    if ( !has_vlapic(curr->domain) && vpmu->xenpmu_data &&
        vpmu_is_set(vpmu, VPMU_CACHED) )
    {
        vpmu_set(vpmu, VPMU_CONTEXT_SAVE);
        alternative_vcall(vpmu_ops.arch_vpmu_save, curr, 0);
        vpmu_reset(vpmu, VPMU_CONTEXT_SAVE | VPMU_CONTEXT_LOADED);
    }

    return ret;

 nop:
    if ( !is_write && (msr != MSR_IA32_MISC_ENABLE) )
        *msr_content = 0;

    return 0;
}

static inline struct vcpu *choose_hwdom_vcpu(void)
{
    unsigned idx;

    if ( hardware_domain->max_vcpus == 0 )
        return NULL;

    idx = smp_processor_id() % hardware_domain->max_vcpus;

    return hardware_domain->vcpu[idx];
}

void vpmu_do_interrupt(void)
{
    struct vcpu *sampled = current, *sampling;
    struct vpmu_struct *vpmu;
#ifdef CONFIG_HVM
    struct vlapic *vlapic;
    uint32_t vlapic_lvtpc;
#endif

    /*
     * dom0 will handle interrupt for special domains (e.g. idle domain) or,
     * in XENPMU_MODE_ALL, for everyone.
     */
    if ( (vpmu_mode & XENPMU_MODE_ALL) ||
         (sampled->domain->domain_id >= DOMID_FIRST_RESERVED) )
    {
        sampling = choose_hwdom_vcpu();
        if ( !sampling )
            return;
    }
    else
        sampling = sampled;

    vpmu = vcpu_vpmu(sampling);
    if ( !vpmu_is_set(vpmu, VPMU_INITIALIZED) )
        return;

    /* PV(H) guest */
    if ( !has_vlapic(sampling->domain) || (vpmu_mode & XENPMU_MODE_ALL) )
    {
        const struct cpu_user_regs *cur_regs;
        uint64_t *flags = &vpmu->xenpmu_data->pmu.pmu_flags;
        domid_t domid;

        if ( !vpmu->xenpmu_data )
            return;

        if ( vpmu_is_set(vpmu, VPMU_CACHED) )
            return;

        /* PV guest will be reading PMU MSRs from xenpmu_data */
        vpmu_set(vpmu, VPMU_CONTEXT_SAVE | VPMU_CONTEXT_LOADED);
        alternative_vcall(vpmu_ops.arch_vpmu_save, sampling, 1);
        vpmu_reset(vpmu, VPMU_CONTEXT_SAVE | VPMU_CONTEXT_LOADED);

        if ( is_hvm_vcpu(sampled) )
            *flags = 0;
        else
            *flags = PMU_SAMPLE_PV;

        if ( sampled == sampling )
            domid = DOMID_SELF;
        else
            domid = sampled->domain->domain_id;

        /* Store appropriate registers in xenpmu_data */
#ifdef CONFIG_COMPAT
        /* FIXME: 32-bit PVH should go here as well */
        if ( is_pv_32bit_vcpu(sampling) )
        {
            /*
             * 32-bit dom0 cannot process Xen's addresses (which are 64 bit)
             * and therefore we treat it the same way as a non-privileged
             * PV 32-bit domain.
             */
            struct compat_pmu_regs *cmp;

            cur_regs = guest_cpu_user_regs();

            cmp = (void *)&vpmu->xenpmu_data->pmu.r.regs;
            cmp->ip = cur_regs->rip;
            cmp->sp = cur_regs->rsp;
            cmp->flags = cur_regs->rflags;
            cmp->ss = cur_regs->ss;
            cmp->cs = cur_regs->cs;
            if ( (cmp->cs & 3) > 1 )
                *flags |= PMU_SAMPLE_USER;
        }
        else
#endif
        {
            const struct cpu_user_regs *regs = get_irq_regs();
            struct xen_pmu_regs *r = &vpmu->xenpmu_data->pmu.r.regs;

            if ( (vpmu_mode & XENPMU_MODE_SELF) )
                cur_regs = guest_cpu_user_regs();
            else if ( !guest_mode(regs) &&
                      is_hardware_domain(sampling->domain) )
            {
                cur_regs = regs;
                domid = DOMID_XEN;
            }
            else
                cur_regs = guest_cpu_user_regs();

            r->ip = cur_regs->rip;
            r->sp = cur_regs->rsp;
            r->flags = cur_regs->rflags;

            if ( !is_hvm_vcpu(sampled) )
            {
                r->ss = cur_regs->ss;
                r->cs = cur_regs->cs;
                if ( !(sampled->arch.flags & TF_kernel_mode) )
                    *flags |= PMU_SAMPLE_USER;
            }
            else
            {
                struct segment_register seg;

                hvm_get_segment_register(sampled, x86_seg_cs, &seg);
                r->cs = seg.sel;
                hvm_get_segment_register(sampled, x86_seg_ss, &seg);
                r->ss = seg.sel;
                r->cpl = seg.dpl;
                if ( !(sampled->arch.hvm.guest_cr[0] & X86_CR0_PE) )
                    *flags |= PMU_SAMPLE_REAL;
            }
        }

        vpmu->xenpmu_data->domain_id = domid;
        vpmu->xenpmu_data->vcpu_id = sampled->vcpu_id;
        if ( is_hardware_domain(sampling->domain) )
            vpmu->xenpmu_data->pcpu_id = smp_processor_id();
        else
            vpmu->xenpmu_data->pcpu_id = sampled->vcpu_id;

        vpmu->hw_lapic_lvtpc |= APIC_LVT_MASKED;
        apic_write(APIC_LVTPC, vpmu->hw_lapic_lvtpc);
        *flags |= PMU_CACHED;
        vpmu_set(vpmu, VPMU_CACHED);

        send_guest_vcpu_virq(sampling, VIRQ_XENPMU);

        return;
    }

#ifdef CONFIG_HVM
    /* HVM guests */
    vlapic = vcpu_vlapic(sampling);

    /* We don't support (yet) HVM dom0 */
    ASSERT(sampling == sampled);

    if ( !alternative_call(vpmu_ops.do_interrupt) ||
         !is_vlapic_lvtpc_enabled(vlapic) )
        return;

    vlapic_lvtpc = vlapic_get_reg(vlapic, APIC_LVTPC);

    switch ( vlapic_lvtpc & APIC_DM_MASK )
    {
    case APIC_DM_FIXED:
        vlapic_set_irq(vlapic, vlapic_lvtpc & APIC_VECTOR_MASK, 0);
        break;
    case APIC_DM_NMI:
        sampling->arch.nmi_pending = true;
        break;
    }
#endif
}

#ifdef CONFIG_MEM_SHARING
int vpmu_allocate_context(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
        return 0;

    return alternative_call(vpmu_ops.allocate_context, v) ? 0 : -ENOMEM;
}
#endif

void cf_check vpmu_save_force(void *arg)
{
    struct vcpu *v = arg;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
        return;

    vpmu_set(vpmu, VPMU_CONTEXT_SAVE);

    alternative_vcall(vpmu_ops.arch_vpmu_save, v, 0);

    vpmu_reset(vpmu, VPMU_CONTEXT_SAVE);

    per_cpu(last_vcpu, smp_processor_id()) = NULL;
}

void vpmu_save(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    int pcpu = smp_processor_id();

    if ( !vpmu_are_all_set(vpmu, VPMU_CONTEXT_ALLOCATED | VPMU_CONTEXT_LOADED) )
       return;

    vpmu->last_pcpu = pcpu;
    per_cpu(last_vcpu, pcpu) = v;

    vpmu_set(vpmu, VPMU_CONTEXT_SAVE);

    if ( alternative_call(vpmu_ops.arch_vpmu_save, v, 0) )
        vpmu_reset(vpmu, VPMU_CONTEXT_LOADED);

    vpmu_reset(vpmu, VPMU_CONTEXT_SAVE);

    apic_write(APIC_LVTPC, PMU_APIC_VECTOR | APIC_LVT_MASKED);
}

int vpmu_load(struct vcpu *v, bool from_guest)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    int ret;

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
        return 0;

    /* Only when PMU is counting, we load PMU context immediately. */
    if ( !vpmu_is_set(vpmu, VPMU_RUNNING) ||
         (!has_vlapic(vpmu_vcpu(vpmu)->domain) &&
         vpmu_is_set(vpmu, VPMU_CACHED)) )
        return 0;

    apic_write(APIC_LVTPC, vpmu->hw_lapic_lvtpc);
    /* Arch code needs to set VPMU_CONTEXT_LOADED */
    ret = alternative_call(vpmu_ops.arch_vpmu_load, v, from_guest);
    if ( ret )
        apic_write(APIC_LVTPC, vpmu->hw_lapic_lvtpc | APIC_LVT_MASKED);

    return ret;
}

static int vpmu_arch_initialise(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    uint8_t vendor = current_cpu_data.x86_vendor;
    int ret;

    BUILD_BUG_ON(sizeof(struct xen_pmu_intel_ctxt) > XENPMU_CTXT_PAD_SZ);
    BUILD_BUG_ON(sizeof(struct xen_pmu_amd_ctxt) > XENPMU_CTXT_PAD_SZ);
    BUILD_BUG_ON(sizeof(struct xen_pmu_regs) > XENPMU_REGS_PAD_SZ);
#ifdef CONFIG_COMPAT
    BUILD_BUG_ON(sizeof(struct compat_pmu_regs) > XENPMU_REGS_PAD_SZ);
#endif

    ASSERT(!(vpmu->flags & ~VPMU_AVAILABLE) && !vpmu->context);

    if ( !vpmu_available(v) || vpmu_mode == XENPMU_MODE_OFF )
        return 0;

    if ( !opt_vpmu_enabled )
    {
        if ( vpmu_mode != XENPMU_MODE_OFF )
        {
            printk(XENLOG_G_WARNING "VPMU: Unknown CPU vendor %d. "
                   "Disabling VPMU\n", vendor);
            opt_vpmu_enabled = 0;
            vpmu_mode = XENPMU_MODE_OFF;
        }
        return -EINVAL;
    }

    ret = alternative_call(vpmu_ops.initialise, v);
    if ( ret )
    {
        printk(XENLOG_G_WARNING "VPMU: Initialization failed for %pv\n", v);
        return ret;
    }

    vpmu->hw_lapic_lvtpc = PMU_APIC_VECTOR | APIC_LVT_MASKED;
    vpmu_set(vpmu, VPMU_INITIALIZED);

    return 0;
}

static void get_vpmu(struct vcpu *v)
{
    spin_lock(&vpmu_lock);

    /*
     * Keep count of VPMUs in the system so that we won't try to change
     * vpmu_mode while a guest might be using one.
     * vpmu_mode can be safely updated while dom0's VPMUs are active and
     * so we don't need to include it in the count.
     */
    if ( !is_hardware_domain(v->domain) &&
        (vpmu_mode & (XENPMU_MODE_SELF | XENPMU_MODE_HV)) )
    {
        vpmu_count++;
        vpmu_set(vcpu_vpmu(v), VPMU_AVAILABLE);
    }
    else if ( is_hardware_domain(v->domain) &&
              (vpmu_mode != XENPMU_MODE_OFF) )
        vpmu_set(vcpu_vpmu(v), VPMU_AVAILABLE);

    spin_unlock(&vpmu_lock);
}

static void put_vpmu(struct vcpu *v)
{
    spin_lock(&vpmu_lock);

    if ( !vpmu_available(v) )
        goto out;

    if ( !is_hardware_domain(v->domain) &&
         (vpmu_mode & (XENPMU_MODE_SELF | XENPMU_MODE_HV)) )
    {
        vpmu_count--;
        vpmu_reset(vcpu_vpmu(v), VPMU_AVAILABLE);
    }
    else if ( is_hardware_domain(v->domain) &&
              (vpmu_mode != XENPMU_MODE_OFF) )
        vpmu_reset(vcpu_vpmu(v), VPMU_AVAILABLE);

 out:
    spin_unlock(&vpmu_lock);
}

void vpmu_initialise(struct vcpu *v)
{
    get_vpmu(v);

    /*
     * Guests without LAPIC (i.e. PV) call vpmu_arch_initialise()
     * from pvpmu_init().
     */
    if ( has_vlapic(v->domain) && vpmu_arch_initialise(v) )
        put_vpmu(v);
}

static void cf_check vpmu_clear_last(void *arg)
{
    if ( this_cpu(last_vcpu) == arg )
        this_cpu(last_vcpu) = NULL;
}

static void vpmu_arch_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
        return;

    /*
     * Need to clear last_vcpu in case it points to v.
     * We can check here non-atomically whether it is 'v' since
     * last_vcpu can never become 'v' again at this point.
     * We will test it again in vpmu_clear_last() with interrupts
     * disabled to make sure we don't clear someone else.
     */
    if ( cpu_online(vpmu->last_pcpu) &&
         per_cpu(last_vcpu, vpmu->last_pcpu) == v )
        on_selected_cpus(cpumask_of(vpmu->last_pcpu),
                         vpmu_clear_last, v, 1);

    /*
     * Unload VPMU first if VPMU_CONTEXT_LOADED being set.
     * This will stop counters.
     */
    if ( vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
        on_selected_cpus(cpumask_of(vcpu_vpmu(v)->last_pcpu),
                         vpmu_save_force, v, 1);

    alternative_vcall(vpmu_ops.arch_vpmu_destroy, v);

    vpmu_reset(vpmu, VPMU_CONTEXT_ALLOCATED);
}

static void vpmu_cleanup(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    void *xenpmu_data;

    spin_lock(&vpmu->vpmu_lock);

    vpmu_arch_destroy(v);
    xenpmu_data = vpmu->xenpmu_data;
    vpmu->xenpmu_data = NULL;

    spin_unlock(&vpmu->vpmu_lock);

    if ( xenpmu_data )
    {
        mfn_t mfn = domain_page_map_to_mfn(xenpmu_data);

        ASSERT(mfn_valid(mfn));
        unmap_domain_page_global(xenpmu_data);
        put_page_and_type(mfn_to_page(mfn));
    }
}

void vpmu_destroy(struct vcpu *v)
{
    vpmu_cleanup(v);

    put_vpmu(v);
}

static int pvpmu_init(struct domain *d, xen_pmu_params_t *params)
{
    struct vcpu *v;
    struct vpmu_struct *vpmu;
    struct page_info *page;
    uint64_t gfn = params->val;

    if ( (params->vcpu >= d->max_vcpus) || (d->vcpu[params->vcpu] == NULL) )
        return -EINVAL;

    v = d->vcpu[params->vcpu];
    vpmu = vcpu_vpmu(v);

    if ( !vpmu_available(v) )
        return -ENOENT;

    page = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
    if ( !page )
        return -EINVAL;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        return -EINVAL;
    }

    spin_lock(&vpmu->vpmu_lock);

    if ( v->arch.vpmu.xenpmu_data )
    {
        spin_unlock(&vpmu->vpmu_lock);
        put_page_and_type(page);
        return -EEXIST;
    }

    v->arch.vpmu.xenpmu_data = __map_domain_page_global(page);
    if ( !v->arch.vpmu.xenpmu_data )
    {
        spin_unlock(&vpmu->vpmu_lock);
        put_page_and_type(page);
        return -ENOMEM;
    }

    if ( vpmu_arch_initialise(v) )
        put_vpmu(v);

    spin_unlock(&vpmu->vpmu_lock);

    return 0;
}

static void pvpmu_finish(struct domain *d, xen_pmu_params_t *params)
{
    struct vcpu *v;

    if ( (params->vcpu >= d->max_vcpus) || (d->vcpu[params->vcpu] == NULL) )
        return;

    v = d->vcpu[params->vcpu];
    if ( v != current )
        vcpu_pause(v);

    vpmu_cleanup(v);

    if ( v != current )
        vcpu_unpause(v);
}

/* Dump some vpmu information to console. Used in keyhandler dump_domains(). */
void vpmu_dump(struct vcpu *v)
{
    if ( vpmu_is_set(vcpu_vpmu(v), VPMU_INITIALIZED) )
        alternative_vcall(vpmu_ops.arch_vpmu_dump, v);
}

long do_xenpmu_op(
    unsigned int op, XEN_GUEST_HANDLE_PARAM(xen_pmu_params_t) arg)
{
    int ret;
    struct vcpu *curr;
    struct xen_pmu_params pmu_params = {.val = 0};
    struct xen_pmu_data *xenpmu_data;
    struct vpmu_struct *vpmu;

    if ( !opt_vpmu_enabled || has_vlapic(current->domain) )
        return -EOPNOTSUPP;

    ret = xsm_pmu_op(XSM_OTHER, current->domain, op);
    if ( ret )
        return ret;

    /* Check major version when parameters are specified */
    switch ( op )
    {
    case XENPMU_mode_set:
    case XENPMU_feature_set:
    case XENPMU_init:
    case XENPMU_finish:
        if ( copy_from_guest(&pmu_params, arg, 1) )
            return -EFAULT;

        if ( pmu_params.version.maj != XENPMU_VER_MAJ )
            return -EINVAL;

        break;
    }

    switch ( op )
    {
    case XENPMU_mode_set:
    {
        if ( (pmu_params.val &
              ~(XENPMU_MODE_SELF | XENPMU_MODE_HV | XENPMU_MODE_ALL)) ||
             multiple_bits_set(pmu_params.val) )
            return -EINVAL;

        /* 32-bit dom0 can only sample itself. */
        if ( is_pv_32bit_vcpu(current) &&
             (pmu_params.val & (XENPMU_MODE_HV | XENPMU_MODE_ALL)) )
            return -EINVAL;

        spin_lock(&vpmu_lock);

        /*
         * We can always safely switch between XENPMU_MODE_SELF and
         * XENPMU_MODE_HV while other VPMUs are active.
         */
        if ( (vpmu_count == 0) ||
             ((vpmu_mode ^ pmu_params.val) ==
              (XENPMU_MODE_SELF | XENPMU_MODE_HV)) )
            vpmu_mode = pmu_params.val;
        else if ( vpmu_mode != pmu_params.val )
        {
            gprintk(XENLOG_WARNING,
                    "VPMU: Cannot change mode while active VPMUs exist\n");
            ret = -EBUSY;
        }

        spin_unlock(&vpmu_lock);

        break;
    }

    case XENPMU_mode_get:
        memset(&pmu_params, 0, sizeof(pmu_params));
        pmu_params.val = vpmu_mode;

        pmu_params.version.maj = XENPMU_VER_MAJ;
        pmu_params.version.min = XENPMU_VER_MIN;

        if ( copy_to_guest(arg, &pmu_params, 1) )
            ret = -EFAULT;

        break;

    case XENPMU_feature_set:
        if ( pmu_params.val & ~(XENPMU_FEATURE_INTEL_BTS |
                                XENPMU_FEATURE_IPC_ONLY |
                                XENPMU_FEATURE_ARCH_ONLY))
            return -EINVAL;

        spin_lock(&vpmu_lock);

        if ( (vpmu_count == 0) || (vpmu_features == pmu_params.val) )
            vpmu_features = pmu_params.val;
        else
        {
            gprintk(XENLOG_WARNING,
                    "VPMU: Cannot change features while active VPMUs exist\n");
            ret = -EBUSY;
        }

        spin_unlock(&vpmu_lock);

        break;

    case XENPMU_feature_get:
        pmu_params.val = vpmu_features;
        if ( copy_field_to_guest(arg, &pmu_params, val) )
            ret = -EFAULT;

        break;

    case XENPMU_init:
        ret = pvpmu_init(current->domain, &pmu_params);
        break;

    case XENPMU_finish:
        pvpmu_finish(current->domain, &pmu_params);
        break;

    case XENPMU_lvtpc_set:
        xenpmu_data = current->arch.vpmu.xenpmu_data;
        if ( xenpmu_data != NULL )
            vpmu_lvtpc_update(xenpmu_data->pmu.l.lapic_lvtpc);
        else
            ret = -EINVAL;
        break;

    case XENPMU_flush:
        curr = current;
        vpmu = vcpu_vpmu(curr);
        xenpmu_data = curr->arch.vpmu.xenpmu_data;
        if ( xenpmu_data == NULL )
            return -EINVAL;
        xenpmu_data->pmu.pmu_flags &= ~PMU_CACHED;
        vpmu_reset(vpmu, VPMU_CACHED);
        vpmu_lvtpc_update(xenpmu_data->pmu.l.lapic_lvtpc);
        if ( vpmu_load(curr, 1) )
        {
            xenpmu_data->pmu.pmu_flags |= PMU_CACHED;
            vpmu_set(vpmu, VPMU_CACHED);
            ret = -EIO;
        }
        break ;

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

static int cf_check cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    struct vcpu *vcpu = per_cpu(last_vcpu, cpu);
    struct vpmu_struct *vpmu;

    if ( !vcpu )
        return NOTIFY_DONE;

    vpmu = vcpu_vpmu(vcpu);
    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
        return NOTIFY_DONE;

    if ( action == CPU_DYING )
    {
        vpmu_save_force(vcpu);
        vpmu_reset(vpmu, VPMU_CONTEXT_LOADED);
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

static int __init cf_check vpmu_init(void)
{
    int vendor = current_cpu_data.x86_vendor;
    const struct arch_vpmu_ops *ops = NULL;

    if ( !opt_vpmu_enabled )
        return 0;

    /* NMI watchdog uses LVTPC and HW counter */
    if ( opt_watchdog && opt_vpmu_enabled )
    {
        printk(XENLOG_WARNING "NMI watchdog is enabled. Turning VPMU off.\n");
        opt_vpmu_enabled = 0;
        vpmu_mode = XENPMU_MODE_OFF;
        return 0;
    }

    switch ( vendor )
    {
#ifdef CONFIG_AMD
    case X86_VENDOR_AMD:
        ops = amd_vpmu_init();
        break;

    case X86_VENDOR_HYGON:
        ops = hygon_vpmu_init();
        break;
#endif

#ifdef CONFIG_INTEL
    case X86_VENDOR_INTEL:
        ops = core2_vpmu_init();
        break;
#endif

    default:
        printk(XENLOG_WARNING "VPMU: Unknown CPU vendor: %d. "
               "Turning VPMU off.\n", vendor);
        break;
    }

    if ( !IS_ERR_OR_NULL(ops) )
    {
        vpmu_ops = *ops;
        register_cpu_notifier(&cpu_nfb);
        printk(XENLOG_INFO "VPMU: version " __stringify(XENPMU_VER_MAJ) "."
               __stringify(XENPMU_VER_MIN) "\n");
    }
    else
    {
        vpmu_mode = XENPMU_MODE_OFF;
        opt_vpmu_enabled = 0;
    }

    return 0;
}
presmp_initcall(vpmu_init);
