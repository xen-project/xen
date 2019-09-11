/******************************************************************************
 * Arch-specific sysctl.c
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/nospec.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <public/sysctl.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/smp.h>
#include <asm/numa.h>
#include <xen/nodemask.h>
#include <xen/cpu.h>
#include <xsm/xsm.h>
#include <asm/psr.h>
#include <asm/cpuid.h>

const struct cpu_policy system_policies[] = {
    [ XEN_SYSCTL_cpu_policy_raw ] = {
        &raw_cpuid_policy,
        &raw_msr_policy,
    },
    [ XEN_SYSCTL_cpu_policy_host ] = {
        &host_cpuid_policy,
        &host_msr_policy,
    },
    [ XEN_SYSCTL_cpu_policy_pv_max ] = {
        &pv_max_cpuid_policy,
        &pv_max_msr_policy,
    },
    [ XEN_SYSCTL_cpu_policy_hvm_max ] = {
        &hvm_max_cpuid_policy,
        &hvm_max_msr_policy,
    },
    [ XEN_SYSCTL_cpu_policy_pv_default ] = {
        &pv_max_cpuid_policy,
        &pv_max_msr_policy,
    },
    [ XEN_SYSCTL_cpu_policy_hvm_default ] = {
        &hvm_max_cpuid_policy,
        &hvm_max_msr_policy,
    },
};

struct l3_cache_info {
    int ret;
    unsigned long size;
};

static void l3_cache_get(void *arg)
{
    struct cpuid4_info info;
    struct l3_cache_info *l3_info = arg;

    l3_info->ret = cpuid4_cache_lookup(3, &info);
    if ( !l3_info->ret )
        l3_info->size = info.size / 1024; /* in KB unit */
}

long cpu_up_helper(void *data)
{
    unsigned int cpu = (unsigned long)data;
    int ret = cpu_up(cpu);

    if ( ret == -EBUSY )
    {
        /* On EBUSY, flush RCU work and have one more go. */
        rcu_barrier();
        ret = cpu_up(cpu);
    }

    if ( !ret && !opt_smt &&
         cpu_data[cpu].compute_unit_id == INVALID_CUID &&
         cpumask_weight(per_cpu(cpu_sibling_mask, cpu)) > 1 )
    {
        ret = cpu_down_helper(data);
        if ( ret )
            printk("Could not re-offline CPU%u (%d)\n", cpu, ret);
        else
            ret = -EPERM;
    }

    return ret;
}

long cpu_down_helper(void *data)
{
    int cpu = (unsigned long)data;
    int ret = cpu_down(cpu);
    if ( ret == -EBUSY )
    {
        /* On EBUSY, flush RCU work and have one more go. */
        rcu_barrier();
        ret = cpu_down(cpu);
    }
    return ret;
}

static long smt_up_down_helper(void *data)
{
    bool up = (bool)data;
    unsigned int cpu, sibling_mask = boot_cpu_data.x86_num_siblings - 1;
    int ret = 0;

    opt_smt = up;

    for_each_present_cpu ( cpu )
    {
        /* Skip primary siblings (those whose thread id is 0). */
        if ( !(x86_cpu_to_apicid[cpu] & sibling_mask) )
            continue;

        ret = up ? cpu_up_helper(_p(cpu))
                 : cpu_down_helper(_p(cpu));

        if ( ret && ret != -EEXIST )
            break;

        /*
         * Ensure forward progress by only considering preemption when we have
         * changed the state of one or more cpus.
         */
        if ( ret != -EEXIST && general_preempt_check() )
        {
            /* In tasklet context - can't create a contination. */
            ret = -EBUSY;
            break;
        }

        ret = 0; /* Avoid exiting with -EEXIST in the success case. */
    }

    if ( !ret )
        printk(XENLOG_INFO "SMT %s - online CPUs 0x%*pb\n",
               up ? "enabled" : "disabled", CPUMASK_PR(&cpu_online_map));

    return ret;
}

void arch_do_physinfo(struct xen_sysctl_physinfo *pi)
{
    memcpy(pi->hw_cap, boot_cpu_data.x86_capability,
           min(sizeof(pi->hw_cap), sizeof(boot_cpu_data.x86_capability)));
    if ( hvm_enabled )
        pi->capabilities |= XEN_SYSCTL_PHYSCAP_hvm;
    if ( IS_ENABLED(CONFIG_PV) )
        pi->capabilities |= XEN_SYSCTL_PHYSCAP_pv;
    if ( hvm_hap_supported() )
        pi->capabilities |= XEN_SYSCTL_PHYSCAP_hap;
}

long arch_do_sysctl(
    struct xen_sysctl *sysctl, XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl)
{
    long ret = 0;

    switch ( sysctl->cmd )
    {

    case XEN_SYSCTL_cpu_hotplug:
    {
        unsigned int cpu = sysctl->u.cpu_hotplug.cpu;
        unsigned int op  = sysctl->u.cpu_hotplug.op;
        bool plug;
        long (*fn)(void *);
        void *hcpu;

        switch ( op )
        {
        case XEN_SYSCTL_CPU_HOTPLUG_ONLINE:
            plug = true;
            fn = cpu_up_helper;
            hcpu = _p(cpu);
            break;

        case XEN_SYSCTL_CPU_HOTPLUG_OFFLINE:
            plug = false;
            fn = cpu_down_helper;
            hcpu = _p(cpu);
            break;

        case XEN_SYSCTL_CPU_HOTPLUG_SMT_ENABLE:
        case XEN_SYSCTL_CPU_HOTPLUG_SMT_DISABLE:
            if ( !cpu_has_htt || boot_cpu_data.x86_num_siblings < 2 )
            {
                ret = -EOPNOTSUPP;
                break;
            }
            plug = op == XEN_SYSCTL_CPU_HOTPLUG_SMT_ENABLE;
            fn = smt_up_down_helper;
            hcpu = _p(plug);
            break;

        default:
            ret = -EOPNOTSUPP;
            break;
        }

        if ( !ret )
            ret = plug ? xsm_resource_plug_core(XSM_HOOK)
                       : xsm_resource_unplug_core(XSM_HOOK);

        if ( !ret )
            ret = continue_hypercall_on_cpu(0, fn, hcpu);
    }
    break;

    case XEN_SYSCTL_psr_cmt_op:
        if ( !psr_cmt_enabled() )
            return -ENODEV;

        if ( sysctl->u.psr_cmt_op.flags != 0 )
            return -EINVAL;

        switch ( sysctl->u.psr_cmt_op.cmd )
        {
        case XEN_SYSCTL_PSR_CMT_enabled:
            sysctl->u.psr_cmt_op.u.data =
                (psr_cmt->features & PSR_RESOURCE_TYPE_L3) &&
                (psr_cmt->l3.features & PSR_CMT_L3_OCCUPANCY);
            break;
        case XEN_SYSCTL_PSR_CMT_get_total_rmid:
            sysctl->u.psr_cmt_op.u.data = psr_cmt->rmid_max;
            break;
        case XEN_SYSCTL_PSR_CMT_get_l3_upscaling_factor:
            sysctl->u.psr_cmt_op.u.data = psr_cmt->l3.upscaling_factor;
            break;
        case XEN_SYSCTL_PSR_CMT_get_l3_cache_size:
        {
            struct l3_cache_info info;
            unsigned int cpu = sysctl->u.psr_cmt_op.u.l3_cache.cpu;

            if ( (cpu >= nr_cpu_ids) || !cpu_online(cpu) )
            {
                ret = -ENODEV;
                sysctl->u.psr_cmt_op.u.data = 0;
                break;
            }
            if ( cpu == smp_processor_id() )
                l3_cache_get(&info);
            else
                on_selected_cpus(cpumask_of(cpu), l3_cache_get, &info, 1);

            ret = info.ret;
            sysctl->u.psr_cmt_op.u.data = (ret ? 0 : info.size);
            break;
        }
        case XEN_SYSCTL_PSR_CMT_get_l3_event_mask:
            sysctl->u.psr_cmt_op.u.data = psr_cmt->l3.features;
            break;
        default:
            sysctl->u.psr_cmt_op.u.data = 0;
            ret = -ENOSYS;
            break;
        }

        if ( __copy_to_guest(u_sysctl, sysctl, 1) )
            ret = -EFAULT;

        break;

    case XEN_SYSCTL_psr_alloc:
    {
        uint32_t data[PSR_INFO_ARRAY_SIZE] = { };

        switch ( sysctl->u.psr_alloc.cmd )
        {
        case XEN_SYSCTL_PSR_get_l3_info:
            ret = psr_get_info(sysctl->u.psr_alloc.target,
                               PSR_TYPE_L3_CBM, data, ARRAY_SIZE(data));
            if ( ret )
                break;

            sysctl->u.psr_alloc.u.cat_info.cos_max =
                                      data[PSR_INFO_IDX_COS_MAX];
            sysctl->u.psr_alloc.u.cat_info.cbm_len =
                                      data[PSR_INFO_IDX_CAT_CBM_LEN];
            sysctl->u.psr_alloc.u.cat_info.flags =
                                      data[PSR_INFO_IDX_CAT_FLAGS];

            if ( __copy_field_to_guest(u_sysctl, sysctl, u.psr_alloc) )
                ret = -EFAULT;
            break;

        case XEN_SYSCTL_PSR_get_l2_info:
            ret = psr_get_info(sysctl->u.psr_alloc.target,
                               PSR_TYPE_L2_CBM, data, ARRAY_SIZE(data));
            if ( ret )
                break;

            sysctl->u.psr_alloc.u.cat_info.cos_max =
                                      data[PSR_INFO_IDX_COS_MAX];
            sysctl->u.psr_alloc.u.cat_info.cbm_len =
                                      data[PSR_INFO_IDX_CAT_CBM_LEN];
            sysctl->u.psr_alloc.u.cat_info.flags =
                                      data[PSR_INFO_IDX_CAT_FLAGS];

            if ( __copy_field_to_guest(u_sysctl, sysctl, u.psr_alloc) )
                ret = -EFAULT;
            break;

        case XEN_SYSCTL_PSR_get_mba_info:
            ret = psr_get_info(sysctl->u.psr_alloc.target,
                               PSR_TYPE_MBA_THRTL, data, ARRAY_SIZE(data));
            if ( ret )
                break;

            sysctl->u.psr_alloc.u.mba_info.cos_max =
                                      data[PSR_INFO_IDX_COS_MAX];
            sysctl->u.psr_alloc.u.mba_info.thrtl_max =
                                      data[PSR_INFO_IDX_MBA_THRTL_MAX];
            sysctl->u.psr_alloc.u.mba_info.flags =
                                      data[PSR_INFO_IDX_MBA_FLAGS];

            if ( __copy_field_to_guest(u_sysctl, sysctl, u.psr_alloc) )
                ret = -EFAULT;
            break;

        default:
            ret = -EOPNOTSUPP;
            break;
        }
        break;
    }

    case XEN_SYSCTL_get_cpu_levelling_caps:
        sysctl->u.cpu_levelling_caps.caps = levelling_caps;
        if ( __copy_field_to_guest(u_sysctl, sysctl, u.cpu_levelling_caps.caps) )
            ret = -EFAULT;
        break;

    case XEN_SYSCTL_get_cpu_featureset:
    {
        static const struct cpuid_policy *const policy_table[] = {
            [XEN_SYSCTL_cpu_featureset_raw]  = &raw_cpuid_policy,
            [XEN_SYSCTL_cpu_featureset_host] = &host_cpuid_policy,
            [XEN_SYSCTL_cpu_featureset_pv]   = &pv_max_cpuid_policy,
            [XEN_SYSCTL_cpu_featureset_hvm]  = &hvm_max_cpuid_policy,
        };
        const struct cpuid_policy *p = NULL;
        uint32_t featureset[FSCAPINTS];
        unsigned int nr;

        /* Request for maximum number of features? */
        if ( guest_handle_is_null(sysctl->u.cpu_featureset.features) )
        {
            sysctl->u.cpu_featureset.nr_features = FSCAPINTS;
            if ( __copy_field_to_guest(u_sysctl, sysctl,
                                       u.cpu_featureset.nr_features) )
                ret = -EFAULT;
            break;
        }

        /* Clip the number of entries. */
        nr = min_t(unsigned int, sysctl->u.cpu_featureset.nr_features,
                   FSCAPINTS);

        /* Look up requested featureset. */
        if ( sysctl->u.cpu_featureset.index < ARRAY_SIZE(policy_table) )
            p = policy_table[sysctl->u.cpu_featureset.index];

        /* Bad featureset index? */
        if ( !p )
            ret = -EINVAL;
        else
            cpuid_policy_to_featureset(p, featureset);

        /* Copy the requested featureset into place. */
        if ( !ret && copy_to_guest(sysctl->u.cpu_featureset.features,
                                   featureset, nr) )
            ret = -EFAULT;

        /* Inform the caller of how many features we wrote. */
        sysctl->u.cpu_featureset.nr_features = nr;
        if ( !ret && __copy_field_to_guest(u_sysctl, sysctl,
                                           u.cpu_featureset.nr_features) )
            ret = -EFAULT;

        /* Inform the caller if there was more data to provide. */
        if ( !ret && nr < FSCAPINTS )
            ret = -ENOBUFS;

        break;
    }

    case XEN_SYSCTL_get_cpu_policy:
    {
        const struct cpu_policy *policy;

        /* Reserved field set, or bad policy index? */
        if ( sysctl->u.cpu_policy._rsvd ||
             sysctl->u.cpu_policy.index >= ARRAY_SIZE(system_policies) )
        {
            ret = -EINVAL;
            break;
        }
        policy = &system_policies[
            array_index_nospec(sysctl->u.cpu_policy.index,
                               ARRAY_SIZE(system_policies))];

        /* Process the CPUID leaves. */
        if ( guest_handle_is_null(sysctl->u.cpu_policy.cpuid_policy) )
            sysctl->u.cpu_policy.nr_leaves = CPUID_MAX_SERIALISED_LEAVES;
        else if ( (ret = x86_cpuid_copy_to_buffer(
                       policy->cpuid,
                       sysctl->u.cpu_policy.cpuid_policy,
                       &sysctl->u.cpu_policy.nr_leaves)) )
            break;

        if ( __copy_field_to_guest(u_sysctl, sysctl,
                                   u.cpu_policy.nr_leaves) )
        {
            ret = -EFAULT;
            break;
        }

        /* Process the MSR entries. */
        if ( guest_handle_is_null(sysctl->u.cpu_policy.msr_policy) )
            sysctl->u.cpu_policy.nr_msrs = MSR_MAX_SERIALISED_ENTRIES;
        else if ( (ret = x86_msr_copy_to_buffer(
                       policy->msr,
                       sysctl->u.cpu_policy.msr_policy,
                       &sysctl->u.cpu_policy.nr_msrs)) )
            break;

        if ( __copy_field_to_guest(u_sysctl, sysctl,
                                   u.cpu_policy.nr_msrs)  )
            ret = -EFAULT;

        break;
    }

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
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
