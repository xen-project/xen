/*
 *  This work is based on the LSM implementation in Linux 2.6.13.4.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  Contributors: Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#define XSM_NO_WRAPPERS
#include <xsm/dummy.h>

static const struct xsm_ops __initconst_cf_clobber dummy_ops = {
    .set_system_active             = xsm_set_system_active,
    .security_domaininfo           = xsm_security_domaininfo,
    .domain_create                 = xsm_domain_create,
    .getdomaininfo                 = xsm_getdomaininfo,
    .domctl_scheduler_op           = xsm_domctl_scheduler_op,
    .sysctl_scheduler_op           = xsm_sysctl_scheduler_op,
    .set_target                    = xsm_set_target,
    .domctl                        = xsm_domctl,
    .sysctl                        = xsm_sysctl,
    .readconsole                   = xsm_readconsole,

    .evtchn_unbound                = xsm_evtchn_unbound,
    .evtchn_interdomain            = xsm_evtchn_interdomain,
    .evtchn_close_post             = xsm_evtchn_close_post,
    .evtchn_send                   = xsm_evtchn_send,
    .evtchn_status                 = xsm_evtchn_status,
    .evtchn_reset                  = xsm_evtchn_reset,

    .grant_mapref                  = xsm_grant_mapref,
    .grant_unmapref                = xsm_grant_unmapref,
    .grant_setup                   = xsm_grant_setup,
    .grant_transfer                = xsm_grant_transfer,
    .grant_copy                    = xsm_grant_copy,
    .grant_query_size              = xsm_grant_query_size,

    .alloc_security_domain         = xsm_alloc_security_domain,
    .free_security_domain          = xsm_free_security_domain,
    .alloc_security_evtchns        = xsm_alloc_security_evtchns,
    .free_security_evtchns         = xsm_free_security_evtchns,
    .show_security_evtchn          = xsm_show_security_evtchn,
    .init_hardware_domain          = xsm_init_hardware_domain,

    .get_pod_target                = xsm_get_pod_target,
    .set_pod_target                = xsm_set_pod_target,

    .memory_exchange               = xsm_memory_exchange,
    .memory_adjust_reservation     = xsm_memory_adjust_reservation,
    .memory_stat_reservation       = xsm_memory_stat_reservation,
    .memory_pin_page               = xsm_memory_pin_page,
    .claim_pages                   = xsm_claim_pages,

    .console_io                    = xsm_console_io,

    .profile                       = xsm_profile,

    .kexec                         = xsm_kexec,
    .schedop_shutdown              = xsm_schedop_shutdown,

    .show_irq_sid                  = xsm_show_irq_sid,
    .map_domain_pirq               = xsm_map_domain_pirq,
    .map_domain_irq                = xsm_map_domain_irq,
    .unmap_domain_pirq             = xsm_unmap_domain_pirq,
    .unmap_domain_irq              = xsm_unmap_domain_irq,
    .bind_pt_irq                   = xsm_bind_pt_irq,
    .unbind_pt_irq                 = xsm_unbind_pt_irq,
    .irq_permission                = xsm_irq_permission,
    .iomem_permission              = xsm_iomem_permission,
    .iomem_mapping                 = xsm_iomem_mapping,
    .pci_config_permission         = xsm_pci_config_permission,
    .get_vnumainfo                 = xsm_get_vnumainfo,

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
    .get_device_group              = xsm_get_device_group,
    .assign_device                 = xsm_assign_device,
    .deassign_device               = xsm_deassign_device,
#endif

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_DEVICE_TREE)
    .assign_dtdevice               = xsm_assign_dtdevice,
    .deassign_dtdevice             = xsm_deassign_dtdevice,
#endif

    .resource_plug_core            = xsm_resource_plug_core,
    .resource_unplug_core          = xsm_resource_unplug_core,
    .resource_plug_pci             = xsm_resource_plug_pci,
    .resource_unplug_pci           = xsm_resource_unplug_pci,
    .resource_setup_pci            = xsm_resource_setup_pci,
    .resource_setup_gsi            = xsm_resource_setup_gsi,
    .resource_setup_misc           = xsm_resource_setup_misc,

    .page_offline                  = xsm_page_offline,
    .hypfs_op                      = xsm_hypfs_op,
    .hvm_param                     = xsm_hvm_param,
    .hvm_param_altp2mhvm           = xsm_hvm_param_altp2mhvm,
    .hvm_altp2mhvm_op              = xsm_hvm_altp2mhvm_op,

    .do_xsm_op                     = xsm_do_xsm_op,
#ifdef CONFIG_COMPAT
    .do_compat_op                  = xsm_do_compat_op,
#endif

    .add_to_physmap                = xsm_add_to_physmap,
    .remove_from_physmap           = xsm_remove_from_physmap,
    .map_gmfn_foreign              = xsm_map_gmfn_foreign,

    .vm_event_control              = xsm_vm_event_control,

#ifdef CONFIG_MEM_ACCESS
    .mem_access                    = xsm_mem_access,
#endif

#ifdef CONFIG_MEM_PAGING
    .mem_paging                    = xsm_mem_paging,
#endif

#ifdef CONFIG_MEM_SHARING
    .mem_sharing                   = xsm_mem_sharing,
#endif

    .platform_op                   = xsm_platform_op,
#ifdef CONFIG_X86
    .do_mca                        = xsm_do_mca,
    .shadow_control                = xsm_shadow_control,
    .mem_sharing_op                = xsm_mem_sharing_op,
    .apic                          = xsm_apic,
    .machine_memory_map            = xsm_machine_memory_map,
    .domain_memory_map             = xsm_domain_memory_map,
    .mmu_update                    = xsm_mmu_update,
    .mmuext_op                     = xsm_mmuext_op,
    .update_va_mapping             = xsm_update_va_mapping,
    .priv_mapping                  = xsm_priv_mapping,
    .ioport_permission             = xsm_ioport_permission,
    .ioport_mapping                = xsm_ioport_mapping,
    .pmu_op                        = xsm_pmu_op,
#endif
    .dm_op                         = xsm_dm_op,
    .xen_version                   = xsm_xen_version,
    .domain_resource_map           = xsm_domain_resource_map,
#ifdef CONFIG_ARGO
    .argo_enable                   = xsm_argo_enable,
    .argo_register_single_source   = xsm_argo_register_single_source,
    .argo_register_any_source      = xsm_argo_register_any_source,
    .argo_send                     = xsm_argo_send,
#endif
};

void __init xsm_fixup_ops(struct xsm_ops *ops)
{
    /*
     * We make some simplifying assumptions about struct xsm_ops; that it is
     * made exclusively of function pointers to non-init text.
     *
     * This allows us to walk over struct xsm_ops as if it were an array of
     * unsigned longs.
     */
    unsigned long *dst = _p(ops);
    const unsigned long *src = _p(&dummy_ops);

    for ( ; dst < (unsigned long *)(ops + 1); src++, dst++ )
    {
        /*
         * If you encounter this BUG(), then you've most likely added a new
         * XSM hook but failed to provide the default implementation in
         * dummy_ops.
         *
         * If not, then perhaps a function pointer to an init function, or
         * something which isn't a function pointer at all.
         */
        BUG_ON(!is_kernel_text(*src));

        if ( !*dst )
            *dst = *src;
    }
}
