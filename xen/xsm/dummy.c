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
#define XSM_INLINE /* */
#include <xsm/dummy.h>

struct xsm_operations dummy_xsm_ops;

#define set_to_dummy_if_null(ops, function)                            \
    do {                                                               \
        if ( !ops->function )                                          \
        {                                                              \
            ops->function = xsm_##function;                            \
            if (ops != &dummy_xsm_ops)                                 \
                dprintk(XENLOG_DEBUG, "Had to override the " #function \
                    " security operation with the dummy one.\n");      \
        }                                                              \
    } while (0)

void xsm_fixup_ops (struct xsm_operations *ops)
{
    set_to_dummy_if_null(ops, security_domaininfo);
    set_to_dummy_if_null(ops, setvcpucontext);
    set_to_dummy_if_null(ops, pausedomain);
    set_to_dummy_if_null(ops, unpausedomain);
    set_to_dummy_if_null(ops, resumedomain);
    set_to_dummy_if_null(ops, domain_create);
    set_to_dummy_if_null(ops, max_vcpus);
    set_to_dummy_if_null(ops, destroydomain);
    set_to_dummy_if_null(ops, vcpuaffinity);
    set_to_dummy_if_null(ops, scheduler);
    set_to_dummy_if_null(ops, getdomaininfo);
    set_to_dummy_if_null(ops, getvcpucontext);
    set_to_dummy_if_null(ops, getvcpuinfo);
    set_to_dummy_if_null(ops, domain_settime);
    set_to_dummy_if_null(ops, set_target);
    set_to_dummy_if_null(ops, domctl);
    set_to_dummy_if_null(ops, sysctl);
    set_to_dummy_if_null(ops, set_virq_handler);
    set_to_dummy_if_null(ops, tbufcontrol);
    set_to_dummy_if_null(ops, readconsole);
    set_to_dummy_if_null(ops, sched_id);
    set_to_dummy_if_null(ops, setdomainmaxmem);
    set_to_dummy_if_null(ops, setdomainhandle);
    set_to_dummy_if_null(ops, setdebugging);
    set_to_dummy_if_null(ops, perfcontrol);
    set_to_dummy_if_null(ops, debug_keys);
    set_to_dummy_if_null(ops, getcpuinfo);
    set_to_dummy_if_null(ops, availheap);
    set_to_dummy_if_null(ops, get_pmstat);
    set_to_dummy_if_null(ops, setpminfo);
    set_to_dummy_if_null(ops, pm_op);
    set_to_dummy_if_null(ops, do_mca);

    set_to_dummy_if_null(ops, evtchn_unbound);
    set_to_dummy_if_null(ops, evtchn_interdomain);
    set_to_dummy_if_null(ops, evtchn_close_post);
    set_to_dummy_if_null(ops, evtchn_send);
    set_to_dummy_if_null(ops, evtchn_status);
    set_to_dummy_if_null(ops, evtchn_reset);

    set_to_dummy_if_null(ops, grant_mapref);
    set_to_dummy_if_null(ops, grant_unmapref);
    set_to_dummy_if_null(ops, grant_setup);
    set_to_dummy_if_null(ops, grant_transfer);
    set_to_dummy_if_null(ops, grant_copy);
    set_to_dummy_if_null(ops, grant_query_size);

    set_to_dummy_if_null(ops, alloc_security_domain);
    set_to_dummy_if_null(ops, free_security_domain);
    set_to_dummy_if_null(ops, alloc_security_evtchn);
    set_to_dummy_if_null(ops, free_security_evtchn);
    set_to_dummy_if_null(ops, show_security_evtchn);
    set_to_dummy_if_null(ops, get_pod_target);
    set_to_dummy_if_null(ops, set_pod_target);

    set_to_dummy_if_null(ops, memory_adjust_reservation);
    set_to_dummy_if_null(ops, memory_stat_reservation);
    set_to_dummy_if_null(ops, memory_pin_page);

    set_to_dummy_if_null(ops, console_io);

    set_to_dummy_if_null(ops, profile);

    set_to_dummy_if_null(ops, kexec);
    set_to_dummy_if_null(ops, schedop_shutdown);

    set_to_dummy_if_null(ops, show_irq_sid);
    set_to_dummy_if_null(ops, map_domain_pirq);
    set_to_dummy_if_null(ops, unmap_domain_pirq);
    set_to_dummy_if_null(ops, irq_permission);
    set_to_dummy_if_null(ops, iomem_permission);
    set_to_dummy_if_null(ops, iomem_mapping);
    set_to_dummy_if_null(ops, pci_config_permission);

    set_to_dummy_if_null(ops, get_device_group);
    set_to_dummy_if_null(ops, test_assign_device);
    set_to_dummy_if_null(ops, assign_device);
    set_to_dummy_if_null(ops, deassign_device);

    set_to_dummy_if_null(ops, resource_plug_core);
    set_to_dummy_if_null(ops, resource_unplug_core);
    set_to_dummy_if_null(ops, resource_plug_pci);
    set_to_dummy_if_null(ops, resource_unplug_pci);
    set_to_dummy_if_null(ops, resource_setup_pci);
    set_to_dummy_if_null(ops, resource_setup_gsi);
    set_to_dummy_if_null(ops, resource_setup_misc);

    set_to_dummy_if_null(ops, page_offline);
    set_to_dummy_if_null(ops, lockprof);
    set_to_dummy_if_null(ops, cpupool_op);
    set_to_dummy_if_null(ops, sched_op);

    set_to_dummy_if_null(ops, do_xsm_op);

#ifdef CONFIG_X86
    set_to_dummy_if_null(ops, shadow_control);
    set_to_dummy_if_null(ops, getpageframeinfo);
    set_to_dummy_if_null(ops, getmemlist);
    set_to_dummy_if_null(ops, hypercall_init);
    set_to_dummy_if_null(ops, hvmcontext);
    set_to_dummy_if_null(ops, address_size);
    set_to_dummy_if_null(ops, machine_address_size);
    set_to_dummy_if_null(ops, hvm_param);
    set_to_dummy_if_null(ops, hvm_set_pci_intx_level);
    set_to_dummy_if_null(ops, hvm_set_isa_irq_level);
    set_to_dummy_if_null(ops, hvm_set_pci_link_route);
    set_to_dummy_if_null(ops, hvm_inject_msi);
    set_to_dummy_if_null(ops, mem_event);
    set_to_dummy_if_null(ops, mem_sharing);
    set_to_dummy_if_null(ops, apic);
    set_to_dummy_if_null(ops, xen_settime);
    set_to_dummy_if_null(ops, memtype);
    set_to_dummy_if_null(ops, microcode);
    set_to_dummy_if_null(ops, physinfo);
    set_to_dummy_if_null(ops, platform_quirk);
    set_to_dummy_if_null(ops, firmware_info);
    set_to_dummy_if_null(ops, efi_call);
    set_to_dummy_if_null(ops, acpi_sleep);
    set_to_dummy_if_null(ops, change_freq);
    set_to_dummy_if_null(ops, getidletime);
    set_to_dummy_if_null(ops, machine_memory_map);
    set_to_dummy_if_null(ops, domain_memory_map);
    set_to_dummy_if_null(ops, mmu_normal_update);
    set_to_dummy_if_null(ops, mmu_machphys_update);
    set_to_dummy_if_null(ops, update_va_mapping);
    set_to_dummy_if_null(ops, add_to_physmap);
    set_to_dummy_if_null(ops, remove_from_physmap);
    set_to_dummy_if_null(ops, sendtrigger);
    set_to_dummy_if_null(ops, bind_pt_irq);
    set_to_dummy_if_null(ops, unbind_pt_irq);
    set_to_dummy_if_null(ops, pin_mem_cacheattr);
    set_to_dummy_if_null(ops, ext_vcpucontext);
    set_to_dummy_if_null(ops, vcpuextstate);
    set_to_dummy_if_null(ops, ioport_permission);
    set_to_dummy_if_null(ops, ioport_mapping);
#endif
}
