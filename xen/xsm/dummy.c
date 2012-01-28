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

#include <xen/sched.h>
#include <xsm/xsm.h>

static void dummy_security_domaininfo(struct domain *d,
                                    struct xen_domctl_getdomaininfo *info)
{
    return;
}

static int dummy_setvcpucontext(struct domain *d)
{
    return 0;
}

static int dummy_pausedomain (struct domain *d)
{
    return 0;
}

static int dummy_unpausedomain (struct domain *d)
{
    return 0;
}

static int dummy_resumedomain (struct domain *d)
{
    return 0;
}

static int dummy_domain_create(struct domain *d, u32 ssidref)
{
    return 0;
}

static int dummy_max_vcpus(struct domain *d)
{
    return 0;
}

static int dummy_destroydomain (struct domain *d)
{
    return 0;
}

static int dummy_vcpuaffinity (int cmd, struct domain *d)
{
    return 0;
}

static int dummy_scheduler (struct domain *d)
{
    return 0;
}

static int dummy_getdomaininfo (struct domain *d)
{
    return 0;
}

static int dummy_getvcpucontext (struct domain *d)
{
    return 0;
}

static int dummy_getvcpuinfo (struct domain *d)
{
    return 0;
}

static int dummy_domain_settime (struct domain *d)
{
    return 0;
}

static int dummy_set_target (struct domain *d, struct domain *e)
{
    return 0;
}

static int dummy_domctl(struct domain *d, int cmd)
{
    return 0;
}

static int dummy_tbufcontrol (void)
{
    return 0;
}

static int dummy_readconsole (uint32_t clear)
{
    return 0;
}

static int dummy_sched_id (void)
{
    return 0;
}

static int dummy_setdomainmaxmem (struct domain *d)
{
    return 0;
}

static int dummy_setdomainhandle (struct domain *d)
{
    return 0;
}

static int dummy_setdebugging (struct domain *d)
{
    return 0;
}

static int dummy_perfcontrol (void)
{
    return 0;
}

static int dummy_debug_keys (void)
{
    return 0;
}

static int dummy_getcpuinfo (void)
{
    return 0;
}

static int dummy_get_pmstat (void)
{
    return 0;
}

static int dummy_setpminfo (void)
{
    return 0;
}

static int dummy_pm_op (void)
{
    return 0;
}

static int dummy_do_mca (void)
{
    return 0;
}

static int dummy_availheap (void)
{
    return 0;
}

static int dummy_alloc_security_domain (struct domain *d)
{
    return 0;
}

static void dummy_free_security_domain (struct domain *d)
{
    return;
}

static int dummy_grant_mapref (struct domain *d1, struct domain *d2,
                                                                uint32_t flags)
{
    return 0;
}

static int dummy_grant_unmapref (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_grant_setup (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_grant_transfer (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_grant_copy (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_grant_query_size (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_memory_adjust_reservation (struct domain *d1,
                                                            struct domain *d2)
{
    return 0;
}

static int dummy_memory_stat_reservation (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_console_io (struct domain *d, int cmd)
{
    return 0;
}

static int dummy_profile (struct domain *d, int op)
{
    return 0;
}

static int dummy_kexec (void)
{
    return 0;
}

static int dummy_schedop_shutdown (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_memory_pin_page(struct domain *d, struct page_info *page)
{
    return 0;
}

static int dummy_evtchn_unbound (struct domain *d, struct evtchn *chn,
                                                                    domid_t id2)
{
    return 0;
}

static int dummy_evtchn_interdomain (struct domain *d1, struct evtchn
                                *chan1, struct domain *d2, struct evtchn *chan2)
{
    return 0;
}

static void dummy_evtchn_close_post (struct evtchn *chn)
{
    return;
}

static int dummy_evtchn_send (struct domain *d, struct evtchn *chn)
{
    return 0;
}

static int dummy_evtchn_status (struct domain *d, struct evtchn *chn)
{
    return 0;
}

static int dummy_evtchn_reset (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_alloc_security_evtchn (struct evtchn *chn)
{
    return 0;
}

static void dummy_free_security_evtchn (struct evtchn *chn)
{
    return;
}

static int dummy_test_assign_device (uint32_t machine_bdf)
{
    return 0;
}

static int dummy_assign_device (struct domain *d, uint32_t machine_bdf)
{
    return 0;
}

static int dummy_deassign_device (struct domain *d, uint32_t machine_bdf)
{
    return 0;
}

static int dummy_resource_plug_core (void)
{
    return 0;
}

static int dummy_resource_unplug_core (void)
{
    return 0;
}

static int dummy_resource_plug_pci (uint32_t machine_bdf)
{
    return 0;
}

static int dummy_resource_unplug_pci (uint32_t machine_bdf)
{
    return 0;
}

static int dummy_resource_setup_pci (uint32_t machine_bdf)
{
    return 0;
}

static int dummy_resource_setup_gsi (int gsi)
{
    return 0;
}

static int dummy_resource_setup_misc (void)
{
    return 0;
}

static int dummy_page_offline (uint32_t cmd)
{
    return 0;
}

static int dummy_lockprof (void)
{
    return 0;
}

static int dummy_cpupool_op (void)
{
    return 0;
}

static int dummy_sched_op (void)
{
    return 0;
}


static long dummy___do_xsm_op(XEN_GUEST_HANDLE(xsm_op_t) op)
{
    return -ENOSYS;
}

static int dummy_irq_permission (struct domain *d, int pirq, uint8_t allow)
{
    return 0;
}

static int dummy_iomem_permission (struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return 0;
}

static int dummy_pci_config_permission (struct domain *d, uint32_t machine_bdf,
                                        uint16_t start, uint16_t end,
                                        uint8_t access)
{
    return 0;
}

#ifdef CONFIG_X86
static int dummy_shadow_control (struct domain *d, uint32_t op)
{
    return 0;
}

static int dummy_getpageframeinfo (struct page_info *page)
{
    return 0;
}

static int dummy_getmemlist (struct domain *d)
{
    return 0;
}

static int dummy_hypercall_init (struct domain *d)
{
    return 0;
}

static int dummy_hvmcontext (struct domain *d, uint32_t cmd)
{
    return 0;
}

static int dummy_address_size (struct domain *d, uint32_t cmd)
{
    return 0;
}

static int dummy_machine_address_size (struct domain *d, uint32_t cmd)
{
    return 0;
}

static int dummy_hvm_param (struct domain *d, unsigned long op)
{
    return 0;
}

static int dummy_hvm_set_pci_intx_level (struct domain *d)
{
    return 0;
}

static int dummy_hvm_set_isa_irq_level (struct domain *d)
{
    return 0;
}

static int dummy_hvm_set_pci_link_route (struct domain *d)
{
    return 0;
}

static int dummy_hvm_inject_msi (struct domain *d)
{
    return 0;
}

static int dummy_mem_event (struct domain *d)
{
    return 0;
}

static int dummy_mem_sharing (struct domain *d)
{
    return 0;
}

static int dummy_apic (struct domain *d, int cmd)
{
    return 0;
}

static int dummy_xen_settime (void)
{
    return 0;
}

static int dummy_memtype (uint32_t access)
{
    return 0;
}

static int dummy_microcode (void)
{
    return 0;
}

static int dummy_physinfo (void)
{
    return 0;
}

static int dummy_platform_quirk (uint32_t quirk)
{
    return 0;
}

static int dummy_firmware_info (void)
{
    return 0;
}

static int dummy_acpi_sleep (void)
{
    return 0;
}

static int dummy_change_freq (void)
{
    return 0;
}

static int dummy_getidletime (void)
{
    return 0;
}

static int dummy_machine_memory_map (void)
{
    return 0;
}

static int dummy_domain_memory_map (struct domain *d)
{
    return 0;
}

static int dummy_mmu_normal_update (struct domain *d, struct domain *t,
                                    struct domain *f, intpte_t fpte)
{
    return 0;
}

static int dummy_mmu_machphys_update (struct domain *d, unsigned long mfn)
{
    return 0;
}

static int dummy_update_va_mapping (struct domain *d, struct domain *f, 
                                                            l1_pgentry_t pte)
{
    return 0;
}

static int dummy_add_to_physmap (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_remove_from_physmap (struct domain *d1, struct domain *d2)
{
    return 0;
}

static int dummy_sendtrigger (struct domain *d)
{
    return 0;
}

static int dummy_bind_pt_irq (struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    return 0;
}

static int dummy_pin_mem_cacheattr (struct domain *d)
{
    return 0;
}

static int dummy_ext_vcpucontext (struct domain *d, uint32_t cmd)
{
    return 0;
}

static int dummy_vcpuextstate (struct domain *d, uint32_t cmd)
{
    return 0;
}

static int dummy_ioport_permission (struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return 0;
}
#endif

struct xsm_operations dummy_xsm_ops;

#define set_to_dummy_if_null(ops, function)                            \
    do {                                                               \
        if ( !ops->function )                                          \
        {                                                              \
            ops->function = dummy_##function;                          \
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

    set_to_dummy_if_null(ops, memory_adjust_reservation);
    set_to_dummy_if_null(ops, memory_stat_reservation);
    set_to_dummy_if_null(ops, memory_pin_page);

    set_to_dummy_if_null(ops, console_io);

    set_to_dummy_if_null(ops, profile);

    set_to_dummy_if_null(ops, kexec);
    set_to_dummy_if_null(ops, schedop_shutdown);

    set_to_dummy_if_null(ops, irq_permission);
    set_to_dummy_if_null(ops, iomem_permission);
    set_to_dummy_if_null(ops, pci_config_permission);

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

    set_to_dummy_if_null(ops, __do_xsm_op);

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
    set_to_dummy_if_null(ops, pin_mem_cacheattr);
    set_to_dummy_if_null(ops, ext_vcpucontext);
    set_to_dummy_if_null(ops, vcpuextstate);
    set_to_dummy_if_null(ops, ioport_permission);
#endif
}
