/*
 *  Default XSM hooks - IS_PRIV and IS_PRIV_FOR checks
 *
 *  Author: Daniel De Graaf <dgdegra@tyhco.nsa.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <xen/sched.h>
#include <xsm/xsm.h>

static XSM_INLINE void xsm_security_domaininfo(struct domain *d,
                                    struct xen_domctl_getdomaininfo *info)
{
    return;
}

static XSM_INLINE int xsm_setvcpucontext(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_pausedomain(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_unpausedomain(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_resumedomain(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_domain_create(struct domain *d, u32 ssidref)
{
    return 0;
}

static XSM_INLINE int xsm_max_vcpus(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_destroydomain(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_vcpuaffinity(int cmd, struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_scheduler(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_getdomaininfo(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_getvcpucontext(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_getvcpuinfo(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_domain_settime(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_set_target(struct domain *d, struct domain *e)
{
    return 0;
}

static XSM_INLINE int xsm_domctl(struct domain *d, int cmd)
{
    switch ( cmd )
    {
    case XEN_DOMCTL_ioport_mapping:
    case XEN_DOMCTL_memory_mapping:
    case XEN_DOMCTL_bind_pt_irq:
    case XEN_DOMCTL_unbind_pt_irq: {
        if ( !IS_PRIV_FOR(current->domain, d) )
            return -EPERM;
        break;
    }
    default:
        if ( !IS_PRIV(current->domain) )
            return -EPERM;
    }
    return 0;
}

static XSM_INLINE int xsm_sysctl(int cmd)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_set_virq_handler(struct domain *d, uint32_t virq)
{
    return 0;
}

static XSM_INLINE int xsm_tbufcontrol(void)
{
    return 0;
}

static XSM_INLINE int xsm_readconsole(uint32_t clear)
{
    return 0;
}

static XSM_INLINE int xsm_sched_id(void)
{
    return 0;
}

static XSM_INLINE int xsm_setdomainmaxmem(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_setdomainhandle(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_setdebugging(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_perfcontrol(void)
{
    return 0;
}

static XSM_INLINE int xsm_debug_keys(void)
{
    return 0;
}

static XSM_INLINE int xsm_getcpuinfo(void)
{
    return 0;
}

static XSM_INLINE int xsm_get_pmstat(void)
{
    return 0;
}

static XSM_INLINE int xsm_setpminfo(void)
{
    return 0;
}

static XSM_INLINE int xsm_pm_op(void)
{
    return 0;
}

static XSM_INLINE int xsm_do_mca(void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_availheap(void)
{
    return 0;
}

static XSM_INLINE int xsm_alloc_security_domain(struct domain *d)
{
    return 0;
}

static XSM_INLINE void xsm_free_security_domain(struct domain *d)
{
    return;
}

static XSM_INLINE int xsm_grant_mapref(struct domain *d1, struct domain *d2,
                                                                uint32_t flags)
{
    return 0;
}

static XSM_INLINE int xsm_grant_unmapref(struct domain *d1, struct domain *d2)
{
    return 0;
}

static XSM_INLINE int xsm_grant_setup(struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_grant_transfer(struct domain *d1, struct domain *d2)
{
    return 0;
}

static XSM_INLINE int xsm_grant_copy(struct domain *d1, struct domain *d2)
{
    return 0;
}

static XSM_INLINE int xsm_grant_query_size(struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_memory_exchange(struct domain *d)
{
    if ( d != current->domain && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_memory_adjust_reservation(struct domain *d1,
                                                            struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_memory_stat_reservation(struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_console_io(struct domain *d, int cmd)
{
#ifndef VERBOSE
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
#endif
    return 0;
}

static XSM_INLINE int xsm_profile(struct domain *d, int op)
{
    return 0;
}

static XSM_INLINE int xsm_kexec(void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_schedop_shutdown(struct domain *d1, struct domain *d2)
{
    if ( !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_memory_pin_page(struct domain *d1, struct domain *d2,
                                          struct page_info *page)
{
    return 0;
}

static XSM_INLINE int xsm_evtchn_unbound(struct domain *d, struct evtchn *chn,
                                         domid_t id2)
{
    if ( current->domain != d && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_evtchn_interdomain(struct domain *d1, struct evtchn
                                *chan1, struct domain *d2, struct evtchn *chan2)
{
    return 0;
}

static XSM_INLINE void xsm_evtchn_close_post(struct evtchn *chn)
{
    return;
}

static XSM_INLINE int xsm_evtchn_send(struct domain *d, struct evtchn *chn)
{
    return 0;
}

static XSM_INLINE int xsm_evtchn_status(struct domain *d, struct evtchn *chn)
{
    if ( current->domain != d && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_evtchn_reset(struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_alloc_security_evtchn(struct evtchn *chn)
{
    return 0;
}

static XSM_INLINE void xsm_free_security_evtchn(struct evtchn *chn)
{
    return;
}

static XSM_INLINE char *xsm_show_security_evtchn(struct domain *d, const struct evtchn *chn)
{
    return NULL;
}

static XSM_INLINE int xsm_get_pod_target(struct domain *d)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_set_pod_target(struct domain *d)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_get_device_group(uint32_t machine_bdf)
{
    return 0;
}

static XSM_INLINE int xsm_test_assign_device(uint32_t machine_bdf)
{
    return 0;
}

static XSM_INLINE int xsm_assign_device(struct domain *d, uint32_t machine_bdf)
{
    return 0;
}

static XSM_INLINE int xsm_deassign_device(struct domain *d, uint32_t machine_bdf)
{
    return 0;
}

static XSM_INLINE int xsm_resource_plug_core(void)
{
    return 0;
}

static XSM_INLINE int xsm_resource_unplug_core(void)
{
    return 0;
}

static XSM_INLINE int xsm_resource_plug_pci(uint32_t machine_bdf)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_resource_unplug_pci(uint32_t machine_bdf)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_resource_setup_pci(uint32_t machine_bdf)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_resource_setup_gsi(int gsi)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_resource_setup_misc(void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_page_offline(uint32_t cmd)
{
    return 0;
}

static XSM_INLINE int xsm_lockprof(void)
{
    return 0;
}

static XSM_INLINE int xsm_cpupool_op(void)
{
    return 0;
}

static XSM_INLINE int xsm_sched_op(void)
{
    return 0;
}

static XSM_INLINE long xsm_do_xsm_op(XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    return -ENOSYS;
}

static XSM_INLINE char *xsm_show_irq_sid(int irq)
{
    return NULL;
}

static XSM_INLINE int xsm_map_domain_pirq(struct domain *d, int irq, void *data)
{
    return 0;
}

static XSM_INLINE int xsm_unmap_domain_pirq(struct domain *d, int irq)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_irq_permission(struct domain *d, int pirq, uint8_t allow)
{
    return 0;
}

static XSM_INLINE int xsm_iomem_permission(struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return 0;
}

static XSM_INLINE int xsm_iomem_mapping(struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return 0;
}

static XSM_INLINE int xsm_pci_config_permission(struct domain *d, uint32_t machine_bdf,
                                        uint16_t start, uint16_t end,
                                        uint8_t access)
{
    return 0;
}

#ifdef CONFIG_X86
static XSM_INLINE int xsm_shadow_control(struct domain *d, uint32_t op)
{
    return 0;
}

static XSM_INLINE int xsm_getpageframeinfo(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_getmemlist(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_hypercall_init(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_hvmcontext(struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_INLINE int xsm_address_size(struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_INLINE int xsm_machine_address_size(struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_INLINE int xsm_hvm_param(struct domain *d, unsigned long op)
{
    if ( current->domain != d && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_hvm_set_pci_intx_level(struct domain *d)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_hvm_set_isa_irq_level(struct domain *d)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_hvm_set_pci_link_route(struct domain *d)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_hvm_inject_msi(struct domain *d)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_mem_event_setup(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_mem_event_control(struct domain *d, int mode, int op)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_mem_event_op(struct domain *d, int op)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_mem_sharing(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_mem_sharing_op(struct domain *d, struct domain *cd, int op)
{
    if ( !IS_PRIV_FOR(current->domain, cd) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_apic(struct domain *d, int cmd)
{
    if ( !IS_PRIV(d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_xen_settime(void)
{
    return 0;
}

static XSM_INLINE int xsm_memtype(uint32_t access)
{
    return 0;
}

static XSM_INLINE int xsm_microcode(void)
{
    return 0;
}

static XSM_INLINE int xsm_physinfo(void)
{
    return 0;
}

static XSM_INLINE int xsm_platform_quirk(uint32_t quirk)
{
    return 0;
}

static XSM_INLINE int xsm_platform_op(uint32_t op)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_firmware_info(void)
{
    return 0;
}

static XSM_INLINE int xsm_efi_call(void)
{
    return 0;
}

static XSM_INLINE int xsm_acpi_sleep(void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_change_freq(void)
{
    return 0;
}

static XSM_INLINE int xsm_getidletime(void)
{
    return 0;
}

static XSM_INLINE int xsm_machine_memory_map(void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_domain_memory_map(struct domain *d)
{
    if ( current->domain != d && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_mmu_update(struct domain *d, struct domain *t,
                                     struct domain *f, uint32_t flags)
{
    if ( t && d != t && !IS_PRIV_FOR(d, t) )
        return -EPERM;
    if ( d != f && !IS_PRIV_FOR(d, f) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_mmuext_op(struct domain *d, struct domain *f)
{
    if ( d != f && !IS_PRIV_FOR(d, f) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_update_va_mapping(struct domain *d, struct domain *f, 
                                                            l1_pgentry_t pte)
{
    if ( d != f && !IS_PRIV_FOR(d, f) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_add_to_physmap(struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_remove_from_physmap(struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_INLINE int xsm_sendtrigger(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_bind_pt_irq(struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    return 0;
}

static XSM_INLINE int xsm_unbind_pt_irq(struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    return 0;
}

static XSM_INLINE int xsm_pin_mem_cacheattr(struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_ext_vcpucontext(struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_INLINE int xsm_vcpuextstate(struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_INLINE int xsm_ioport_permission(struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return 0;
}

static XSM_INLINE int xsm_ioport_mapping(struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return 0;
}

#endif
