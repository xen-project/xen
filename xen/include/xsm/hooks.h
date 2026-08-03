/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This file is intended to be included multiple times. */

#ifndef XSM_HOOK

#include <xen/macros.h>

#define XSM_HOOK__(rtype, name, nargs, types...) \
    XSM_HOOK ## nargs(rtype, name, ## types)

#define XSM_HOOK_(rtype, name, nargs, types...) \
    XSM_HOOK__(rtype, name, nargs, ## types)

#define XSM_HOOK(rtype, name, types...) \
    XSM_HOOK_(rtype, name, count_args(types), ## types)

#endif /* XSM_HOOK */

XSM_HOOK(int, domain_create, struct domain *, uint32_t)
XSM_HOOK(int, getdomaininfo, struct domain *)
XSM_HOOK(int, get_domain_state, struct domain *)

#ifdef CONFIG_SYSCTL
XSM_HOOK(int, sysctl, const struct xen_sysctl *)
#endif

XSM_HOOK(int, set_target, struct domain *, struct domain *)
XSM_HOOK(int, domctl, struct domain *, struct xen_domctl *)

XSM_HOOK(int, evtchn_unbound, struct domain *, struct evtchn *, domid_t)
XSM_HOOK(int, evtchn_interdomain, struct domain *, struct evtchn *,
                                  struct domain *, struct evtchn *)
XSM_HOOK(int, evtchn_send, struct domain *, struct evtchn *)
XSM_HOOK(int, evtchn_status, struct domain *, struct evtchn *)
XSM_HOOK(int, evtchn_reset, struct domain *, struct domain *)

#ifdef CONFIG_GRANT_TABLE
XSM_HOOK(int, grant_mapref, struct domain *, struct domain *, uint32_t)
XSM_HOOK(int, grant_unmapref, struct domain *, struct domain *)
XSM_HOOK(int, grant_setup, struct domain *, struct domain *)
XSM_HOOK(int, grant_transfer, struct domain *, struct domain *)
XSM_HOOK(int, grant_copy, struct domain *, struct domain *)
XSM_HOOK(int, grant_query_size, struct domain *, struct domain *)
#endif

XSM_HOOK(int, init_hardware_domain, struct domain *)

XSM_HOOK(int, get_pod_target, struct domain *)
XSM_HOOK(int, set_pod_target, struct domain *)

XSM_HOOK(int, memory_exchange, struct domain *)
XSM_HOOK(int, memory_adjust_reservation, struct domain *, struct domain *)
XSM_HOOK(int, memory_stat_reservation, struct domain *, struct domain *)
XSM_HOOK(int, memory_pin_page, struct domain *, struct domain *,
                               struct page_info *)
XSM_HOOK(int, add_to_physmap, struct domain *, struct domain *)
XSM_HOOK(int, remove_from_physmap, struct domain *, struct domain *)
XSM_HOOK(int, map_gmfn_foreign, struct domain *, struct domain *)
XSM_HOOK(int, claim_pages, struct domain *)

XSM_HOOK(int, console_io, struct domain *, int)

#ifdef CONFIG_KEXEC
XSM_HOOK(int, kexec)
#endif

XSM_HOOK(int, schedop_shutdown, struct domain *, struct domain *)

#ifdef CONFIG_HAS_PIRQ
XSM_HOOK(int, map_domain_pirq, struct domain *)
XSM_HOOK(int, unmap_domain_pirq, struct domain *)
#endif

XSM_HOOK(int, map_domain_irq, struct domain *, int, const void *)
XSM_HOOK(int, unmap_domain_irq, struct domain *, int, const void *)
XSM_HOOK(int, bind_pt_irq, struct domain *, struct xen_domctl_bind_pt_irq *)
XSM_HOOK(int, unbind_pt_irq, struct domain *, struct xen_domctl_bind_pt_irq *)

XSM_HOOK(int, irq_permission, struct domain *, int, uint8_t)
XSM_HOOK(int, iomem_permission, struct domain *, uint64_t, uint64_t, uint8_t)

XSM_HOOK(int, iomem_mapping, struct domain *, uint64_t, uint64_t, uint8_t)
#ifdef CONFIG_HAS_VPCI
XSM_HOOK(int, iomem_mapping_vpci, struct domain *, uint64_t, uint64_t, uint8_t)
#endif

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
XSM_HOOK(int, resource_plug_pci, uint32_t)
XSM_HOOK(int, resource_unplug_pci, uint32_t)
XSM_HOOK(int, get_device_group, uint32_t)
#endif

XSM_HOOK(int, resource_setup_misc)

#ifdef CONFIG_HAS_PCI
XSM_HOOK(int, resource_setup_pci, uint32_t)
XSM_HOOK(int, resource_setup_gsi, int)
XSM_HOOK(int, pci_config_permission, struct domain *, uint32_t, uint16_t,
                                     uint16_t, uint8_t)
#endif

#ifdef CONFIG_HYPFS
XSM_HOOK(int, hypfs_op)
#endif

#ifdef CONFIG_HVM
XSM_HOOK(int, hvm_param, struct domain *, unsigned long)
XSM_HOOK(int, hvm_param_altp2mhvm, struct domain *)
#endif

#ifdef CONFIG_ALTP2M
XSM_HOOK(int, hvm_altp2mhvm_op, struct domain *, uint64_t, uint32_t)
#endif

XSM_HOOK(int, get_vnumainfo, struct domain *)

#ifdef CONFIG_VM_EVENT
XSM_HOOK(int, mem_access, struct domain *)
#endif

#ifdef CONFIG_MEM_PAGING
XSM_HOOK(int, mem_paging, struct domain *)
#endif

#ifdef CONFIG_MEM_SHARING
XSM_HOOK(int, mem_sharing, struct domain *)
XSM_HOOK(int, mem_sharing_op, struct domain *, struct domain *, int)
#endif

XSM_HOOK(int, platform_op, uint32_t)

#ifdef CONFIG_X86
XSM_HOOK(int, do_mca)
XSM_HOOK(int, apic, struct domain *, int)
XSM_HOOK(int, machine_memory_map)
XSM_HOOK(int, domain_memory_map, struct domain *)
XSM_HOOK(int, mmu_update, struct domain *, struct domain *, struct domain *,
                          uint32_t)
XSM_HOOK(int, mmuext_op, struct domain *, struct domain *)
XSM_HOOK(int, update_va_mapping, struct domain *, struct domain *, l1_pgentry_t)
XSM_HOOK(int, priv_mapping, struct domain *, struct domain *)
XSM_HOOK(int, ioport_permission, struct domain *, uint32_t, uint32_t, uint8_t)
XSM_HOOK(int, ioport_mapping, struct domain *, uint32_t, uint32_t, uint8_t)
XSM_HOOK(int, pmu_op, struct domain *, unsigned int)
#endif /* CONFIG_X86 */

#ifdef CONFIG_IOREQ_SERVER
XSM_HOOK(int, dm_op, struct domain *)
#endif

XSM_HOOK(int, xen_version, uint32_t)
XSM_HOOK(int, domain_resource_map, struct domain *)

#undef XSM_HOOK0
#undef XSM_HOOK1
#undef XSM_HOOK2
#undef XSM_HOOK3
#undef XSM_HOOK4
#undef XSM_HOOK5
