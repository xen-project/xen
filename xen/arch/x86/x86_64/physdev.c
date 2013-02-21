/******************************************************************************
 * physdev.c
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/guest_access.h>
#include <compat/xen.h>
#include <compat/event_channel.h>
#include <compat/physdev.h>
#include <asm/hypercall.h>

#define do_physdev_op compat_physdev_op

#define physdev_apic               compat_physdev_apic
#define physdev_apic_t             physdev_apic_compat_t

#define xen_physdev_eoi physdev_eoi
CHECK_physdev_eoi;
#undef xen_physdev_eoi

#define physdev_pirq_eoi_gmfn      compat_physdev_pirq_eoi_gmfn
#define physdev_pirq_eoi_gmfn_t    physdev_pirq_eoi_gmfn_compat_t

#define physdev_set_iobitmap       compat_physdev_set_iobitmap
#define physdev_set_iobitmap_t     physdev_set_iobitmap_compat_t

#define xen_physdev_set_iopl physdev_set_iopl
CHECK_physdev_set_iopl;
#undef xen_physdev_set_iopl

#define xen_physdev_irq physdev_irq
CHECK_physdev_irq;
#undef xen_physdev_irq

#define xen_physdev_irq_status_query physdev_irq_status_query
CHECK_physdev_irq_status_query;
#undef xen_physdev_irq_status_query

#define physdev_map_pirq_t         physdev_map_pirq_compat_t

#define xen_physdev_unmap_pirq physdev_unmap_pirq
CHECK_physdev_unmap_pirq;
#undef xen_physdev_unmap_pirq

#define xen_physdev_manage_pci physdev_manage_pci
CHECK_physdev_manage_pci;
#undef xen_physdev_manage_pci

#define xen_physdev_manage_pci_ext physdev_manage_pci_ext
CHECK_physdev_manage_pci_ext;
#undef xen_physdev_manage_pci_ext

#define xen_physdev_restore_msi physdev_restore_msi
CHECK_physdev_restore_msi;
#undef xen_physdev_restore_msi

#define xen_physdev_setup_gsi physdev_setup_gsi
CHECK_physdev_setup_gsi;
#undef xen_physdev_setup_gsi

#define xen_physdev_get_free_pirq physdev_get_free_pirq
CHECK_physdev_get_free_pirq;
#undef xen_physdev_get_free_pirq

#define xen_physdev_pci_mmcfg_reserved physdev_pci_mmcfg_reserved
CHECK_physdev_pci_mmcfg_reserved;
#undef xen_physdev_pci_mmcfg_reserved

#define xen_physdev_pci_device_add physdev_pci_device_add
CHECK_physdev_pci_device_add
#undef xen_physdev_pci_device_add

#define xen_physdev_pci_device physdev_pci_device
CHECK_physdev_pci_device
#undef xen_physdev_pci_device

#define COMPAT
#undef guest_handle_okay
#define guest_handle_okay          compat_handle_okay
typedef int ret_t;

#include "../physdev.c"

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
