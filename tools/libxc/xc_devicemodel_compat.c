/*
 * Compat shims for use of 3rd party consumers of libxenctrl device model
 * functionality which has been split into separate libraries.
 */

#define XC_WANT_COMPAT_DEVICEMODEL_API
#include "xc_private.h"

int xc_hvm_create_ioreq_server(
    xc_interface *xch, uint32_t domid, int handle_bufioreq,
    ioservid_t *id)
{
    return xendevicemodel_create_ioreq_server(xch->dmod, domid,
                                              handle_bufioreq, id);
}

int xc_hvm_get_ioreq_server_info(
    xc_interface *xch, uint32_t domid, ioservid_t id, xen_pfn_t *ioreq_pfn,
    xen_pfn_t *bufioreq_pfn, evtchn_port_t *bufioreq_port)
{
    return xendevicemodel_get_ioreq_server_info(xch->dmod, domid, id,
                                                ioreq_pfn, bufioreq_pfn,
                                                bufioreq_port);
}

int xc_hvm_map_io_range_to_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id, int is_mmio,
    uint64_t start, uint64_t end)
{
    return xendevicemodel_map_io_range_to_ioreq_server(xch->dmod, domid,
                                                       id, is_mmio, start,
                                                       end);
}

int xc_hvm_unmap_io_range_from_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id, int is_mmio,
    uint64_t start, uint64_t end)
{
    return xendevicemodel_unmap_io_range_from_ioreq_server(xch->dmod, domid,
                                                           id, is_mmio,
                                                           start, end);
}

int xc_hvm_map_pcidev_to_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id, uint16_t segment,
    uint8_t bus, uint8_t device, uint8_t function)
{
    return xendevicemodel_map_pcidev_to_ioreq_server(xch->dmod, domid, id,
                                                     segment, bus, device,
                                                     function);
}

int xc_hvm_unmap_pcidev_from_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id, uint16_t segment,
    uint8_t bus, uint8_t device, uint8_t function)
{
    return xendevicemodel_unmap_pcidev_from_ioreq_server(xch->dmod, domid,
                                                         id, segment, bus,
                                                         device, function);
}

int xc_hvm_destroy_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id)
{
    return xendevicemodel_destroy_ioreq_server(xch->dmod, domid, id);
}

int xc_hvm_set_ioreq_server_state(
    xc_interface *xch, uint32_t domid, ioservid_t id, int enabled)
{
    return xendevicemodel_set_ioreq_server_state(xch->dmod, domid, id,
                                                 enabled);
}

int xc_hvm_set_pci_intx_level(
    xc_interface *xch, uint32_t domid, uint16_t segment, uint8_t bus,
    uint8_t device, uint8_t intx, unsigned int level)
{
    return xendevicemodel_set_pci_intx_level(xch->dmod, domid, segment,
                                             bus, device, intx, level);
}

int xc_hvm_set_isa_irq_level(
    xc_interface *xch, uint32_t domid, uint8_t irq, unsigned int level)
{
    return xendevicemodel_set_isa_irq_level(xch->dmod, domid, irq, level);
}

int xc_hvm_set_pci_link_route(
    xc_interface *xch, uint32_t domid, uint8_t link, uint8_t irq)
{
    return xendevicemodel_set_pci_link_route(xch->dmod, domid, link, irq);
}

int xc_hvm_inject_msi(
    xc_interface *xch, uint32_t domid, uint64_t msi_addr, uint32_t msi_data)
{
    return xendevicemodel_inject_msi(xch->dmod, domid, msi_addr, msi_data);
}

int xc_hvm_track_dirty_vram(
    xc_interface *xch, uint32_t domid, uint64_t first_pfn, uint32_t nr,
    unsigned long *dirty_bitmap)
{
    return xendevicemodel_track_dirty_vram(xch->dmod, domid, first_pfn,
                                           nr, dirty_bitmap);
}

int xc_hvm_modified_memory(
    xc_interface *xch, uint32_t domid, uint64_t first_pfn, uint32_t nr)
{
    return xendevicemodel_modified_memory(xch->dmod, domid, first_pfn, nr);
}

int xc_hvm_set_mem_type(
    xc_interface *xch, uint32_t domid, hvmmem_type_t type,
    uint64_t first_pfn, uint32_t nr)
{
    return xendevicemodel_set_mem_type(xch->dmod, domid, type, first_pfn,
                                       nr);
}

int xc_hvm_inject_trap(
    xc_interface *xch, uint32_t domid, int vcpu, uint8_t vector,
    uint8_t type, uint32_t error_code, uint8_t insn_len, uint64_t cr2)
{
    return xendevicemodel_inject_event(xch->dmod, domid, vcpu, vector,
                                       type, error_code, insn_len, cr2);
}

int xc_domain_pin_memory_cacheattr(
    xc_interface *xch, uint32_t domid, uint64_t start, uint64_t end,
    uint32_t type)
{
    return xendevicemodel_pin_memory_cacheattr(xch->dmod, domid, start, end,
                                               type);
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
