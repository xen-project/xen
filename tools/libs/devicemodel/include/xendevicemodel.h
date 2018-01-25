/*
 * Copyright (c) 2017 Citrix Systems Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef XENDEVICEMODEL_H
#define XENDEVICEMODEL_H

#ifdef __XEN_TOOLS__

#include <stdint.h>

#include <xen/xen.h>
#include <xen/hvm/dm_op.h>
#include <xen/hvm/hvm_op.h>

/* Callers who don't care don't need to #include <xentoollog.h> */
struct xentoollog_logger;

typedef struct xendevicemodel_handle xendevicemodel_handle;

xendevicemodel_handle *xendevicemodel_open(struct xentoollog_logger *logger,
                                           unsigned int open_flags);

int xendevicemodel_close(xendevicemodel_handle *dmod);

/*
 * IOREQ Server API. (See section on IOREQ Servers in public/hvm_op.h).
 */

/**
 * This function instantiates an IOREQ Server.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm handle_bufioreq how should the IOREQ Server handle buffered
 *                       requests (HVM_IOREQSRV_BUFIOREQ_*)?
 * @parm id pointer to an ioservid_t to receive the IOREQ Server id.
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_create_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, int handle_bufioreq,
    ioservid_t *id);

/**
 * This function retrieves the necessary information to allow an
 * emulator to use an IOREQ Server.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm id the IOREQ Server id.
 * @parm ioreq_gfn pointer to a xen_pfn_t to receive the synchronous ioreq
 *                  gfn
 * @parm bufioreq_gfn pointer to a xen_pfn_t to receive the buffered ioreq
 *                    gfn
 * @parm bufioreq_port pointer to a evtchn_port_t to receive the buffered
 *                     ioreq event channel
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_get_ioreq_server_info(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id,
    xen_pfn_t *ioreq_gfn, xen_pfn_t *bufioreq_gfn,
    evtchn_port_t *bufioreq_port);

/**
 * This function registers a range of memory or I/O ports for emulation.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm id the IOREQ Server id.
 * @parm is_mmio is this a range of ports or memory
 * @parm start start of range
 * @parm end end of range (inclusive).
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_map_io_range_to_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id, int is_mmio,
    uint64_t start, uint64_t end);

/**
 * This function deregisters a range of memory or I/O ports for emulation.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm id the IOREQ Server id.
 * @parm is_mmio is this a range of ports or memory
 * @parm start start of range
 * @parm end end of range (inclusive).
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_unmap_io_range_from_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id, int is_mmio,
    uint64_t start, uint64_t end);

/**
 * This function registers/deregisters a memory type for emulation.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced.
 * @parm id the IOREQ Server id.
 * @parm type the memory type to be emulated. For now, only HVMMEM_ioreq_server
 *            is supported, and in the future new types can be introduced, e.g.
 *            HVMMEM_ioreq_serverX mapped to ioreq server X.
 * @parm flags operations to be emulated; 0 for unmap. For now, only write
 *             operations will be emulated and can be extended to emulate
 *             read ones in the future.
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_map_mem_type_to_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id, uint16_t type,
    uint32_t flags);

/**
 * This function registers a PCI device for config space emulation.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm id the IOREQ Server id.
 * @parm segment the PCI segment of the device
 * @parm bus the PCI bus of the device
 * @parm device the 'slot' number of the device
 * @parm function the function number of the device
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_map_pcidev_to_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id,
    uint16_t segment, uint8_t bus, uint8_t device, uint8_t function);

/**
 * This function deregisters a PCI device for config space emulation.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm id the IOREQ Server id.
 * @parm segment the PCI segment of the device
 * @parm bus the PCI bus of the device
 * @parm device the 'slot' number of the device
 * @parm function the function number of the device
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_unmap_pcidev_from_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id,
    uint16_t segment, uint8_t bus, uint8_t device, uint8_t function);

/**
 * This function destroys an IOREQ Server.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm id the IOREQ Server id.
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_destroy_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id);

/**
 * This function sets IOREQ Server state. An IOREQ Server
 * will not be passed emulation requests until it is in
 * the enabled state.
 * Note that the contents of the ioreq_gfn and bufioreq_gfn are
 * not meaningful until the IOREQ Server is in the enabled state.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm id the IOREQ Server id.
 * @parm enabled the state.
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_set_ioreq_server_state(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id, int enabled);

/**
 * This function sets the level of INTx pin of an emulated PCI device.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm segment the PCI segment number of the emulated device
 * @parm bus the PCI bus number of the emulated device
 * @parm device the PCI device number of the emulated device
 * @parm intx the INTx pin to modify (0 => A .. 3 => D)
 * @parm level the level (1 for asserted, 0 for de-asserted)
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_set_pci_intx_level(
    xendevicemodel_handle *dmod, domid_t domid, uint16_t segment,
    uint8_t bus, uint8_t device, uint8_t intx, unsigned int level);

/**
 * This function sets the level of an ISA IRQ line.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm irq the IRQ number (0 - 15)
 * @parm level the level (1 for asserted, 0 for de-asserted)
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_set_isa_irq_level(
    xendevicemodel_handle *dmod, domid_t domid, uint8_t irq,
    unsigned int level);

/**
 * This function maps a PCI INTx line to a an IRQ line.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm line the INTx line (0 => A .. 3 => B)
 * @parm irq the IRQ number (0 - 15)
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_set_pci_link_route(
    xendevicemodel_handle *dmod, domid_t domid, uint8_t link, uint8_t irq);

/**
 * This function injects an MSI into a guest.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm msi_addr the MSI address (0xfeexxxxx)
 * @parm msi_data the MSI data
 * @return 0 on success, -1 on failure.
*/
int xendevicemodel_inject_msi(
    xendevicemodel_handle *dmod, domid_t domid, uint64_t msi_addr,
    uint32_t msi_data);

/**
 * This function enables tracking of changes in the VRAM area.
 *
 * The following is done atomically:
 * - get the dirty bitmap since the last call.
 * - set up dirty tracking area for period up to the next call.
 * - clear the dirty tracking area.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm first_pfn the start of the area to track
 * @parm nr the number of pages to track
 * @parm dirty_bitmal a pointer to the bitmap to be updated
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_track_dirty_vram(
    xendevicemodel_handle *dmod, domid_t domid, uint64_t first_pfn,
    uint32_t nr, unsigned long *dirty_bitmap);

/**
 * This function notifies the hypervisor that a set of contiguous
 * domain pages have been modified.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm first_pfn the start of the modified area
 * @parm nr the number of pages modified
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_modified_memory(
    xendevicemodel_handle *dmod, domid_t domid, uint64_t first_pfn,
    uint32_t nr);

/**
 * This function notifies the hypervisor that a set of discontiguous
 * domain pages have been modified.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm extents an array of extent structs, which each hold
                 a start_pfn and nr (number of pfns).
 * @parm nr the number of extents in the array
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_modified_memory_bulk(
    xendevicemodel_handle *dmod, domid_t domid,
    struct xen_dm_op_modified_memory_extent extents[], uint32_t nr);

/**
 * This function notifies the hypervisor that a set of domain pages
 * are to be treated in a specific way. (See the definition of
 * hvmmem_type_t).
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm mem_type determines how the set is to be treated
 * @parm first_pfn the start of the set
 * @parm nr the number of pages in the set
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_set_mem_type(
    xendevicemodel_handle *dmod, domid_t domid, hvmmem_type_t mem_type,
    uint64_t first_pfn, uint32_t nr);

/**
 * This function injects an event into a vCPU to take effect the next
 * time it resumes.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm vcpu the vcpu id
 * @parm vector the interrupt vector
 * @parm type the event type (see the definition of enum x86_event_type)
 * @parm error_code the error code or ~0 to skip
 * @parm insn_len the instruction length
 * @parm cr2 the value of CR2 for page faults
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_inject_event(
    xendevicemodel_handle *dmod, domid_t domid, int vcpu, uint8_t vector,
    uint8_t type, uint32_t error_code, uint8_t insn_len, uint64_t cr2);

/**
 * Shuts the domain down.
 *
 * @parm reason usually enum sched_shutdown_reason, see xen/sched.h
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_shutdown(
    xendevicemodel_handle *dmod, domid_t domid, unsigned int reason);

/*
 * Relocate GFNs for the specified domain.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm size Number of GFNs to process
 * @parm src_gfn Starting GFN to relocate
 * @parm dst_gfn Starting GFN where GFNs should be relocated
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_relocate_memory(
    xendevicemodel_handle *dmod, domid_t domid, uint32_t size, uint64_t src_gfn,
    uint64_t dst_gfn);

/**
 * Pins caching type of RAM space.
 *
 * @parm dmod a handle to an open devicemodel interface.
 * @parm domid the domain id to be serviced
 * @parm start Start gfn
 * @parm end End gfn
 * @parm type XEN_DMOP_MEM_CACHEATTR_*
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_pin_memory_cacheattr(
    xendevicemodel_handle *dmod, domid_t domid, uint64_t start, uint64_t end,
    uint32_t type);

/**
 * This function restricts the use of this handle to the specified
 * domain.
 *
 * @parm dmod handle to the open devicemodel interface
 * @parm domid the domain id
 * @return 0 on success, -1 on failure.
 */
int xendevicemodel_restrict(xendevicemodel_handle *dmod, domid_t domid);

#endif /* __XEN_TOOLS__ */

#endif /* XENDEVICEMODEL_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
