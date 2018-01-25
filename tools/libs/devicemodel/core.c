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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "private.h"

static int all_restrict_cb(Xentoolcore__Active_Handle *ah, domid_t domid) {
    xendevicemodel_handle *dmod = CONTAINER_OF(ah, *dmod, tc_ah);

    if (dmod->fd < 0)
        /* just in case */
        return 0;

    return xendevicemodel_restrict(dmod, domid);
}

xendevicemodel_handle *xendevicemodel_open(xentoollog_logger *logger,
                                           unsigned open_flags)
{
    xendevicemodel_handle *dmod = calloc(1, sizeof(*dmod));
    int rc;

    if (!dmod)
        return NULL;

    dmod->fd = -1;
    dmod->tc_ah.restrict_callback = all_restrict_cb;
    xentoolcore__register_active_handle(&dmod->tc_ah);

    dmod->flags = open_flags;
    dmod->logger = logger;
    dmod->logger_tofree = NULL;

    if (!dmod->logger) {
        dmod->logger = dmod->logger_tofree =
            (xentoollog_logger*)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if (!dmod->logger)
            goto err;
    }

    dmod->xcall = xencall_open(dmod->logger, 0);
    if (!dmod->xcall)
        goto err;

    rc = osdep_xendevicemodel_open(dmod);
    if (rc)
        goto err;

    return dmod;

err:
    xtl_logger_destroy(dmod->logger_tofree);
    xentoolcore__deregister_active_handle(&dmod->tc_ah);
    xencall_close(dmod->xcall);
    free(dmod);
    return NULL;
}

int xendevicemodel_close(xendevicemodel_handle *dmod)
{
    int rc;

    if (!dmod)
        return 0;

    rc = osdep_xendevicemodel_close(dmod);

    xentoolcore__deregister_active_handle(&dmod->tc_ah);
    xencall_close(dmod->xcall);
    xtl_logger_destroy(dmod->logger_tofree);
    free(dmod);
    return rc;
}

int xendevicemodel_xcall(xendevicemodel_handle *dmod,
                         domid_t domid, unsigned int nr_bufs,
                         struct xendevicemodel_buf bufs[])
{
    int ret = -1;
    void **xcall_bufs;
    xen_dm_op_buf_t *op_bufs = NULL;
    unsigned int i;

    xcall_bufs = calloc(nr_bufs, sizeof(*xcall_bufs));
    if (xcall_bufs == NULL)
        goto out;

    op_bufs = xencall_alloc_buffer(dmod->xcall, sizeof(xen_dm_op_buf_t) *
                                   nr_bufs);
    if (op_bufs == NULL)
        goto out;

    for (i = 0; i < nr_bufs; i++)  {
        xcall_bufs[i] = xencall_alloc_buffer(dmod->xcall, bufs[i].size);
        if ( xcall_bufs[i] == NULL )
            goto out;

        memcpy(xcall_bufs[i], bufs[i].ptr, bufs[i].size);
        set_xen_guest_handle_raw(op_bufs[i].h, xcall_bufs[i]);

        op_bufs[i].size = bufs[i].size;
    }

    ret = xencall3(dmod->xcall, __HYPERVISOR_dm_op,
                   domid, nr_bufs, (unsigned long)op_bufs);
    if (ret < 0)
        goto out;

    for (i = 0; i < nr_bufs; i++)
        memcpy(bufs[i].ptr, xcall_bufs[i], bufs[i].size);

out:
    if (xcall_bufs)
        for (i = 0; i < nr_bufs; i++)
            xencall_free_buffer(dmod->xcall, xcall_bufs[i]);

    xencall_free_buffer(dmod->xcall, op_bufs);
    free(xcall_bufs);

    return ret;
}

static int xendevicemodel_op(
    xendevicemodel_handle *dmod, domid_t domid,  unsigned int nr_bufs, ...)
{
    struct xendevicemodel_buf *bufs;
    va_list args;
    unsigned int i;
    int ret;

    bufs = calloc(nr_bufs, sizeof(*bufs));
    if (!bufs)
        return -1;

    va_start(args, nr_bufs);
    for (i = 0; i < nr_bufs; i++) {
        bufs[i].ptr = va_arg(args, void *);
        bufs[i].size = va_arg(args, size_t);
    }
    va_end(args);

    ret = osdep_xendevicemodel_op(dmod, domid, nr_bufs, bufs);

    free(bufs);

    return ret;
}

int xendevicemodel_create_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, int handle_bufioreq,
    ioservid_t *id)
{
    struct xen_dm_op op;
    struct xen_dm_op_create_ioreq_server *data;
    int rc;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_create_ioreq_server;
    data = &op.u.create_ioreq_server;

    data->handle_bufioreq = handle_bufioreq;

    rc = xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
    if (rc)
        return rc;

    *id = data->id;

    return 0;
}

int xendevicemodel_get_ioreq_server_info(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id,
    xen_pfn_t *ioreq_gfn, xen_pfn_t *bufioreq_gfn,
    evtchn_port_t *bufioreq_port)
{
    struct xen_dm_op op;
    struct xen_dm_op_get_ioreq_server_info *data;
    int rc;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_get_ioreq_server_info;
    data = &op.u.get_ioreq_server_info;

    data->id = id;

    rc = xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
    if (rc)
        return rc;

    if (ioreq_gfn)
        *ioreq_gfn = data->ioreq_gfn;

    if (bufioreq_gfn)
        *bufioreq_gfn = data->bufioreq_gfn;

    if (bufioreq_port)
        *bufioreq_port = data->bufioreq_port;

    return 0;
}

int xendevicemodel_map_io_range_to_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id, int is_mmio,
    uint64_t start, uint64_t end)
{
    struct xen_dm_op op;
    struct xen_dm_op_ioreq_server_range *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_map_io_range_to_ioreq_server;
    data = &op.u.map_io_range_to_ioreq_server;

    data->id = id;
    data->type = is_mmio ? XEN_DMOP_IO_RANGE_MEMORY : XEN_DMOP_IO_RANGE_PORT;
    data->start = start;
    data->end = end;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_unmap_io_range_from_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id, int is_mmio,
    uint64_t start, uint64_t end)
{
    struct xen_dm_op op;
    struct xen_dm_op_ioreq_server_range *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_unmap_io_range_from_ioreq_server;
    data = &op.u.unmap_io_range_from_ioreq_server;

    data->id = id;
    data->type = is_mmio ? XEN_DMOP_IO_RANGE_MEMORY : XEN_DMOP_IO_RANGE_PORT;
    data->start = start;
    data->end = end;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_map_mem_type_to_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id, uint16_t type,
    uint32_t flags)
{
    struct xen_dm_op op;
    struct xen_dm_op_map_mem_type_to_ioreq_server *data;

    if (type != HVMMEM_ioreq_server ||
        flags & ~XEN_DMOP_IOREQ_MEM_ACCESS_WRITE) {
        errno = EINVAL;
        return -1;
    }

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_map_mem_type_to_ioreq_server;
    data = &op.u.map_mem_type_to_ioreq_server;

    data->id = id;
    data->type = type;
    data->flags = flags;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_map_pcidev_to_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id,
    uint16_t segment, uint8_t bus, uint8_t device, uint8_t function)
{
    struct xen_dm_op op;
    struct xen_dm_op_ioreq_server_range *data;

    if (device > 0x1f || function > 0x7) {
        errno = EINVAL;
        return -1;
    }

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_map_io_range_to_ioreq_server;
    data = &op.u.map_io_range_to_ioreq_server;

    data->id = id;
    data->type = XEN_DMOP_IO_RANGE_PCI;

    /*
     * The underlying hypercall will deal with ranges of PCI SBDF
     * but, for simplicity, the API only uses singletons.
     */
    data->start = data->end = XEN_DMOP_PCI_SBDF((uint64_t)segment,
                                                (uint64_t)bus,
                                                (uint64_t)device,
                                                (uint64_t)function);

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_unmap_pcidev_from_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id,
    uint16_t segment, uint8_t bus, uint8_t device, uint8_t function)
{
    struct xen_dm_op op;
    struct xen_dm_op_ioreq_server_range *data;

    if (device > 0x1f || function > 0x7) {
        errno = EINVAL;
        return -1;
    }

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_unmap_io_range_from_ioreq_server;
    data = &op.u.unmap_io_range_from_ioreq_server;

    data->id = id;
    data->type = XEN_DMOP_IO_RANGE_PCI;

    /*
     * The underlying hypercall will deal with ranges of PCI SBDF
     * but, for simplicity, the API only uses singletons.
     */
    data->start = data->end = XEN_DMOP_PCI_SBDF((uint64_t)segment,
                                                (uint64_t)bus,
                                                (uint64_t)device,
                                                (uint64_t)function);

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_destroy_ioreq_server(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id)
{
    struct xen_dm_op op;
    struct xen_dm_op_destroy_ioreq_server *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_destroy_ioreq_server;
    data = &op.u.destroy_ioreq_server;

    data->id = id;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_set_ioreq_server_state(
    xendevicemodel_handle *dmod, domid_t domid, ioservid_t id, int enabled)
{
    struct xen_dm_op op;
    struct xen_dm_op_set_ioreq_server_state *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_set_ioreq_server_state;
    data = &op.u.set_ioreq_server_state;

    data->id = id;
    data->enabled = !!enabled;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_set_pci_intx_level(
    xendevicemodel_handle *dmod, domid_t domid, uint16_t segment,
    uint8_t bus, uint8_t device, uint8_t intx, unsigned int level)
{
    struct xen_dm_op op;
    struct xen_dm_op_set_pci_intx_level *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_set_pci_intx_level;
    data = &op.u.set_pci_intx_level;

    data->domain = segment;
    data->bus = bus;
    data->device = device;
    data->intx = intx;
    data->level = level;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_set_isa_irq_level(
    xendevicemodel_handle *dmod, domid_t domid, uint8_t irq,
    unsigned int level)
{
    struct xen_dm_op op;
    struct xen_dm_op_set_isa_irq_level *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_set_isa_irq_level;
    data = &op.u.set_isa_irq_level;

    data->isa_irq = irq;
    data->level = level;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_set_pci_link_route(
    xendevicemodel_handle *dmod, domid_t domid, uint8_t link, uint8_t irq)
{
    struct xen_dm_op op;
    struct xen_dm_op_set_pci_link_route *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_set_pci_link_route;
    data = &op.u.set_pci_link_route;

    data->link = link;
    data->isa_irq = irq;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_inject_msi(
    xendevicemodel_handle *dmod, domid_t domid, uint64_t msi_addr,
    uint32_t msi_data)
{
    struct xen_dm_op op;
    struct xen_dm_op_inject_msi *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_inject_msi;
    data = &op.u.inject_msi;

    data->addr = msi_addr;
    data->data = msi_data;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_track_dirty_vram(
    xendevicemodel_handle *dmod, domid_t domid, uint64_t first_pfn,
    uint32_t nr, unsigned long *dirty_bitmap)
{
    struct xen_dm_op op;
    struct xen_dm_op_track_dirty_vram *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_track_dirty_vram;
    data = &op.u.track_dirty_vram;

    data->first_pfn = first_pfn;
    data->nr = nr;

    return xendevicemodel_op(dmod, domid, 2, &op, sizeof(op),
                             dirty_bitmap, (size_t)(nr + 7) / 8);
}

int xendevicemodel_modified_memory_bulk(
    xendevicemodel_handle *dmod, domid_t domid,
    struct xen_dm_op_modified_memory_extent *extents, uint32_t nr)
{
    struct xen_dm_op op;
    struct xen_dm_op_modified_memory *header;
    size_t extents_size = nr * sizeof(struct xen_dm_op_modified_memory_extent);

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_modified_memory;
    header = &op.u.modified_memory;

    header->nr_extents = nr;
    header->opaque = 0;

    return xendevicemodel_op(dmod, domid, 2, &op, sizeof(op),
                             extents, extents_size);
}

int xendevicemodel_modified_memory(
    xendevicemodel_handle *dmod, domid_t domid, uint64_t first_pfn,
    uint32_t nr)
{
    struct xen_dm_op_modified_memory_extent extent = {
        .first_pfn = first_pfn,
        .nr = nr,
    };

    return xendevicemodel_modified_memory_bulk(dmod, domid, &extent, 1);
}

int xendevicemodel_set_mem_type(
    xendevicemodel_handle *dmod, domid_t domid, hvmmem_type_t mem_type,
    uint64_t first_pfn, uint32_t nr)
{
    struct xen_dm_op op;
    struct xen_dm_op_set_mem_type *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_set_mem_type;
    data = &op.u.set_mem_type;

    data->mem_type = mem_type;
    data->first_pfn = first_pfn;
    data->nr = nr;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_inject_event(
    xendevicemodel_handle *dmod, domid_t domid, int vcpu, uint8_t vector,
    uint8_t type, uint32_t error_code, uint8_t insn_len, uint64_t cr2)
{
    struct xen_dm_op op;
    struct xen_dm_op_inject_event *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_inject_event;
    data = &op.u.inject_event;

    data->vcpuid = vcpu;
    data->vector = vector;
    data->type = type;
    data->error_code = error_code;
    data->insn_len = insn_len;
    data->cr2 = cr2;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_shutdown(
    xendevicemodel_handle *dmod, domid_t domid, unsigned int reason)
{
    struct xen_dm_op op;
    struct xen_dm_op_remote_shutdown *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_remote_shutdown;
    data = &op.u.remote_shutdown;

    data->reason = reason;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_relocate_memory(
    xendevicemodel_handle *dmod, domid_t domid, uint32_t size, uint64_t src_gfn,
    uint64_t dst_gfn)
{
    struct xen_dm_op op;
    struct xen_dm_op_relocate_memory *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_relocate_memory;
    data = &op.u.relocate_memory;

    data->size = size;
    data->pad = 0;
    data->src_gfn = src_gfn;
    data->dst_gfn = dst_gfn;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_pin_memory_cacheattr(
    xendevicemodel_handle *dmod, domid_t domid, uint64_t start, uint64_t end,
    uint32_t type)
{
    struct xen_dm_op op;
    struct xen_dm_op_pin_memory_cacheattr *data;

    memset(&op, 0, sizeof(op));

    op.op = XEN_DMOP_pin_memory_cacheattr;
    data = &op.u.pin_memory_cacheattr;

    data->start = start;
    data->end = end;
    data->type = type;

    return xendevicemodel_op(dmod, domid, 1, &op, sizeof(op));
}

int xendevicemodel_restrict(xendevicemodel_handle *dmod, domid_t domid)
{
    return osdep_xendevicemodel_restrict(dmod, domid);
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
