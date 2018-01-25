/*
 * Compat shims for use of 3rd party consumers of libxenctrl
 * functionality which has been split into separate libraries.
 *
 * New code should use the separate libraries.
 *
 * Each interface must be opted-into separately by defining:
 *
 * XC_WANT_COMPAT_EVTCHN_API
 *  - Functions relating to /dev/xen/evtchn
 */
#ifndef XENCTRL_COMPAT_H
#define XENCTRL_COMPAT_H

#ifdef XC_WANT_COMPAT_MAP_FOREIGN_API
/**
 * Memory maps a range within one domain to a local address range.  Mappings
 * should be unmapped with munmap and should follow the same rules as mmap
 * regarding page alignment.  Returns NULL on failure.
 *
 * @parm xch a handle on an open hypervisor interface
 * @parm dom the domain to map memory from
 * @parm size the amount of memory to map (in multiples of page size)
 * @parm prot same flag as in mmap().
 * @parm mfn the frame address to map.
 */
void *xc_map_foreign_range(xc_interface *xch, uint32_t dom,
                            int size, int prot,
                            unsigned long mfn );

void *xc_map_foreign_pages(xc_interface *xch, uint32_t dom, int prot,
                           const xen_pfn_t *arr, int num );

/* Nothing within the library itself other than the compat wrapper
 * itself should be using this, everything inside has access to
 * xenforeignmemory_map().
 */
#if !defined(XC_INTERNAL_COMPAT_MAP_FOREIGN_API) || \
     defined(XC_BUILDING_COMPAT_MAP_FOREIGN_API)
/**
 * Like xc_map_foreign_pages(), except it can succeed partially.
 * When a page cannot be mapped, its respective field in @err is
 * set to the corresponding errno value.
 */
void *xc_map_foreign_bulk(xc_interface *xch, uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err, unsigned int num);
#endif

#endif

#ifdef XC_WANT_COMPAT_EVTCHN_API

typedef struct xenevtchn_handle xc_evtchn;
typedef xc_evtchn_port_or_error_t evtchn_port_or_error_t;

xc_evtchn *xc_evtchn_open(xentoollog_logger *logger,
                             unsigned open_flags);
int xc_evtchn_close(xc_evtchn *xce);
int xc_evtchn_fd(xc_evtchn *xce);
int xc_evtchn_notify(xc_evtchn *xce, evtchn_port_t port);
xc_evtchn_port_or_error_t
xc_evtchn_bind_unbound_port(xc_evtchn *xce, uint32_t domid);
xc_evtchn_port_or_error_t
xc_evtchn_bind_interdomain(xc_evtchn *xce, uint32_t domid,
                           evtchn_port_t remote_port);
xc_evtchn_port_or_error_t
xc_evtchn_bind_virq(xc_evtchn *xce, unsigned int virq);
int xc_evtchn_unbind(xc_evtchn *xce, evtchn_port_t port);
xc_evtchn_port_or_error_t
xc_evtchn_pending(xc_evtchn *xce);
int xc_evtchn_unmask(xc_evtchn *xce, evtchn_port_t port);

#endif /* XC_WANT_COMPAT_EVTCHN_API */

#ifdef XC_WANT_COMPAT_GNTTAB_API

typedef struct xengntdev_handle xc_gnttab;

xc_gnttab *xc_gnttab_open(xentoollog_logger *logger,
                          unsigned open_flags);
int xc_gnttab_close(xc_gnttab *xcg);
void *xc_gnttab_map_grant_ref(xc_gnttab *xcg,
                              uint32_t domid,
                              uint32_t ref,
                              int prot);
void *xc_gnttab_map_grant_refs(xc_gnttab *xcg,
                               uint32_t count,
                               uint32_t *domids,
                               uint32_t *refs,
                               int prot);
void *xc_gnttab_map_domain_grant_refs(xc_gnttab *xcg,
                                      uint32_t count,
                                      uint32_t domid,
                                      uint32_t *refs,
                                      int prot);
void *xc_gnttab_map_grant_ref_notify(xc_gnttab *xcg,
                                     uint32_t domid,
                                     uint32_t ref,
                                     int prot,
                                     uint32_t notify_offset,
                                     evtchn_port_t notify_port);
int xc_gnttab_munmap(xc_gnttab *xcg,
                     void *start_address,
                     uint32_t count);
int xc_gnttab_set_max_grants(xc_gnttab *xcg,
                             uint32_t count);

typedef struct xengntdev_handle xc_gntshr;

xc_gntshr *xc_gntshr_open(xentoollog_logger *logger,
                          unsigned open_flags);
int xc_gntshr_close(xc_gntshr *xcg);
void *xc_gntshr_share_pages(xc_gntshr *xcg, uint32_t domid,
                            int count, uint32_t *refs, int writable);
void *xc_gntshr_share_page_notify(xc_gntshr *xcg, uint32_t domid,
                                  uint32_t *ref, int writable,
                                  uint32_t notify_offset,
                                  evtchn_port_t notify_port);
int xc_gntshr_munmap(xc_gntshr *xcg, void *start_address, uint32_t count);

#endif /* XC_WANT_COMPAT_GNTTAB_API */

#ifdef XC_WANT_COMPAT_DEVICEMODEL_API

int xc_hvm_create_ioreq_server(
    xc_interface *xch, uint32_t domid, int handle_bufioreq,
    ioservid_t *id);
int xc_hvm_get_ioreq_server_info(
    xc_interface *xch, uint32_t domid, ioservid_t id, xen_pfn_t *ioreq_pfn,
    xen_pfn_t *bufioreq_pfn, evtchn_port_t *bufioreq_port);
int xc_hvm_map_io_range_to_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id, int is_mmio,
    uint64_t start, uint64_t end);
int xc_hvm_unmap_io_range_from_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id, int is_mmio,
    uint64_t start, uint64_t end);
int xc_hvm_map_pcidev_to_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id, uint16_t segment,
    uint8_t bus, uint8_t device, uint8_t function);
int xc_hvm_unmap_pcidev_from_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id, uint16_t segment,
    uint8_t bus, uint8_t device, uint8_t function);
int xc_hvm_destroy_ioreq_server(
    xc_interface *xch, uint32_t domid, ioservid_t id);
int xc_hvm_set_ioreq_server_state(
    xc_interface *xch, uint32_t domid, ioservid_t id, int enabled);
int xc_hvm_set_pci_intx_level(
    xc_interface *xch, uint32_t domid, uint16_t segment, uint8_t bus,
    uint8_t device, uint8_t intx, unsigned int level);
int xc_hvm_set_isa_irq_level(
    xc_interface *xch, uint32_t domid, uint8_t irq, unsigned int level);
int xc_hvm_set_pci_link_route(
    xc_interface *xch, uint32_t domid, uint8_t link, uint8_t irq);
int xc_hvm_inject_msi(
    xc_interface *xch, uint32_t domid, uint64_t msi_addr, uint32_t msi_data);
int xc_hvm_track_dirty_vram(
    xc_interface *xch, uint32_t domid, uint64_t first_pfn, uint32_t nr,
    unsigned long *dirty_bitmap);
int xc_hvm_modified_memory(
    xc_interface *xch, uint32_t domid, uint64_t first_pfn, uint32_t nr);
int xc_hvm_set_mem_type(
    xc_interface *xch, uint32_t domid, hvmmem_type_t type,
    uint64_t first_pfn, uint32_t nr);
int xc_hvm_inject_trap(
    xc_interface *xch, uint32_t domid, int vcpu, uint8_t vector,
    uint8_t type, uint32_t error_code, uint8_t insn_len, uint64_t cr2);
int xc_domain_pin_memory_cacheattr(
    xc_interface *xch, uint32_t domid, uint64_t start, uint64_t end,
    uint32_t type);

#endif /* XC_WANT_COMPAT_DEVICEMODEL_API */

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
