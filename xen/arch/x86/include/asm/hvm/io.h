/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * io.h: HVM IO support
 *
 * Copyright (c) 2004, Intel Corporation.
 */

#ifndef __ASM_X86_HVM_IO_H__
#define __ASM_X86_HVM_IO_H__

#include <xen/pci.h>
#include <public/hvm/ioreq.h>

#define NR_IO_HANDLERS 32

typedef int (*hvm_mmio_read_t)(struct vcpu *v,
                               unsigned long addr,
                               unsigned int length,
                               unsigned long *val);
typedef int (*hvm_mmio_write_t)(struct vcpu *v,
                                unsigned long addr,
                                unsigned int length,
                                unsigned long val);
typedef int (*hvm_mmio_check_t)(struct vcpu *v, unsigned long addr);

struct hvm_mmio_ops {
    hvm_mmio_check_t check;
    hvm_mmio_read_t  read;
    hvm_mmio_write_t write;
};

typedef int (*portio_action_t)(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val);

struct hvm_io_handler {
    union {
        struct {
            const struct hvm_mmio_ops *ops;
        } mmio;
        struct {
            unsigned int port, size;
            portio_action_t action;
        } portio;
    };
    const struct hvm_io_ops *ops;
    uint8_t type;
};

typedef int (*hvm_io_read_t)(const struct hvm_io_handler *handler,
                             uint64_t addr,
                             uint32_t size,
                             uint64_t *data);
typedef int (*hvm_io_write_t)(const struct hvm_io_handler *handler,
                              uint64_t addr,
                              uint32_t size,
                              uint64_t data);
typedef bool (*hvm_io_accept_t)(const struct hvm_io_handler *handler,
                                const ioreq_t *p);
typedef void (*hvm_io_complete_t)(const struct hvm_io_handler *handler);

struct hvm_io_ops {
    hvm_io_accept_t   accept;
    hvm_io_read_t     read;
    hvm_io_write_t    write;
    hvm_io_complete_t complete;
};

int hvm_process_io_intercept(const struct hvm_io_handler *handler,
                             ioreq_t *p);

int hvm_io_intercept(ioreq_t *p);

struct hvm_io_handler *hvm_next_io_handler(struct domain *d);

bool hvm_mmio_internal(paddr_t gpa);

void register_mmio_handler(struct domain *d,
                           const struct hvm_mmio_ops *ops);

void register_portio_handler(
    struct domain *d, unsigned int port, unsigned int size,
    portio_action_t action);

bool relocate_portio_handler(
    struct domain *d, unsigned int old_port, unsigned int new_port,
    unsigned int size);

void send_timeoffset_req(unsigned long timeoff);
bool handle_mmio_with_translation(unsigned long gla, unsigned long gpfn,
                                  struct npfec access);
bool handle_pio(uint16_t port, unsigned int size, int dir);
void hvm_interrupt_post(struct vcpu *v, int vector, int type);
void hvm_dpci_eoi(struct domain *d, unsigned int guest_gsi);
void msix_write_completion(struct vcpu *v);

#ifdef CONFIG_HVM
void msixtbl_init(struct domain *d);
#else
static inline void msixtbl_init(struct domain *d) {}
#endif

/* Arch-specific MSI data for vPCI. */
struct vpci_arch_msi {
    int pirq;
    bool bound;
};

/* Arch-specific MSI-X entry data for vPCI. */
struct vpci_arch_msix_entry {
    int pirq;
};

enum stdvga_cache_state {
    STDVGA_CACHE_UNINITIALIZED,
    STDVGA_CACHE_ENABLED,
    STDVGA_CACHE_DISABLED
};

struct hvm_hw_stdvga {
    uint8_t sr_index;
    uint8_t sr[8];
    uint8_t gr_index;
    uint8_t gr[9];
    bool stdvga;
    enum stdvga_cache_state cache;
    uint32_t latch;
    struct page_info *vram_page[64];  /* shadow of 0xa0000-0xaffff */
    spinlock_t lock;
};

void stdvga_init(struct domain *d);
void stdvga_deinit(struct domain *d);

extern void hvm_dpci_msi_eoi(struct domain *d, int vector);

/* Decode a PCI port IO access into a bus/slot/func/reg. */
unsigned int hvm_pci_decode_addr(unsigned int cf8, unsigned int addr,
                                 pci_sbdf_t *sbdf);

/*
 * HVM port IO handler that performs forwarding of guest IO ports into machine
 * IO ports.
 */
void register_g2m_portio_handler(struct domain *d);

/* HVM port IO handler for vPCI accesses. */
void register_vpci_portio_handler(struct domain *d);

/* HVM MMIO handler for PCI MMCFG accesses. */
int register_vpci_mmcfg_handler(struct domain *d, paddr_t addr,
                                unsigned int start_bus, unsigned int end_bus,
                                unsigned int seg);
/* Destroy tracked MMCFG areas. */
void destroy_vpci_mmcfg(struct domain *d);

/* Remove MMCFG regions from a given rangeset. */
int vpci_subtract_mmcfg(const struct domain *d, struct rangeset *r);

#endif /* __ASM_X86_HVM_IO_H__ */


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
