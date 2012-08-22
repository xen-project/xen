/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 */

#ifndef _IOMMU_H_
#define _IOMMU_H_

#include <xen/init.h>
#include <xen/spinlock.h>
#include <xen/pci.h>
#include <public/hvm/ioreq.h>
#include <public/domctl.h>

extern bool_t iommu_enabled;
extern bool_t force_iommu, iommu_verbose;
extern bool_t iommu_workaround_bios_bug, iommu_passthrough;
extern bool_t iommu_snoop, iommu_qinval, iommu_intremap;
extern bool_t iommu_hap_pt_share;
extern bool_t iommu_debug;
extern bool_t amd_iommu_perdev_intremap;

/* Does this domain have a P2M table we can use as its IOMMU pagetable? */
#define iommu_use_hap_pt(d) (hap_enabled(d) && iommu_hap_pt_share)

extern struct rangeset *mmio_ro_ranges;

#define domain_hvm_iommu(d)     (&d->arch.hvm_domain.hvm_iommu)

#define MAX_IOMMUS 32

#define PAGE_SHIFT_4K       (12)
#define PAGE_SIZE_4K        (1UL << PAGE_SHIFT_4K)
#define PAGE_MASK_4K        (((u64)-1) << PAGE_SHIFT_4K)
#define PAGE_ALIGN_4K(addr) (((addr) + PAGE_SIZE_4K - 1) & PAGE_MASK_4K)

struct iommu {
    struct list_head list;
    void __iomem *reg; /* Pointer to hardware regs, virtual addr */
    u32	index;         /* Sequence number of iommu */
    u32 nr_pt_levels;
    u64	cap;
    u64	ecap;
    spinlock_t lock; /* protect context, domain ids */
    spinlock_t register_lock; /* protect iommu register handling */
    u64 root_maddr; /* root entry machine address */
    int irq;
    struct intel_iommu *intel;
    unsigned long *domid_bitmap;  /* domain id bitmap */
    u16 *domid_map;               /* domain id mapping array */
};

int iommu_setup(void);
int iommu_supports_eim(void);
int iommu_enable_x2apic_IR(void);
void iommu_disable_x2apic_IR(void);

int iommu_add_device(struct pci_dev *pdev);
int iommu_enable_device(struct pci_dev *pdev);
int iommu_remove_device(struct pci_dev *pdev);
int iommu_domain_init(struct domain *d);
void iommu_dom0_init(struct domain *d);
void iommu_domain_destroy(struct domain *d);
int deassign_device(struct domain *d, u16 seg, u8 bus, u8 devfn);

/* iommu_map_page() takes flags to direct the mapping operation. */
#define _IOMMUF_readable 0
#define IOMMUF_readable  (1u<<_IOMMUF_readable)
#define _IOMMUF_writable 1
#define IOMMUF_writable  (1u<<_IOMMUF_writable)
int iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                   unsigned int flags);
int iommu_unmap_page(struct domain *d, unsigned long gfn);
void iommu_pte_flush(struct domain *d, u64 gfn, u64 *pte, int order, int present);
void iommu_set_pgd(struct domain *d);
void iommu_domain_teardown(struct domain *d);

void pt_pci_init(void);

struct pirq;
int hvm_do_IRQ_dpci(struct domain *, struct pirq *);
int dpci_ioport_intercept(ioreq_t *p);
int pt_irq_create_bind_vtd(struct domain *d,
                           xen_domctl_bind_pt_irq_t *pt_irq_bind);
int pt_irq_destroy_bind_vtd(struct domain *d,
                            xen_domctl_bind_pt_irq_t *pt_irq_bind);
unsigned int io_apic_read_remap_rte(unsigned int apic, unsigned int reg);
void io_apic_write_remap_rte(unsigned int apic,
                             unsigned int reg, unsigned int value);

struct msi_desc;
struct msi_msg;
void msi_msg_read_remap_rte(struct msi_desc *msi_desc, struct msi_msg *msg);
void msi_msg_write_remap_rte(struct msi_desc *msi_desc, struct msi_msg *msg);
struct qi_ctrl *iommu_qi_ctrl(struct iommu *iommu);
struct ir_ctrl *iommu_ir_ctrl(struct iommu *iommu);
struct iommu_flush *iommu_get_flush(struct iommu *iommu);
void hvm_dpci_isairq_eoi(struct domain *d, unsigned int isairq);
struct hvm_irq_dpci *domain_get_irq_dpci(const struct domain *);
void free_hvm_irq_dpci(struct hvm_irq_dpci *dpci);
bool_t pt_irq_need_timer(uint32_t flags);

#define PT_IRQ_TIME_OUT MILLISECS(8)
#define VTDPREFIX "[VT-D]"

struct iommu_ops {
    int (*init)(struct domain *d);
    void (*dom0_init)(struct domain *d);
    int (*add_device)(struct pci_dev *pdev);
    int (*enable_device)(struct pci_dev *pdev);
    int (*remove_device)(struct pci_dev *pdev);
    int (*assign_device)(struct domain *d, u16 seg, u8 bus, u8 devfn);
    void (*teardown)(struct domain *d);
    int (*map_page)(struct domain *d, unsigned long gfn, unsigned long mfn,
                    unsigned int flags);
    int (*unmap_page)(struct domain *d, unsigned long gfn);
    int (*reassign_device)(struct domain *s, struct domain *t,
			   u16 seg, u8 bus, u8 devfn);
    int (*get_device_group_id)(u16 seg, u8 bus, u8 devfn);
    void (*update_ire_from_apic)(unsigned int apic, unsigned int reg, unsigned int value);
    void (*update_ire_from_msi)(struct msi_desc *msi_desc, struct msi_msg *msg);
    void (*read_msi_from_ire)(struct msi_desc *msi_desc, struct msi_msg *msg);
    unsigned int (*read_apic_from_ire)(unsigned int apic, unsigned int reg);
    void (*suspend)(void);
    void (*resume)(void);
    void (*share_p2m)(struct domain *d);
    void (*crash_shutdown)(void);
    void (*iotlb_flush)(struct domain *d, unsigned long gfn, unsigned int page_count);
    void (*iotlb_flush_all)(struct domain *d);
    void (*dump_p2m_table)(struct domain *d);
};

void iommu_update_ire_from_apic(unsigned int apic, unsigned int reg, unsigned int value);
void iommu_update_ire_from_msi(struct msi_desc *msi_desc, struct msi_msg *msg);
void iommu_read_msi_from_ire(struct msi_desc *msi_desc, struct msi_msg *msg);
unsigned int iommu_read_apic_from_ire(unsigned int apic, unsigned int reg);

void iommu_suspend(void);
void iommu_resume(void);
void iommu_crash_shutdown(void);

void iommu_set_dom0_mapping(struct domain *d);
void iommu_share_p2m_table(struct domain *d);

int iommu_do_domctl(struct xen_domctl *, XEN_GUEST_HANDLE(xen_domctl_t));

void iommu_iotlb_flush(struct domain *d, unsigned long gfn, unsigned int page_count);
void iommu_iotlb_flush_all(struct domain *d);

/*
 * The purpose of the iommu_dont_flush_iotlb optional cpu flag is to
 * avoid unecessary iotlb_flush in the low level IOMMU code.
 *
 * iommu_map_page/iommu_unmap_page must flush the iotlb but somethimes
 * this operation can be really expensive. This flag will be set by the
 * caller to notify the low level IOMMU code to avoid the iotlb flushes.
 * iommu_iotlb_flush/iommu_iotlb_flush_all will be explicitly called by
 * the caller.
 */
DECLARE_PER_CPU(bool_t, iommu_dont_flush_iotlb);

#endif /* _IOMMU_H_ */
