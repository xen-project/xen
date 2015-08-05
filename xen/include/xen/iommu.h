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
 * this program; If not, see <http://www.gnu.org/licenses/>.
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
#include <asm/device.h>
#include <asm/iommu.h>

extern bool_t iommu_enable, iommu_enabled;
extern bool_t force_iommu, iommu_verbose;
extern bool_t iommu_workaround_bios_bug, iommu_igfx, iommu_passthrough;
extern bool_t iommu_snoop, iommu_qinval, iommu_intremap;
extern bool_t iommu_hap_pt_share;
extern bool_t iommu_debug;
extern bool_t amd_iommu_perdev_intremap;

#define IOMMU_PAGE_SIZE(sz) (1UL << PAGE_SHIFT_##sz)
#define IOMMU_PAGE_MASK(sz) (~(u64)0 << PAGE_SHIFT_##sz)
#define IOMMU_PAGE_ALIGN(sz, addr)  (((addr) + ~PAGE_MASK_##sz) & PAGE_MASK_##sz)

#define PAGE_SHIFT_4K       (12)
#define PAGE_SIZE_4K        IOMMU_PAGE_SIZE(4K)
#define PAGE_MASK_4K        IOMMU_PAGE_MASK(4K)
#define PAGE_ALIGN_4K(addr) IOMMU_PAGE_ALIGN(4K, addr)

#define PAGE_SHIFT_64K          (16)
#define PAGE_SIZE_64K           IOMMU_PAGE_SIZE(64K)
#define PAGE_MASK_64K           IOMMU_PAGE_MASK(64K)
#define PAGE_ALIGN_64K(addr)    IOMMU_PAGE_ALIGN(64K, addr)

int iommu_setup(void);

int iommu_add_device(struct pci_dev *pdev);
int iommu_enable_device(struct pci_dev *pdev);
int iommu_remove_device(struct pci_dev *pdev);
int iommu_domain_init(struct domain *d);
void iommu_hwdom_init(struct domain *d);
void iommu_domain_destroy(struct domain *d);
int deassign_device(struct domain *d, u16 seg, u8 bus, u8 devfn);

void arch_iommu_domain_destroy(struct domain *d);
int arch_iommu_domain_init(struct domain *d);
int arch_iommu_populate_page_table(struct domain *d);
void arch_iommu_check_autotranslated_hwdom(struct domain *d);

int iommu_construct(struct domain *d);

/* Function used internally, use iommu_domain_destroy */
void iommu_teardown(struct domain *d);

/* iommu_map_page() takes flags to direct the mapping operation. */
#define _IOMMUF_readable 0
#define IOMMUF_readable  (1u<<_IOMMUF_readable)
#define _IOMMUF_writable 1
#define IOMMUF_writable  (1u<<_IOMMUF_writable)
int iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                   unsigned int flags);
int iommu_unmap_page(struct domain *d, unsigned long gfn);

enum iommu_feature
{
    IOMMU_FEAT_COHERENT_WALK,
    IOMMU_FEAT_count
};

bool_t iommu_has_feature(struct domain *d, enum iommu_feature feature);


#ifdef HAS_PCI
void pt_pci_init(void);

struct pirq;
int hvm_do_IRQ_dpci(struct domain *, struct pirq *);
int pt_irq_create_bind(struct domain *, xen_domctl_bind_pt_irq_t *);
int pt_irq_destroy_bind(struct domain *, xen_domctl_bind_pt_irq_t *);

void hvm_dpci_isairq_eoi(struct domain *d, unsigned int isairq);
struct hvm_irq_dpci *domain_get_irq_dpci(const struct domain *);
void free_hvm_irq_dpci(struct hvm_irq_dpci *dpci);
bool_t pt_irq_need_timer(uint32_t flags);

struct msi_desc;
struct msi_msg;

int iommu_update_ire_from_msi(struct msi_desc *msi_desc, struct msi_msg *msg);
void iommu_read_msi_from_ire(struct msi_desc *msi_desc, struct msi_msg *msg);

#define PT_IRQ_TIME_OUT MILLISECS(8)
#endif /* HAS_PCI */

#ifdef HAS_DEVICE_TREE
#include <xen/device_tree.h>

int iommu_assign_dt_device(struct domain *d, struct dt_device_node *dev);
int iommu_deassign_dt_device(struct domain *d, struct dt_device_node *dev);
int iommu_dt_domain_init(struct domain *d);
int iommu_release_dt_devices(struct domain *d);

int iommu_do_dt_domctl(struct xen_domctl *, struct domain *,
                       XEN_GUEST_HANDLE_PARAM(xen_domctl_t));

#endif /* HAS_DEVICE_TREE */

struct page_info;

/*
 * Any non-zero value returned from callbacks of this type will cause the
 * function the callback was handed to terminate its iteration. Assigning
 * meaning of these non-zero values is left to the top level caller /
 * callback pair.
 */
typedef int iommu_grdm_t(xen_pfn_t start, xen_ulong_t nr, u32 id, void *ctxt);

struct iommu_ops {
    int (*init)(struct domain *d);
    void (*hwdom_init)(struct domain *d);
    int (*add_device)(u8 devfn, device_t *dev);
    int (*enable_device)(device_t *dev);
    int (*remove_device)(u8 devfn, device_t *dev);
    int (*assign_device)(struct domain *, u8 devfn, device_t *dev, u32 flag);
    int (*reassign_device)(struct domain *s, struct domain *t,
                           u8 devfn, device_t *dev);
#ifdef HAS_PCI
    int (*get_device_group_id)(u16 seg, u8 bus, u8 devfn);
    int (*update_ire_from_msi)(struct msi_desc *msi_desc, struct msi_msg *msg);
    void (*read_msi_from_ire)(struct msi_desc *msi_desc, struct msi_msg *msg);
#endif /* HAS_PCI */

    void (*teardown)(struct domain *d);
    int (*map_page)(struct domain *d, unsigned long gfn, unsigned long mfn,
                    unsigned int flags);
    int (*unmap_page)(struct domain *d, unsigned long gfn);
    void (*free_page_table)(struct page_info *);
#ifdef CONFIG_X86
    void (*update_ire_from_apic)(unsigned int apic, unsigned int reg, unsigned int value);
    unsigned int (*read_apic_from_ire)(unsigned int apic, unsigned int reg);
    int (*setup_hpet_msi)(struct msi_desc *);
#endif /* CONFIG_X86 */
    void (*suspend)(void);
    void (*resume)(void);
    void (*share_p2m)(struct domain *d);
    void (*crash_shutdown)(void);
    void (*iotlb_flush)(struct domain *d, unsigned long gfn, unsigned int page_count);
    void (*iotlb_flush_all)(struct domain *d);
    int (*get_reserved_device_memory)(iommu_grdm_t *, void *);
    void (*dump_p2m_table)(struct domain *d);
};

void iommu_suspend(void);
void iommu_resume(void);
void iommu_crash_shutdown(void);
int iommu_get_reserved_device_memory(iommu_grdm_t *, void *);

void iommu_share_p2m_table(struct domain *d);

#ifdef HAS_PCI
int iommu_do_pci_domctl(struct xen_domctl *, struct domain *d,
                        XEN_GUEST_HANDLE_PARAM(xen_domctl_t));
#endif

int iommu_do_domctl(struct xen_domctl *, struct domain *d,
                    XEN_GUEST_HANDLE_PARAM(xen_domctl_t));

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

extern struct spinlock iommu_pt_cleanup_lock;
extern struct page_list_head iommu_pt_cleanup_list;

#endif /* _IOMMU_H_ */
