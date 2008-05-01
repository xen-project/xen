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
#include <xen/pci.h>
#include <xen/spinlock.h>
#include <public/hvm/ioreq.h>
#include <public/domctl.h>

extern int vtd_enabled;
extern int iommu_enabled;

#define domain_hvm_iommu(d)     (&d->arch.hvm_domain.hvm_iommu)
#define domain_vmx_iommu(d)     (&d->arch.hvm_domain.hvm_iommu.vmx_iommu)

#define MAX_IOMMUS 32

#define PAGE_SHIFT_4K       (12)
#define PAGE_SIZE_4K        (1UL << PAGE_SHIFT_4K)
#define PAGE_MASK_4K        (((u64)-1) << PAGE_SHIFT_4K)
#define PAGE_ALIGN_4K(addr) (((addr) + PAGE_SIZE_4K - 1) & PAGE_MASK_4K)

struct iommu {
    struct list_head list;
    void __iomem *reg; /* Pointer to hardware regs, virtual addr */
    u32	gcmd;          /* Holds TE, EAFL. Don't need SRTP, SFL, WBF */
    u64	cap;
    u64	ecap;
    spinlock_t lock; /* protect context, domain ids */
    spinlock_t register_lock; /* protect iommu register handling */
    u64 root_maddr; /* root entry machine address */
    unsigned int vector;
    struct intel_iommu *intel;
};

int iommu_domain_init(struct domain *d);
void iommu_domain_destroy(struct domain *d);
int device_assigned(u8 bus, u8 devfn);
int assign_device(struct domain *d, u8 bus, u8 devfn);
void deassign_device(struct domain *d, u8 bus, u8 devfn);
void reassign_device_ownership(struct domain *source,
                               struct domain *target,
                               u8 bus, u8 devfn);
int iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn);
int iommu_unmap_page(struct domain *d, unsigned long gfn);
void iommu_flush(struct domain *d, unsigned long gfn, u64 *p2m_entry);
void iommu_set_pgd(struct domain *d);
void iommu_free_pgd(struct domain *d);
void iommu_domain_teardown(struct domain *d);
int hvm_do_IRQ_dpci(struct domain *d, unsigned int irq);
int dpci_ioport_intercept(ioreq_t *p);
int pt_irq_create_bind_vtd(struct domain *d,
                           xen_domctl_bind_pt_irq_t *pt_irq_bind);
int pt_irq_destroy_bind_vtd(struct domain *d,
                            xen_domctl_bind_pt_irq_t *pt_irq_bind);
unsigned int io_apic_read_remap_rte(unsigned int apic, unsigned int reg);
void io_apic_write_remap_rte(unsigned int apic,
                             unsigned int reg, unsigned int value);
struct qi_ctrl *iommu_qi_ctrl(struct iommu *iommu);
struct ir_ctrl *iommu_ir_ctrl(struct iommu *iommu);
struct iommu_flush *iommu_get_flush(struct iommu *iommu);
void hvm_dpci_isairq_eoi(struct domain *d, unsigned int isairq);
struct hvm_irq_dpci *domain_get_irq_dpci(struct domain *domain);
int domain_set_irq_dpci(struct domain *domain, struct hvm_irq_dpci *dpci);

#define PT_IRQ_TIME_OUT MILLISECS(8)
#define VTDPREFIX "[VT-D]"

struct iommu_ops {
    int (*init)(struct domain *d);
    int (*assign_device)(struct domain *d, u8 bus, u8 devfn);
    void (*teardown)(struct domain *d);
    int (*map_page)(struct domain *d, unsigned long gfn, unsigned long mfn);
    int (*unmap_page)(struct domain *d, unsigned long gfn);
    void (*reassign_device)(struct domain *s, struct domain *t,
                            u8 bus, u8 devfn);
};

#endif /* _IOMMU_H_ */
