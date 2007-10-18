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
#include <xen/bitmap.h>
#include <xen/irq.h>
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <asm/hvm/vmx/intel-iommu.h>
#include <public/hvm/ioreq.h>
#include <public/domctl.h>

extern int vtd_enabled;

#define domain_hvm_iommu(d)     (&d->arch.hvm_domain.hvm_iommu)
#define domain_vmx_iommu(d)     (&d->arch.hvm_domain.hvm_iommu.vmx_iommu)

/*
 * The PCI interface treats multi-function devices as independent
 * devices.  The slot/function address of each device is encoded
 * in a single byte as follows:
 *
 * 15:8 = bus
 *  7:3 = slot
 *  2:0 = function
 */
#define PCI_DEVFN(slot,func)  (((slot & 0x1f) << 3) | (func & 0x07))
#define PCI_SLOT(devfn)       (((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)       ((devfn) & 0x07)

struct pci_dev {
    struct list_head list;
    u8 bus;
    u8 devfn;
};

struct iommu {
    struct list_head list;
    void __iomem *reg; /* Pointer to hardware regs, virtual addr */
    u32	gcmd;          /* Holds TE, EAFL. Don't need SRTP, SFL, WBF */
    u64	cap;
    u64	ecap;
    spinlock_t lock; /* protect context, domain ids */
    spinlock_t register_lock; /* protect iommu register handling */
    struct root_entry *root_entry; /* virtual address */
    unsigned int vector;
};

int iommu_setup(void);
int iommu_domain_init(struct domain *d);
void iommu_domain_destroy(struct domain *d);
int device_assigned(u8 bus, u8 devfn);
int assign_device(struct domain *d, u8 bus, u8 devfn);
int iommu_map_page(struct domain *d, dma_addr_t gfn, dma_addr_t mfn);
int iommu_unmap_page(struct domain *d, dma_addr_t gfn);
void iommu_flush(struct domain *d, dma_addr_t gfn, u64 *p2m_entry);
void iommu_set_pgd(struct domain *d);
void iommu_domain_teardown(struct domain *d);
int hvm_do_IRQ_dpci(struct domain *d, unsigned int irq);
int dpci_ioport_intercept(ioreq_t *p);
int pt_irq_create_bind_vtd(struct domain *d,
    xen_domctl_bind_pt_irq_t * pt_irq_bind);


#endif // _IOMMU_H_
