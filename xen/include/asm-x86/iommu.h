/*
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
*/
#ifndef __ARCH_X86_IOMMU_H__
#define __ARCH_X86_IOMMU_H__

#include <xen/errno.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <asm/processor.h>
#include <asm/hvm/vmx/vmcs.h>

#define DEFAULT_DOMAIN_ADDRESS_WIDTH 48
#define MAX_IOMMUS 32

struct g2m_ioport {
    struct list_head list;
    unsigned int gport;
    unsigned int mport;
    unsigned int np;
};

struct arch_iommu
{
    u64 pgd_maddr;                 /* io page directory machine address */
    spinlock_t mapping_lock;            /* io page table lock */
    int agaw;     /* adjusted guest address width, 0 is level 2 30-bit */
    u64 iommu_bitmap;              /* bitmap of iommu(s) that the domain uses */
    struct list_head mapped_rmrrs;

    /* amd iommu support */
    int paging_mode;
    struct page_info *root_table;
    struct guest_iommu *g_iommu;
};

extern const struct iommu_ops intel_iommu_ops;
extern const struct iommu_ops amd_iommu_ops;
int intel_vtd_setup(void);
int amd_iov_detect(void);

static inline const struct iommu_ops *iommu_get_ops(void)
{
    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        return &intel_iommu_ops;
    case X86_VENDOR_AMD:
        return &amd_iommu_ops;
    }

    BUG();

    return NULL;
}

static inline int iommu_hardware_setup(void)
{
    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        return intel_vtd_setup();
    case X86_VENDOR_AMD:
        return amd_iov_detect();
    }

    return -ENODEV;
}

/* Does this domain have a P2M table we can use as its IOMMU pagetable? */
#define iommu_use_hap_pt(d) (hap_enabled(d) && iommu_hap_pt_share)

void iommu_update_ire_from_apic(unsigned int apic, unsigned int reg, unsigned int value);
unsigned int iommu_read_apic_from_ire(unsigned int apic, unsigned int reg);
int iommu_setup_hpet_msi(struct msi_desc *);

/* While VT-d specific, this must get declared in a generic header. */
int adjust_vtd_irq_affinities(void);
int __must_check iommu_pte_flush(struct domain *d, u64 gfn, u64 *pte,
                                 int order, int present);
bool_t iommu_supports_eim(void);
int iommu_enable_x2apic_IR(void);
void iommu_disable_x2apic_IR(void);

extern bool untrusted_msi;

int pi_update_irte(const struct pi_desc *pi_desc, const struct pirq *pirq,
                   const uint8_t gvec);

#endif /* !__ARCH_X86_IOMMU_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
