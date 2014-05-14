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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
*/
#ifndef __ARCH_X86_IOMMU_H__
#define __ARCH_X86_IOMMU_H__

#define MAX_IOMMUS 32

#include <asm/msi.h>

void iommu_update_ire_from_apic(unsigned int apic, unsigned int reg, unsigned int value);
unsigned int iommu_read_apic_from_ire(unsigned int apic, unsigned int reg);
int iommu_setup_hpet_msi(struct msi_desc *);

/* While VT-d specific, this must get declared in a generic header. */
int adjust_vtd_irq_affinities(void);
void iommu_pte_flush(struct domain *d, u64 gfn, u64 *pte, int order, int present);
int iommu_supports_eim(void);
int iommu_enable_x2apic_IR(void);
void iommu_disable_x2apic_IR(void);

#endif /* !__ARCH_X86_IOMMU_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
