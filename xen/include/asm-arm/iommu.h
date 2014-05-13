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
#ifndef __ARCH_ARM_IOMMU_H__
#define __ARCH_ARM_IOMMU_H__

/* Always share P2M Table between the CPU and the IOMMU */
#define iommu_use_hap_pt(d) (1)
#define domain_hvm_iommu(d) (&d->arch.hvm_domain.iommu)

const struct iommu_ops *iommu_get_ops(void);
void __init iommu_set_ops(const struct iommu_ops *ops);

int __init iommu_hardware_setup(void);

#endif /* __ARCH_ARM_IOMMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
