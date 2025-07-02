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
#ifndef __ARCH_ARM_IOMMU_H__
#define __ARCH_ARM_IOMMU_H__

struct arch_iommu
{
    /* Private information for the IOMMU drivers */
    void *priv;
};

const struct iommu_ops *iommu_get_ops(void);
void iommu_set_ops(const struct iommu_ops *ops);

/*
 * The mapping helpers below should only be used if P2M Table is shared
 * between the CPU and the IOMMU.
 */
int __must_check arm_iommu_map_page(struct domain *d, dfn_t dfn, mfn_t mfn,
                                    unsigned int flags,
                                    unsigned int *flush_flags);
int __must_check arm_iommu_unmap_page(struct domain *d, dfn_t dfn,
                                      unsigned int order,
                                      unsigned int *flush_flags);

/*
 * This function is not strictly ARM-specific, but it is only used by ARM
 * as of now. So put it here to avoid creating dead code on other
 * architectures. When usage is extended to other architectures, it should
 * be moved to the generic header.
 *
 *
 * Fills out the device's IOMMU fwspec with IOMMU ids.
 *
 * Return values:
 *  0 : iommu_fwspec is filled out successfully.
 * <0 : error while filling out the iommu_fwspec.
 * >0 : IOMMU is not enabled/present or device is not connected to it.
 */
int iommu_add_pci_sideband_ids(struct pci_dev *pdev);
#endif /* __ARCH_ARM_IOMMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
