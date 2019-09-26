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
                                      unsigned int *flush_flags);

#endif /* __ARCH_ARM_IOMMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
