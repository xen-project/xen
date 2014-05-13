#ifndef __ASM_ARM_HVM_IOMMU_H_
#define __ASM_ARM_HVM_IOMMU_H_

struct arch_hvm_iommu
{
    /* Private information for the IOMMU drivers */
    void *priv;
};

#endif /* __ASM_ARM_HVM_IOMMU_H_ */
