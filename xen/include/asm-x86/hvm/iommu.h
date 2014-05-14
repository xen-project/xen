#ifndef __ASM_X86_HVM_IOMMU_H__
#define __ASM_X86_HVM_IOMMU_H__

#include <xen/errno.h>

struct iommu_ops;
extern const struct iommu_ops intel_iommu_ops;
extern const struct iommu_ops amd_iommu_ops;
extern int intel_vtd_setup(void);
extern int amd_iov_detect(void);

static inline const struct iommu_ops *iommu_get_ops(void)
{
    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        return &intel_iommu_ops;
    case X86_VENDOR_AMD:
        return &amd_iommu_ops;
    default:
        BUG();
    }

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
    default:
        return -ENODEV;
    }

    return 0;
}

struct g2m_ioport {
    struct list_head list;
    unsigned int gport;
    unsigned int mport;
    unsigned int np;
};

struct arch_hvm_iommu
{
    u64 pgd_maddr;                 /* io page directory machine address */
    spinlock_t mapping_lock;            /* io page table lock */
    int agaw;     /* adjusted guest address width, 0 is level 2 30-bit */
    struct list_head g2m_ioport_list;   /* guest to machine ioport mapping */
    u64 iommu_bitmap;              /* bitmap of iommu(s) that the domain uses */
    struct list_head mapped_rmrrs;

    /* amd iommu support */
    int paging_mode;
    struct page_info *root_table;
    struct guest_iommu *g_iommu;
};

#endif /* __ASM_X86_HVM_IOMMU_H__ */
