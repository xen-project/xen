#ifndef __X86_PCI_H__
#define __X86_PCI_H__

#include <xen/mm.h>

#define CF8_BDF(cf8)     (  ((cf8) & 0x00ffff00U) >> 8)
#define CF8_ADDR_LO(cf8) (   (cf8) & 0x000000fcU)
#define CF8_ADDR_HI(cf8) (  ((cf8) & 0x0f000000U) >> 16)
#define CF8_ENABLED(cf8) (!!((cf8) & 0x80000000U))

#define IS_SNB_GFX(id) ((id) == 0x01068086 || (id) == 0x01168086 \
                        || (id) == 0x01268086 || (id) == 0x01028086 \
                        || (id) == 0x01128086 || (id) == 0x01228086 \
                        || (id) == 0x010A8086 )

struct arch_pci_dev {
    vmask_t used_vectors;
    /*
     * These fields are (de)initialized under pcidevs-lock. Other uses of
     * them don't race (de)initialization and hence don't strictly need any
     * locking.
     */
    union {
        /* Subset of struct arch_iommu's fields, to be used in dom_io. */
        struct {
            uint64_t pgd_maddr;
        } vtd;
        struct {
            struct page_info *root_table;
        } amd;
    };
    domid_t pseudo_domid;
    mfn_t leaf_mfn;
    struct page_list_head pgtables_list;
};

int pci_conf_write_intercept(unsigned int seg, unsigned int bdf,
                             unsigned int reg, unsigned int size,
                             uint32_t *data);
int pci_msi_conf_write_intercept(struct pci_dev *pdev, unsigned int reg,
                                 unsigned int size, uint32_t *data);
bool pci_mmcfg_decode(unsigned long mfn, unsigned int *seg,
                      unsigned int *bdf);

bool pci_ro_mmcfg_decode(unsigned long mfn, unsigned int *seg,
                         unsigned int *bdf);

/* MMCFG external variable defines */
extern int pci_mmcfg_config_num;
extern struct acpi_mcfg_allocation *pci_mmcfg_config;

/* Unlike ARM, PCI passthrough is always enabled for x86. */
static always_inline bool is_pci_passthrough_enabled(void)
{
    return true;
}

void arch_pci_init_pdev(struct pci_dev *pdev);

static inline bool pci_check_bar(const struct pci_dev *pdev,
                                 mfn_t start, mfn_t end)
{
    /*
     * Check if BAR is not overlapping with any memory region defined
     * in the memory map.
     */
    return is_memory_hole(start, end);
}

#endif /* __X86_PCI_H__ */
