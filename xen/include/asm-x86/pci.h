#ifndef __X86_PCI_H__
#define __X86_PCI_H__

#define CF8_BDF(cf8)     (  ((cf8) & 0x00ffff00) >> 8)
#define CF8_ADDR_LO(cf8) (   (cf8) & 0x000000fc)
#define CF8_ADDR_HI(cf8) (  ((cf8) & 0x0f000000) >> 16)
#define CF8_ENABLED(cf8) (!!((cf8) & 0x80000000))

#define IS_SNB_GFX(id) (id == 0x01068086 || id == 0x01168086 \
                        || id == 0x01268086 || id == 0x01028086 \
                        || id == 0x01128086 || id == 0x01228086 \
                        || id == 0x010A8086 )

struct arch_pci_dev {
    vmask_t used_vectors;
};

int pci_conf_write_intercept(unsigned int seg, unsigned int bdf,
                             unsigned int reg, unsigned int size,
                             uint32_t *data);
int pci_msi_conf_write_intercept(struct pci_dev *, unsigned int reg,
                                 unsigned int size, uint32_t *data);
bool_t pci_mmcfg_decode(unsigned long mfn, unsigned int *seg,
                        unsigned int *bdf);

bool_t pci_ro_mmcfg_decode(unsigned long mfn, unsigned int *seg,
                           unsigned int *bdf);

#endif /* __X86_PCI_H__ */
