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

#endif /* __X86_PCI_H__ */
