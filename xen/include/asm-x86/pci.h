#ifndef __X86_PCI_H__
#define __X86_PCI_H__

#define IS_SNB_GFX(id) (id == 0x01068086 || id == 0x01168086 \
                        || id == 0x01268086 || id == 0x01028086 \
                        || id == 0x01128086 || id == 0x01228086 \
                        || id == 0x010A8086 )

struct arch_pci_dev {
    vmask_t used_vectors;
};

#endif /* __X86_PCI_H__ */
