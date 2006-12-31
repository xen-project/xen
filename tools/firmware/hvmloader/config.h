#ifndef __HVMLOADER_CONFIG_H__
#define __HVMLOADER_CONFIG_H__

#define IOAPIC_BASE_ADDRESS 0xfec00000
#define IOAPIC_ID           0x01
#define IOAPIC_VERSION      0x11

#define LAPIC_BASE_ADDRESS  0xfee00000
#define LAPIC_ID(vcpu_id)   ((vcpu_id) * 2)

#define PCI_ISA_DEVFN       0x08    /* dev 1, fn 0 */
#define PCI_ISA_IRQ_MASK    0x0c60U /* ISA IRQs 5,6,10,11 are PCI connected */

#endif /* __HVMLOADER_CONFIG_H__ */
