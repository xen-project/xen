#ifndef __HVMLOADER_CONFIG_H__
#define __HVMLOADER_CONFIG_H__

#include <stdint.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE  (1ul << PAGE_SHIFT)

#define IOAPIC_BASE_ADDRESS 0xfec00000
#define IOAPIC_ID           0x01
#define IOAPIC_VERSION      0x11

#define LAPIC_BASE_ADDRESS  0xfee00000
#define LAPIC_ID(vcpu_id)   ((vcpu_id) * 2)

#define PCI_ISA_DEVFN       0x08    /* dev 1, fn 0 */
#define PCI_ISA_IRQ_MASK    0x0c20U /* ISA IRQs 5,10,11 are PCI connected */

/* MMIO hole: Hardcoded defaults, which can be dynamically expanded. */
#define PCI_MEM_START       0xf0000000
#define PCI_MEM_END         0xfc000000
extern unsigned long pci_mem_start, pci_mem_end;

/* We reserve 16MB for special BIOS mappings, etc. */
#define RESERVED_MEMBASE    0xfc000000
#define RESERVED_MEMSIZE    0x01000000

#define ROMBIOS_BEGIN          0x000F0000
#define ROMBIOS_SIZE           0x00010000
#define ROMBIOS_MAXOFFSET      0x0000FFFF
#define ROMBIOS_END            (ROMBIOS_BEGIN + ROMBIOS_SIZE)

#include "e820.h"
#include "../rombios/config.h"

#define SCRATCH_PHYSICAL_ADDRESS      0x00010000
#define HYPERCALL_PHYSICAL_ADDRESS    0x00080000

#define VGABIOS_PHYSICAL_ADDRESS      0x000C0000

#endif /* __HVMLOADER_CONFIG_H__ */
