/*
 * pci_regs.h
 *
 * PCI standard defines
 * Copyright 1994, Drew Eckhardt
 * Copyright 1997--1999 Martin Mares <mj@ucw.cz>
 *
 * For more information, please consult the following manuals (look at
 * http://www.pcisig.com/ for how to get them):
 *
 * PCI BIOS Specification
 * PCI Local Bus Specification
 * PCI to PCI Bridge Specification
 * PCI System Design Guide
 */

#ifndef __HVMLOADER_PCI_REGS_H__
#define __HVMLOADER_PCI_REGS_H__

#define PCI_VENDOR_ID  0x00 /* 16 bits */
#define PCI_DEVICE_ID  0x02 /* 16 bits */
#define PCI_COMMAND  0x04 /* 16 bits */
#define  PCI_COMMAND_IO  0x1 /* Enable response in I/O space */
#define  PCI_COMMAND_MEMORY 0x2 /* Enable response in Memory space */
#define  PCI_COMMAND_MASTER 0x4 /* Enable bus mastering */
#define  PCI_COMMAND_SPECIAL 0x8 /* Enable response to special cycles */
#define  PCI_COMMAND_INVALIDATE 0x10 /* Use memory write and invalidate */
#define  PCI_COMMAND_VGA_PALETTE 0x20 /* Enable palette snooping */
#define  PCI_COMMAND_PARITY 0x40 /* Enable parity checking */
#define  PCI_COMMAND_WAIT  0x80 /* Enable address/data stepping */
#define  PCI_COMMAND_SERR 0x100 /* Enable SERR */
#define  PCI_COMMAND_FAST_BACK 0x200 /* Enable back-to-back writes */
#define  PCI_COMMAND_INTX_DISABLE 0x400 /* INTx Emulation Disable */

#define PCI_STATUS  0x06 /* 16 bits */
#define  PCI_STATUS_CAP_LIST 0x10 /* Support Capability List */
#define  PCI_STATUS_66MHZ 0x20 /* Support 66 Mhz PCI 2.1 bus */
#define  PCI_STATUS_UDF  0x40 /* Support User Definable Features [obsolete] */
#define  PCI_STATUS_FAST_BACK 0x80 /* Accept fast-back to back */
#define  PCI_STATUS_PARITY 0x100 /* Detected parity error */
#define  PCI_STATUS_DEVSEL_MASK 0x600 /* DEVSEL timing */
#define  PCI_STATUS_DEVSEL_FAST  0x000
#define  PCI_STATUS_DEVSEL_MEDIUM 0x200
#define  PCI_STATUS_DEVSEL_SLOW  0x400
#define  PCI_STATUS_SIG_TARGET_ABORT 0x800 /* Set on target abort */
#define  PCI_STATUS_REC_TARGET_ABORT 0x1000 /* Master ack of " */
#define  PCI_STATUS_REC_MASTER_ABORT 0x2000 /* Set on master abort */
#define  PCI_STATUS_SIG_SYSTEM_ERROR 0x4000 /* Set when we drive SERR */
#define  PCI_STATUS_DETECTED_PARITY 0x8000 /* Set on parity error */

#define PCI_CLASS_REVISION 0x08 /* High 24 bits are class, low 8 revision */
#define PCI_REVISION_ID  0x08 /* Revision ID */
#define PCI_CLASS_PROG  0x09 /* Reg. Level Programming Interface */
#define PCI_CLASS_DEVICE 0x0a /* Device class */

#define PCI_CACHE_LINE_SIZE 0x0c /* 8 bits */
#define PCI_LATENCY_TIMER 0x0d /* 8 bits */
#define PCI_HEADER_TYPE  0x0e /* 8 bits */
#define  PCI_HEADER_TYPE_NORMAL  0
#define  PCI_HEADER_TYPE_BRIDGE  1
#define  PCI_HEADER_TYPE_CARDBUS 2

#define PCI_BIST  0x0f /* 8 bits */
#define  PCI_BIST_CODE_MASK 0x0f /* Return result */
#define  PCI_BIST_START  0x40 /* 1 to start BIST, 2 secs or less */
#define  PCI_BIST_CAPABLE 0x80 /* 1 if BIST capable */

/*
 * Base addresses specify locations in memory or I/O space.
 * Decoded size can be determined by writing a value of
 * 0xffffffff to the register, and reading it back.  Only
 * 1 bits are decoded.
 */
#define PCI_BASE_ADDRESS_0 0x10 /* 32 bits */
#define PCI_BASE_ADDRESS_1 0x14 /* 32 bits [htype 0,1 only] */
#define PCI_BASE_ADDRESS_2 0x18 /* 32 bits [htype 0 only] */
#define PCI_BASE_ADDRESS_3 0x1c /* 32 bits */
#define PCI_BASE_ADDRESS_4 0x20 /* 32 bits */
#define PCI_BASE_ADDRESS_5 0x24 /* 32 bits */
#define  PCI_BASE_ADDRESS_SPACE  0x01 /* 0 = memory, 1 = I/O */
#define  PCI_BASE_ADDRESS_SPACE_IO 0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY 0x00
#define  PCI_BASE_ADDRESS_MEM_TYPE_MASK 0x06
#define  PCI_BASE_ADDRESS_MEM_TYPE_32 0x00 /* 32 bit address */
#define  PCI_BASE_ADDRESS_MEM_TYPE_1M 0x02 /* Below 1M [obsolete] */
#define  PCI_BASE_ADDRESS_MEM_TYPE_64 0x04 /* 64 bit address */
#define  PCI_BASE_ADDRESS_MEM_PREFETCH 0x08 /* prefetchable? */
#define  PCI_BASE_ADDRESS_MEM_MASK (~0x0fUL)
#define  PCI_BASE_ADDRESS_IO_MASK (~0x03UL)
/* bit 1 is reserved if address_space = 1 */

/* Header type 0 (normal devices) */
#define PCI_CARDBUS_CIS  0x28
#define PCI_SUBSYSTEM_VENDOR_ID 0x2c
#define PCI_SUBSYSTEM_ID 0x2e
#define PCI_ROM_ADDRESS  0x30 /* Bits 31..11 are address, 10..1 reserved */
#define  PCI_ROM_ADDRESS_ENABLE 0x01
#define PCI_ROM_ADDRESS_MASK (~0x7ffUL)

#define PCI_CAPABILITY_LIST 0x34 /* Offset of first capability list entry */

/* 0x35-0x3b are reserved */
#define PCI_INTERRUPT_LINE 0x3c /* 8 bits */
#define PCI_INTERRUPT_PIN 0x3d /* 8 bits */
#define PCI_MIN_GNT  0x3e /* 8 bits */
#define PCI_MAX_LAT  0x3f /* 8 bits */

#define PCI_INTEL_OPREGION 0xfc /* 4 bits */

#endif /* __HVMLOADER_PCI_REGS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
