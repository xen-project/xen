#ifndef _PT_MSI_H
#define _PT_MSI_H

#include "vl.h"
#include "pci/header.h"
#include "pci/pci.h"
#include "pass-through.h"

#define MSI_FLAG_UNINIT 0x1000
#define PT_MSI_MAPPED   0x2000

#define MSI_DATA_VECTOR_SHIFT          0
#define     MSI_DATA_VECTOR(v)         (((u8)v) << MSI_DATA_VECTOR_SHIFT)

#define MSI_DATA_DELIVERY_SHIFT        8
#define     MSI_DATA_DELIVERY_FIXED    (0 << MSI_DATA_DELIVERY_SHIFT)
#define     MSI_DATA_DELIVERY_LOWPRI   (1 << MSI_DATA_DELIVERY_SHIFT)

#define MSI_DATA_LEVEL_SHIFT           14
#define     MSI_DATA_LEVEL_DEASSERT    (0 << MSI_DATA_LEVEL_SHIFT)
#define     MSI_DATA_LEVEL_ASSERT      (1 << MSI_DATA_LEVEL_SHIFT)

#define MSI_DATA_TRIGGER_SHIFT         15
#define     MSI_DATA_TRIGGER_EDGE      (0 << MSI_DATA_TRIGGER_SHIFT)
#define     MSI_DATA_TRIGGER_LEVEL     (1 << MSI_DATA_TRIGGER_SHIFT)

/*
   + * Shift/mask fields for APIC-based bus address
   + */

#define MSI_ADDR_HEADER                0xfee00000
#define MSI_TARGET_CPU_SHIFT   	       12

#define MSI_ADDR_DESTID_MASK           0xfff0000f
#define     MSI_ADDR_DESTID_CPU(cpu)   ((cpu) << MSI_TARGET_CPU_SHIFT)

#define MSI_ADDR_DESTMODE_SHIFT        2
#define     MSI_ADDR_DESTMODE_PHYS     (0 << MSI_ADDR_DESTMODE_SHIFT)
#define        MSI_ADDR_DESTMODE_LOGIC (1 << MSI_ADDR_DESTMODE_SHIFT)

#define MSI_ADDR_REDIRECTION_SHIFT     3
#define     MSI_ADDR_REDIRECTION_CPU   (0 << MSI_ADDR_REDIRECTION_SHIFT)
#define     MSI_ADDR_REDIRECTION_LOWPRI (1 << MSI_ADDR_REDIRECTION_SHIFT)

#define PCI_MSI_FLAGS_PVMASK           0x100

#define AUTO_ASSIGN -1

/* shift count for gflags */
#define GFLAGS_SHIFT_DEST_ID        0
#define GFLAGS_SHIFT_RH             8
#define GFLAGS_SHIFT_DM             9
#define GLFAGS_SHIFT_DELIV_MODE     12
#define GLFAGS_SHIFT_TRG_MODE       15

int
pt_msi_init(struct pt_dev *dev, int pos);

int
pt_msi_write(struct pt_dev *d, uint32_t addr, uint32_t val, uint32_t len);

int
pt_msi_read(struct pt_dev *d, int addr, int len, uint32_t *val);

int
remove_msix_mapping(struct pt_dev *dev, int bar_index);

int
add_msix_mapping(struct pt_dev *dev, int bar_index);

int
pt_msix_init(struct pt_dev *dev, int pos);

int
pt_msix_write(struct pt_dev *d, uint32_t addr, uint32_t val, uint32_t len);

int
pt_msix_read(struct pt_dev *d, int addr, int len, uint32_t *val);

#endif
