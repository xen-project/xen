/*
 * Copyright (c) 2007, Neocleus Corporation.
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
#ifndef __PASSTHROUGH_H__
#define __PASSTHROUGH_H__

#include "vl.h"
#include "pci/header.h"
#include "pci/pci.h"

/* Log acesss */
#define PT_LOGGING_ENABLED

#ifdef PT_LOGGING_ENABLED
#define PT_LOG(_f, _a...)   fprintf(logfile, "%s: " _f, __func__, ##_a)
#else
#define PT_LOG(_f, _a...)
#endif

/* Some compilation flags */
// #define PT_DEBUG_PCI_CONFIG_ACCESS

#define PT_MACHINE_IRQ_AUTO (0xFFFFFFFF)
#define PT_VIRT_DEVFN_AUTO  (-1)

/* Misc PCI constants that should be moved to a separate library :) */
#define PCI_CONFIG_SIZE         (256)
#define PCI_EXP_DEVCAP_FLR      (1 << 28)
#define PCI_EXP_DEVCTL_FLR      (1 << 15)
#define PCI_BAR_ENTRIES         (6)

struct pt_region {
    /* Virtual phys base & size */
    uint32_t e_physbase;
    uint32_t e_size;
    /* Index of region in qemu */
    uint32_t memory_index;
    /* Translation of the emulated address */
    union {
        uint32_t maddr;
        uint32_t pio_base;
        uint32_t u;
    } access;
};

struct pt_msi_info {
    uint32_t flags;
    int offset;
    int size;
    int pirq;  /* guest pirq corresponding */
};

struct msix_entry_info {
    int pirq;   /* -1 means unmapped */
    int flags;  /* flags indicting whether MSI ADDR or DATA is updated */
    uint32_t io_mem[4];
};

struct pt_msix_info {
    int enabled;
    int offset;
    int total_entries;
    int bar_index;
    uint32_t table_off;
    uint64_t mmio_base_addr;
    int mmio_index;
    int fd;
    void *phys_iomem_base;
    struct msix_entry_info msix_entry[0];
};

/*
    This structure holds the context of the mapping functions
    and data that is relevant for qemu device management.
*/
struct pt_dev {
    PCIDevice dev;
    struct pci_dev *pci_dev;                     /* libpci struct */
    struct pt_region bases[PCI_NUM_REGIONS];    /* Access regions */
    struct pt_msi_info *msi;                    /* MSI virtualization */
    struct pt_msix_info *msix;                  /* MSI-X virtualization */
};

/* Used for formatting PCI BDF into cf8 format */
struct pci_config_cf8 {
    union {
        unsigned int value;
        struct {
            unsigned int reserved1:2;
            unsigned int reg:6;
            unsigned int func:3;
            unsigned int dev:5;
            unsigned int bus:8;
            unsigned int reserved2:7;
            unsigned int enable:1;
        };
    };
};

int pt_init(PCIBus * e_bus, char * direct_pci);

#endif /* __PASSTHROUGH_H__ */

