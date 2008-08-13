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
#include "audio/sys-queue.h"

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

/* because the current version of libpci (2.2.0) doesn't define these ID,
 * so we define Capability ID here.
 */
#ifndef PCI_CAP_ID_HOTPLUG
/* SHPC Capability List Item reg group */
#define PCI_CAP_ID_HOTPLUG      0x0C
#endif

#ifndef PCI_CAP_ID_SSVID
/* Subsystem ID and Subsystem Vendor ID Capability List Item reg group */
#define PCI_CAP_ID_SSVID        0x0D
#endif

#ifndef PCI_MSI_FLAGS_MASK_BIT
/* interrupt masking & reporting supported */
#define PCI_MSI_FLAGS_MASK_BIT  0x0100
#endif

#define PT_INVALID_REG          0xFFFFFFFF      /* invalid register value */
#define PT_BAR_ALLF             0xFFFFFFFF      /* BAR ALLF value */
#define PT_BAR_MEM_RO_MASK      0x0000000F      /* BAR ReadOnly mask(Memory) */
#define PT_BAR_MEM_EMU_MASK     0xFFFFFFF0      /* BAR emul mask(Memory) */
#define PT_BAR_IO_RO_MASK       0x00000003      /* BAR ReadOnly mask(I/O) */
#define PT_BAR_IO_EMU_MASK      0xFFFFFFFC      /* BAR emul mask(I/O) */
enum {
    PT_BAR_FLAG_MEM = 0,                        /* Memory type BAR */
    PT_BAR_FLAG_IO,                             /* I/O type BAR */
    PT_BAR_FLAG_UPPER,                          /* upper 64bit BAR */
    PT_BAR_FLAG_UNUSED,                         /* unused BAR */
};
enum {
    GRP_TYPE_HARDWIRED = 0,                     /* 0 Hardwired reg group */
    GRP_TYPE_EMU,                               /* emul reg group */
};

#define PT_GET_EMUL_SIZE(flag, r_size) do { \
    if (flag == PT_BAR_FLAG_MEM) {\
        r_size = (((r_size) + XC_PAGE_SIZE - 1) & ~(XC_PAGE_SIZE - 1)); \
    }\
} while(0)


struct pt_region {
    /* Virtual phys base & size */
    uint32_t e_physbase;
    uint32_t e_size;
    /* Index of region in qemu */
    uint32_t memory_index;
    /* BAR flag */
    uint32_t bar_flag;
    /* Translation of the emulated address */
    union {
        uint64_t maddr;
        uint64_t pio_base;
        uint64_t u;
    } access;
};

struct pt_msi_info {
    uint32_t flags;
    int pirq;          /* guest pirq corresponding */
    uint32_t addr_lo;  /* guest message address */
    uint32_t addr_hi;  /* guest message upper address */
    uint16_t data;     /* guest message data */
};

struct msix_entry_info {
    int pirq;          /* -1 means unmapped */
    int flags;         /* flags indicting whether MSI ADDR or DATA is updated */
    uint32_t io_mem[4];
};

struct pt_msix_info {
    int enabled;
    int total_entries;
    int bar_index;
    uint64_t table_base;
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
    struct pci_dev *pci_dev;                    /* libpci struct */
    struct pt_region bases[PCI_NUM_REGIONS];    /* Access regions */
    LIST_HEAD (reg_grp_tbl_listhead, pt_reg_grp_tbl) reg_grp_tbl_head;
                                                /* emul reg group list */
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

/* emul reg group management table */
struct pt_reg_grp_tbl {
    /* emul reg group list */
    LIST_ENTRY (pt_reg_grp_tbl) entries;
    /* emul reg group info table */
    struct pt_reg_grp_info_tbl *reg_grp;
    /* emul reg group base offset */
    uint32_t base_offset;
    /* emul reg group size */
    uint8_t size;
    /* emul reg management table list */
    LIST_HEAD (reg_tbl_listhead, pt_reg_tbl) reg_tbl_head;
};

/* emul reg group size initialize method */
typedef uint8_t (*pt_reg_size_init) (struct pt_dev *ptdev, 
                                     struct pt_reg_grp_info_tbl *grp_reg, 
                                     uint32_t base_offset);
/* emul reg group infomation table */
struct pt_reg_grp_info_tbl {
    /* emul reg group ID */
    uint8_t grp_id;
    /* emul reg group type */
    uint8_t grp_type;
    /* emul reg group size */
    uint8_t grp_size;
    /* emul reg get size method */
    pt_reg_size_init size_init;
    /* emul reg info table */
    struct pt_reg_info_tbl *emu_reg_tbl;
};

/* emul reg management table */
struct pt_reg_tbl {
    /* emul reg table list */
    LIST_ENTRY (pt_reg_tbl) entries;
    /* emul reg info table */
    struct pt_reg_info_tbl *reg;
    /* emul reg value */
    uint32_t data;
};

/* emul reg initialize method */
typedef uint32_t (*conf_reg_init) (struct pt_dev *ptdev, 
                                   struct pt_reg_info_tbl *reg, 
                                   uint32_t real_offset);
/* emul reg long write method */
typedef int (*conf_dword_write) (struct pt_dev *ptdev,
                                 struct pt_reg_tbl *cfg_entry, 
                                 uint32_t *value, 
                                 uint32_t dev_value,
                                 uint32_t valid_mask);
/* emul reg word write method */
typedef int (*conf_word_write) (struct pt_dev *ptdev,
                                struct pt_reg_tbl *cfg_entry, 
                                uint16_t *value, 
                                uint16_t dev_value,
                                uint16_t valid_mask);
/* emul reg byte write method */
typedef int (*conf_byte_write) (struct pt_dev *ptdev,
                                struct pt_reg_tbl *cfg_entry, 
                                uint8_t *value, 
                                uint8_t dev_value,
                                uint8_t valid_mask);
/* emul reg long read methods */
typedef int (*conf_dword_read) (struct pt_dev *ptdev,
                                struct pt_reg_tbl *cfg_entry, 
                                uint32_t *value,
                                uint32_t valid_mask);
/* emul reg word read method */
typedef int (*conf_word_read) (struct pt_dev *ptdev,
                               struct pt_reg_tbl *cfg_entry, 
                               uint16_t *value,
                               uint16_t valid_mask);
/* emul reg byte read method */
typedef int (*conf_byte_read) (struct pt_dev *ptdev,
                               struct pt_reg_tbl *cfg_entry, 
                               uint8_t *value,
                               uint8_t valid_mask);

/* emul reg infomation table */
struct pt_reg_info_tbl {
    /* reg relative offset */
    uint32_t offset;
    /* reg size */
    uint32_t size;
    /* reg initial value */
    uint32_t init_val;
    /* reg read only field mask (ON:RO/ROS, OFF:other) */
    uint32_t ro_mask;
    /* reg emulate field mask (ON:emu, OFF:passthrough) */
    uint32_t emu_mask;
    /* emul reg initialize method */
    conf_reg_init init;
    union {
        struct {
            /* emul reg long write method */
            conf_dword_write write;
            /* emul reg long read method */
            conf_dword_read read;
        } dw;
        struct {
            /* emul reg word write method */
            conf_word_write write;
            /* emul reg word read method */
            conf_word_read read;
        } w;
        struct {
            /* emul reg byte write method */
            conf_byte_write write;
            /* emul reg byte read method */
            conf_byte_read read;
        } b;
    } u;
};

#endif /* __PASSTHROUGH_H__ */

