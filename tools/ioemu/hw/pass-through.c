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
 *
 * Alex Novik <alex@neocleus.com>
 * Allen Kay <allen.m.kay@intel.com>
 * Guy Zana <guy@neocleus.com>
 *
 * This file implements direct PCI assignment to a HVM guest
 */

#include "vl.h"
#include "pass-through.h"
#include "pci/header.h"
#include "pci/pci.h"
#include "pt-msi.h"

extern FILE *logfile;

struct php_dev {
    struct pt_dev *pt_dev;
    uint8_t valid;
    uint8_t r_bus;
    uint8_t r_dev;
    uint8_t r_func;
};
struct dpci_infos {

    struct php_dev php_devs[PHP_SLOT_LEN];

    PCIBus *e_bus;
    struct pci_access *pci_access;

} dpci_infos;

/* prototype */
static uint32_t pt_common_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_ptr_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_status_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_irqpin_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_bar_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_linkctrl2_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_msgctrl_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_msgaddr32_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_msgaddr64_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_msgdata_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint32_t pt_msixctrl_reg_init(struct pt_dev *ptdev,
    struct pt_reg_info_tbl *reg, uint32_t real_offset);
static uint8_t pt_reg_grp_size_init(struct pt_dev *ptdev,
    struct pt_reg_grp_info_tbl *grp_reg, uint32_t base_offset);
static uint8_t pt_msi_size_init(struct pt_dev *ptdev,
    struct pt_reg_grp_info_tbl *grp_reg, uint32_t base_offset);
static uint8_t pt_msix_size_init(struct pt_dev *ptdev,
    struct pt_reg_grp_info_tbl *grp_reg, uint32_t base_offset);
static uint8_t pt_vendor_size_init(struct pt_dev *ptdev,
    struct pt_reg_grp_info_tbl *grp_reg, uint32_t base_offset);
static int pt_byte_reg_read(struct pt_dev *ptdev,
    struct pt_reg_tbl *cfg_entry,
    uint8_t *valueu, uint8_t valid_mask);
static int pt_word_reg_read(struct pt_dev *ptdev,
    struct pt_reg_tbl *cfg_entry,
    uint16_t *value, uint16_t valid_mask);
static int pt_long_reg_read(struct pt_dev *ptdev,
    struct pt_reg_tbl *cfg_entry,
    uint32_t *value, uint32_t valid_mask);
static int pt_bar_reg_read(struct pt_dev *ptdev,
    struct pt_reg_tbl *cfg_entry,
    uint32_t *value, uint32_t valid_mask);
static int pt_byte_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint8_t *value, uint8_t dev_value, uint8_t valid_mask);
static int pt_word_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_long_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint32_t *value, uint32_t dev_value, uint32_t valid_mask);
static int pt_cmd_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_bar_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint32_t *value, uint32_t dev_value, uint32_t valid_mask);
static int pt_exp_rom_bar_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint32_t *value, uint32_t dev_value, uint32_t valid_mask);
static int pt_pmcsr_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_devctrl_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_linkctrl_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_devctrl2_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_linkctrl2_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_msgctrl_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_msgaddr32_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint32_t *value, uint32_t dev_value, uint32_t valid_mask);
static int pt_msgaddr64_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint32_t *value, uint32_t dev_value, uint32_t valid_mask);
static int pt_msgdata_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);
static int pt_msixctrl_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask);

/* pt_reg_info_tbl declaration
 * - only for emulated register (either a part or whole bit).
 * - for passthrough register that need special behavior (like interacting with
 *   other component), set emu_mask to all 0 and specify r/w func properly.
 * - do NOT use ALL F for init_val, otherwise the tbl will not be registered.
 */
 
/* Header Type0 reg static infomation table */
static struct pt_reg_info_tbl pt_emu_reg_header0_tbl[] = {
    /* Command reg */
    {
        .offset     = PCI_COMMAND,
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0xF880,
        .emu_mask   = 0x0340,
        .init       = pt_common_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_cmd_reg_write,
    },
    /* Capabilities Pointer reg */
    {
        .offset     = PCI_CAPABILITY_LIST,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_ptr_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Status reg */
    /* use emulated Cap Ptr value to initialize, 
     * so need to be declared after Cap Ptr reg 
     */
    {
        .offset     = PCI_STATUS,
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x06FF,
        .emu_mask   = 0x0010,
        .init       = pt_status_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_word_reg_write,
    },
    /* Cache Line Size reg */
    {
        .offset     = PCI_CACHE_LINE_SIZE,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0x00,
        .emu_mask   = 0xFF,
        .init       = pt_common_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Latency Timer reg */
    {
        .offset     = PCI_LATENCY_TIMER,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0x00,
        .emu_mask   = 0xFF,
        .init       = pt_common_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Header Type reg */
    {
        .offset     = PCI_HEADER_TYPE,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0x80,
        .init       = pt_common_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Interrupt Line reg */
    {
        .offset     = PCI_INTERRUPT_LINE,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0x00,
        .emu_mask   = 0xFF,
        .init       = pt_common_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Interrupt Pin reg */
    {
        .offset     = PCI_INTERRUPT_PIN,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_irqpin_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* BAR 0 reg */
    /* mask of BAR need to be decided later, depends on IO/MEM type */
    {
        .offset     = PCI_BASE_ADDRESS_0,
        .size       = 4,
        .init_val   = 0x00000000,
        .init       = pt_bar_reg_init,
        .u.dw.read  = pt_bar_reg_read,
        .u.dw.write = pt_bar_reg_write,
    },
    /* BAR 1 reg */
    {
        .offset     = PCI_BASE_ADDRESS_1,
        .size       = 4,
        .init_val   = 0x00000000,
        .init       = pt_bar_reg_init,
        .u.dw.read  = pt_bar_reg_read,
        .u.dw.write = pt_bar_reg_write,
    },
    /* BAR 2 reg */
    {
        .offset     = PCI_BASE_ADDRESS_2,
        .size       = 4,
        .init_val   = 0x00000000,
        .init       = pt_bar_reg_init,
        .u.dw.read  = pt_bar_reg_read,
        .u.dw.write = pt_bar_reg_write,
    },
    /* BAR 3 reg */
    {
        .offset     = PCI_BASE_ADDRESS_3,
        .size       = 4,
        .init_val   = 0x00000000,
        .init       = pt_bar_reg_init,
        .u.dw.read  = pt_bar_reg_read,
        .u.dw.write = pt_bar_reg_write,
    },
    /* BAR 4 reg */
    {
        .offset     = PCI_BASE_ADDRESS_4,
        .size       = 4,
        .init_val   = 0x00000000,
        .init       = pt_bar_reg_init,
        .u.dw.read  = pt_bar_reg_read,
        .u.dw.write = pt_bar_reg_write,
    },
    /* BAR 5 reg */
    {
        .offset     = PCI_BASE_ADDRESS_5,
        .size       = 4,
        .init_val   = 0x00000000,
        .init       = pt_bar_reg_init,
        .u.dw.read  = pt_bar_reg_read,
        .u.dw.write = pt_bar_reg_write,
    },
    /* Expansion ROM BAR reg */
    {
        .offset     = PCI_ROM_ADDRESS,
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0x000007FE,
        .emu_mask   = 0xFFFFF800,
        .init       = pt_bar_reg_init,
        .u.dw.read  = pt_long_reg_read,
        .u.dw.write = pt_exp_rom_bar_reg_write,
    },
    {
        .size = 0,
    }, 
};

/* Power Management Capability reg static infomation table */
static struct pt_reg_info_tbl pt_emu_reg_pm_tbl[] = {
    /* Next Pointer reg */
    {
        .offset     = PCI_CAP_LIST_NEXT,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_ptr_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Power Management Capabilities reg */
    {
        .offset     = PCI_CAP_FLAGS,
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0xFFFF,
        .emu_mask   = 0xFFE8,
        .init       = pt_common_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_word_reg_write,
    },
    /* PCI Power Management Control/Status reg */
    {
        .offset     = PCI_PM_CTRL,
        .size       = 2,
        .init_val   = 0x0008,
        .ro_mask    = 0x60FC,
        .emu_mask   = 0xFF0B,
        .init       = pt_common_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_pmcsr_reg_write,
    },
    /* Data reg */
    {
        .offset     = PCI_PM_DATA_REGISTER,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_common_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    {
        .size = 0,
    }, 
};

/* Vital Product Data Capability Structure reg static infomation table */
static struct pt_reg_info_tbl pt_emu_reg_vpd_tbl[] = {
    /* Next Pointer reg */
    {
        .offset     = PCI_CAP_LIST_NEXT,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_ptr_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    {
        .size = 0,
    }, 
};

/* Vendor Specific Capability Structure reg static infomation table */
static struct pt_reg_info_tbl pt_emu_reg_vendor_tbl[] = {
    /* Next Pointer reg */
    {
        .offset     = PCI_CAP_LIST_NEXT,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_ptr_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    {
        .size = 0,
    }, 
};

/* PCI Express Capability Structure reg static infomation table */
static struct pt_reg_info_tbl pt_emu_reg_pcie_tbl[] = {
    /* Next Pointer reg */
    {
        .offset     = PCI_CAP_LIST_NEXT,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_ptr_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Device Capabilities reg */
    {
        .offset     = PCI_EXP_DEVCAP,
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0x1FFCFFFF,
        .emu_mask   = 0x10000000,
        .init       = pt_common_reg_init,
        .u.dw.read  = pt_long_reg_read,
        .u.dw.write = pt_long_reg_write,
    },
    /* Device Control reg */
    {
        .offset     = PCI_EXP_DEVCTL,
        .size       = 2,
        .init_val   = 0x2810,
        .ro_mask    = 0x0000,
        .emu_mask   = 0xFFFF,
        .init       = pt_common_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_devctrl_reg_write,
    },
    /* Link Control reg */
    {
        .offset     = PCI_EXP_LNKCTL,
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x0000,
        .emu_mask   = 0xFFFF,
        .init       = pt_common_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_linkctrl_reg_write,
    },
    /* Device Control 2 reg */
    {
        .offset     = 0x28,
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x0000,
        .emu_mask   = 0xFFFF,
        .init       = pt_common_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_devctrl2_reg_write,
    },
    /* Link Control 2 reg */
    {
        .offset     = 0x30,
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x0000,
        .emu_mask   = 0xFFFF,
        .init       = pt_linkctrl2_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_linkctrl2_reg_write,
    },
    {
        .size = 0,
    }, 
};

/* MSI Capability Structure reg static infomation table */
static struct pt_reg_info_tbl pt_emu_reg_msi_tbl[] = {
    /* Next Pointer reg */
    {
        .offset     = PCI_CAP_LIST_NEXT,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_ptr_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Message Control reg */
    {
        .offset     = PCI_MSI_FLAGS, // 2
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x018E,
        .emu_mask   = 0xFFFE,
        .init       = pt_msgctrl_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_msgctrl_reg_write,
    },
    /* Message Address reg */
    {
        .offset     = PCI_MSI_ADDRESS_LO, // 4
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0x00000FF0,    /* bit 4~11 is reserved for MSI in x86 */
        .emu_mask   = 0xFFFFFFFF,
        .init       = pt_msgaddr32_reg_init,
        .u.dw.read  = pt_long_reg_read,
        .u.dw.write = pt_msgaddr32_reg_write,
    },
    /* Message Upper Address reg (if PCI_MSI_FLAGS_64BIT set) */
    {
        .offset     = PCI_MSI_ADDRESS_HI, // 8
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0x00000000,
        .emu_mask   = 0xFFFFFFFF,
        .init       = pt_msgaddr64_reg_init,
        .u.dw.read  = pt_long_reg_read,
        .u.dw.write = pt_msgaddr64_reg_write,
    },
    /* Message Data reg (16 bits of data for 32-bit devices) */
    {
        .offset     = PCI_MSI_DATA_32, // 8
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x3800,
        .emu_mask   = 0xFFFF,
        .init       = pt_msgdata_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_msgdata_reg_write,
    },
    /* Message Data reg (16 bits of data for 64-bit devices) */
    {
        .offset     = PCI_MSI_DATA_64, // 12
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x3800,
        .emu_mask   = 0xFFFF,
        .init       = pt_msgdata_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_msgdata_reg_write,
    },
    {
        .size = 0,
    }, 
};

/* MSI-X Capability Structure reg static infomation table */
static struct pt_reg_info_tbl pt_emu_reg_msix_tbl[] = {
    /* Next Pointer reg */
    {
        .offset     = PCI_CAP_LIST_NEXT,
        .size       = 1,
        .init_val   = 0x00,
        .ro_mask    = 0xFF,
        .emu_mask   = 0xFF,
        .init       = pt_ptr_reg_init,
        .u.b.read   = pt_byte_reg_read,
        .u.b.write  = pt_byte_reg_write,
    },
    /* Message Control reg */
    {
        .offset     = PCI_MSI_FLAGS, // 2
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x3FFF,
        .emu_mask   = 0x0000,
        .init       = pt_msixctrl_reg_init,
        .u.w.read   = pt_word_reg_read,
        .u.w.write  = pt_msixctrl_reg_write,
    },
    {
        .size = 0,
    }, 
};

/* pt_reg_grp_info_tbl declaration
 * - only for emulated or zero-hardwired register group.
 * - for register group with dynamic size, just set grp_size to 0xFF and 
 *   specify size_init func properly.
 * - no need to specify emu_reg_tbl for zero-hardwired type.
 */

/* emul reg group static infomation table */
static const struct pt_reg_grp_info_tbl pt_emu_reg_grp_tbl[] = {
    /* Header Type0 reg group */
    {
        .grp_id     = 0xFF,
        .grp_type   = GRP_TYPE_EMU,
        .grp_size   = 0x40,
        .size_init  = pt_reg_grp_size_init,
        .emu_reg_tbl= pt_emu_reg_header0_tbl,
    },
    /* PCI PowerManagement Capability reg group */
    {
        .grp_id     = PCI_CAP_ID_PM,
        .grp_type   = GRP_TYPE_EMU,
        .grp_size   = PCI_PM_SIZEOF,
        .size_init  = pt_reg_grp_size_init,
        .emu_reg_tbl= pt_emu_reg_pm_tbl,
    },
    /* AGP Capability Structure reg group */
    {
        .grp_id     = PCI_CAP_ID_AGP,
        .grp_type   = GRP_TYPE_HARDWIRED,
        .grp_size   = 0x30,
        .size_init  = pt_reg_grp_size_init,
    },
    /* Vital Product Data Capability Structure reg group */
    {
        .grp_id     = PCI_CAP_ID_VPD,
        .grp_type   = GRP_TYPE_EMU,
        .grp_size   = 0x08,
        .size_init  = pt_reg_grp_size_init,
        .emu_reg_tbl= pt_emu_reg_vpd_tbl,
    },
    /* Slot Identification reg group */
    {
        .grp_id     = PCI_CAP_ID_SLOTID,
        .grp_type   = GRP_TYPE_HARDWIRED,
        .grp_size   = 0x04,
        .size_init  = pt_reg_grp_size_init,
    },
    /* MSI Capability Structure reg group */
    {
        .grp_id     = PCI_CAP_ID_MSI,
        .grp_type   = GRP_TYPE_EMU,
        .grp_size   = 0xFF,
        .size_init  = pt_msi_size_init,
        .emu_reg_tbl= pt_emu_reg_msi_tbl,
    },
    /* PCI-X Capabilities List Item reg group */
    {
        .grp_id     = PCI_CAP_ID_PCIX,
        .grp_type   = GRP_TYPE_HARDWIRED,
        .grp_size   = 0x18,
        .size_init  = pt_reg_grp_size_init,
    },
    /* Vendor Specific Capability Structure reg group */
    {
        .grp_id     = PCI_CAP_ID_VNDR,
        .grp_type   = GRP_TYPE_EMU,
        .grp_size   = 0xFF,
        .size_init  = pt_vendor_size_init,
        .emu_reg_tbl= pt_emu_reg_vendor_tbl,
    },
    /* SHPC Capability List Item reg group */
    {
        .grp_id     = PCI_CAP_ID_HOTPLUG,
        .grp_type   = GRP_TYPE_HARDWIRED,
        .grp_size   = 0x08,
        .size_init  = pt_reg_grp_size_init,
    },
    /* Subsystem ID and Subsystem Vendor ID Capability List Item reg group */
    {
        .grp_id     = PCI_CAP_ID_SSVID,
        .grp_type   = GRP_TYPE_HARDWIRED,
        .grp_size   = 0x08,
        .size_init  = pt_reg_grp_size_init,
    },
    /* AGP 8x Capability Structure reg group */
    {
        .grp_id     = PCI_CAP_ID_AGP3,
        .grp_type   = GRP_TYPE_HARDWIRED,
        .grp_size   = 0x30,
        .size_init  = pt_reg_grp_size_init,
    },
    /* PCI Express Capability Structure reg group */
    {
        .grp_id     = PCI_CAP_ID_EXP,
        .grp_type   = GRP_TYPE_EMU,
        .grp_size   = 0x3C,
        .size_init  = pt_reg_grp_size_init,
        .emu_reg_tbl= pt_emu_reg_pcie_tbl,
    },
    /* MSI-X Capability Structure reg group */
    {
        .grp_id     = PCI_CAP_ID_MSIX,
        .grp_type   = GRP_TYPE_EMU,
        .grp_size   = 0x0C,
        .size_init  = pt_msix_size_init,
        .emu_reg_tbl= pt_emu_reg_msix_tbl,
    },
    {
        .grp_size = 0,
    }, 
};

static int token_value(char *token)
{
    return strtol(token, NULL, 16);
}

static int next_bdf(char **str, int *seg, int *bus, int *dev, int *func)
{
    char *token, *delim = ":.-";

    if ( !(*str) ||
          ( !strchr(*str, ':') && !strchr(*str, '.')) )
        return 0;

    token  = strsep(str, delim);
    *seg = token_value(token);

    token  = strsep(str, delim);
    *bus  = token_value(token);

    token  = strsep(str, delim);
    *dev  = token_value(token);

    token  = strsep(str, delim);
    *func  = token_value(token);

    return 1;
}

/* Insert a new pass-through device into a specific pci slot.
 * input  dom:bus:dev.func@slot, chose free one if slot == 0
 * return -1: required slot not available
 *         0: no free hotplug slots, but normal slot should okay
 *        >0: the new hotplug slot
 */
static int __insert_to_pci_slot(int bus, int dev, int func, int slot)
{
    int i, php_slot;

    /* preferred virt pci slot */
    if ( slot >= PHP_SLOT_START && slot < PHP_SLOT_END )
    {
        php_slot = PCI_TO_PHP_SLOT(slot);
        if ( !dpci_infos.php_devs[php_slot].valid )
        {
            goto found;
        }
        else
            return -1;
    }

    if ( slot != 0 )
        return -1;

    /* slot == 0, pick up a free one */
    for ( i = 0; i < PHP_SLOT_LEN; i++ )
    {
        if ( !dpci_infos.php_devs[i].valid )
        {
            php_slot = i;
            goto found;
        }
    }

    /* not found */
    return 0;

found:
    dpci_infos.php_devs[php_slot].valid  = 1;
    dpci_infos.php_devs[php_slot].r_bus  = bus;
    dpci_infos.php_devs[php_slot].r_dev  = dev;
    dpci_infos.php_devs[php_slot].r_func = func;
    return PHP_TO_PCI_SLOT(php_slot);
}

/* Insert a new pass-through device into a specific pci slot.
 * input  dom:bus:dev.func@slot
 */
int insert_to_pci_slot(char *bdf_slt)
{
    int seg, bus, dev, func, slot;
    char *bdf_str, *slt_str, *delim="@";

    bdf_str = strsep(&bdf_slt, delim);
    slt_str = bdf_slt;
    slot = token_value(slt_str);

    if ( !next_bdf(&bdf_str, &seg, &bus, &dev, &func))
    {
        return -1;
    }

    return __insert_to_pci_slot(bus, dev, func, slot);

}

/* Test if a pci slot has a device
 * 1:  present
 * 0:  not present
 * -1: invalide pci slot input
 */
int test_pci_slot(int slot)
{
    int php_slot;

    if ( slot < PHP_SLOT_START || slot >= PHP_SLOT_END )
        return -1;

    php_slot = PCI_TO_PHP_SLOT(slot);
    if ( dpci_infos.php_devs[php_slot].valid )
        return 1;
    else
        return 0;
}

/* find the pci slot for pass-through dev with specified BDF */
int bdf_to_slot(char *bdf_str)
{
    int seg, bus, dev, func, i;

    if ( !next_bdf(&bdf_str, &seg, &bus, &dev, &func))
    {
        return -1;
    }

    /* locate the virtual pci slot for this VTd device */
    for ( i = 0; i < PHP_SLOT_LEN; i++ )
    {
        if ( dpci_infos.php_devs[i].valid &&
           dpci_infos.php_devs[i].r_bus == bus &&
           dpci_infos.php_devs[i].r_dev  == dev &&
           dpci_infos.php_devs[i].r_func == func )
        {
            return PHP_TO_PCI_SLOT(i);
        }
    }

    return -1;
}

/* Being called each time a mmio region has been updated */
void pt_iomem_map(PCIDevice *d, int i, uint32_t e_phys, uint32_t e_size,
                  int type)
{
    struct pt_dev *assigned_device  = (struct pt_dev *)d; 
    uint32_t old_ebase = assigned_device->bases[i].e_physbase;
    int first_map = ( assigned_device->bases[i].e_size == 0 );
    int ret = 0;

    assigned_device->bases[i].e_physbase = e_phys;
    assigned_device->bases[i].e_size= e_size;

    PT_LOG("e_phys=%08x maddr=%lx type=%d len=%d index=%d first_map=%d\n",
        e_phys, (unsigned long)assigned_device->bases[i].access.maddr, 
        type, e_size, i, first_map);

    if ( e_size == 0 )
        return;

    if ( !first_map && old_ebase != -1 )
    {
        add_msix_mapping(assigned_device, i);
        /* Remove old mapping */
        ret = xc_domain_memory_mapping(xc_handle, domid,
                old_ebase >> XC_PAGE_SHIFT,
                assigned_device->bases[i].access.maddr >> XC_PAGE_SHIFT,
                (e_size+XC_PAGE_SIZE-1) >> XC_PAGE_SHIFT,
                DPCI_REMOVE_MAPPING);
        if ( ret != 0 )
        {
            PT_LOG("Error: remove old mapping failed!\n");
            return;
        }
    }

    /* map only valid guest address */
    if (e_phys != -1)
    {
        /* Create new mapping */
        ret = xc_domain_memory_mapping(xc_handle, domid,
                assigned_device->bases[i].e_physbase >> XC_PAGE_SHIFT,
                assigned_device->bases[i].access.maddr >> XC_PAGE_SHIFT,
                (e_size+XC_PAGE_SIZE-1) >> XC_PAGE_SHIFT,
                DPCI_ADD_MAPPING);

        if ( ret != 0 )
        {
            PT_LOG("Error: create new mapping failed!\n");
        }
        
        ret = remove_msix_mapping(assigned_device, i);
        if ( ret != 0 )
            PT_LOG("Error: remove MSI-X mmio mapping failed!\n");
    }
}

/* Being called each time a pio region has been updated */
void pt_ioport_map(PCIDevice *d, int i,
                   uint32_t e_phys, uint32_t e_size, int type)
{
    struct pt_dev *assigned_device  = (struct pt_dev *)d;
    uint32_t old_ebase = assigned_device->bases[i].e_physbase;
    int first_map = ( assigned_device->bases[i].e_size == 0 );
    int ret = 0;

    assigned_device->bases[i].e_physbase = e_phys;
    assigned_device->bases[i].e_size= e_size;

    PT_LOG("e_phys=%04x pio_base=%04x len=%d index=%d first_map=%d\n",
        (uint16_t)e_phys, (uint16_t)assigned_device->bases[i].access.pio_base,
        (uint16_t)e_size, i, first_map);

    if ( e_size == 0 )
        return;

    if ( !first_map && old_ebase != -1 )
    {
        /* Remove old mapping */
        ret = xc_domain_ioport_mapping(xc_handle, domid, old_ebase,
                    assigned_device->bases[i].access.pio_base, e_size,
                    DPCI_REMOVE_MAPPING);
        if ( ret != 0 )
        {
            PT_LOG("Error: remove old mapping failed!\n");
            return;
        }
    }

    /* map only valid guest address (include 0) */
    if (e_phys != -1)
    {
        /* Create new mapping */
        ret = xc_domain_ioport_mapping(xc_handle, domid, e_phys,
                    assigned_device->bases[i].access.pio_base, e_size,
                    DPCI_ADD_MAPPING);
        if ( ret != 0 )
        {
            PT_LOG("Error: create new mapping failed!\n");
        }
    }
}

/* find emulate register group entry */
struct pt_reg_grp_tbl* pt_find_reg_grp(
        struct pt_dev *ptdev, uint32_t address)
{
    struct pt_reg_grp_tbl* reg_grp_entry = NULL;

    /* find register group entry */
    for (reg_grp_entry = ptdev->reg_grp_tbl_head.lh_first; reg_grp_entry;
        reg_grp_entry = reg_grp_entry->entries.le_next)
    {
        /* check address */
        if ((reg_grp_entry->base_offset <= address) &&
            ((reg_grp_entry->base_offset + reg_grp_entry->size) > address))
            goto out;
    }
    /* group entry not found */
    reg_grp_entry = NULL;

out:
    return reg_grp_entry;
}

/* find emulate register entry */
struct pt_reg_tbl* pt_find_reg(
        struct pt_reg_grp_tbl* reg_grp, uint32_t address)
{
    struct pt_reg_tbl* reg_entry = NULL;
    struct pt_reg_info_tbl* reg = NULL;
    uint32_t real_offset = 0;

    /* find register entry */
    for (reg_entry = reg_grp->reg_tbl_head.lh_first; reg_entry;
        reg_entry = reg_entry->entries.le_next)
    {
        reg = reg_entry->reg;
        real_offset = (reg_grp->base_offset + reg->offset);
        /* check address */
        if ((real_offset <= address) && ((real_offset + reg->size) > address))
            goto out;
    }
    /* register entry not found */
    reg_entry = NULL;

out:
    return reg_entry;
}

/* get BAR index */
static int pt_bar_offset_to_index(uint32_t offset)
{
    int index = 0;

    /* check Exp ROM BAR */
    if (offset == PCI_ROM_ADDRESS)
    {
        index = PCI_ROM_SLOT;
        goto out;
    }

    /* calculate BAR index */
    index = ((offset - PCI_BASE_ADDRESS_0) >> 2);
    if (index >= PCI_NUM_REGIONS)
        index = -1;

out:
    return index;
}

static void pt_pci_write_config(PCIDevice *d, uint32_t address, uint32_t val,
                                int len)
{
    struct pt_dev *assigned_device = (struct pt_dev *)d;
    struct pci_dev *pci_dev = assigned_device->pci_dev;
    struct pt_reg_grp_tbl *reg_grp_entry = NULL;
    struct pt_reg_grp_info_tbl *reg_grp = NULL;
    struct pt_reg_tbl *reg_entry = NULL;
    struct pt_reg_info_tbl *reg = NULL;
    uint32_t find_addr = address;
    uint32_t real_offset = 0;
    uint32_t valid_mask = 0xFFFFFFFF;
    uint32_t read_val = 0;
    uint8_t *ptr_val = NULL;
    int emul_len = 0;
    int index = 0;
    int ret = 0;

#ifdef PT_DEBUG_PCI_CONFIG_ACCESS
    PT_LOG("[%02x:%02x.%x]: address=%04x val=0x%08x len=%d\n",
       pci_bus_num(d->bus), (d->devfn >> 3) & 0x1F, (d->devfn & 0x7),
       address, val, len);
#endif

    /* check offset range */
    if (address >= 0xFF)
    {
        PT_LOG("Failed to write register with offset exceeding FFh. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
            address, len);
        goto exit;
    }

    /* check write size */
    if ((len != 1) && (len != 2) && (len != 4))
    {
        PT_LOG("Failed to write register with invalid access length. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
            address, len);
        goto exit;
    }

    /* check offset alignment */
    if (address & (len-1))
    {
        PT_LOG("Failed to write register with invalid access size alignment. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
            address, len);
        goto exit;
    }

    /* check unused BAR register */
    index = pt_bar_offset_to_index(address);
    if ((index >= 0) && (val > 0 && val < PT_BAR_ALLF) &&
        (assigned_device->bases[index].bar_flag == PT_BAR_FLAG_UNUSED))
    {
        PT_LOG("Guest attempt to set address to unused Base Address Register. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), 
            (d->devfn & 0x7), address, len);
    }

    /* find register group entry */
    reg_grp_entry = pt_find_reg_grp(assigned_device, address);
    if (reg_grp_entry)
    {
        reg_grp = reg_grp_entry->reg_grp;
        /* check 0 Hardwired register group */
        if (reg_grp->grp_type == GRP_TYPE_HARDWIRED)
        {
            /* ignore silently */
            PT_LOG("Access to 0 Hardwired register. "
                "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
                pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), 
                (d->devfn & 0x7), address, len);
            goto exit;
        }
    }

    /* read I/O device register value */
    switch (len) {
    case 1:
        read_val = pci_read_byte(pci_dev, address);
        break;
    case 2:
        read_val = pci_read_word(pci_dev, address);
        break;
    case 4:
        read_val = pci_read_long(pci_dev, address);
        break;
    }

    /* check libpci error */
    valid_mask = (0xFFFFFFFF >> ((4 - len) << 3));
    if ((read_val & valid_mask) == valid_mask)
    {
        PT_LOG("libpci read error. No emulation. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
            address, len);
        goto exit;
    }
    
    /* pass directly to libpci for passthrough type register group */
    if (reg_grp_entry == NULL)
        goto out;

    /* adjust the write value to appropriate CFC-CFF window */
    val <<= ((address & 3) << 3);
    emul_len = len;

    /* loop Guest request size */
    while (0 < emul_len)
    {
        /* find register entry to be emulated */
        reg_entry = pt_find_reg(reg_grp_entry, find_addr);
        if (reg_entry)
        {
            reg = reg_entry->reg;
            real_offset = (reg_grp_entry->base_offset + reg->offset);
            valid_mask = (0xFFFFFFFF >> ((4 - emul_len) << 3));
            valid_mask <<= ((find_addr - real_offset) << 3);
            ptr_val = ((uint8_t *)&val + (real_offset & 3));

            /* do emulation depend on register size */
            switch (reg->size) {
            case 1:
                /* emulate write to byte register */
                if (reg->u.b.write)
                    ret = reg->u.b.write(assigned_device, reg_entry,
                               (uint8_t *)ptr_val, 
                               (uint8_t)(read_val >> ((real_offset & 3) << 3)),
                               (uint8_t)valid_mask);
                break;
            case 2:
                /* emulate write to word register */
                if (reg->u.w.write)
                    ret = reg->u.w.write(assigned_device, reg_entry,
                               (uint16_t *)ptr_val, 
                               (uint16_t)(read_val >> ((real_offset & 3) << 3)),
                               (uint16_t)valid_mask);
                break;
            case 4:
                /* emulate write to double word register */
                if (reg->u.dw.write)
                    ret = reg->u.dw.write(assigned_device, reg_entry,
                               (uint32_t *)ptr_val, 
                               (uint32_t)(read_val >> ((real_offset & 3) << 3)),
                               (uint32_t)valid_mask);
                break;
            }

            /* write emulation error */
            if (ret < 0)
            {
                /* exit I/O emulator */
                PT_LOG("Internal error: Invalid write emulation "
                    "return value[%d]. I/O emulator exit.\n", ret);
                exit(1);
            }

            /* calculate next address to find */
            emul_len -= reg->size;
            if (emul_len > 0)
                find_addr = real_offset + reg->size;
        }
        else
        {
            /* nothing to do with passthrough type register, 
             * continue to find next byte 
             */
            emul_len--;
            find_addr++;
        }
    }
    
    /* need to shift back before passing them to libpci */
    val >>= ((address & 3) << 3);

out:
    switch (len){
    case 1:
        pci_write_byte(pci_dev, address, val);
        break;
    case 2:
        pci_write_word(pci_dev, address, val);
        break;
    case 4:
        pci_write_long(pci_dev, address, val);
        break;
    }

exit:
    return;
}

static uint32_t pt_pci_read_config(PCIDevice *d, uint32_t address, int len)
{
    struct pt_dev *assigned_device = (struct pt_dev *)d;
    struct pci_dev *pci_dev = assigned_device->pci_dev;
    uint32_t val = 0xFFFFFFFF;
    struct pt_reg_grp_tbl *reg_grp_entry = NULL;
    struct pt_reg_grp_info_tbl *reg_grp = NULL;
    struct pt_reg_tbl *reg_entry = NULL;
    struct pt_reg_info_tbl *reg = NULL;
    uint32_t find_addr = address;
    uint32_t real_offset = 0;
    uint32_t valid_mask = 0xFFFFFFFF;
    uint8_t *ptr_val = NULL;
    int emul_len = 0;
    int ret = 0;

    /* check offset range */
    if (address >= 0xFF)
    {
        PT_LOG("Failed to read register with offset exceeding FFh. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
            address, len);
        goto exit;
    }

    /* check read size */
    if ((len != 1) && (len != 2) && (len != 4))
    {
        PT_LOG("Failed to read register with invalid access length. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
            address, len);
        goto exit;
    }

    /* check offset alignment */
    if (address & (len-1))
    {
        PT_LOG("Failed to read register with invalid access size alignment. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
            address, len);
        goto exit;
    }

    /* find register group entry */
    reg_grp_entry = pt_find_reg_grp(assigned_device, address);
    if (reg_grp_entry)
    {
        reg_grp = reg_grp_entry->reg_grp;
        /* check 0 Hardwired register group */
        if (reg_grp->grp_type == GRP_TYPE_HARDWIRED)
        {
            /* no need to emulate, just return 0 */
            val = 0;
            goto exit;
        }
    }

    /* read I/O device register value */
    switch (len) {
    case 1:
        val = pci_read_byte(pci_dev, address);
        break;
    case 2:
        val = pci_read_word(pci_dev, address);
        break;
    case 4:
        val = pci_read_long(pci_dev, address);
        break;
    }

    /* check libpci error */
    valid_mask = (0xFFFFFFFF >> ((4 - len) << 3));
    if ((val & valid_mask) == valid_mask)
    {
        PT_LOG("libpci read error. No emulation. "
            "[%02x:%02x.%x][Offset:%02xh][Length:%d]\n",
            pci_bus_num(d->bus), ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
            address, len);
        goto exit;
    }

    /* just return the I/O device register value for 
     * passthrough type register group 
     */
    if (reg_grp_entry == NULL)
        goto exit;

    /* adjust the read value to appropriate CFC-CFF window */
    val <<= ((address & 3) << 3);
    emul_len = len;

    /* loop Guest request size */
    while (0 < emul_len)
    {
        /* find register entry to be emulated */
        reg_entry = pt_find_reg(reg_grp_entry, find_addr);
        if (reg_entry)
        {
            reg = reg_entry->reg;
            real_offset = (reg_grp_entry->base_offset + reg->offset);
            valid_mask = (0xFFFFFFFF >> ((4 - emul_len) << 3));
            valid_mask <<= ((find_addr - real_offset) << 3);
            ptr_val = ((uint8_t *)&val + (real_offset & 3));

            /* do emulation depend on register size */
            switch (reg->size) {
            case 1:
                /* emulate read to byte register */
                if (reg->u.b.read)
                    ret = reg->u.b.read(assigned_device, reg_entry,
                                        (uint8_t *)ptr_val, 
                                        (uint8_t)valid_mask);
                break;
            case 2:
                /* emulate read to word register */
                if (reg->u.w.read)
                    ret = reg->u.w.read(assigned_device, reg_entry,
                                        (uint16_t *)ptr_val, 
                                        (uint16_t)valid_mask);
                break;
            case 4:
                /* emulate read to double word register */
                if (reg->u.dw.read)
                    ret = reg->u.dw.read(assigned_device, reg_entry,
                                        (uint32_t *)ptr_val, 
                                        (uint32_t)valid_mask);
                break;
            }

            /* read emulation error */
            if (ret < 0)
            {
                /* exit I/O emulator */
                PT_LOG("Internal error: Invalid read emulation "
                    "return value[%d]. I/O emulator exit.\n", ret);
                exit(1);
            }

            /* calculate next address to find */
            emul_len -= reg->size;
            if (emul_len > 0)
                find_addr = real_offset + reg->size;
        }
        else
        {
            /* nothing to do with passthrough type register, 
             * continue to find next byte 
             */
            emul_len--;
            find_addr++;
        }
    }
    
    /* need to shift back before returning them to pci bus emulator */
    val >>= ((address & 3) << 3);

exit:

#ifdef PT_DEBUG_PCI_CONFIG_ACCESS
    PT_LOG("[%02x:%02x.%x]: address=%04x val=0x%08x len=%d\n",
       pci_bus_num(d->bus), (d->devfn >> 3) & 0x1F, (d->devfn & 0x7),
       address, val, len);
#endif

    return val;
}

static int pt_register_regions(struct pt_dev *assigned_device)
{
    int i = 0;
    uint32_t bar_data = 0;
    struct pci_dev *pci_dev = assigned_device->pci_dev;
    PCIDevice *d = &assigned_device->dev;

    /* Register PIO/MMIO BARs */
    for ( i = 0; i < PCI_BAR_ENTRIES; i++ )
    {
        if ( pci_dev->base_addr[i] )
        {
            assigned_device->bases[i].e_physbase = pci_dev->base_addr[i];
            assigned_device->bases[i].access.u = pci_dev->base_addr[i];

            /* Register current region */
            bar_data = *((uint32_t*)(d->config + PCI_BASE_ADDRESS_0) + i);
            if ( bar_data & PCI_ADDRESS_SPACE_IO )
                pci_register_io_region((PCIDevice *)assigned_device, i,
                    (uint32_t)pci_dev->size[i], PCI_ADDRESS_SPACE_IO,
                    pt_ioport_map);
            else if ( bar_data & PCI_ADDRESS_SPACE_MEM_PREFETCH )
                pci_register_io_region((PCIDevice *)assigned_device, i,
                    (uint32_t)pci_dev->size[i], PCI_ADDRESS_SPACE_MEM_PREFETCH,
                    pt_iomem_map);
            else
                pci_register_io_region((PCIDevice *)assigned_device, i, 
                    (uint32_t)pci_dev->size[i], PCI_ADDRESS_SPACE_MEM,
                    pt_iomem_map);

            PT_LOG("IO region registered (size=0x%08x base_addr=0x%08x)\n",
                (uint32_t)(pci_dev->size[i]),
                (uint32_t)(pci_dev->base_addr[i]));
        }
    }

    /* Register expansion ROM address */
    if ( pci_dev->rom_base_addr && pci_dev->rom_size )
    {
        assigned_device->bases[PCI_ROM_SLOT].e_physbase =
            pci_dev->rom_base_addr;
        assigned_device->bases[PCI_ROM_SLOT].access.maddr =
            pci_dev->rom_base_addr;
        pci_register_io_region((PCIDevice *)assigned_device, PCI_ROM_SLOT,
            pci_dev->rom_size, PCI_ADDRESS_SPACE_MEM_PREFETCH,
            pt_iomem_map);

        PT_LOG("Expansion ROM registered (size=0x%08x base_addr=0x%08x)\n",
            (uint32_t)(pci_dev->rom_size), (uint32_t)(pci_dev->rom_base_addr));
    }

    return 0;
}

static void pt_unregister_regions(struct pt_dev *assigned_device)
{
    int i, type, ret;
    uint32_t e_size;
    PCIDevice *d = (PCIDevice*)assigned_device;

    for ( i = 0; i < PCI_NUM_REGIONS; i++ )
    {
        e_size = assigned_device->bases[i].e_size;
        if ( e_size == 0 )
            continue;

        type = d->io_regions[i].type;

        if ( type == PCI_ADDRESS_SPACE_MEM ||
             type == PCI_ADDRESS_SPACE_MEM_PREFETCH )
        {
            ret = xc_domain_memory_mapping(xc_handle, domid,
                    assigned_device->bases[i].e_physbase >> XC_PAGE_SHIFT,
                    assigned_device->bases[i].access.maddr >> XC_PAGE_SHIFT,
                    (e_size+XC_PAGE_SIZE-1) >> XC_PAGE_SHIFT,
                    DPCI_REMOVE_MAPPING);
            if ( ret != 0 )
            {
                PT_LOG("Error: remove old mem mapping failed!\n");
                continue;
            }

        }
        else if ( type == PCI_ADDRESS_SPACE_IO )
        {
            ret = xc_domain_ioport_mapping(xc_handle, domid,
                        assigned_device->bases[i].e_physbase,
                        assigned_device->bases[i].access.pio_base,
                        e_size,
                        DPCI_REMOVE_MAPPING);
            if ( ret != 0 )
            {
                PT_LOG("Error: remove old io mapping failed!\n");
                continue;
            }

        }
        
    }

}

uint8_t find_cap_offset(struct pci_dev *pci_dev, uint8_t cap)
{
    int id;
    int max_cap = 48;
    int pos = PCI_CAPABILITY_LIST;
    int status;

    status = pci_read_byte(pci_dev, PCI_STATUS);
    if ( (status & PCI_STATUS_CAP_LIST) == 0 )
        return 0;

    while ( max_cap-- )
    {
        pos = pci_read_byte(pci_dev, pos);
        if ( pos < 0x40 )
            break;

        pos &= ~3;
        id = pci_read_byte(pci_dev, pos + PCI_CAP_LIST_ID);

        if ( id == 0xff )
            break;
        if ( id == cap )
            return pos;

        pos += PCI_CAP_LIST_NEXT;
    }
    return 0;
}

/* parse BAR */
static int pt_bar_reg_parse(
        struct pt_dev *ptdev, struct pt_reg_info_tbl *reg)
{
    PCIDevice *d = &ptdev->dev;
    struct pt_region *region = NULL;
    PCIIORegion *r;
    uint32_t bar_64 = (reg->offset - 4);
    int bar_flag = PT_BAR_FLAG_UNUSED;
    int index = 0;
    int i;

    /* set again the BAR config because it has been overwritten
     * by pci_register_io_region()
     */
    for (i=reg->offset; i<(reg->offset + 4); i++)
        d->config[i] = pci_read_byte(ptdev->pci_dev, i);

    /* check 64bit BAR */
    index = pt_bar_offset_to_index(reg->offset);
    if ((index > 0) && (index < PCI_ROM_SLOT) &&
        (d->config[bar_64] & PCI_BASE_ADDRESS_MEM_TYPE_64))
    {
        region = &ptdev->bases[index-1];
        if (region->bar_flag != PT_BAR_FLAG_UPPER)
        {
            bar_flag = PT_BAR_FLAG_UPPER;
            goto out;
        }
    }

    /* check unused BAR */
    r = &d->io_regions[index];
    if (!r->size)
        goto out;

    /* check BAR I/O indicator */
    if (d->config[reg->offset] & PCI_BASE_ADDRESS_SPACE_IO)
        bar_flag = PT_BAR_FLAG_IO;
    else
        bar_flag = PT_BAR_FLAG_MEM;

out:
    return bar_flag;
}

/* mapping BAR */
static void pt_bar_mapping(struct pt_dev *ptdev, int io_enable, int mem_enable)
{
    PCIDevice *dev = (PCIDevice *)&ptdev->dev;
    PCIIORegion *r;
    struct pt_region *base = NULL;
    uint32_t r_size = 0, r_addr = -1;
    int ret = 0;
    int i;

    for (i=0; i<PCI_NUM_REGIONS; i++)
    {
        r = &dev->io_regions[i];

        /* check valid region */
        if (!r->size)
            continue;

        base = &ptdev->bases[i];
        /* skip unused BAR or upper 64bit BAR */
        if ((base->bar_flag == PT_BAR_FLAG_UNUSED) || 
           (base->bar_flag == PT_BAR_FLAG_UPPER))
               continue;

        /* copy region address to temporary */
        r_addr = r->addr;

        /* need unmapping in case I/O Space or Memory Space disable */
        if (((base->bar_flag == PT_BAR_FLAG_IO) && !io_enable ) ||
            ((base->bar_flag == PT_BAR_FLAG_MEM) && !mem_enable ))
            r_addr = -1;

        /* prevent guest software mapping memory resource to 00000000h */
        if ((base->bar_flag == PT_BAR_FLAG_MEM) && (r_addr == 0))
            r_addr = -1;

        /* align resource size (memory type only) */
        r_size = r->size;
        PT_GET_EMUL_SIZE(base->bar_flag, r_size);

        /* check overlapped address */
        ret = pt_chk_bar_overlap(dev->bus, dev->devfn, r_addr, r_size);
        if (ret > 0)
            PT_LOG("ptdev[%02x:%02x.%x][Region:%d][Address:%08xh][Size:%08xh] "
                "is overlapped.\n", pci_bus_num(dev->bus), 
                (dev->devfn >> 3) & 0x1F, (dev->devfn & 0x7),
                i, r_addr, r_size);

        /* check whether we need to update the mapping or not */
        if (r_addr != ptdev->bases[i].e_physbase)
        {
            /* mapping BAR */
            r->map_func((PCIDevice *)ptdev, i, r_addr, 
                         r_size, r->type);
        }
    }

    return;
}

/* initialize emulate register */
static int pt_config_reg_init(struct pt_dev *ptdev,
        struct pt_reg_grp_tbl *reg_grp,
        struct pt_reg_info_tbl *reg)
{
    struct pt_reg_tbl *reg_entry;
    uint32_t data = 0;
    int err = 0;

    /* allocate register entry */
    reg_entry = qemu_mallocz(sizeof(struct pt_reg_tbl));
    if (reg_entry == NULL)
    {
        PT_LOG("Failed to allocate memory.\n");
        err = -1;
        goto out;
    }

    /* initialize register entry */
    reg_entry->reg = reg;
    reg_entry->data = 0;

    if (reg->init)
    {
        /* initialize emulate register */
        data = reg->init(ptdev, reg_entry->reg,
                        (reg_grp->base_offset + reg->offset));
        if (data == PT_INVALID_REG)
        {
            /* free unused BAR register entry */
            free(reg_entry);
            goto out;
        }
        /* set register value */
        reg_entry->data = data;
    }
    /* list add register entry */
    QEMU_LIST_INSERT_HEAD(&reg_grp->reg_tbl_head, reg_entry, entries);

out:
    return err;
}

/* initialize emulate register group */
static int pt_config_init(struct pt_dev *ptdev)
{
    struct pt_reg_grp_tbl *reg_grp_entry = NULL;
    struct pt_reg_info_tbl *reg_tbl = NULL;
    uint32_t reg_grp_offset = 0;
    int i, j, err = 0;

    /* initialize register group list */
    QEMU_LIST_INIT(&ptdev->reg_grp_tbl_head);

    /* initialize register group */
    for (i=0; pt_emu_reg_grp_tbl[i].grp_size != 0; i++)
    {
        if (pt_emu_reg_grp_tbl[i].grp_id != 0xFF)
        {
            reg_grp_offset = (uint32_t)find_cap_offset(ptdev->pci_dev, 
                                 pt_emu_reg_grp_tbl[i].grp_id);
            if (!reg_grp_offset) 
                continue;
        }

        /* allocate register group table */
        reg_grp_entry = qemu_mallocz(sizeof(struct pt_reg_grp_tbl));
        if (reg_grp_entry == NULL)
        {
            PT_LOG("Failed to allocate memory.\n");
            err = -1;
            goto out;
        }

        /* initialize register group entry */
        QEMU_LIST_INIT(&reg_grp_entry->reg_tbl_head);

        /* need to declare here, to enable searching Cap Ptr reg 
         * (which is in the same reg group) when initializing Status reg 
         */
        QEMU_LIST_INSERT_HEAD(&ptdev->reg_grp_tbl_head, reg_grp_entry, entries);

        reg_grp_entry->base_offset = reg_grp_offset;
        reg_grp_entry->reg_grp = 
                (struct pt_reg_grp_info_tbl*)&pt_emu_reg_grp_tbl[i];
        if (pt_emu_reg_grp_tbl[i].size_init)
        {
            /* get register group size */
            reg_grp_entry->size = pt_emu_reg_grp_tbl[i].size_init(ptdev,
                                      reg_grp_entry->reg_grp, 
                                      reg_grp_offset);
        }

        if (pt_emu_reg_grp_tbl[i].grp_type == GRP_TYPE_EMU)
        {
            if (pt_emu_reg_grp_tbl[i].emu_reg_tbl)
            {
                reg_tbl = pt_emu_reg_grp_tbl[i].emu_reg_tbl;
                /* initialize capability register */
                for (j=0; reg_tbl->size != 0; j++, reg_tbl++)
                {
                    /* initialize capability register */
                    err = pt_config_reg_init(ptdev, reg_grp_entry, reg_tbl);
                    if (err < 0)
                        goto out;
                }
            }
        }
        reg_grp_offset = 0;
    }

out:
    return err;
}

/* delete all emulate register */
static void pt_config_delete(struct pt_dev *ptdev)
{
    struct pt_reg_grp_tbl *reg_grp_entry = NULL;
    struct pt_reg_tbl *reg_entry = NULL;

    /* free MSI/MSI-X info table */
    if (ptdev->msix)
        pt_msix_delete(ptdev);
    if (ptdev->msi)
        free(ptdev->msi);

    /* free all register group entry */
    while ((reg_grp_entry = ptdev->reg_grp_tbl_head.lh_first) != NULL)
    {
        /* free all register entry */
        while ((reg_entry = reg_grp_entry->reg_tbl_head.lh_first) != NULL)
        {
            QEMU_LIST_REMOVE(reg_entry, entries);
            qemu_free(reg_entry);
        }

        QEMU_LIST_REMOVE(reg_grp_entry, entries);
        qemu_free(reg_grp_entry);
    }
}

/* initialize common register value */
static uint32_t pt_common_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    return reg->init_val;
}

/* initialize Capabilities Pointer or Next Pointer register */
static uint32_t pt_ptr_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    uint32_t reg_field = (uint32_t)ptdev->dev.config[real_offset];
    int i;

    /* find capability offset */
    while (reg_field)
    {
        for (i=0; pt_emu_reg_grp_tbl[i].grp_size != 0; i++)
        {
            /* check whether the next capability 
             * should be exported to guest or not 
             */
            if (pt_emu_reg_grp_tbl[i].grp_id == ptdev->dev.config[reg_field])
            {
                if (pt_emu_reg_grp_tbl[i].grp_type == GRP_TYPE_EMU)
                    goto out;
                /* ignore the 0 hardwired capability, find next one */
                break;
            }
        }
        /* next capability */
        reg_field = (uint32_t)ptdev->dev.config[reg_field + 1];
    }

out:
    return reg_field;
}

/* initialize Status register */
static uint32_t pt_status_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    struct pt_reg_grp_tbl *reg_grp_entry = NULL;
    struct pt_reg_tbl *reg_entry = NULL;
    int reg_field = 0;

    /* find Header register group */
    reg_grp_entry = pt_find_reg_grp(ptdev, PCI_CAPABILITY_LIST);
    if (reg_grp_entry)
    {
        /* find Capabilities Pointer register */
        reg_entry = pt_find_reg(reg_grp_entry, PCI_CAPABILITY_LIST);
        if (reg_entry)
        {
            /* check Capabilities Pointer register */
            if (reg_entry->data)
                reg_field |= PCI_STATUS_CAP_LIST;
            else
                reg_field &= ~PCI_STATUS_CAP_LIST;
        }
        else
        {
            /* exit I/O emulator */
            PT_LOG("Internal error: Couldn't find pt_reg_tbl for "
                "Capabilities Pointer register. I/O emulator exit.\n");
            exit(1);
        }
    }
    else
    {
        /* exit I/O emulator */
        PT_LOG("Internal error: Couldn't find pt_reg_grp_tbl for Header. "
            "I/O emulator exit.\n");
        exit(1);
    }

    return reg_field;
}

/* initialize Interrupt Pin register */
static uint32_t pt_irqpin_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    int reg_field = 0;

    /* set Interrupt Pin register to use INTA# if it has */
    if (ptdev->dev.config[real_offset])
        reg_field = 0x01;

    return reg_field;
}

/* initialize BAR */
static uint32_t pt_bar_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    int reg_field = 0;
    int index;

    /* get BAR index */
    index = pt_bar_offset_to_index(reg->offset);
    if (index < 0)
    {
        /* exit I/O emulator */
        PT_LOG("Internal error: Invalid BAR index[%d]. "
            "I/O emulator exit.\n", index);
        exit(1);
    }

    /* set initial guest physical base address to -1 */
    ptdev->bases[index].e_physbase = -1;

    /* set BAR flag */
    ptdev->bases[index].bar_flag = pt_bar_reg_parse(ptdev, reg);
    if (ptdev->bases[index].bar_flag == PT_BAR_FLAG_UNUSED)
        reg_field = PT_INVALID_REG;

    return reg_field;
}

/* initialize Link Control 2 register */
static uint32_t pt_linkctrl2_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    int reg_field = 0;

    /* set Supported Link Speed */
    reg_field |= 
        (0x0F & 
         ptdev->dev.config[(real_offset - reg->offset) + PCI_EXP_LNKCAP]);

    return reg_field;
}

/* initialize Message Control register */
static uint32_t pt_msgctrl_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    PCIDevice *d = (struct PCIDevice *)ptdev;
    struct pci_dev *pdev = ptdev->pci_dev;
    uint32_t reg_field = 0;
    
    /* use I/O device register's value as initial value */
    reg_field |= *((uint16_t*)(d->config + real_offset));
    
    if (reg_field & PCI_MSI_FLAGS_ENABLE)
    {
        PT_LOG("MSI enabled already, disable first\n");
        pci_write_word(pdev, real_offset, reg_field & ~PCI_MSI_FLAGS_ENABLE);
    }
    ptdev->msi->flags |= (reg_field | MSI_FLAG_UNINIT);
    
    /* All register is 0 after reset, except first 4 byte */
    reg_field &= reg->ro_mask;
    
    return reg_field;
}

/* initialize Message Address register */
static uint32_t pt_msgaddr32_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    PCIDevice *d = (struct PCIDevice *)ptdev;
    uint32_t reg_field = 0;
    
    /* use I/O device register's value as initial value */
    reg_field |= *((uint32_t*)(d->config + real_offset));
    
    return reg_field;
}

/* initialize Message Upper Address register */
static uint32_t pt_msgaddr64_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    PCIDevice *d = (struct PCIDevice *)ptdev;
    uint32_t reg_field = 0;
    
    /* no need to initialize in case of 32 bit type */
    if (!(ptdev->msi->flags & PCI_MSI_FLAGS_64BIT))
        return PT_INVALID_REG;
    
    /* use I/O device register's value as initial value */
    reg_field |= *((uint32_t*)(d->config + real_offset));
    
    return reg_field;
}

/* this function will be called twice (for 32 bit and 64 bit type) */
/* initialize Message Data register */
static uint32_t pt_msgdata_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    PCIDevice *d = (struct PCIDevice *)ptdev;
    uint32_t flags = ptdev->msi->flags;
    uint32_t offset = reg->offset;
    
    /* check the offset whether matches the type or not */
    if (((offset == PCI_MSI_DATA_64) &&  (flags & PCI_MSI_FLAGS_64BIT)) ||
        ((offset == PCI_MSI_DATA_32) && !(flags & PCI_MSI_FLAGS_64BIT)))
        return *((uint16_t*)(d->config + real_offset));
    else
        return PT_INVALID_REG;
}

/* initialize Message Control register for MSI-X */
static uint32_t pt_msixctrl_reg_init(struct pt_dev *ptdev,
        struct pt_reg_info_tbl *reg, uint32_t real_offset)
{
    PCIDevice *d = (struct PCIDevice *)ptdev;
    struct pci_dev *pdev = ptdev->pci_dev;
    uint16_t reg_field = 0;
    
    /* use I/O device register's value as initial value */
    reg_field |= *((uint16_t*)(d->config + real_offset));
    
    if (reg_field & PCI_MSIX_ENABLE)
    {
        PT_LOG("MSIX enabled already, disable first\n");
        pci_write_word(pdev, real_offset, reg_field & ~PCI_MSIX_ENABLE);
        reg_field &= ~(PCI_MSIX_ENABLE | PCI_MSIX_MASK);
    }
    
    return reg_field;
}

/* get register group size */
static uint8_t pt_reg_grp_size_init(struct pt_dev *ptdev,
        struct pt_reg_grp_info_tbl *grp_reg, uint32_t base_offset)
{
    return grp_reg->grp_size;
}

/* get MSI Capability Structure register group size */
static uint8_t pt_msi_size_init(struct pt_dev *ptdev,
        struct pt_reg_grp_info_tbl *grp_reg, uint32_t base_offset)
{
    PCIDevice *d = &ptdev->dev;
    uint16_t msg_ctrl = 0;
    uint8_t msi_size = 0xa;

    msg_ctrl = *((uint16_t*)(d->config + (base_offset + PCI_MSI_FLAGS)));

    /* check 64 bit address capable & Per-vector masking capable */
    if (msg_ctrl & PCI_MSI_FLAGS_64BIT)
        msi_size += 4;
    if (msg_ctrl & PCI_MSI_FLAGS_MASK_BIT)
        msi_size += 10;

    ptdev->msi = malloc(sizeof(struct pt_msi_info));
    if ( !ptdev->msi )
    {
        /* exit I/O emulator */
        PT_LOG("error allocation pt_msi_info. I/O emulator exit.\n");
        exit(1);
    }
    memset(ptdev->msi, 0, sizeof(struct pt_msi_info));
    
    return msi_size;
}

/* get MSI-X Capability Structure register group size */
static uint8_t pt_msix_size_init(struct pt_dev *ptdev,
        struct pt_reg_grp_info_tbl *grp_reg, uint32_t base_offset)
{
    int ret = 0;

    ret = pt_msix_init(ptdev, base_offset);

    if (ret == -1)
    {
        /* exit I/O emulator */
        PT_LOG("Internal error: Invalid pt_msix_init return value[%d]. "
            "I/O emulator exit.\n", ret);
        exit(1);
    }

    return grp_reg->grp_size;
}

/* get Vendor Specific Capability Structure register group size */
static uint8_t pt_vendor_size_init(struct pt_dev *ptdev,
        struct pt_reg_grp_info_tbl *grp_reg, uint32_t base_offset)
{
    return ptdev->dev.config[base_offset + 0x02];
}

/* read byte size emulate register */
static int pt_byte_reg_read(struct pt_dev *ptdev,
        struct pt_reg_tbl *cfg_entry,
        uint8_t *value, uint8_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint8_t valid_emu_mask = 0;

    /* emulate byte register */
    valid_emu_mask = reg->emu_mask & valid_mask;
    *value = ((*value & ~valid_emu_mask) | 
              (cfg_entry->data & valid_emu_mask));

    return 0;
}

/* read word size emulate register */
static int pt_word_reg_read(struct pt_dev *ptdev,
        struct pt_reg_tbl *cfg_entry,
        uint16_t *value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t valid_emu_mask = 0;

    /* emulate word register */
    valid_emu_mask = reg->emu_mask & valid_mask;
    *value = ((*value & ~valid_emu_mask) | 
              (cfg_entry->data & valid_emu_mask));

    return 0;
}

/* read long size emulate register */
static int pt_long_reg_read(struct pt_dev *ptdev,
        struct pt_reg_tbl *cfg_entry,
        uint32_t *value, uint32_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint32_t valid_emu_mask = 0;

    /* emulate long register */
    valid_emu_mask = reg->emu_mask & valid_mask;
    *value = ((*value & ~valid_emu_mask) | 
              (cfg_entry->data & valid_emu_mask));

   return 0;
}

/* read BAR */
static int pt_bar_reg_read(struct pt_dev *ptdev,
        struct pt_reg_tbl *cfg_entry,
        uint32_t *value, uint32_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint32_t valid_emu_mask = 0;
    uint32_t bar_emu_mask = 0;
    int index;

    /* get BAR index */
    index = pt_bar_offset_to_index(reg->offset);
    if (index < 0)
    {
        /* exit I/O emulator */
        PT_LOG("Internal error: Invalid BAR index[%d]. "
            "I/O emulator exit.\n", index);
        exit(1);
    }

    /* set emulate mask depend on BAR flag */
    switch (ptdev->bases[index].bar_flag)
    {
    case PT_BAR_FLAG_MEM:
        bar_emu_mask = PT_BAR_MEM_EMU_MASK;
        break;
    case PT_BAR_FLAG_IO:
        bar_emu_mask = PT_BAR_IO_EMU_MASK;
        break;
    case PT_BAR_FLAG_UPPER:
        bar_emu_mask = PT_BAR_ALLF;
        break;
    default:
        break;
    }

    /* emulate BAR */
    valid_emu_mask = bar_emu_mask & valid_mask;
    *value = ((*value & ~valid_emu_mask) | 
              (cfg_entry->data & valid_emu_mask));

   return 0;
}

/* write byte size emulate register */
static int pt_byte_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint8_t *value, uint8_t dev_value, uint8_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint8_t writable_mask = 0;
    uint8_t throughable_mask = 0;

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write word size emulate register */
static int pt_word_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write long size emulate register */
static int pt_long_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint32_t *value, uint32_t dev_value, uint32_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write Command register */
static int pt_cmd_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t wr_value = *value;

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) | (dev_value & ~throughable_mask));

    /* mapping BAR */
    pt_bar_mapping(ptdev, wr_value & PCI_COMMAND_IO, 
                          wr_value & PCI_COMMAND_MEMORY);

    return 0;
}

/* write BAR */
static int pt_bar_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint32_t *value, uint32_t dev_value, uint32_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    struct pt_reg_grp_tbl *reg_grp_entry = NULL;
    struct pt_reg_tbl *reg_entry = NULL;
    struct pt_region *base = NULL;
    PCIDevice *d = (PCIDevice *)&ptdev->dev;
    PCIIORegion *r;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;
    uint32_t bar_emu_mask = 0;
    uint32_t bar_ro_mask = 0;
    uint32_t new_addr, last_addr;
    uint32_t prev_offset;
    uint32_t r_size = 0;
    int index = 0;

    /* get BAR index */
    index = pt_bar_offset_to_index(reg->offset);
    if (index < 0)
    {
        /* exit I/O emulator */
        PT_LOG("Internal error: Invalid BAR index[%d]. "
            "I/O emulator exit.\n", index);
        exit(1);
    }

    r = &d->io_regions[index];
    r_size = r->size;
    base = &ptdev->bases[index];
    /* align resource size (memory type only) */
    PT_GET_EMUL_SIZE(base->bar_flag, r_size);

    /* set emulate mask and read-only mask depend on BAR flag */
    switch (ptdev->bases[index].bar_flag)
    {
    case PT_BAR_FLAG_MEM:
        bar_emu_mask = PT_BAR_MEM_EMU_MASK;
        bar_ro_mask = PT_BAR_MEM_RO_MASK | (r_size - 1);
        break;
    case PT_BAR_FLAG_IO:
        bar_emu_mask = PT_BAR_IO_EMU_MASK;
        bar_ro_mask = PT_BAR_IO_RO_MASK | (r_size - 1);
        break;
    case PT_BAR_FLAG_UPPER:
        bar_emu_mask = PT_BAR_ALLF;
        bar_ro_mask = 0;    /* all upper 32bit are R/W */
        break;
    default:
        break;
    }

    /* modify emulate register */
    writable_mask = bar_emu_mask & ~bar_ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* check whether we need to update the virtual region address or not */
    switch (ptdev->bases[index].bar_flag)
    {
    case PT_BAR_FLAG_MEM:
        /* nothing to do */
        break;
    case PT_BAR_FLAG_IO:
        new_addr = cfg_entry->data;
        last_addr = new_addr + r_size - 1;
        /* check invalid address */
        if (last_addr <= new_addr || !new_addr || last_addr >= 0x10000)
        {
            /* check 64K range */
            if ((last_addr >= 0x10000) &&
                (cfg_entry->data != (PT_BAR_ALLF & ~bar_ro_mask)))
            {
                PT_LOG("Guest attempt to set Base Address over the 64KB. "
                    "[%02x:%02x.%x][Offset:%02xh][Address:%08xh][Size:%08xh]\n",
                    pci_bus_num(d->bus), 
                    ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
                    reg->offset, new_addr, r_size);
            }
            /* just remove mapping */
            r->addr = -1;
            goto exit;
        }
        break;
    case PT_BAR_FLAG_UPPER:
        if (cfg_entry->data)
        {
            if (cfg_entry->data != (PT_BAR_ALLF & ~bar_ro_mask))
            {
                PT_LOG("Guest attempt to set high MMIO Base Address. "
                    "Ignore mapping. "
                    "[%02x:%02x.%x][Offset:%02xh][High Address:%08xh]\n",
                    pci_bus_num(d->bus), 
                    ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
                    reg->offset, cfg_entry->data);
            }
            /* clear lower address */
            d->io_regions[index-1].addr = -1;
        }
        else
        {
            /* find lower 32bit BAR */
            prev_offset = (reg->offset - 4);
            reg_grp_entry = pt_find_reg_grp(ptdev, prev_offset);
            if (reg_grp_entry)
            {
                reg_entry = pt_find_reg(reg_grp_entry, prev_offset);
                if (reg_entry)
                    /* restore lower address */
                    d->io_regions[index-1].addr = reg_entry->data;
                else
                    return -1;
            }
            else
                return -1;
        }

        /* always keep the emulate register value to 0,
         * because hvmloader does not support high MMIO for now.
         */
        cfg_entry->data = 0;

        /* never mapping the 'empty' upper region,
         * because we'll do it enough for the lower region.
         */
        r->addr = -1;
        goto exit;
    default:
        break;
    }

    /* update the corresponding virtual region address */
    r->addr = cfg_entry->data;

exit:
    /* create value for writing to I/O device register */
    throughable_mask = ~bar_emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write Exp ROM BAR */
static int pt_exp_rom_bar_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint32_t *value, uint32_t dev_value, uint32_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    struct pt_region *base = NULL;
    PCIDevice *d = (PCIDevice *)&ptdev->dev;
    PCIIORegion *r;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;
    uint32_t r_size = 0;
    uint32_t bar_emu_mask = 0;
    uint32_t bar_ro_mask = 0;

    r = &d->io_regions[PCI_ROM_SLOT];
    r_size = r->size;
    base = &ptdev->bases[PCI_ROM_SLOT];
    /* align memory type resource size */
    PT_GET_EMUL_SIZE(base->bar_flag, r_size);

    /* set emulate mask and read-only mask */
    bar_emu_mask = reg->emu_mask;
    bar_ro_mask = reg->ro_mask | (r_size - 1);

    /* modify emulate register */
    writable_mask = bar_emu_mask & ~bar_ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* update the corresponding virtual region address */
    r->addr = cfg_entry->data;
    
    /* create value for writing to I/O device register */
    throughable_mask = ~bar_emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write Power Management Control/Status register */
static int pt_pmcsr_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t pmcsr_mask = (PCI_PM_CTRL_PME_ENABLE | 
                           PCI_PM_CTRL_DATA_SEL_MASK |
                           PCI_PM_CTRL_PME_STATUS);

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask & ~pmcsr_mask;
    /* ignore it when the requested state neither D3 nor D0 */
    if (((*value & PCI_PM_CTRL_STATE_MASK) != PCI_PM_CTRL_STATE_MASK) &&
        ((*value & PCI_PM_CTRL_STATE_MASK) != 0))
        writable_mask &= ~PCI_PM_CTRL_STATE_MASK;

    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write Device Control register */
static int pt_devctrl_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t devctrl_mask = (PCI_EXP_DEVCTL_AUX_PME | 0x8000);

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask & ~devctrl_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write Link Control register */
static int pt_linkctrl_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t linkctrl_mask = (PCI_EXP_LNKCTL_ASPM | 0x04 |
                              PCI_EXP_LNKCTL_DISABLE |
                              PCI_EXP_LNKCTL_RETRAIN | 
                              0x0400 | 0x0800 | 0xF000);

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask & ~linkctrl_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write Device Control2 register */
static int pt_devctrl2_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t devctrl2_mask = 0xFFE0;

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask & ~devctrl2_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write Link Control2 register */
static int pt_linkctrl2_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t linkctrl2_mask = (0x0040 | 0xE000);

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask & 
                    ~linkctrl2_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) |
              (dev_value & ~throughable_mask));

    return 0;
}

/* write Message Control register */
static int pt_msgctrl_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t old_ctrl = cfg_entry->data;
    PCIDevice *pd = (PCIDevice *)ptdev;

    /* Currently no support for multi-vector */
    if ((*value & PCI_MSI_FLAGS_QSIZE) != 0x0)
        PT_LOG("try to set more than 1 vector ctrl %x\n", *value);

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));
    /* update the msi_info too */
    ptdev->msi->flags |= cfg_entry->data & 
        ~(MSI_FLAG_UNINIT | PT_MSI_MAPPED | PCI_MSI_FLAGS_ENABLE);

    PT_LOG("old_ctrl:%04xh new_ctrl:%04xh\n", old_ctrl, cfg_entry->data);
    
    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) | (dev_value & ~throughable_mask));

    /* update MSI */
    if (*value & PCI_MSI_FLAGS_ENABLE)
    {
        /* setup MSI pirq for the first time */
        if (ptdev->msi->flags & MSI_FLAG_UNINIT)
        {
            /* Init physical one */
            PT_LOG("setup msi for dev %x\n", pd->devfn);
            if (pt_msi_setup(ptdev))
            {
                PT_LOG("pt_msi_setup error!!!\n");
                return -1;
            }
            pt_msi_update(ptdev);

            ptdev->msi->flags &= ~MSI_FLAG_UNINIT;
            ptdev->msi->flags |= PT_MSI_MAPPED;
        }
        ptdev->msi->flags |= PCI_MSI_FLAGS_ENABLE;
    }
    else
        ptdev->msi->flags &= ~PCI_MSI_FLAGS_ENABLE;

    return 0;
}

/* write Message Address register */
static int pt_msgaddr32_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint32_t *value, uint32_t dev_value, uint32_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;
    uint32_t old_addr = cfg_entry->data;

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));
    /* update the msi_info too */
    ptdev->msi->addr_lo = cfg_entry->data;
    
    PT_LOG("old_addr_lo:%08xh new_addr_lo:%08xh\n", old_addr, cfg_entry->data);
    
    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) | (dev_value & ~throughable_mask));

    /* update MSI */
    if (cfg_entry->data != old_addr)
    {
        if (ptdev->msi->flags & PCI_MSI_FLAGS_ENABLE)
            pt_msi_update(ptdev);
    }

    return 0;
}

/* write Message Upper Address register */
static int pt_msgaddr64_reg_write(struct pt_dev *ptdev, 
        struct pt_reg_tbl *cfg_entry, 
        uint32_t *value, uint32_t dev_value, uint32_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;
    uint32_t old_addr = cfg_entry->data;

    /* check whether the type is 64 bit or not */
    if (!(ptdev->msi->flags & PCI_MSI_FLAGS_64BIT))
    {
        /* exit I/O emulator */
        PT_LOG("why comes to Upper Address without 64 bit support??\n");
        return -1;
    }

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));
    /* update the msi_info too */
    ptdev->msi->addr_hi = cfg_entry->data;
    
    PT_LOG("old_addr_hi:%08xh new_addr_hi:%08xh\n", old_addr, cfg_entry->data);
    
    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) | (dev_value & ~throughable_mask));

    /* update MSI */
    if (cfg_entry->data != old_addr)
    {
        if (ptdev->msi->flags & PCI_MSI_FLAGS_ENABLE)
            pt_msi_update(ptdev);
    }

    return 0;
}

/* this function will be called twice (for 32 bit and 64 bit type) */
/* write Message Data register */
static int pt_msgdata_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t old_data = cfg_entry->data;
    uint32_t flags = ptdev->msi->flags;
    uint32_t offset = reg->offset;

    /* check the offset whether matches the type or not */
    if (!((offset == PCI_MSI_DATA_64) &&  (flags & PCI_MSI_FLAGS_64BIT)) &&
        !((offset == PCI_MSI_DATA_32) && !(flags & PCI_MSI_FLAGS_64BIT)))
    {
        /* exit I/O emulator */
        PT_LOG("Error: the offset is not match with the 32/64 bit type!!\n");
        return -1;
    }

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));
    /* update the msi_info too */
    ptdev->msi->data = cfg_entry->data;

    PT_LOG("old_data:%04xh new_data:%04xh\n", old_data, cfg_entry->data);

    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) | (dev_value & ~throughable_mask));

    /* update MSI */
    if (cfg_entry->data != old_data)
    {
        if (flags & PCI_MSI_FLAGS_ENABLE)
            pt_msi_update(ptdev);
    }

    return 0;
}

/* write Message Control register for MSI-X */
static int pt_msixctrl_reg_write(struct pt_dev *ptdev, 
    struct pt_reg_tbl *cfg_entry, 
    uint16_t *value, uint16_t dev_value, uint16_t valid_mask)
{
    struct pt_reg_info_tbl *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t old_ctrl = cfg_entry->data;

    /* modify emulate register */
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = ((*value & writable_mask) |
                       (cfg_entry->data & ~writable_mask));

    PT_LOG("old_ctrl:%04xh new_ctrl:%04xh\n", old_ctrl, cfg_entry->data);
    
    /* create value for writing to I/O device register */
    throughable_mask = ~reg->emu_mask & valid_mask;
    *value = ((*value & throughable_mask) | (dev_value & ~throughable_mask));

    /* update MSI-X */
    if ((*value & PCI_MSIX_ENABLE) && !(*value & PCI_MSIX_MASK))
        pt_msix_update(ptdev);

    ptdev->msix->enabled = !!(*value & PCI_MSIX_ENABLE);

    return 0;
}

struct pt_dev * register_real_device(PCIBus *e_bus,
        const char *e_dev_name, int e_devfn, uint8_t r_bus, uint8_t r_dev,
        uint8_t r_func, uint32_t machine_irq, struct pci_access *pci_access)
{
    int rc = -1, i;
    struct pt_dev *assigned_device = NULL;
    struct pci_dev *pci_dev;
    uint8_t e_device, e_intx;
    struct pci_config_cf8 machine_bdf;
    int free_pci_slot = -1;

    PT_LOG("Assigning real physical device %02x:%02x.%x ...\n",
        r_bus, r_dev, r_func);

    /* Find real device structure */
    for (pci_dev = pci_access->devices; pci_dev != NULL;
         pci_dev = pci_dev->next)
    {
        if ((r_bus == pci_dev->bus) && (r_dev == pci_dev->dev)
            && (r_func == pci_dev->func))
            break;
    }
    if ( pci_dev == NULL )
    {
        PT_LOG("Error: couldn't locate device in libpci structures\n");
        return NULL;
    }
    pci_fill_info(pci_dev, PCI_FILL_IRQ | PCI_FILL_BASES | PCI_FILL_ROM_BASE | PCI_FILL_SIZES);

    if ( e_devfn == PT_VIRT_DEVFN_AUTO ) {
        /*indicate a static assignment(not hotplug), so find a free PCI hot plug slot */
        free_pci_slot = __insert_to_pci_slot(r_bus, r_dev, r_func, 0);
        if ( free_pci_slot > 0 )
            e_devfn = free_pci_slot  << 3;
        else
            PT_LOG("Error: no free virtual PCI hot plug slot, thus no live migration.\n");
    }

    /* Register device */
    assigned_device = (struct pt_dev *) pci_register_device(e_bus, e_dev_name,
                                sizeof(struct pt_dev), e_devfn,
                                pt_pci_read_config, pt_pci_write_config);
    if ( assigned_device == NULL )
    {
        PT_LOG("Error: couldn't register real device\n");
        return NULL;
    }

    if ( free_pci_slot > 0 )
        dpci_infos.php_devs[PCI_TO_PHP_SLOT(free_pci_slot)].pt_dev = assigned_device;

    assigned_device->pci_dev = pci_dev;

    /* Assign device */
    machine_bdf.reg = 0;
    machine_bdf.bus = r_bus;
    machine_bdf.dev = r_dev;
    machine_bdf.func = r_func;
    rc = xc_assign_device(xc_handle, domid, machine_bdf.value);
    if ( rc < 0 )
        PT_LOG("Error: xc_assign_device error %d\n", rc);

    /* Initialize virtualized PCI configuration (Extended 256 Bytes) */
    for ( i = 0; i < PCI_CONFIG_SIZE; i++ )
        assigned_device->dev.config[i] = pci_read_byte(pci_dev, i);

    /* Handle real device's MMIO/PIO BARs */
    pt_register_regions(assigned_device);

    /* reinitialize each config register to be emulated */
    rc = pt_config_init(assigned_device);
    if ( rc < 0 ) {
        return NULL;
    }

    /* Bind interrupt */
    if (!assigned_device->dev.config[0x3d])
        goto out;

    e_device = (assigned_device->dev.devfn >> 3) & 0x1f;
    /* fix virtual interrupt pin to INTA# */
    e_intx = 0;

    if ( PT_MACHINE_IRQ_AUTO == machine_irq )
    {
        int pirq = pci_dev->irq;

        machine_irq = pci_dev->irq;
        rc = xc_physdev_map_pirq(xc_handle, domid, machine_irq, &pirq);

        if ( rc )
        {
            /* TBD: unregister device in case of an error */
            PT_LOG("Error: Mapping irq failed, rc = %d\n", rc);
        }
        else
            machine_irq = pirq;
    }

    /* bind machine_irq to device */
    if ( 0 != machine_irq )
    {
        rc = xc_domain_bind_pt_pci_irq(xc_handle, domid, machine_irq, 0,
                                       e_device, e_intx);
        if ( rc < 0 )
        {
            /* TBD: unregister device in case of an error */
            PT_LOG("Error: Binding of interrupt failed! rc=%d\n", rc);
        }
    }
    else {
        /* Disable PCI intx assertion (turn on bit10 of devctl) */
        assigned_device->dev.config[0x05] |= 0x04;
        pci_write_word(pci_dev, 0x04,
            *(uint16_t *)(&assigned_device->dev.config[0x04]));
    }

out:
    PT_LOG("Real physical device %02x:%02x.%x registered successfuly!\n", 
        r_bus, r_dev, r_func);

    return assigned_device;
}

int unregister_real_device(int php_slot)
{
    struct php_dev *php_dev;
    struct pci_dev *pci_dev;
    uint8_t e_device, e_intx;
    struct pt_dev *assigned_device = NULL;
    uint32_t machine_irq;
    uint32_t bdf = 0;
    int rc = -1;

    if ( php_slot < 0 || php_slot >= PHP_SLOT_LEN )
       return -1;

    php_dev = &dpci_infos.php_devs[php_slot];
    assigned_device = php_dev->pt_dev;

    if ( !assigned_device || !php_dev->valid )
        return -1;

    pci_dev = assigned_device->pci_dev;

    /* hide pci dev from qemu */
    pci_hide_device((PCIDevice*)assigned_device);

    /* Unbind interrupt */
    e_device = (assigned_device->dev.devfn >> 3) & 0x1f;
    /* fix virtual interrupt pin to INTA# */
    e_intx = 0;
    machine_irq = pci_dev->irq;

    if ( machine_irq != 0 ) {
        rc = xc_domain_unbind_pt_irq(xc_handle, domid, machine_irq, PT_IRQ_TYPE_PCI, 0,
                                       e_device, e_intx, 0);
        if ( rc < 0 )
        {
            /* TBD: unregister device in case of an error */
            PT_LOG("Error: Unbinding of interrupt failed! rc=%d\n", rc);
        }
    }

    /* delete all emulated config registers */
    pt_config_delete(assigned_device);

    /* unregister real device's MMIO/PIO BARs */
    pt_unregister_regions(assigned_device);
    
    /* deassign the dev to dom0 */
    bdf |= (pci_dev->bus  & 0xff) << 16;
    bdf |= (pci_dev->dev  & 0x1f) << 11;
    bdf |= (pci_dev->func & 0x1f) << 8;
    if ( (rc = xc_deassign_device(xc_handle, domid, bdf)) != 0)
        PT_LOG("Error: Revoking the device failed! rc=%d\n", rc);

    /* mark this slot as free */
    php_dev->valid = 0;
    php_dev->pt_dev = NULL;
    qemu_free(assigned_device);

    return 0;
}

int power_on_php_slot(int php_slot)
{
    struct php_dev *php_dev = &dpci_infos.php_devs[php_slot];
    int pci_slot = php_slot + PHP_SLOT_START;
    struct pt_dev *pt_dev;
    pt_dev = 
        register_real_device(dpci_infos.e_bus,
            "DIRECT PCI",
            pci_slot << 3,
            php_dev->r_bus,
            php_dev->r_dev,
            php_dev->r_func,
            PT_MACHINE_IRQ_AUTO,
            dpci_infos.pci_access);

    php_dev->pt_dev = pt_dev;

    return 0;

}

int power_off_php_slot(int php_slot)
{
    return unregister_real_device(php_slot);
}

int pt_init(PCIBus *e_bus, char *direct_pci)
{
    int seg, b, d, f, php_slot = 0;
    struct pt_dev *pt_dev;
    struct pci_access *pci_access;
    char *vslots;
    char slot_str[8];

    /* Initialize libpci */
    pci_access = pci_alloc();
    if ( pci_access == NULL )
    {
        PT_LOG("pci_access is NULL\n");
        return -1;
    }
    pci_init(pci_access);
    pci_scan_bus(pci_access);

    memset(&dpci_infos, 0, sizeof(struct dpci_infos));
    dpci_infos.pci_access = pci_access;
    dpci_infos.e_bus      = e_bus;

    if ( strlen(direct_pci) == 0 ) {
        return 0;
    }

    /* the virtual pci slots of all pass-through devs
     * with hex format: xx;xx...;
     */
    vslots = qemu_mallocz ( strlen(direct_pci) / 3 );

    /* Assign given devices to guest */
    while ( next_bdf(&direct_pci, &seg, &b, &d, &f) )
    {
        /* Register real device with the emulated bus */
        pt_dev = register_real_device(e_bus, "DIRECT PCI", PT_VIRT_DEVFN_AUTO,
            b, d, f, PT_MACHINE_IRQ_AUTO, pci_access);
        if ( pt_dev == NULL )
        {
            PT_LOG("Error: Registration failed (%02x:%02x.%x)\n", b, d, f);
            return -1;
        }

        /* Record the virtual slot info */
        if ( php_slot < PHP_SLOT_LEN &&
              dpci_infos.php_devs[php_slot].pt_dev == pt_dev )
        {
            sprintf(slot_str, "0x%x;", PHP_TO_PCI_SLOT(php_slot));
        }
        else
            sprintf(slot_str, "0x%x;", 0);

        strcat(vslots, slot_str);
        php_slot++;
    }

    /* Write virtual slots info to xenstore for Control panel use */
    xenstore_write_vslots(vslots);

    qemu_free(vslots);

    /* Success */
    return 0;
}

