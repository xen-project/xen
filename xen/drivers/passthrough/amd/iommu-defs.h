/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef AMD_IOMMU_DEFS_H
#define AMD_IOMMU_DEFS_H

/* IOMMU Command Buffer entries: in power of 2 increments, minimum of 256 */
#define IOMMU_CMD_BUFFER_DEFAULT_ENTRIES	512

/* IOMMU Event Log entries: in power of 2 increments, minimum of 256 */
#define IOMMU_EVENT_LOG_DEFAULT_ENTRIES     512

/* IOMMU PPR Log entries: in power of 2 increments, minimum of 256 */
#define IOMMU_PPR_LOG_DEFAULT_ENTRIES       512

#define PTE_PER_TABLE_SHIFT		9
#define PTE_PER_TABLE_SIZE		(1 << PTE_PER_TABLE_SHIFT)
#define PTE_PER_TABLE_MASK		(~(PTE_PER_TABLE_SIZE - 1))
#define PTE_PER_TABLE_ALIGN(entries) 	\
	(((entries) + PTE_PER_TABLE_SIZE - 1) & PTE_PER_TABLE_MASK)
#define PTE_PER_TABLE_ALLOC(entries)	\
	PAGE_SIZE * (PTE_PER_TABLE_ALIGN(entries) >> PTE_PER_TABLE_SHIFT)

#define amd_offset_level_address(offset, level) \
        ((uint64_t)(offset) << (12 + (PTE_PER_TABLE_SHIFT * ((level) - 1))))

/* IOMMU Capability */
#define PCI_CAP_ID_MASK		0x000000FF
#define PCI_CAP_ID_SHIFT	0
#define PCI_CAP_NEXT_PTR_MASK	0x0000FF00
#define PCI_CAP_NEXT_PTR_SHIFT	8
#define PCI_CAP_TYPE_MASK	0x00070000
#define PCI_CAP_TYPE_SHIFT	16
#define PCI_CAP_REV_MASK	0x00F80000
#define PCI_CAP_REV_SHIFT	19
#define PCI_CAP_IOTLB_MASK	0x01000000
#define PCI_CAP_IOTLB_SHIFT	24
#define PCI_CAP_HT_TUNNEL_MASK	0x02000000
#define PCI_CAP_HT_TUNNEL_SHIFT	25
#define PCI_CAP_NP_CACHE_MASK	0x04000000
#define PCI_CAP_NP_CACHE_SHIFT	26
#define PCI_CAP_EFRSUP_SHIFT    27
#define PCI_CAP_RESET_MASK	0x80000000
#define PCI_CAP_RESET_SHIFT	31

#define PCI_CAP_TYPE_IOMMU		0x3

#define PCI_CAP_MMIO_BAR_LOW_OFFSET	0x04
#define PCI_CAP_MMIO_BAR_HIGH_OFFSET	0x08
#define PCI_CAP_MMIO_BAR_LOW_MASK	0xFFFFC000
#define IOMMU_MMIO_REGION_LENGTH	0x4000

#define PCI_CAP_RANGE_OFFSET		0x0C
#define PCI_CAP_BUS_NUMBER_MASK		0x0000FF00
#define PCI_CAP_BUS_NUMBER_SHIFT	8
#define PCI_CAP_FIRST_DEVICE_MASK	0x00FF0000
#define PCI_CAP_FIRST_DEVICE_SHIFT	16
#define PCI_CAP_LAST_DEVICE_MASK	0xFF000000
#define PCI_CAP_LAST_DEVICE_SHIFT	24

#define PCI_CAP_UNIT_ID_MASK    0x0000001F
#define PCI_CAP_UNIT_ID_SHIFT   0
#define PCI_CAP_MISC_INFO_OFFSET    0x10
#define PCI_CAP_MSI_NUMBER_MASK     0x0000001F
#define PCI_CAP_MSI_NUMBER_SHIFT    0

/* Device Table */
#define IOMMU_DEV_TABLE_BASE_LOW_OFFSET		0x00
#define IOMMU_DEV_TABLE_BASE_HIGH_OFFSET	0x04
#define IOMMU_DEV_TABLE_SIZE_MASK		0x000001FF
#define IOMMU_DEV_TABLE_SIZE_SHIFT		0

#define IOMMU_DEV_TABLE_ENTRIES_PER_BUS		256
#define IOMMU_DEV_TABLE_ENTRY_SIZE		32
#define IOMMU_DEV_TABLE_U32_PER_ENTRY		(IOMMU_DEV_TABLE_ENTRY_SIZE / 4)

#define IOMMU_DEV_TABLE_SYS_MGT_DMA_ABORTED	0x0
#define IOMMU_DEV_TABLE_SYS_MGT_MSG_FORWARDED	0x1
#define IOMMU_DEV_TABLE_SYS_MGT_INT_FORWARDED	0x2
#define IOMMU_DEV_TABLE_SYS_MGT_DMA_FORWARDED	0x3

#define IOMMU_DEV_TABLE_IO_CONTROL_ABORTED	0x0
#define IOMMU_DEV_TABLE_IO_CONTROL_FORWARDED	0x1
#define IOMMU_DEV_TABLE_IO_CONTROL_TRANSLATED	0x2

#define IOMMU_DEV_TABLE_INT_CONTROL_ABORTED	0x0
#define IOMMU_DEV_TABLE_INT_CONTROL_FORWARDED	0x1
#define IOMMU_DEV_TABLE_INT_CONTROL_TRANSLATED	0x2

struct amd_iommu_dte {
    /* 0 - 63 */
    bool v:1;
    bool tv:1;
    unsigned int :5;
    unsigned int had:2;
    unsigned int paging_mode:3;
    uint64_t pt_root:40;
    bool ppr:1;
    bool gprp:1;
    bool giov:1;
    bool gv:1;
    unsigned int glx:2;
    unsigned int gcr3_trp_14_12:3;
    bool ir:1;
    bool iw:1;
    unsigned int :1;

    /* 64 - 127 */
    unsigned int domain_id:16;
    unsigned int gcr3_trp_30_15:16;
    bool i:1;
    bool se:1;
    bool sa:1;
    unsigned int ioctl:2;
    bool cache:1;
    bool sd:1;
    bool ex:1;
    unsigned int sys_mgt:2;
    unsigned int :1;
    unsigned int gcr3_trp_51_31:21;

    /* 128 - 191 */
    bool iv:1;
    unsigned int int_tab_len:4;
    bool ig:1;
    uint64_t it_root:46;
    unsigned int :4;
    bool init_pass:1;
    bool ext_int_pass:1;
    bool nmi_pass:1;
    unsigned int :1;
    unsigned int int_ctl:2;
    bool lint0_pass:1;
    bool lint1_pass:1;

    /* 192 - 255 */
    uint64_t :54;
    bool attr_v:1;
    bool mode0_fc:1;
    unsigned int snoop_attr:8;
};

/* Command Buffer */
#define IOMMU_CMD_BUFFER_BASE_LOW_OFFSET	0x08
#define IOMMU_CMD_BUFFER_BASE_HIGH_OFFSET	0x0C
#define IOMMU_CMD_BUFFER_HEAD_OFFSET		0x2000
#define IOMMU_CMD_BUFFER_TAIL_OFFSET		0x2008
#define IOMMU_CMD_BUFFER_LENGTH_MASK		0x0F000000
#define IOMMU_CMD_BUFFER_LENGTH_SHIFT		24

#define IOMMU_CMD_BUFFER_ENTRY_SIZE			16
#define IOMMU_CMD_BUFFER_POWER_OF2_ENTRIES_PER_PAGE	8

#define IOMMU_CMD_OPCODE_MASK			0xF0000000
#define IOMMU_CMD_OPCODE_SHIFT			28
#define IOMMU_CMD_COMPLETION_WAIT		0x1
#define IOMMU_CMD_INVALIDATE_DEVTAB_ENTRY	0x2
#define IOMMU_CMD_INVALIDATE_IOMMU_PAGES	0x3
#define IOMMU_CMD_INVALIDATE_IOTLB_PAGES	0x4
#define IOMMU_CMD_INVALIDATE_INT_TABLE		0x5
#define IOMMU_CMD_COMPLETE_PPR_REQUEST      0x7
#define IOMMU_CMD_INVALIDATE_IOMMU_ALL      0x8

/* COMPLETION_WAIT command */
#define IOMMU_COMP_WAIT_DATA_BUFFER_SIZE	8
#define IOMMU_COMP_WAIT_DATA_BUFFER_ALIGNMENT	8
#define IOMMU_COMP_WAIT_S_FLAG_MASK		0x00000001
#define IOMMU_COMP_WAIT_S_FLAG_SHIFT		0
#define IOMMU_COMP_WAIT_I_FLAG_MASK		0x00000002
#define IOMMU_COMP_WAIT_I_FLAG_SHIFT		1
#define IOMMU_COMP_WAIT_F_FLAG_MASK		0x00000004
#define IOMMU_COMP_WAIT_F_FLAG_SHIFT		2
#define IOMMU_COMP_WAIT_ADDR_LOW_MASK		0xFFFFFFF8
#define IOMMU_COMP_WAIT_ADDR_LOW_SHIFT		3
#define IOMMU_COMP_WAIT_ADDR_HIGH_MASK		0x000FFFFF
#define IOMMU_COMP_WAIT_ADDR_HIGH_SHIFT		0

/* INVALIDATE_IOMMU_PAGES command */
#define IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_MASK	0x0000FFFF
#define IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_SHIFT	0
#define IOMMU_INV_IOMMU_PAGES_S_FLAG_MASK	0x00000001
#define IOMMU_INV_IOMMU_PAGES_S_FLAG_SHIFT	0
#define IOMMU_INV_IOMMU_PAGES_PDE_FLAG_MASK	0x00000002
#define IOMMU_INV_IOMMU_PAGES_PDE_FLAG_SHIFT	1
#define IOMMU_INV_IOMMU_PAGES_ADDR_LOW_MASK	0xFFFFF000
#define IOMMU_INV_IOMMU_PAGES_ADDR_LOW_SHIFT	12
#define IOMMU_INV_IOMMU_PAGES_ADDR_HIGH_MASK	0xFFFFFFFF
#define IOMMU_INV_IOMMU_PAGES_ADDR_HIGH_SHIFT	0

/* INVALIDATE_DEVTAB_ENTRY command */
#define IOMMU_INV_DEVTAB_ENTRY_DEVICE_ID_MASK   0x0000FFFF
#define IOMMU_INV_DEVTAB_ENTRY_DEVICE_ID_SHIFT  0

/* INVALIDATE_INTERRUPT_TABLE command */
#define IOMMU_INV_INT_TABLE_DEVICE_ID_MASK   0x0000FFFF
#define IOMMU_INV_INT_TABLE_DEVICE_ID_SHIFT  0

/* INVALIDATE_IOTLB_PAGES command */
#define IOMMU_INV_IOTLB_PAGES_MAXPEND_MASK          0xff000000
#define IOMMU_INV_IOTLB_PAGES_MAXPEND_SHIFT         24
#define IOMMU_INV_IOTLB_PAGES_PASID1_MASK           0x00ff0000
#define IOMMU_INV_IOTLB_PAGES_PASID1_SHIFT          16
#define IOMMU_INV_IOTLB_PAGES_PASID2_MASK           0x0fff0000
#define IOMMU_INV_IOTLB_PAGES_PASID2_SHIFT          16
#define IOMMU_INV_IOTLB_PAGES_QUEUEID_MASK          0x0000ffff
#define IOMMU_INV_IOTLB_PAGES_QUEUEID_SHIFT         0
#define IOMMU_INV_IOTLB_PAGES_DEVICE_ID_MASK        0x0000FFFF
#define IOMMU_INV_IOTLB_PAGES_DEVICE_ID_SHIFT       0
#define IOMMU_INV_IOTLB_PAGES_ADDR_LOW_MASK         0xFFFFF000
#define IOMMU_INV_IOTLB_PAGES_ADDR_LOW_SHIFT        12
#define IOMMU_INV_IOTLB_PAGES_ADDR_HIGH_MASK        0xFFFFFFFF
#define IOMMU_INV_IOTLB_PAGES_ADDR_HIGH_SHIFT       0
#define IOMMU_INV_IOTLB_PAGES_S_FLAG_MASK           0x00000001
#define IOMMU_INV_IOTLB_PAGES_S_FLAG_SHIFT          0

/* Event Log */
#define IOMMU_EVENT_LOG_BASE_LOW_OFFSET		0x10
#define IOMMU_EVENT_LOG_BASE_HIGH_OFFSET	0x14
#define IOMMU_EVENT_LOG_HEAD_OFFSET		0x2010
#define IOMMU_EVENT_LOG_TAIL_OFFSET		0x2018
#define IOMMU_EVENT_LOG_LENGTH_MASK		0x0F000000
#define IOMMU_EVENT_LOG_LENGTH_SHIFT		24
#define IOMMU_EVENT_LOG_HEAD_MASK		0x0007FFF0
#define IOMMU_EVENT_LOG_HEAD_SHIFT		4
#define IOMMU_EVENT_LOG_TAIL_MASK		0x0007FFF0
#define IOMMU_EVENT_LOG_TAIL_SHIFT		4

#define IOMMU_EVENT_LOG_ENTRY_SIZE 			16
#define IOMMU_EVENT_LOG_POWER_OF2_ENTRIES_PER_PAGE	8
#define IOMMU_EVENT_LOG_U32_PER_ENTRY	(IOMMU_EVENT_LOG_ENTRY_SIZE / 4)

#define IOMMU_EVENT_CODE_MASK			0xF0000000
#define IOMMU_EVENT_CODE_SHIFT			28
#define IOMMU_EVENT_ILLEGAL_DEV_TABLE_ENTRY	0x1
#define IOMMU_EVENT_IO_PAGE_FAULT		0x2
#define IOMMU_EVENT_DEV_TABLE_HW_ERROR		0x3
#define IOMMU_EVENT_PAGE_TABLE_HW_ERROR		0x4
#define IOMMU_EVENT_ILLEGAL_COMMAND_ERROR	0x5
#define IOMMU_EVENT_COMMAND_HW_ERROR		0x6
#define IOMMU_EVENT_IOTLB_INV_TIMEOUT		0x7
#define IOMMU_EVENT_INVALID_DEV_REQUEST		0x8

#define IOMMU_EVENT_DOMAIN_ID_MASK           0x0000FFFF
#define IOMMU_EVENT_DOMAIN_ID_SHIFT          0
#define IOMMU_EVENT_DEVICE_ID_MASK           0x0000FFFF
#define IOMMU_EVENT_DEVICE_ID_SHIFT          0
#define IOMMU_EVENT_FLAGS_SHIFT              16
#define IOMMU_EVENT_FLAGS_MASK               0x0FFF0000

/* PPR Log */
#define IOMMU_PPR_LOG_ENTRY_SIZE                        16
#define IOMMU_PPR_LOG_POWER_OF2_ENTRIES_PER_PAGE        8
#define IOMMU_PPR_LOG_U32_PER_ENTRY   (IOMMU_PPR_LOG_ENTRY_SIZE / 4)

#define IOMMU_PPR_LOG_BASE_LOW_OFFSET                   0x0038
#define IOMMU_PPR_LOG_BASE_HIGH_OFFSET                  0x003C
#define IOMMU_PPR_LOG_BASE_LOW_MASK                     0xFFFFF000
#define IOMMU_PPR_LOG_BASE_LOW_SHIFT                    12
#define IOMMU_PPR_LOG_BASE_HIGH_MASK                    0x000FFFFF
#define IOMMU_PPR_LOG_BASE_HIGH_SHIFT                   0
#define IOMMU_PPR_LOG_LENGTH_MASK                       0x0F000000
#define IOMMU_PPR_LOG_LENGTH_SHIFT                      24
#define IOMMU_PPR_LOG_HEAD_MASK                         0x0007FFF0
#define IOMMU_PPR_LOG_HEAD_SHIFT                        4
#define IOMMU_PPR_LOG_TAIL_MASK                         0x0007FFF0
#define IOMMU_PPR_LOG_TAIL_SHIFT                        4
#define IOMMU_PPR_LOG_HEAD_OFFSET                       0x2030
#define IOMMU_PPR_LOG_TAIL_OFFSET                       0x2038
#define IOMMU_PPR_LOG_DEVICE_ID_MASK                    0x0000FFFF
#define IOMMU_PPR_LOG_DEVICE_ID_SHIFT                   0
#define IOMMU_PPR_LOG_CODE_MASK                         0xF0000000
#define IOMMU_PPR_LOG_CODE_SHIFT                        28

#define IOMMU_LOG_ENTRY_TIMEOUT                         1000

/* Control Register */
#define IOMMU_CONTROL_MMIO_OFFSET			0x18

union amd_iommu_control {
    uint64_t raw;
    struct {
        bool iommu_en:1;
        bool ht_tun_en:1;
        bool event_log_en:1;
        bool event_int_en:1;
        bool com_wait_int_en:1;
        unsigned int inv_timeout:3;
        bool pass_pw:1;
        bool res_pass_pw:1;
        bool coherent:1;
        bool isoc:1;
        bool cmd_buf_en:1;
        bool ppr_log_en:1;
        bool ppr_int_en:1;
        bool ppr_en:1;
        bool gt_en:1;
        bool ga_en:1;
        unsigned int crw:4;
        bool smif_en:1;
        bool slf_wb_dis:1;
        bool smif_log_en:1;
        unsigned int gam_en:3;
        bool ga_log_en:1;
        bool ga_int_en:1;
        unsigned int dual_ppr_log_en:2;
        unsigned int dual_event_log_en:2;
        unsigned int dev_tbl_seg_en:3;
        unsigned int priv_abrt_en:2;
        bool ppr_auto_rsp_en:1;
        bool marc_en:1;
        bool blk_stop_mrk_en:1;
        bool ppr_auto_rsp_aon:1;
        bool domain_id_pne:1;
        unsigned int :1;
        bool eph_en:1;
        unsigned int had_update:2;
        bool gd_update_dis:1;
        unsigned int :1;
        bool xt_en:1;
        bool int_cap_xt_en:1;
        bool vcmd_en:1;
        bool viommu_en:1;
        bool ga_update_dis:1;
        bool gappi_en:1;
        unsigned int :8;
    };
};

/* Exclusion Register */
#define IOMMU_EXCLUSION_BASE_LOW_OFFSET		0x20
#define IOMMU_EXCLUSION_BASE_HIGH_OFFSET	0x24
#define IOMMU_EXCLUSION_LIMIT_LOW_OFFSET	0x28
#define IOMMU_EXCLUSION_LIMIT_HIGH_OFFSET	0x2C
#define IOMMU_EXCLUSION_BASE_LOW_MASK		0xFFFFF000
#define IOMMU_EXCLUSION_BASE_LOW_SHIFT		12
#define IOMMU_EXCLUSION_BASE_HIGH_MASK		0xFFFFFFFF
#define IOMMU_EXCLUSION_BASE_HIGH_SHIFT		0
#define IOMMU_EXCLUSION_RANGE_ENABLE_MASK	0x00000001
#define IOMMU_EXCLUSION_RANGE_ENABLE_SHIFT	0
#define IOMMU_EXCLUSION_ALLOW_ALL_MASK		0x00000002
#define IOMMU_EXCLUSION_ALLOW_ALL_SHIFT		1
#define IOMMU_EXCLUSION_LIMIT_LOW_MASK		0xFFFFF000
#define IOMMU_EXCLUSION_LIMIT_LOW_SHIFT		12
#define IOMMU_EXCLUSION_LIMIT_HIGH_MASK		0xFFFFFFFF
#define IOMMU_EXCLUSION_LIMIT_HIGH_SHIFT	0

/* Extended Feature Register */
#define IOMMU_EXT_FEATURE_MMIO_OFFSET                   0x30

union amd_iommu_ext_features {
    uint64_t raw;
    struct {
        unsigned int pref_sup:1;
        unsigned int ppr_sup:1;
        unsigned int xt_sup:1;
        unsigned int nx_sup:1;
        unsigned int gt_sup:1;
        unsigned int gappi_sup:1;
        unsigned int ia_sup:1;
        unsigned int ga_sup:1;
        unsigned int he_sup:1;
        unsigned int pc_sup:1;
        unsigned int hats:2;
        unsigned int gats:2;
        unsigned int glx_sup:2;
        unsigned int smif_sup:2;
        unsigned int smif_rc:3;
        unsigned int gam_sup:3;
        unsigned int dual_ppr_log_sup:2;
        unsigned int :2;
        unsigned int dual_event_log_sup:2;
        unsigned int :1;
        unsigned int sats_sup:1;
        unsigned int pas_max:5;
        unsigned int us_sup:1;
        unsigned int dev_tbl_seg_sup:2;
        unsigned int ppr_early_of_sup:1;
        unsigned int ppr_auto_rsp_sup:1;
        unsigned int marc_sup:2;
        unsigned int blk_stop_mrk_sup:1;
        unsigned int perf_opt_sup:1;
        unsigned int msi_cap_mmio_sup:1;
        unsigned int :1;
        unsigned int gio_sup:1;
        unsigned int ha_sup:1;
        unsigned int eph_sup:1;
        unsigned int attr_fw_sup:1;
        unsigned int hd_sup:1;
        unsigned int :1;
        unsigned int inv_iotlb_type_sup:1;
        unsigned int viommu_sup:1;
        unsigned int vm_guard_io_sup:1;
        unsigned int vm_table_size:4;
        unsigned int ga_update_dis_sup:1;
        unsigned int :2;
    } flds;
};

/* x2APIC Control Registers */
#define IOMMU_XT_INT_CTRL_MMIO_OFFSET		0x0170
#define IOMMU_XT_PPR_INT_CTRL_MMIO_OFFSET	0x0178
#define IOMMU_XT_GA_INT_CTRL_MMIO_OFFSET	0x0180

union amd_iommu_x2apic_control {
    uint64_t raw;
    struct {
        unsigned int :2;
        unsigned int dest_mode:1;
        unsigned int :5;
        unsigned int dest_lo:24;
        unsigned int vector:8;
        unsigned int int_type:1; /* DM in IOMMU spec 3.04 */
        unsigned int :15;
        unsigned int dest_hi:8;
    };
};

/* Status Register*/
#define IOMMU_STATUS_MMIO_OFFSET		0x2020

#define IOMMU_STATUS_EVENT_LOG_OVERFLOW   0x00000001
#define IOMMU_STATUS_EVENT_LOG_INT        0x00000002
#define IOMMU_STATUS_COMP_WAIT_INT        0x00000004
#define IOMMU_STATUS_EVENT_LOG_RUN        0x00000008
#define IOMMU_STATUS_CMD_BUFFER_RUN       0x00000010
#define IOMMU_STATUS_PPR_LOG_OVERFLOW     0x00000020
#define IOMMU_STATUS_PPR_LOG_INT          0x00000040
#define IOMMU_STATUS_PPR_LOG_RUN          0x00000080
#define IOMMU_STATUS_GAPIC_LOG_OVERFLOW   0x00000100
#define IOMMU_STATUS_GAPIC_LOG_INT        0x00000200
#define IOMMU_STATUS_GAPIC_LOG_RUN        0x00000400

/* I/O Page Table */
#define IOMMU_PAGE_TABLE_ENTRY_SIZE	8
#define IOMMU_PAGE_TABLE_U32_PER_ENTRY	(IOMMU_PAGE_TABLE_ENTRY_SIZE / 4)
#define IOMMU_PAGE_TABLE_ALIGNMENT	4096

struct amd_iommu_pte {
    uint64_t pr:1;
    uint64_t ignored0:4;
    uint64_t a:1;
    uint64_t d:1;
    uint64_t ignored1:2;
    uint64_t next_level:3;
    uint64_t mfn:40;
    uint64_t reserved:7;
    uint64_t u:1;
    uint64_t fc:1;
    uint64_t ir:1;
    uint64_t iw:1;
    uint64_t ignored2:1;
};

/* Paging modes */
#define IOMMU_PAGING_MODE_DISABLED	0x0

/* Flags */
#define IOMMU_CONTROL_DISABLED	0
#define IOMMU_CONTROL_ENABLED	1

#define INV_IOMMU_ALL_PAGES_ADDRESS      ((1ULL << 63) - 1)

#define IOMMU_RING_BUFFER_PTR_MASK                  0x0007FFF0

#define IOMMU_CMD_DEVICE_ID_MASK                    0x0000FFFF
#define IOMMU_CMD_DEVICE_ID_SHIFT                   0

#define IOMMU_REG_BASE_ADDR_LOW_MASK                0xFFFFF000
#define IOMMU_REG_BASE_ADDR_LOW_SHIFT               12
#define IOMMU_REG_BASE_ADDR_HIGH_MASK               0x000FFFFF
#define IOMMU_REG_BASE_ADDR_HIGH_SHIFT              0

#endif /* AMD_IOMMU_DEFS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
